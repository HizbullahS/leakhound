import contextlib
import io
import os
from pathlib import Path
import subprocess
import string
import tempfile
import unittest
from unittest.mock import patch

from rich.console import Console
from leakhound import cli
from leakhound.detector import calculate_shannon_entropy, scan_text


def fake_key():
    return 'AK' + 'IA' + '1234567890ABCDEF'


class DetectionTests(unittest.TestCase):
    def test_entropy(self):
        self.assertEqual(calculate_shannon_entropy(''), 0)
        self.assertEqual(calculate_shannon_entropy('aaaa'), 0)
        self.assertEqual(calculate_shannon_entropy('abcd'), 2)

    def test_patterns_and_redaction(self):
        cases = [fake_key(), 'gh' + 'p_' + 'a' * 36,
                 'github_' + 'pat_' + 'b' * 40,
                 'https://hooks.' + 'slack.com/services/T123/B456/' + 'x' * 24,
                 '-----BEGIN ' + 'PRIVATE KEY-----',
                 'Bearer ' + 'a' * 30]
        for value in cases:
            with self.subTest(value=value[:6]):
                findings = scan_text('prefix\n' + value, 6)
                self.assertTrue(findings)
                self.assertTrue(all(f['line'] == 2 for f in findings))
                self.assertTrue(all(f['preview'] == '[REDACTED]' for f in findings))

    def test_entropy_finding_and_no_double_count(self):
        token = string.ascii_lowercase + string.digits
        self.assertEqual(scan_text(token)[0]['type'], 'High-Entropy Secret')
        self.assertEqual(len(scan_text('gh' + 'p_' + token)), 1)
        self.assertEqual(scan_text('nothing sensitive here'), [])


class IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        previous = Path.cwd()
        os.chdir(self.tmp.name)
        self.addCleanup(os.chdir, previous)
        self.git('init', '-q')
        self.git('config', 'user.name', 'Test')
        self.git('config', 'user.email', 'test@example.invalid')
        self.git('config', 'core.autocrlf', 'false')

    def git(self, *args):
        return subprocess.run(['git', *args], check=True, capture_output=True)

    def run_cli(self, *args):
        output = io.StringIO()
        with patch.object(cli, 'console', Console(file=output, width=120, color_system=None)):
            code = cli.main(list(args))
        return code, output.getvalue()

    def test_staged_secret_cannot_be_hidden_by_clean_working_copy(self):
        path = Path('file with spaces.txt')
        path.write_text(fake_key(), encoding='utf-8')
        self.git('add', str(path))
        path.write_text('clean', encoding='utf-8')
        code, output = self.run_cli('--staged')
        self.assertEqual(code, 1)
        self.assertNotIn(fake_key(), output)
        self.assertIn('[REDACTED]', output)

    def test_unstaged_secret_is_not_part_of_staged_scan(self):
        path = Path('test.txt')
        path.write_text('clean', encoding='utf-8')
        self.git('add', str(path))
        path.write_text(fake_key(), encoding='utf-8')
        self.assertEqual(self.run_cli('--staged')[0], 0)

    def test_staged_scan_from_subdirectory(self):
        Path('test.txt').write_text(fake_key(), encoding='utf-8')
        self.git('add', '.')
        Path('nested').mkdir()
        os.chdir('nested')
        self.assertEqual(self.run_cli('--staged')[0], 1)

    def test_staged_deletion_is_ignored(self):
        Path('test.txt').write_text('clean', encoding='utf-8')
        self.git('add', '.')
        self.git('commit', '-qm', 'test')
        self.git('rm', 'test.txt')
        self.assertEqual(self.run_cli('--staged')[0], 0)

    def test_hook_preserves_existing_hook(self):
        self.assertEqual(self.run_cli('--install-hook')[0], 0)
        hook = Path('.git/hooks/pre-commit')
        before = hook.read_bytes()
        self.assertEqual(self.run_cli('--install-hook')[0], 2)
        self.assertEqual(hook.read_bytes(), before)

    def test_custom_hook_path(self):
        self.git('config', 'core.hooksPath', '.custom-hooks')
        self.assertEqual(self.run_cli('--install-hook')[0], 0)
        self.assertTrue(Path('.custom-hooks/pre-commit').exists())

    def test_missing_path_and_git_errors_fail(self):
        self.assertEqual(self.run_cli('--path', 'missing')[0], 2)
        with patch.object(cli, 'git', side_effect=RuntimeError('Git failed')):
            self.assertEqual(self.run_cli('--staged')[0], 2)

    def test_binary_files_reported_and_large_files_fail(self):
        Path('binary').write_bytes(b'\x00\xff')
        code, output = self.run_cli('--path', 'binary')
        self.assertEqual(code, 0)
        self.assertIn('1 binary/non-UTF-8', output)
        Path('large').write_bytes(b'a' * (cli.MAX_BYTES + 1))
        self.assertEqual(self.run_cli('--path', 'large')[0], 2)

    def test_hidden_env_scanned_but_virtual_environment_skipped(self):
        Path('venv').mkdir()
        Path('venv/key').write_text(fake_key(), encoding='utf-8')
        self.assertEqual(self.run_cli('--path', '.')[0], 0)
        Path('.env').write_text(fake_key(), encoding='utf-8')
        self.assertEqual(self.run_cli('--path', '.')[0], 1)

    def test_invalid_threshold(self):
        for value in ['nan', 'inf', '-1', '7']:
            with self.subTest(value=value), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as result:
                    self.run_cli('--staged', '--threshold', value)
                self.assertEqual(result.exception.code, 2)


if __name__ == '__main__':
    unittest.main()
