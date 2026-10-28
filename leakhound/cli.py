"""Local scanning with fail-closed errors and redacted terminal output."""
import argparse
import math
import os
from pathlib import Path
import subprocess
from rich.console import Console
from rich.table import Table
from leakhound.detector import scan_text
from leakhound.hooks import install_hook

console = Console()
SKIP_DIRS = {'.git', '.hg', '.svn', 'venv', '.venv', 'node_modules', '__pycache__',
             'build', 'dist', '.pytest_cache', '.mypy_cache', '.tox'}
MAX_BYTES = 2 * 1024 * 1024


def git(*args):
    """Run Git without a shell. Never print captured blob data on failure."""
    try:
        return subprocess.run(['git', *args], capture_output=True, check=True).stdout
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        raise RuntimeError('Git command failed. Check that Git is installed and this is a repository.') from exc


def staged_sources():
    """Read exact staged blobs, including filenames containing spaces/newlines."""
    root = Path(os.fsdecode(git('rev-parse', '--show-toplevel').rstrip(b'\r\n')))
    names = git('-C', str(root), 'diff', '--cached', '--name-only', '-z', '--diff-filter=ACMRT')
    for raw in names.split(b'\0'):
        if not raw:
            continue
        name = os.fsdecode(raw)
        spec = ':' + name
        size = int(git('-C', str(root), 'cat-file', '-s', spec).strip())
        if size > MAX_BYTES:
            raise RuntimeError(f'Staged file exceeds 2 MiB scan limit: {name!r}. Split or remove it from the commit.')
        yield name, git('-C', str(root), 'show', spec)


def path_sources(target):
    if not target.exists():
        raise RuntimeError(f'Path does not exist: {str(target)!r}')
    if target.is_symlink():
        raise RuntimeError('Select the original file instead of a symlink.')
    paths = []
    if target.is_file():
        paths = [target]
    elif target.is_dir():
        def fail(exc):
            raise exc
        for root, dirs, files in os.walk(target, onerror=fail, followlinks=False):
            dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not d.endswith('.egg-info')
                             and not Path(root, d).is_symlink())
            paths.extend(Path(root, name) for name in sorted(files) if not Path(root, name).is_symlink())
    else:
        raise RuntimeError('Select a regular file or directory.')
    for path in paths:
        if path.stat().st_size > MAX_BYTES:
            raise RuntimeError(f'File exceeds 2 MiB scan limit: {str(path)!r}')
        yield str(path), path.read_bytes()


def main(argv=None):
    parser = argparse.ArgumentParser(prog='leakhound', description='Find potential secrets locally before committing.')
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--path', type=Path, help='Scan a file or directory, including hidden files.')
    mode.add_argument('--staged', action='store_true', help='Scan exact Git index contents, not working files.')
    mode.add_argument('--install-hook', action='store_true', help='Install a hook without overwriting an existing one.')
    parser.add_argument('--threshold', type=float, default=4.3, help='Entropy threshold from 0 to 6 (default: 4.3).')
    args = parser.parse_args(argv)
    if not math.isfinite(args.threshold) or not 0 <= args.threshold <= 6:
        parser.error('--threshold must be a finite number between 0 and 6')
    total = scanned = skipped = 0
    try:
        if args.install_hook:
            hook = install_hook()
            console.print(f'Pre-commit hook installed: {str(hook)!r}', markup=False)
            return 0
        sources = staged_sources() if args.staged else path_sources(args.path)
        for name, data in sources:
            try:
                if b'\0' in data:
                    raise UnicodeError
                content = data.decode('utf-8-sig')
            except UnicodeError:
                skipped += 1
                console.print(f'Skipped binary/non-UTF-8 file: {name!r}', markup=False)
                continue
            scanned += 1
            results = scan_text(content, args.threshold)
            if results:
                table = Table(title=f'Potential leaks: {name!r}', border_style='red')
                table.add_column('Line', justify='right')
                table.add_column('Type')
                table.add_column('Value')
                for result in results:
                    table.add_row(str(result['line']), result['type'], result['preview'])
                console.print(table)
                total += len(results)
    except (RuntimeError, OSError, ValueError) as exc:
        console.print(f'Scan error: {exc}', style='red', markup=False)
        return 2
    console.print(f'{scanned} text file(s) scanned; {skipped} binary/non-UTF-8 file(s) skipped.', markup=False)
    if total:
        console.print(f'SCAN FAILED: {total} potential secret(s). Remove staged credentials before committing.', style='red', markup=False)
        console.print('If a credential was exposed, revoke or rotate it. Adding .gitignore does not unstage tracked files.', markup=False)
        return 1
    console.print('No potential secrets found in scanned text. Heuristic checks cannot guarantee a secret-free commit.', style='green', markup=False)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
