"""Install a portable hook without replacing user-owned hooks."""
from pathlib import Path
import subprocess

HOOK = '''#!/bin/sh
# Installed by LeakHound. Requires leakhound on PATH.
if ! command -v leakhound >/dev/null 2>&1; then
    echo "LeakHound is unavailable. Activate its environment before committing." >&2
    exit 2
fi
exec leakhound --staged
'''


def install_hook():
    try:
        subprocess.run(['git', 'rev-parse', '--git-dir'], capture_output=True, check=True)
        result = subprocess.run(['git', 'rev-parse', '--git-path', 'hooks/pre-commit'],
                                capture_output=True, text=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        raise RuntimeError('Hook installation requires Git and a repository.') from exc
    path = Path(result.stdout.strip())
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open('x', encoding='utf-8', newline='\n') as stream:
            stream.write(HOOK)
    except FileExistsError as exc:
        raise RuntimeError('An existing pre-commit hook was preserved. Integrate leakhound --staged manually.') from exc
    path.chmod(path.stat().st_mode | 0o111)
    return path
