# LeakHound

**Catch potential secrets before they become a commit.**

[![Tests](https://github.com/HizbullahS/leakhound/actions/workflows/tests.yml/badge.svg)](https://github.com/HizbullahS/leakhound/actions/workflows/tests.yml)
![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-3776AB?logo=python&logoColor=white)
![Runs locally](https://img.shields.io/badge/scanning-local_only-2ea44f)

LeakHound is a small Python CLI that combines known credential patterns with Shannon entropy checks. Scan a file, a folder, or the exact content staged in Git. Findings show the file, line, and detection type; credential values stay redacted.

```text
leakhound --staged

Potential leaks: 'config.py'
┏━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━┓
┃ Line ┃ Type           ┃ Value      ┃
┡━━━━━━╇━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━┩
│    7 │ AWS Access Key │ [REDACTED] │
└──────┴────────────────┴────────────┘
SCAN FAILED: 1 potential secret(s).
```

*Illustrative output; no real credentials are included.*

## Why LeakHound?

- **Scan what you commit:** staged mode reads the Git index, including partially staged files, rather than your working copy.
- **Two detection approaches:** recognizable credential formats plus high-entropy strings.
- **Keep values out of logs:** findings are fully redacted, including surrounding source text.
- **Stay local:** scanning makes no network requests.
- **Protect your setup:** hook installation preserves existing hooks and supports Git's configured hook path.
- **Fail visibly:** missing paths, Git failures, unreadable files, and oversized text inputs return an error.

## Install

Requires Python **3.10+**. Git is required for staged scans and hook installation.

```sh
git clone https://github.com/HizbullahS/leakhound.git
cd leakhound
python -m venv .venv
```

Activate the environment:

```powershell
# Windows PowerShell
.\.venv\Scripts\Activate.ps1
```

```sh
# macOS / Linux
source .venv/bin/activate
```

Then install:

```sh
python -m pip install -e .
leakhound --help
```

## Usage

```sh
# Scan one file or a directory
leakhound --path ./src

# Scan only staged content in the current Git repository
leakhound --staged

# Lower the entropy threshold to flag more strings
leakhound --path ./src --threshold 3.8

# Install in the repository you want to protect
leakhound --install-hook
```

The default entropy threshold is **4.3**; accepted values are **0–6**. Lower values increase sensitivity and false positives. Format-based rules remain active at every threshold. Tokens must be at least 24 characters to receive an entropy check.

The hook runs `leakhound --staged` before a commit. Keep the environment active so the command is on `PATH`. If you already have a hook, integrate that command into it manually. Uninstall by removing only the LeakHound hook or command you installed.

| Exit code | Meaning |
| --- | --- |
| `0` | No findings in scanned text; includes an empty staging area |
| `1` | Potential secrets found |
| `2` | Invalid arguments, scan error, or hook installation error |

## Detection coverage

| Rule | What it looks for |
| --- | --- |
| AWS access key | `AKIA` or `ASIA` followed by 16 uppercase letters/digits |
| GitHub personal token | Classic `ghp_` token format |
| GitHub fine-grained token | `github_pat_` token-like strings |
| Slack webhook | Slack incoming webhook URL format |
| Private key | Common PEM/OpenSSH private-key headers |
| Bearer token | Long token-like values following `Bearer` |
| High entropy | Diverse strings of 24+ supported characters |

These are heuristics, not credential validation. Matches can be false positives, and secrets can be missed. Entropy checks may flag hashes, generated identifiers, or documentation links. A format match is not also reported as an overlapping entropy match.

## Scan boundaries

Directory mode includes hidden files, including `.env`, but skips common environment/build folders and symbolic links. It does **not** use `.gitignore` as a scan exclusion list. Staged mode checks all added, copied, modified, renamed, or type-changed files in the index, regardless of directory exclusions, and ignores deletions.

Binary files (NUL bytes) and non-UTF-8 files are explicitly reported as skipped. The per-file limit is **2 MiB**; larger files return error code `2`. This tool does not scan Git history, archives, remote repositories, or decoded binary formats. A passing result is not a guarantee that your repository contains no secrets.

If you find a real credential, remove it from the index and rotate/revoke it if exposed. Adding a tracked file to `.gitignore` does not remove its staged contents or its history.

## Development

```sh
python -m unittest discover -s tests -v
python -m pip wheel . --no-deps --wheel-dir dist
```

Tests exercise redaction, entropy and format detection, staged-versus-working-copy behavior, filenames with spaces, deleted files, hook preservation, and error handling. GitHub Actions runs the suite on Windows and Linux with Python 3.10 and 3.14.

See [Contributing](CONTRIBUTING.md), [Security](SECURITY.md), and [Architecture](docs/architecture.md).
