import argparse
import subprocess
import sys
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from leakhound.detector import scan_text

console = Console()

def get_git_staged_files():
    """Retrieves list of files staged in Git via shell."""
    try:
        proc = subprocess.run(
            ["git", "diff", "--cached", "--name-only"],
            capture_output=True,
            text=True,
            check=True
        )
        return [f.strip() for f in proc.stdout.splitlines() if f.strip()]
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []

def main():
    parser = argparse.ArgumentParser(
        prog="leakhound",
        description="CLI tool to detect secrets and tokens before committing."
    )
    parser.add_argument("--path", type=str, help="Scan a directory or file directly.")
    parser.add_argument("--staged", action="store_true", help="Scan only git-staged files.")
    parser.add_argument("--threshold", type=float, default=4.3, help="Shannon entropy threshold.")

    args = parser.parse_args()

    files = []
    if args.staged:
        files = [Path(p) for p in get_git_staged_files()]
        if not files:
            console.print("[dim]No staged files found in git.[/dim]")
            sys.exit(0)
    elif args.path:
        target = Path(args.path)
        files = [target] if target.is_file() else list(target.rglob("*"))
    else:
        parser.print_help()
        sys.exit(0)

    total_leaks = 0

    for file_path in files:
        if not file_path.is_file() or ".git" in file_path.parts:
            continue

        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
            results = scan_text(content, args.threshold)

            if results:
                total_leaks += len(results)
                table = Table(title=f"Potential Leaks: {file_path}", border_style="red")
                table.add_column("Line", justify="right", style="cyan")
                table.add_column("Type", style="magenta")
                table.add_column("Snippet Preview", style="white")

                for res in results:
                    table.add_row(str(res["line"]), res["type"], res["preview"])

                console.print(table)
        except PermissionError:
            continue

    if total_leaks > 0:
        console.print(Panel(
            f"[bold red]SCAN FAILED: {total_leaks} potential leak(s) detected![/bold red]\n"
            "[yellow]Remove the secrets or adjust your .gitignore before committing.[/yellow]",
            border_style="red"
        ))
        sys.exit(1)
    else:
        console.print("[bold green]✔ Scan passed. No secrets detected.[/bold green]")
        sys.exit(0)

if __name__ == "__main__":
    main()
