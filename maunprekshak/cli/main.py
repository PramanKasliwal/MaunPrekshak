import typer
import os
import subprocess
from pathlib import Path
from typing import List, Optional
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from maunprekshak import __version__
from maunprekshak.config import load_config, DEFAULT_CONFIG_TEMPLATE
from maunprekshak.scanner import scan_project
from maunprekshak.scanner.report import (
    to_json,
    to_markdown,
    to_pdf,
    to_sarif,
    generate_ai_summary,
    aggregate,
)

# Auto-load .env from the current directory or any parent directory
load_dotenv(dotenv_path=Path.cwd() / ".env", override=False)
load_dotenv(override=False)

app = typer.Typer(help="MaunPrekshak — The Silent Observer")
console = Console()


def get_git_staged_files(repo_path: str) -> List[str]:
    """Get list of files staged in git index."""
    try:
        res = subprocess.run(
            ["git", "diff", "--name-only", "--cached"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            check=True,
        )
        files = [f.strip() for f in res.stdout.splitlines() if f.strip()]
        return [os.path.abspath(os.path.join(repo_path, f)) for f in files]
    except Exception:
        return []


def get_git_diff_files(repo_path: str, ref: Optional[str] = None) -> List[str]:
    """Get list of modified files in working tree or against a ref."""
    try:
        cmd = ["git", "diff", "--name-only"]
        if ref:
            cmd.append(ref)
        res = subprocess.run(
            cmd,
            cwd=repo_path,
            capture_output=True,
            text=True,
            check=True,
        )
        files = [f.strip() for f in res.stdout.splitlines() if f.strip()]
        return [os.path.abspath(os.path.join(repo_path, f)) for f in files]
    except Exception:
        return []


@app.command()
def scan(
    path: str = typer.Argument(".", help="Path to project or directory to scan"),
    only: Optional[str] = typer.Option(None, help="Run only: deps, secrets, sast"),
    output: str = typer.Option("console", help="Output format: console, json, markdown, pdf, sarif"),
    output_file: Optional[str] = typer.Option(None, help="Save output to this file path"),
    ci: bool = typer.Option(False, help="CI mode: compact output, non-zero exit on threshold breach"),
    fail_on: Optional[str] = typer.Option(None, help="Fail CI if severity reached: critical, high, medium, low"),
    no_ai: bool = typer.Option(False, help="Skip Gemini AI summary generation"),
    exclude: Optional[str] = typer.Option(None, help="Comma-separated dirs to exclude (e.g. tests,fixtures)"),
    staged: bool = typer.Option(False, "--staged", help="Scan only git staged files (pre-commit mode)"),
    diff: Optional[str] = typer.Option(None, "--diff", help="Scan only git modified files against working tree or REF (e.g. HEAD~1)"),
):
    """Scan a project for CVE dependencies, exposed secrets, and AST code vulnerabilities."""
    cfg = load_config(path)

    # Exclusions precedence: CLI flag > .maunprekshak.toml > default
    if exclude:
        exclude_list = [e.strip() for e in exclude.split(",") if e.strip()]
    else:
        exclude_list = cfg.exclude

    effective_fail_on = fail_on if fail_on is not None else cfg.fail_on
    effective_no_ai = no_ai or cfg.no_ai

    target_files: Optional[List[str]] = None
    if staged:
        target_files = get_git_staged_files(path)
        if not target_files:
            if output == "console":
                console.print("[yellow]No staged files found in git repository. Nothing to scan.[/yellow]")
            return
        if output == "console":
            console.print(f"[bold cyan]Targeting {len(target_files)} staged file(s)...[/bold cyan]")
    elif diff is not None:
        ref = diff if diff.strip() else None
        target_files = get_git_diff_files(path, ref)
        if not target_files:
            if output == "console":
                console.print("[yellow]No modified files found in git diff. Nothing to scan.[/yellow]")
            return
        if output == "console":
            console.print(f"[bold cyan]Targeting {len(target_files)} modified file(s)...[/bold cyan]")

    with console.status("[bold green]Scanning project...") as status:
        result = scan_project(path, exclude=exclude_list, only=only, target_files=target_files)

        # Apply rule exclusions from config if specified
        if cfg.ignore_rules:
            result.sast = [s for s in result.sast if s.check_id not in cfg.ignore_rules]
            # Recalculate score after ignoring rules
            recalculated = aggregate(result.deps, result.secrets, result.sast)
            result.risk_score = recalculated.risk_score

        if not effective_no_ai:
            status.update("[bold green]Generating AI summary...")
            result.ai_summary = generate_ai_summary(result)

    if output == "json":
        out_str = to_json(result)
        if output_file:
            with open(output_file, "w") as f:
                f.write(out_str)
        else:
            print(out_str)
    elif output == "markdown":
        out_str = to_markdown(result)
        if output_file:
            with open(output_file, "w") as f:
                f.write(out_str)
        else:
            print(out_str)
    elif output == "sarif":
        out_str = to_sarif(result, project_root=path)
        if output_file:
            with open(output_file, "w") as f:
                f.write(out_str)
        else:
            print(out_str)
    elif output == "pdf" and output_file:
        to_pdf(result, output_file)
        console.print(f"[bold green]Saved PDF to {output_file}[/bold green]")
    else:
        # Console output
        console.print(
            Panel(
                f"[bold red]Risk Level: {result.risk_score.level}[/bold red] (Score: {result.risk_score.score})"
            )
        )
        if result.ai_summary:
            console.print("\n[bold]AI Summary:[/bold]")
            console.print(result.ai_summary)

    if ci:
        severity_map = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        threshold = severity_map.get(effective_fail_on.lower(), 4)
        breached = sum(
            severity_map.get(finding.severity.lower(), 0) >= threshold
            for finding in result.deps + result.secrets + result.sast
        )
        if breached:
            console.print(
                f"[bold red]CI Check Failed: {breached} finding(s) at or above {effective_fail_on.upper()}[/bold red]"
            )
            raise typer.Exit(code=1)


@app.command()
def init(
    path: str = typer.Option(".", help="Directory where .maunprekshak.toml will be created")
):
    """Initialize a default .maunprekshak.toml configuration file."""
    target = Path(path) / ".maunprekshak.toml"
    if target.exists():
        console.print(f"[yellow].maunprekshak.toml already exists at {target}[/yellow]")
        return
    with open(target, "w") as f:
        f.write(DEFAULT_CONFIG_TEMPLATE)
    console.print(f"[bold green]✓ Created configuration file at {target}[/bold green]")


@app.command()
def version():
    """Print the current version."""
    console.print(f"MaunPrekshak v{__version__}")


@app.command()
def auth_login():
    """Save API key."""
    key = typer.prompt("Enter API Key", hide_input=True)
    with open(os.path.expanduser("~/.maunprekshak.yaml"), "w") as f:
        f.write(f"api_key: {key}")
    console.print("[green]API Key saved.[/green]")


if __name__ == "__main__":
    app()
