import typer
import os
from pathlib import Path
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from maunprekshak import __version__
from maunprekshak.scanner import scan_project
from maunprekshak.scanner.report import to_json, to_markdown, to_pdf, generate_ai_summary

# Auto-load .env from the current directory or any parent directory
# This means `mp scan .` will pick up .env automatically
load_dotenv(dotenv_path=Path.cwd() / ".env", override=False)
load_dotenv(override=False)  # Also check current working dir

app = typer.Typer(help="MaunPrekshak — The Silent Observer")
console = Console()

@app.command()
def scan(
    path: str,
    only: str = typer.Option(None, help="Run only: deps, secrets, sast"),
    output: str = typer.Option("console", help="Output format: console, json, markdown, pdf"),
    output_file: str = typer.Option(None, help="Save output to this file path"),
    ci: bool = typer.Option(False, help="CI mode: compact output, non-zero exit on threshold breach"),
    fail_on: str = typer.Option("critical", help="Fail CI if severity reached: critical, high, medium, low"),
    no_ai: bool = typer.Option(False, help="Skip Gemini AI summary generation"),
    exclude: str = typer.Option(None, help="Comma-separated dirs to exclude (e.g. tests,fixtures)"),
):
    """Scan a Python project for security vulnerabilities, secrets, and insecure patterns."""
    with console.status("[bold green]Scanning project...") as status:
        result = scan_project(path)
        
        if not no_ai:
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
    elif output == "pdf" and output_file:
        to_pdf(result, output_file)
        console.print(f"[bold green]Saved PDF to {output_file}[/bold green]")
    else:
        # Console output
        console.print(Panel(f"[bold red]Risk Level: {result.risk_score.level}[/bold red] (Score: {result.risk_score.score})"))
        if result.ai_summary:
            console.print("\n[bold]AI Summary:[/bold]")
            console.print(result.ai_summary)
            
        if ci:
            severity_map = {"low": 1, "medium": 21, "high": 51, "critical": 100}
            threshold = severity_map.get(fail_on.lower(), 100)
            if result.risk_score.score >= threshold:
                console.print(f"[bold red]CI Check Failed: Score {result.risk_score.score} >= {threshold}[/bold red]")
                raise typer.Exit(code=1)

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
