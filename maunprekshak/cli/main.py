import json
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
    to_cyclonedx,
    to_spdx,
    to_html,
    to_gitlab,
    format_github_annotations,
    generate_ai_summary,
    aggregate,
)
from maunprekshak.scanner.fixer import apply_auto_fixes, fix_requirements_txt

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
    only: Optional[str] = typer.Option(None, help="Run only: deps, secrets, sast, k8s"),
    output: str = typer.Option("console", help="Output format: console, json, markdown, pdf, sarif, cyclonedx, spdx, html, gitlab"),
    output_file: Optional[str] = typer.Option(None, help="Save output to this file path"),
    ci: bool = typer.Option(False, help="CI mode: compact output, non-zero exit on threshold breach"),
    fail_on: Optional[str] = typer.Option(None, help="Fail CI if severity reached: critical, high, medium, low"),
    no_ai: bool = typer.Option(False, help="Skip AI summary generation"),
    exclude: Optional[str] = typer.Option(None, help="Comma-separated dirs to exclude (e.g. tests,fixtures)"),
    staged: bool = typer.Option(False, "--staged", help="Scan only git staged files (pre-commit mode)"),
    diff: Optional[str] = typer.Option(None, "--diff", help="Scan only git modified files against working tree or REF (e.g. HEAD~1)"),
    baseline: Optional[str] = typer.Option(None, "--baseline", help="Path to baseline JSON report to suppress existing findings"),
    fix: bool = typer.Option(False, "--fix", help="Automatically patch safe SAST anti-patterns (MP012, MP023, MP014) and vulnerable requirements.txt entries"),
    ai_provider: str = typer.Option("auto", "--ai-provider", help="AI provider: auto, gemini, openai, anthropic, ollama"),
    ai_model: Optional[str] = typer.Option(None, "--ai-model", help="AI model name (e.g. gpt-4o-mini, claude-3-5-haiku-20241022, gemini-2.5-flash, llama3.2)"),
    ai_base_url: Optional[str] = typer.Option(None, "--ai-base-url", help="Custom AI API base URL (e.g. http://localhost:11434/v1 or private gateway)"),
    rules_file: Optional[str] = typer.Option(None, "--rules-file", help="Path to custom rules file (.maunprekshak-rules.yaml)"),
    history: bool = typer.Option(False, "--history", help="Scan git commit history for leaked credentials"),
    commits: Optional[int] = typer.Option(None, "--commits", help="Maximum number of historical commits to scan (default: 50)"),
    annotations: bool = typer.Option(False, "--annotations", help="Emit GitHub Actions workflow annotation commands (::error:: / ::warning::) for inline PR annotations"),
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
    effective_ai_provider = ai_provider if ai_provider != "auto" else cfg.ai_provider
    effective_ai_model = ai_model if ai_model is not None else cfg.ai_model
    effective_ai_base_url = ai_base_url if ai_base_url is not None else cfg.ai_base_url
    effective_rules_file = rules_file or cfg.rules_file
    effective_history = history or cfg.scan_history
    effective_commits = commits if commits is not None else cfg.commits

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
        result = scan_project(
            path,
            exclude=exclude_list,
            only=only,
            target_files=target_files,
            custom_rules_path=effective_rules_file,
            scan_history=effective_history,
            max_commits=effective_commits,
        )

        # Apply rule exclusions from config if specified
        if cfg.ignore_rules:
            result.sast = [s for s in result.sast if s.check_id not in cfg.ignore_rules]
            # Recalculate score after ignoring rules
            recalculated = aggregate(result.deps, result.secrets, result.sast)
            result.risk_score = recalculated.risk_score

        # Apply baseline suppression if specified
        if baseline:
            if os.path.isfile(baseline):
                try:
                    with open(baseline, "r", encoding="utf-8") as bf:
                        bdata = json.load(bf)
                    base_deps = {
                        (d.get("package", "").lower(), str(d.get("version", "")), str(d.get("cve_id", "")))
                        for d in bdata.get("deps", [])
                    }
                    base_secrets = {
                        (os.path.basename(s.get("file_path", "")), str(s.get("secret_type", "")))
                        for s in bdata.get("secrets", [])
                    }
                    base_sast = {
                        (os.path.basename(s.get("file_path", "")), str(s.get("check_id", "")))
                        for s in bdata.get("sast", [])
                    }

                    initial_total = result.total_findings
                    result.deps = [
                        d for d in result.deps
                        if (d.package.lower(), str(d.version), str(d.cve_id)) not in base_deps
                    ]
                    result.secrets = [
                        s for s in result.secrets
                        if (os.path.basename(s.file_path), str(s.secret_type)) not in base_secrets
                    ]
                    result.sast = [
                        s for s in result.sast
                        if (os.path.basename(s.file_path), str(s.check_id)) not in base_sast
                    ]
                    suppressed = initial_total - result.total_findings
                    if suppressed > 0 and output == "console":
                        console.print(f"[bold cyan]Suppressed {suppressed} finding(s) matching baseline {baseline}[/bold cyan]")

                    recalculated = aggregate(result.deps, result.secrets, result.sast)
                    result.risk_score = recalculated.risk_score
                except Exception as e:
                    if output == "console":
                        console.print(f"[yellow]Warning: Could not parse baseline file {baseline}: {e}[/yellow]")
            else:
                if output == "console":
                    console.print(f"[yellow]Warning: Baseline file not found at {baseline}. Running scan without baseline.[/yellow]")

        if fix:
            status.update("[bold green]Applying auto-fixes for safe anti-patterns...")
            fixed_count, result = apply_auto_fixes(result)
            if fixed_count > 0 and output == "console":
                console.print(f"[bold green]✓ Auto-fixed {fixed_count} SAST security anti-pattern(s)[/bold green]")

            # Dep auto-fix: patch vulnerable requirements.txt entries
            if result.deps:
                req_candidates = [
                    os.path.join(path, "requirements.txt"),
                    os.path.join(path, "requirements", "base.txt"),
                    os.path.join(path, "requirements", "prod.txt"),
                ]
                for req_path in req_candidates:
                    dep_fixed = fix_requirements_txt(req_path, result.deps)
                    if dep_fixed > 0 and output == "console":
                        console.print(f"[bold green]✓ Auto-patched {dep_fixed} vulnerable dependency version(s) in {os.path.basename(req_path)}[/bold green]")

        if not effective_no_ai:
            provider_label = f" ({effective_ai_provider})" if effective_ai_provider != "auto" else ""
            status.update(f"[bold green]Generating AI summary{provider_label}...")
            result.ai_summary = generate_ai_summary(
                result,
                provider=effective_ai_provider,
                model=effective_ai_model,
                base_url=effective_ai_base_url,
            )

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
    elif output == "cyclonedx":
        proj_name = Path(path).resolve().name or "project"
        out_str = to_cyclonedx(result, project_name=proj_name)
        if output_file:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(out_str)
        else:
            print(out_str)
    elif output == "spdx":
        proj_name = Path(path).resolve().name or "project"
        out_str = to_spdx(result, project_name=proj_name)
        if output_file:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(out_str)
        else:
            print(out_str)
    elif output == "html":
        proj_name = Path(path).resolve().name or "project"
        out_str = to_html(result, project_name=proj_name)
        if output_file:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(out_str)
            console.print(f"[bold green]Saved interactive HTML report to {output_file}[/bold green]")
        else:
            print(out_str)
    elif output == "gitlab":
        proj_name = Path(path).resolve().name or "project"
        out_str = to_gitlab(result, project_root=path)
        default_name = "gl-sast-report.json"
        out_path = output_file or default_name
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(out_str)
        console.print(f"[bold green]Saved GitLab SAST report to {out_path}[/bold green]")
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

    # GitHub Actions annotations — auto-detect GITHUB_ACTIONS env var or explicit --annotations flag
    effective_annotations = annotations or os.environ.get("GITHUB_ACTIONS", "").lower() == "true"
    if effective_annotations and result.total_findings > 0:
        annotation_lines = format_github_annotations(result, project_root=path)
        if annotation_lines:
            print(annotation_lines)

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


hook_app = typer.Typer(help="Manage MaunPrekshak Git pre-commit hooks.")

PRE_COMMIT_HOOK_SCRIPT = """#!/usr/bin/env bash
# MaunPrekshak Git Pre-Commit Hook
# Automatically installed by `maunprekshak hook install`

echo "Running MaunPrekshak pre-commit scan on staged files..."

# Locate maunprekshak binary
if command -v maunprekshak >/dev/null 2>&1; then
    MP_BIN="maunprekshak"
elif command -v mp >/dev/null 2>&1; then
    MP_BIN="mp"
elif [ -n "$VIRTUAL_ENV" ] && [ -f "$VIRTUAL_ENV/bin/maunprekshak" ]; then
    MP_BIN="$VIRTUAL_ENV/bin/maunprekshak"
else
    MP_BIN="python3 -m maunprekshak"
fi

$MP_BIN scan . --staged --ci --fail-on high --no-ai
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    echo ""
    echo "❌ MaunPrekshak pre-commit check failed. Commit blocked."
    echo "Fix vulnerabilities or commit with '--no-verify' to bypass."
    exit $EXIT_CODE
fi

exit 0
"""


def _find_git_dir(start_path: str = ".") -> Optional[Path]:
    curr = Path(start_path).resolve()
    for p in [curr] + list(curr.parents):
        git_path = p / ".git"
        if git_path.exists():
            return git_path
    return None


@hook_app.command(name="install")
def hook_install(
    path: str = typer.Option(".", "--path", "-p", help="Path to git repository or subdirectory")
):
    """Install MaunPrekshak as a native Git pre-commit hook."""
    git_ref = _find_git_dir(path)
    if not git_ref:
        console.print(f"[bold red]Error: No .git repository found in {path} or any parent directory.[/bold red]")
        raise typer.Exit(code=1)

    hooks_dir: Optional[Path] = None
    if git_ref.is_dir():
        hooks_dir = git_ref / "hooks"
    elif git_ref.is_file():
        try:
            content = git_ref.read_text().strip()
            if content.startswith("gitdir:"):
                actual_dir = Path(content.split("gitdir:", 1)[1].strip())
                if not actual_dir.is_absolute():
                    actual_dir = git_ref.parent / actual_dir
                hooks_dir = actual_dir / "hooks"
        except Exception:
            pass

    if not hooks_dir:
        console.print(f"[bold red]Error: Could not determine git hooks directory for {git_ref}[/bold red]")
        raise typer.Exit(code=1)

    hooks_dir.mkdir(parents=True, exist_ok=True)
    hook_file = hooks_dir / "pre-commit"

    if hook_file.exists():
        existing_text = hook_file.read_text(encoding="utf-8")
        if "MaunPrekshak Git Pre-Commit Hook" not in existing_text:
            backup_file = hooks_dir / "pre-commit.maunprekshak.bak"
            hook_file.rename(backup_file)
            console.print(f"[yellow]Existing pre-commit hook backed up to {backup_file}[/yellow]")

    hook_file.write_text(PRE_COMMIT_HOOK_SCRIPT, encoding="utf-8")
    try:
        hook_file.chmod(0o755)
    except Exception:
        pass

    console.print(f"[bold green]✓ Successfully installed MaunPrekshak pre-commit hook at {hook_file}[/bold green]")


@hook_app.command(name="uninstall")
def hook_uninstall(
    path: str = typer.Option(".", "--path", "-p", help="Path to git repository or subdirectory")
):
    """Uninstall MaunPrekshak Git pre-commit hook."""
    git_ref = _find_git_dir(path)
    if not git_ref:
        console.print(f"[bold red]Error: No .git repository found in {path} or any parent directory.[/bold red]")
        raise typer.Exit(code=1)

    hooks_dir: Optional[Path] = None
    if git_ref.is_dir():
        hooks_dir = git_ref / "hooks"
    elif git_ref.is_file():
        try:
            content = git_ref.read_text().strip()
            if content.startswith("gitdir:"):
                actual_dir = Path(content.split("gitdir:", 1)[1].strip())
                if not actual_dir.is_absolute():
                    actual_dir = git_ref.parent / actual_dir
                hooks_dir = actual_dir / "hooks"
        except Exception:
            pass

    if not hooks_dir:
        console.print(f"[bold red]Error: Could not determine git hooks directory for {git_ref}[/bold red]")
        raise typer.Exit(code=1)

    hook_file = hooks_dir / "pre-commit"
    if not hook_file.exists():
        console.print(f"[yellow]No pre-commit hook found at {hook_file}.[/yellow]")
        return

    text = hook_file.read_text(encoding="utf-8")
    if "MaunPrekshak Git Pre-Commit Hook" in text:
        hook_file.unlink()
        console.print(f"[bold green]✓ Removed MaunPrekshak pre-commit hook from {hook_file}[/bold green]")
        backup_file = hooks_dir / "pre-commit.maunprekshak.bak"
        if backup_file.exists():
            backup_file.rename(hook_file)
            console.print(f"[bold green]✓ Restored original pre-commit hook from {backup_file}[/bold green]")
    else:
        console.print(f"[yellow]The pre-commit hook at {hook_file} was not installed by MaunPrekshak. Leaving untouched.[/yellow]")


app.add_typer(hook_app, name="hook")


if __name__ == "__main__":
    app()
