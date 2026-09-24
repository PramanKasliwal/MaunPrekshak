import asyncio
import os
from concurrent.futures import ThreadPoolExecutor
from typing import List, Optional
from maunprekshak.scanner.report import ScanResult, aggregate
from maunprekshak.scanner.deps import scan_dependencies
from maunprekshak.scanner.secrets import scan_secrets
from maunprekshak.scanner.sast import scan_sast
from maunprekshak.scanner.dockerfile import scan_dockerfiles
from maunprekshak.scanner.workflows import scan_workflows
from maunprekshak.scanner.k8s import scan_k8s_manifests
from maunprekshak.scanner.git_history import scan_git_history
from maunprekshak.scanner.custom_rules import (
    load_custom_rules,
    evaluate_custom_secrets,
    evaluate_custom_sast,
    CustomRulesConfig,
)

DEFAULT_EXCLUDES = {
    "tests", "test", "testing", "fixtures", ".venv", "venv",
    "node_modules", ".git", "dist", "build", "__pycache__",
}


async def scan_project_async(
    path: str,
    exclude: Optional[List[str]] = None,
    only: Optional[str] = None,
    target_files: Optional[List[str]] = None,
    custom_rules_path: Optional[str] = None,
    scan_history: bool = False,
    max_commits: int = 50,
) -> ScanResult:
    """
    Asynchronously orchestrate scanning of dependencies, secrets, SAST, Dockerfiles,
    CI workflows, and custom rules. Ideal for async servers (e.g. FastAPI) and CLI.
    """
    deps = []
    secrets = []
    sast = []

    # Load custom rules if configured or present in repository
    custom_rules: CustomRulesConfig = load_custom_rules(path=custom_rules_path, root_dir=path)

    if only is None or only == "deps":
        deps = await scan_dependencies(path, target_files=target_files)

    if only is None or only == "secrets":
        secrets = scan_secrets(path, exclude=exclude, target_files=target_files)

        # Scan git history if explicitly requested
        if scan_history:
            history_secrets = scan_git_history(
                path,
                max_commits=max_commits,
                custom_rules=custom_rules,
                exclude=exclude,
            )
            secrets.extend(history_secrets)

    if only is None or only == "sast":
        sast = scan_sast(path, exclude=exclude, target_files=target_files)

    if only is None or only in ("sast", "dockerfile"):
        docker_findings = scan_dockerfiles(path, exclude=exclude, target_files=target_files)
        sast.extend(docker_findings)

    if only is None or only in ("sast", "workflow", "ci"):
        workflow_findings = scan_workflows(path, exclude=exclude, target_files=target_files)
        sast.extend(workflow_findings)

    if only is None or only in ("sast", "k8s", "kubernetes"):
        k8s_findings = scan_k8s_manifests(path, exclude=exclude, target_files=target_files)
        sast.extend(k8s_findings)

    # Evaluate custom rules across files if any rules are loaded
    if custom_rules.total_rules > 0:
        active_excludes = set(DEFAULT_EXCLUDES).union(exclude or [])
        files_to_check: List[str] = []

        if target_files is not None:
            files_to_check = [
                f if os.path.isabs(f) else os.path.join(path, f)
                for f in target_files
                if os.path.isfile(f if os.path.isabs(f) else os.path.join(path, f))
            ]
        else:
            for root, dirs, filenames in os.walk(path):
                dirs[:] = [d for d in dirs if d not in active_excludes]
                for fn in filenames:
                    # Skip common binary/media extensions
                    if fn.endswith((".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".lock", ".pyc")):
                        continue
                    files_to_check.append(os.path.join(root, fn))

        for fpath in files_to_check:
            try:
                with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
            except Exception:
                continue

            if (only is None or only == "secrets") and custom_rules.secrets:
                c_secrets = evaluate_custom_secrets(fpath, content, custom_rules.secrets)
                secrets.extend(c_secrets)

            if (only is None or only == "sast") and custom_rules.sast:
                c_sast = evaluate_custom_sast(fpath, content, custom_rules.sast)
                sast.extend(c_sast)

    return aggregate(deps, secrets, sast)


def scan_project(
    path: str,
    exclude: Optional[List[str]] = None,
    only: Optional[str] = None,
    target_files: Optional[List[str]] = None,
    custom_rules_path: Optional[str] = None,
    scan_history: bool = False,
    max_commits: int = 50,
) -> ScanResult:
    """
    Synchronous entrypoint for CLI. Safe to call from both CLI and async contexts.
    """
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        with ThreadPoolExecutor(max_workers=1) as executor:
            return executor.submit(
                lambda: asyncio.run(
                    scan_project_async(
                        path,
                        exclude=exclude,
                        only=only,
                        target_files=target_files,
                        custom_rules_path=custom_rules_path,
                        scan_history=scan_history,
                        max_commits=max_commits,
                    )
                )
            ).result()

    return asyncio.run(
        scan_project_async(
            path,
            exclude=exclude,
            only=only,
            target_files=target_files,
            custom_rules_path=custom_rules_path,
            scan_history=scan_history,
            max_commits=max_commits,
        )
    )
