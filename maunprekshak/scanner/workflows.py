"""
MaunPrekshak — GitHub Actions CI/CD Security Scanner
Static analysis for .github/workflows/*.{yml,yaml} detecting supply chain risks,
script injection, insecure triggers, and unpinned dependencies.
"""
import os
import re
from pathlib import Path
from typing import List, Optional, Set
from maunprekshak.scanner.report import SASTFinding, Severity

EXCLUDE_DIRS = {
    "node_modules", ".git", "__pycache__", "venv", ".venv",
    "dist", "build", ".eggs", "site-packages", "tests", "test",
    "testing", "fixtures",
}

# Untrusted GitHub event contexts susceptible to command/script injection
UNTRUSTED_CONTEXTS = [
    r"github\.event\.issue\.title",
    r"github\.event\.issue\.body",
    r"github\.event\.pull_request\.title",
    r"github\.event\.pull_request\.body",
    r"github\.event\.comment\.body",
    r"github\.event\.review\.body",
    r"github\.event\.pages.*\.page_name",
    r"github\.head_ref",
]
UNTRUSTED_PATTERN = re.compile(
    r"\$\{\{\s*(" + "|".join(UNTRUSTED_CONTEXTS) + r")\s*\}\}",
    re.IGNORECASE,
)

USES_PATTERN = re.compile(
    r"^\s*(?:-\s*)?uses:\s*['\"]?([A-Za-z0-9_\-\.]+/[A-Za-z0-9_\-\.]+(?:/[A-Za-z0-9_\-\.]+)?)(?:@([A-Za-z0-9_\-\.]+))?['\"]?",
    re.IGNORECASE,
)

ECHO_SECRET_PATTERN = re.compile(
    r"(?:echo|printf)\s+.*?\$\{\{\s*secrets\.[A-Za-z0-9_]+\s*\}\}",
    re.IGNORECASE,
)

COMMIT_SHA_PATTERN = re.compile(r"^[0-9a-fA-F]{40}$")


def _is_suppressed(line_content: str, check_id: str) -> bool:
    """Check if a line has an inline suppression comment."""
    if "#" not in line_content:
        return False
    comment = line_content[line_content.find("#") :].lower()
    if "maunprekshak: ignore" in comment or "maunprekshak:ignore" in comment:
        match = re.search(r"ignore(?:\[(.*?)\])?", comment)
        if match:
            rules_str = match.group(1)
            if not rules_str:
                return True
            rules = [r.strip().upper() for r in rules_str.split(",") if r.strip()]
            if check_id.upper() in rules:
                return True
    if "nosec" in comment:
        match = re.search(r"nosec(?::\s*(.*?))?(?:\s|$)", comment)
        if match:
            rules_str = match.group(1)
            if not rules_str:
                return True
            rules = [r.strip().upper() for r in rules_str.split(",") if r.strip()]
            if check_id.upper() in rules:
                return True
    return False


def scan_single_workflow(file_path: str) -> List[SASTFinding]:
    """Scan a single GitHub Actions workflow YAML file."""
    findings: List[SASTFinding] = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except Exception:
        return []

    # Check file-level suppression
    for line in lines[:20]:
        if "maunprekshak: disable-file" in line.lower():
            return []

    has_pull_request_target = False
    pr_target_line = 1
    has_untrusted_checkout = False
    untrusted_checkout_line = 1

    in_run_block = False
    run_indent = 0

    for idx, raw_line in enumerate(lines, start=1):
        line = raw_line.rstrip()
        stripped = line.strip()

        if not stripped or stripped.startswith("#"):
            continue

        indent = len(line) - len(line.lstrip())

        # Track trigger: on: pull_request_target
        if re.search(r"(?:^on:.*pull_request_target|^\s*pull_request_target:)", line):
            has_pull_request_target = True
            pr_target_line = idx

        # Track checkout of PR head: ref: ${{ github.event.pull_request.head.sha }} or ${{ github.head_ref }}
        if has_pull_request_target and re.search(
            r"ref:\s*['\"]?\$\{\{\s*(?:github\.event\.pull_request\.head\.sha|github\.head_ref)\s*\}\}['\"]?",
            line,
            re.IGNORECASE,
        ):
            has_untrusted_checkout = True
            untrusted_checkout_line = idx

        # Track if we are inside a multi-line `run:` block
        if re.search(r"^\s*(?:-\s*)?run:\s*[|>-]", line):
            in_run_block = True
            run_indent = indent
            continue
        elif in_run_block:
            if indent <= run_indent and not stripped.startswith("-"):
                in_run_block = False

        is_run_line = in_run_block or bool(re.search(r"^\s*(?:-\s*)?run:\s+", line))

        # GHA001: Script injection via untrusted event context in run:
        if is_run_line:
            if not _is_suppressed(raw_line, "GHA001"):
                m = UNTRUSTED_PATTERN.search(line)
                if m:
                    findings.append(
                        SASTFinding(
                            file_path=file_path,
                            line=idx,
                            col=1,
                            check_id="GHA001",
                            severity=Severity.HIGH.value,
                            description=(
                                f"Script injection vulnerability: untrusted GitHub context '{m.group(0)}' "
                                f"interpolated directly into runner shell script."
                            ),
                            recommendation=(
                                "Store untrusted values in intermediate environment variables "
                                "(`env: PR_TITLE: ${{ ... }}`) and reference them via shell variables `$PR_TITLE`."
                            ),
                            code_snippet=stripped[:120],
                        )
                    )

        # GHA002: Unpinned third-party actions
        uses_match = USES_PATTERN.search(line)
        if uses_match:
            action_name = uses_match.group(1)
            action_ref = uses_match.group(2) or ""

            # Skip local actions (.github/actions/...) and docker:// actions
            if not action_name.startswith(("./", "../", "docker://")):
                is_pinned_sha = bool(COMMIT_SHA_PATTERN.match(action_ref))
                is_mutable_branch = action_ref.lower() in ("main", "master", "latest", "dev")

                if is_mutable_branch or (not is_pinned_sha and not action_ref):
                    if not _is_suppressed(raw_line, "GHA002"):
                        findings.append(
                            SASTFinding(
                                file_path=file_path,
                                line=idx,
                                col=1,
                                check_id="GHA002",
                                severity=Severity.MEDIUM.value,
                                description=(
                                    f"Unpinned third-party action '{action_name}@{action_ref}'. "
                                    "Mutable branch references are susceptible to supply chain compromise."
                                ),
                                recommendation=(
                                    f"Pin action '{action_name}' to a full 40-character commit SHA "
                                    f"(e.g. {action_name}@<full-commit-sha>)."
                                ),
                                code_snippet=stripped[:120],
                            )
                        )

        # GHA004: Overly permissive workflow permissions
        if re.search(r"^\s*permissions:\s*write-all\b", line, re.IGNORECASE):
            if not _is_suppressed(raw_line, "GHA004"):
                findings.append(
                    SASTFinding(
                        file_path=file_path,
                        line=idx,
                        col=1,
                        check_id="GHA004",
                        severity=Severity.HIGH.value,
                        description=(
                            "Overly permissive workflow permissions: 'permissions: write-all' grants broad write access "
                            "to repository contents, packages, issues, and pull requests."
                        ),
                        recommendation=(
                            "Apply the principle of least privilege. Grant only necessary granular permissions "
                            "(e.g. 'permissions: contents: read')."
                        ),
                        code_snippet=stripped[:120],
                    )
                )

        # GHA005: Plaintext secrets in run step
        if is_run_line:
            if not _is_suppressed(raw_line, "GHA005"):
                if ECHO_SECRET_PATTERN.search(line):
                    findings.append(
                        SASTFinding(
                            file_path=file_path,
                            line=idx,
                            col=1,
                            check_id="GHA005",
                            severity=Severity.HIGH.value,
                            description=(
                                "Plaintext secret echo detected: outputting secrets to workflow console logs "
                                "risks leaking sensitive credentials in build artifacts or CI history."
                            ),
                            recommendation="Remove echo/printf commands targeting GitHub Secrets.",
                            code_snippet=stripped[:120],
                        )
                    )

    # GHA003: Dangerous pull_request_target with untrusted head checkout
    if has_pull_request_target and has_untrusted_checkout:
        line_no = untrusted_checkout_line or pr_target_line
        target_line_content = lines[line_no - 1] if 0 <= line_no - 1 < len(lines) else ""
        if not _is_suppressed(target_line_content, "GHA003"):
            findings.append(
                SASTFinding(
                    file_path=file_path,
                    line=line_no,
                    col=1,
                    check_id="GHA003",
                    severity=Severity.CRITICAL.value,
                    description=(
                        "Dangerous 'pull_request_target' trigger combined with untrusted PR head checkout. "
                        "This configuration allows external pull requests to execute untrusted code with repository secret access."
                    ),
                    recommendation=(
                        "Use standard 'on: pull_request' for untrusted PR checks, or avoid checking out "
                        "the PR head revision inside privileged 'pull_request_target' workflows."
                    ),
                    code_snippet=target_line_content.strip()[:120],
                )
            )

    return findings


def scan_workflows(
    path: str,
    exclude: Optional[List[str]] = None,
    target_files: Optional[List[str]] = None,
) -> List[SASTFinding]:
    """Scan all GitHub Actions workflows in a project for CI/CD security vulnerabilities."""
    findings: List[SASTFinding] = []
    abs_path = os.path.abspath(path)
    active_excludes = set(EXCLUDE_DIRS)
    if exclude:
        for e in exclude:
            cleaned = e.strip().rstrip("/\\")
            if cleaned.startswith("./"):
                cleaned = cleaned[2:]
            if cleaned:
                active_excludes.add(cleaned)
                base = os.path.basename(cleaned)
                if base:
                    active_excludes.add(base)

    if target_files is not None:
        workflow_files = [
            f for f in target_files
            if f.endswith((".yml", ".yaml"))
            and (".github/workflows" in f or ".github" in f)
            and os.path.isfile(f)
        ]
        for wf in workflow_files:
            rel_wf = os.path.relpath(wf, path).replace("\\", "/")
            path_parts = set(wf.replace("\\", "/").split("/"))
            bname = os.path.basename(wf)
            if path_parts & active_excludes or rel_wf in active_excludes or bname in active_excludes:
                continue
            findings.extend(scan_single_workflow(wf))
        return findings

    workflows_dir = os.path.join(abs_path, ".github", "workflows")
    if not os.path.isdir(workflows_dir):
        return []

    rel_workflows_dir = os.path.relpath(workflows_dir, path).replace("\\", "/")
    if (
        ".github" in active_excludes
        or "workflows" in active_excludes
        or rel_workflows_dir in active_excludes
    ):
        return []

    for root, dirs, files in os.walk(workflows_dir):
        dirs[:] = [
            d for d in dirs
            if d not in active_excludes
            and os.path.relpath(os.path.join(root, d), path).replace("\\", "/") not in active_excludes
        ]
        for file in files:
            if file.endswith((".yml", ".yaml")):
                rel_file = os.path.relpath(os.path.join(root, file), path).replace("\\", "/")
                if file in active_excludes or rel_file in active_excludes:
                    continue
                full_path = os.path.join(root, file)
                findings.extend(scan_single_workflow(full_path))

    return findings
