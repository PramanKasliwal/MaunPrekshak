"""
MaunPrekshak — Git Commit History Secrets Scanner
Scans historical commits across the git repository log to detect leaked credentials
that may have been removed or amended in recent commits.
"""
import os
import re
import subprocess
from typing import List, Optional, Set
from maunprekshak.scanner.report import SecretFinding, Severity
from maunprekshak.scanner.secrets import (
    SECRET_PATTERNS,
    mask_secret,
    SAFE_PATTERNS,
    UUID_PATTERN,
    CANDIDATE_TOKEN_PATTERN,
    HEX_CHARS_PATTERN,
    FILE_EXT_PATTERN,
    SUPPRESSION_KEYWORDS,
    calculate_shannon_entropy,
)
from maunprekshak.scanner.custom_rules import CustomRulesConfig, evaluate_custom_secrets


def scan_git_history(
    repo_path: str,
    max_commits: int = 50,
    custom_rules: Optional[CustomRulesConfig] = None,
    exclude: Optional[List[str]] = None,
) -> List[SecretFinding]:
    """
    Inspect git commit diffs up to max_commits for leaked API keys, tokens, and credentials.
    Returns findings with location indicating 'commit:<short_sha>:<file_path>'.
    """
    findings: List[SecretFinding] = []
    abs_repo = os.path.abspath(repo_path)

    # Verify if directory is inside a valid git repository
    try:
        check_git = subprocess.run(
            ["git", "rev-parse", "--is-inside-work-tree"],
            cwd=abs_repo,
            capture_output=True,
            text=True,
            timeout=5,
        )
        if check_git.returncode != 0 or check_git.stdout.strip() != "true":
            return []
    except Exception:
        return []

    # Run git log -p
    try:
        cmd = [
            "git",
            "log",
            "-p",
            f"-n{max(1, max_commits)}",
            "--no-merges",
            "--full-history",
        ]
        proc = subprocess.run(
            cmd,
            cwd=abs_repo,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=60,
        )
        if proc.returncode != 0:
            return []
        log_output = proc.stdout
    except Exception:
        return []

    commit_sha = "unknown"
    commit_author = ""
    current_file = ""
    diff_line_idx = 0
    seen_secrets: Set[str] = set()

    default_excludes = {"tests", "test", "fixtures", ".venv", "venv", "node_modules", "dist", "build"}
    effective_excludes = set(exclude or []).union(default_excludes)

    for line in log_output.splitlines():
        # Match commit header
        if line.startswith("commit "):
            parts = line.split()
            if len(parts) >= 2:
                commit_sha = parts[1][:8]
            diff_line_idx = 0
            continue

        if line.startswith("Author: "):
            commit_author = line[8:].strip()
            continue

        # Match file header in diff
        if line.startswith("diff --git "):
            diff_line_idx = 0
            # e.g., diff --git a/foo/bar.py b/foo/bar.py
            parts = line.split()
            if len(parts) >= 4 and parts[3].startswith("b/"):
                current_file = parts[3][2:]
            else:
                current_file = ""
            continue

        # Skip headers, deleted lines, or binary notes
        if line.startswith("+++ ") or line.startswith("--- ") or line.startswith("index "):
            continue

        # Only inspect added lines
        if not line.startswith("+"):
            continue

        diff_line_idx += 1
        code_line = line[1:].strip()

        # Filter out excluded directories and files
        if not current_file or any(part in current_file.split("/") for part in effective_excludes):
            continue
        if current_file.endswith((".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".lock")):
            continue
        if "secrets.py" in current_file or "test" in current_file.lower():
            continue

        # Suppression check
        lower_line = code_line.lower()
        if (
            "# nosec" in lower_line
            or "# maunprekshak: ignore" in lower_line
            or "# maunprekshak:ignore" in lower_line
            or "# maunprekshak: ignore-secret" in lower_line
        ):
            continue

        # Check safe patterns
        if any(safe.search(code_line) for safe in SAFE_PATTERNS):
            continue

        # 1. Regex pattern matching
        for secret_type, pattern in SECRET_PATTERNS.items():
            try:
                m = re.search(pattern, code_line)
            except re.error:
                continue
            if m:
                raw_secret = m.group(0)
                # Filter out obvious false positives
                if any(kw in raw_secret.lower() for kw in SUPPRESSION_KEYWORDS):
                    continue

                finding_key = f"{commit_sha}:{current_file}:{secret_type}:{raw_secret}"
                if finding_key in seen_secrets:
                    continue
                seen_secrets.add(finding_key)

                findings.append(
                    SecretFinding(
                        file_path=f"commit:{commit_sha}:{current_file}",
                        line=diff_line_idx,
                        secret_type=f"{secret_type} (git commit {commit_sha})",
                        masked_value=mask_secret(raw_secret),
                        severity=Severity.CRITICAL.value if "Private Key" in secret_type else Severity.HIGH.value,
                    )
                )

        # 2. Custom rules matching
        if custom_rules and custom_rules.secrets:
            custom_findings = evaluate_custom_secrets(
                file_path=f"commit:{commit_sha}:{current_file}",
                content=code_line,
                rules=custom_rules.secrets,
            )
            for cf in custom_findings:
                cf.line = diff_line_idx
                cf.secret_type = f"{cf.secret_type} (git commit {commit_sha})"
                f_key = f"{commit_sha}:{current_file}:{cf.secret_type}:{cf.masked_value}"
                if f_key not in seen_secrets:
                    seen_secrets.add(f_key)
                    findings.append(cf)

        # 3. Shannon Entropy matching for unlabelled high-entropy tokens
        for match in CANDIDATE_TOKEN_PATTERN.finditer(code_line):
            candidate = match.group(1) or match.group(2)
            if not candidate or len(candidate) < 20:
                continue
            if UUID_PATTERN.match(candidate):
                continue
            if FILE_EXT_PATTERN.search(candidate):
                continue
            if any(kw in candidate.lower() for kw in SUPPRESSION_KEYWORDS):
                continue

            entropy = calculate_shannon_entropy(candidate)
            is_hex = bool(HEX_CHARS_PATTERN.match(candidate))

            if (is_hex and entropy >= 3.0 and len(candidate) >= 32) or (
                not is_hex and entropy >= 4.5 and len(candidate) >= 20
            ):
                f_key = f"{commit_sha}:{current_file}:entropy:{candidate}"
                if f_key not in seen_secrets:
                    seen_secrets.add(f_key)
                    findings.append(
                        SecretFinding(
                            file_path=f"commit:{commit_sha}:{current_file}",
                            line=diff_line_idx,
                            secret_type=f"High-Entropy Secret Token (git commit {commit_sha})",
                            masked_value=mask_secret(candidate),
                            severity=Severity.HIGH.value,
                        )
                    )

    return findings
