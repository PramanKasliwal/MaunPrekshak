"""
MaunPrekshak — Dockerfile Container Security Scanner
Analyzes Dockerfile directives for security anti-patterns and misconfigurations.
"""
import os
import re
from typing import List, Optional
from maunprekshak.scanner.report import SASTFinding, Severity

EXCLUDE_DIRS = {
    "node_modules", ".git", "__pycache__", "venv", ".venv",
    "dist", "build", ".eggs", "site-packages", "tests", "test",
    "testing", "fixtures",
}


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


def scan_single_dockerfile(file_path: str) -> List[SASTFinding]:
    """Scan a single Dockerfile for security vulnerabilities."""
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

    has_user_directive = False
    last_user_is_root = False
    last_user_line = 1

    # Join multi-line RUN instructions ending with backslash
    raw_instructions = []
    current_inst = ""
    start_line = 1
    for line_idx, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if not current_inst:
            start_line = line_idx
        if stripped.endswith("\\"):
            current_inst += " " + stripped[:-1].strip()
        else:
            current_inst += " " + stripped
            raw_instructions.append((start_line, current_inst.strip(), lines[start_line - 1]))
            current_inst = ""

    for line_num, full_inst, raw_line in raw_instructions:
        inst_upper = full_inst.upper()

        # Track USER directives
        if inst_upper.startswith("USER "):
            has_user_directive = True
            user_val = full_inst[5:].strip()
            if user_val in ("root", "0", '"root"', "'root'"):
                last_user_is_root = True
            else:
                last_user_is_root = False
            last_user_line = line_num

        # DF002 — Unpinned base image or :latest in FROM
        if inst_upper.startswith("FROM "):
            parts = full_inst.split()
            if len(parts) >= 2:
                base_img = parts[1].strip()
                if base_img != "scratch" and not base_img.startswith("$"):
                    is_unpinned = False
                    if ":latest" in base_img:
                        is_unpinned = True
                    elif ":" not in base_img and "@" not in base_img:
                        is_unpinned = True
                    if is_unpinned and not _is_suppressed(raw_line, "DF002"):
                        findings.append(SASTFinding(
                            file_path=file_path,
                            line=line_num,
                            col=1,
                            check_id="DF002",
                            severity=Severity.MEDIUM.value,
                            description=f"Base image '{base_img}' uses ':latest' or lacks an explicit version tag",
                            recommendation="Pin base images to a specific version tag or immutable SHA256 digest (e.g. python:3.12-slim).",
                            code_snippet=raw_line.strip(),
                        ))

        # DF003 — apt-get install without cleaning cache
        if "APT-GET INSTALL" in inst_upper or "APT INSTALL" in inst_upper:
            if "RM -RF /VAR/LIB/APT/LISTS" not in inst_upper and not _is_suppressed(raw_line, "DF003"):
                findings.append(SASTFinding(
                    file_path=file_path,
                    line=line_num,
                    col=1,
                    check_id="DF003",
                    severity=Severity.HIGH.value,
                    description="apt-get install executed without cleaning package lists (/var/lib/apt/lists/*)",
                    recommendation="Clean apt caches in the same RUN layer: && rm -rf /var/lib/apt/lists/*",
                    code_snippet=raw_line.strip(),
                ))

        # DF004 — Sensitive port exposed (SSH/Telnet/RDP)
        if inst_upper.startswith("EXPOSE "):
            ports = full_inst[7:].split()
            for p in ports:
                p_clean = p.split("/")[0].strip()
                if p_clean in ("22", "23", "3389") and not _is_suppressed(raw_line, "DF004"):
                    findings.append(SASTFinding(
                        file_path=file_path,
                        line=line_num,
                        col=1,
                        check_id="DF004",
                        severity=Severity.MEDIUM.value,
                        description=f"Sensitive port {p_clean} (SSH/Telnet/RDP) exposed in Dockerfile",
                        recommendation="Do not expose SSH or remote administrative services inside containers; use orchestration access instead.",
                        code_snippet=raw_line.strip(),
                    ))

        # DF005 — Insecure curl | bash or wget | sh in RUN
        if inst_upper.startswith("RUN "):
            if re.search(r"(?:curl|wget)\b.*?\|\s*(?:bash|sh)\b", full_inst, re.IGNORECASE):
                if not _is_suppressed(raw_line, "DF005"):
                    findings.append(SASTFinding(
                        file_path=file_path,
                        line=line_num,
                        col=1,
                        check_id="DF005",
                        severity=Severity.HIGH.value,
                        description="Direct piping from curl/wget to shell (curl | bash) detected in RUN instruction",
                        recommendation="Download remote scripts, verify integrity with checksums or signatures, and execute explicitly.",
                        code_snippet=raw_line.strip(),
                    ))

        # DF006 — ADD instead of COPY for local files
        if inst_upper.startswith("ADD "):
            parts = full_inst.split()
            if len(parts) >= 3:
                src = parts[1].strip()
                is_archive = any(src.lower().endswith(ext) for ext in (".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz"))
                is_url = src.lower().startswith(("http://", "https://"))
                if not is_archive and not is_url and not _is_suppressed(raw_line, "DF006"):
                    findings.append(SASTFinding(
                        file_path=file_path,
                        line=line_num,
                        col=1,
                        check_id="DF006",
                        severity=Severity.MEDIUM.value,
                        description="Using ADD instead of COPY for local file transfer",
                        recommendation="Use COPY instead of ADD unless tar archive auto-extraction is specifically required.",
                        code_snippet=raw_line.strip(),
                    ))

    # DF001 — Missing USER or running as root
    if (not has_user_directive or last_user_is_root) and lines:
        flag_line = last_user_line if last_user_is_root else 1
        target_line = lines[flag_line - 1] if flag_line <= len(lines) else ""
        if not _is_suppressed(target_line, "DF001"):
            findings.append(SASTFinding(
                file_path=file_path,
                line=flag_line,
                col=1,
                check_id="DF001",
                severity=Severity.HIGH.value,
                description="Container runs as root by default — missing non-root USER instruction",
                recommendation="Create and switch to a dedicated non-root user (e.g. RUN useradd -m appuser && USER appuser).",
                code_snippet=target_line.strip() if target_line else "FROM ...",
            ))

    return findings


def scan_dockerfiles(
    path: str,
    exclude: Optional[List[str]] = None,
    target_files: Optional[List[str]] = None,
) -> List[SASTFinding]:
    """Find and scan Dockerfiles in path."""
    findings: List[SASTFinding] = []
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
        for f in target_files:
            abs_path = f if os.path.isabs(f) else os.path.join(path, f)
            bname = os.path.basename(abs_path)
            if not os.path.isfile(abs_path):
                continue
            path_parts = set(abs_path.replace("\\", "/").split("/"))
            rel_file = os.path.relpath(abs_path, path).replace("\\", "/")
            if path_parts & active_excludes or rel_file in active_excludes or bname in active_excludes:
                continue
            if bname == "Dockerfile" or bname.startswith("Dockerfile.") or bname.endswith(".Dockerfile"):
                findings.extend(scan_single_dockerfile(abs_path))
    else:
        for root, dirs, files in os.walk(path):
            dirs[:] = [
                d for d in dirs
                if d not in active_excludes
                and os.path.relpath(os.path.join(root, d), path).replace("\\", "/") not in active_excludes
            ]
            for filename in files:
                rel_file = os.path.relpath(os.path.join(root, filename), path).replace("\\", "/")
                if filename in active_excludes or rel_file in active_excludes:
                    continue
                if filename == "Dockerfile" or filename.startswith("Dockerfile.") or filename.endswith(".Dockerfile"):
                    file_path = os.path.join(root, filename)
                    findings.extend(scan_single_dockerfile(file_path))

    return findings
