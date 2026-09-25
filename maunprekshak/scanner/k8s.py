"""
MaunPrekshak — Kubernetes & Helm Manifest Security Scanner
Static analysis for Kubernetes YAML manifests detecting container misconfigurations,
insecure privileges, dangerous capabilities, and supply-chain risks.
"""
import os
import re
from typing import List, Optional, Set
from maunprekshak.scanner.report import SASTFinding, Severity

# ─── Check IDs ────────────────────────────────────────────────────────────────
# K8S001  Privileged container                     HIGH
# K8S002  Missing resource limits/requests         MEDIUM
# K8S003  Root container execution                 HIGH
# K8S004  Sensitive hostPath volume mount          CRITICAL
# K8S005  Dangerous capabilities added             HIGH
# K8S006  Privilege escalation allowed             MEDIUM
# K8S007  Non-read-only root filesystem            LOW
# K8S008  Unrestricted service account token       MEDIUM

EXCLUDE_DIRS: Set[str] = {
    "node_modules", ".git", "__pycache__", "venv", ".venv",
    "dist", "build", ".eggs", "site-packages",
}

SENSITIVE_HOSTPATHS = {
    "/", "/etc", "/proc", "/sys", "/root",
    "/var/run", "/var/run/docker.sock", "/var/run/containerd",
    "/run/containerd", "/run/docker.sock",
    "/usr/bin", "/usr/sbin", "/bin", "/sbin",
}

DANGEROUS_CAPS = {
    "ALL", "SYS_ADMIN", "NET_ADMIN", "NET_RAW", "SYS_PTRACE",
    "SYS_MODULE", "SYS_RAWIO", "DAC_OVERRIDE", "SYS_CHROOT",
    "SETUID", "SETGID",
}


def _is_suppressed(line_content: str, check_id: str) -> bool:
    """Check if a YAML line has an inline suppression comment."""
    if "#" not in line_content:
        return False
    comment = line_content[line_content.find("#"):].lower()
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


def _make_finding(
    file_path: str,
    line: int,
    check_id: str,
    severity: str,
    description: str,
    recommendation: str,
    code_snippet: str = "",
) -> SASTFinding:
    """Helper to create a K8s SASTFinding."""
    return SASTFinding(
        file_path=file_path,
        line=line,
        col=0,
        check_id=check_id,
        severity=severity,
        description=description,
        recommendation=recommendation,
        code_snippet=code_snippet,
    )


def _is_k8s_manifest(lines: List[str]) -> bool:
    """Heuristic: detect if file is a Kubernetes / Helm manifest."""
    header = "\n".join(lines[:40]).lower()
    has_api_version = "apiversion:" in header
    has_kind = "kind:" in header
    return has_api_version and has_kind


def scan_single_k8s_manifest(file_path: str) -> List[SASTFinding]:
    """Scan a single Kubernetes YAML manifest file for security misconfigurations."""
    findings: List[SASTFinding] = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except Exception:
        return []

    if not _is_k8s_manifest(lines):
        return []

    seen_resources_limits = False
    seen_resources_requests = False
    in_containers_block = False
    has_automount_false = False

    for raw in lines:
        stripped = raw.strip().lower()
        if re.match(r"^(containers|initContainers)\s*:", raw.strip()):
            in_containers_block = True
        if re.match(r"^\s*-\s*(name|image)\s*:", raw):
            in_containers_block = True
        if "automountserviceaccounttoken: false" in stripped:
            has_automount_false = True
        if "limits:" in stripped:
            seen_resources_limits = True
        if "requests:" in stripped:
            seen_resources_requests = True

    for i, raw in enumerate(lines):
        lineno = i + 1
        line_lower = raw.lower()

        # K8S001 — Privileged container
        if "privileged:" in line_lower and "true" in line_lower:
            if not _is_suppressed(raw, "K8S001"):
                findings.append(_make_finding(
                    file_path, lineno, "K8S001", Severity.HIGH.value,
                    "Privileged container detected — full host access granted",
                    "Set securityContext.privileged: false. Grant specific required capabilities instead.",
                    raw.rstrip(),
                ))

        # K8S003 — runAsNonRoot: false
        if "runasnonroot:" in line_lower and "false" in line_lower:
            if not _is_suppressed(raw, "K8S003"):
                findings.append(_make_finding(
                    file_path, lineno, "K8S003", Severity.HIGH.value,
                    "Container allowed to run as root (runAsNonRoot: false)",
                    "Set securityContext.runAsNonRoot: true and specify runAsUser with a non-zero UID.",
                    raw.rstrip(),
                ))

        # K8S003 — runAsUser: 0
        if "runasuser:" in line_lower:
            match = re.search(r"runasuser\s*:\s*(\d+)", line_lower)
            if match and int(match.group(1)) == 0:
                if not _is_suppressed(raw, "K8S003"):
                    findings.append(_make_finding(
                        file_path, lineno, "K8S003", Severity.HIGH.value,
                        "Container configured to run as root user (runAsUser: 0)",
                        "Use a non-root UID (e.g. runAsUser: 1000). Running as root increases container escape blast radius.",
                        raw.rstrip(),
                    ))

        # K8S004 — Sensitive hostPath volume mount
        if "path:" in line_lower:
            match = re.search(r"path\s*:\s*(.+)", raw.strip())
            if match:
                path_val = match.group(1).strip().strip("'\"")
                is_sensitive = (
                    path_val in SENSITIVE_HOSTPATHS
                    or any(path_val.startswith(sp + "/") for sp in SENSITIVE_HOSTPATHS if sp != "/")
                    or path_val == "/"
                )
                if is_sensitive and not _is_suppressed(raw, "K8S004"):
                    findings.append(_make_finding(
                        file_path, lineno, "K8S004", Severity.CRITICAL.value,
                        f"Sensitive hostPath volume mount detected: '{path_val}' — container escape risk",
                        "Avoid mounting sensitive host paths. Use PersistentVolumeClaims or ConfigMaps instead.",
                        raw.rstrip(),
                    ))

        # K8S005 — Dangerous capabilities added
        cap_match = re.search(r"^\s*-\s*([A-Z_]{2,})\s*$", raw.strip())
        if cap_match:
            cap_name = cap_match.group(1).upper()
            if cap_name in DANGEROUS_CAPS:
                if not _is_suppressed(raw, "K8S005"):
                    findings.append(_make_finding(
                        file_path, lineno, "K8S005", Severity.HIGH.value,
                        f"Dangerous Linux capability added: {cap_name}",
                        "Drop all capabilities with capabilities.drop: [ALL] and add only specifically required capabilities.",
                        raw.rstrip(),
                    ))

        # K8S006 — allowPrivilegeEscalation: true
        if "allowprivilegeescalation:" in line_lower and "true" in line_lower:
            if not _is_suppressed(raw, "K8S006"):
                findings.append(_make_finding(
                    file_path, lineno, "K8S006", Severity.MEDIUM.value,
                    "allowPrivilegeEscalation: true allows containers to gain additional privileges at runtime",
                    "Set securityContext.allowPrivilegeEscalation: false in all containers.",
                    raw.rstrip(),
                ))

        # K8S007 — readOnlyRootFilesystem: false
        if "readonlyrootfilesystem:" in line_lower and "false" in line_lower:
            if not _is_suppressed(raw, "K8S007"):
                findings.append(_make_finding(
                    file_path, lineno, "K8S007", Severity.LOW.value,
                    "readOnlyRootFilesystem: false — container root filesystem is writable",
                    "Set securityContext.readOnlyRootFilesystem: true. Mount writable paths via emptyDir volumes.",
                    raw.rstrip(),
                ))

    # K8S002 — Missing resource limits or requests (document-level)
    if in_containers_block and not (seen_resources_limits and seen_resources_requests):
        if not _is_suppressed(lines[0] if lines else "", "K8S002"):
            missing = []
            if not seen_resources_limits:
                missing.append("limits")
            if not seen_resources_requests:
                missing.append("requests")
            findings.append(_make_finding(
                file_path, 1, "K8S002", Severity.MEDIUM.value,
                f"Container resource {' and '.join(missing)} not specified — Denial of Service risk",
                "Add resources.limits (cpu/memory) and resources.requests to all containers.",
                "",
            ))

    # K8S008 — automountServiceAccountToken not disabled (document-level)
    if in_containers_block and not has_automount_false:
        if not _is_suppressed(lines[0] if lines else "", "K8S008"):
            findings.append(_make_finding(
                file_path, 1, "K8S008", Severity.MEDIUM.value,
                "automountServiceAccountToken not set to false — service account token auto-mounted to all containers",
                "Set automountServiceAccountToken: false at the Pod spec level unless the workload requires K8s API access.",
                "",
            ))

    severity_order = {
        Severity.CRITICAL.value: 0, Severity.HIGH.value: 1,
        Severity.MEDIUM.value: 2, Severity.LOW.value: 3,
    }
    findings.sort(key=lambda f: (severity_order.get(f.severity, 9), f.line))
    return findings


def scan_k8s_manifests(
    path: str,
    exclude: Optional[List[str]] = None,
    target_files: Optional[List[str]] = None,
) -> List[SASTFinding]:
    """
    Scan Kubernetes and Helm manifest YAML files for security misconfigurations.

    Args:
        path: Absolute path to the project root directory.
        exclude: Optional additional directories to exclude.
        target_files: Optional list of specific files to scan.

    Returns:
        List of SASTFinding objects for K8s security issues.
    """
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
            if not os.path.isfile(abs_path) or not abs_path.endswith((".yaml", ".yml")):
                continue
            path_parts = set(abs_path.replace("\\", "/").split("/"))
            rel_file = os.path.relpath(abs_path, path).replace("\\", "/")
            bname = os.path.basename(abs_path)
            if path_parts & active_excludes or rel_file in active_excludes or bname in active_excludes:
                continue
            findings.extend(scan_single_k8s_manifest(abs_path))
    else:
        for root, dirs, files in os.walk(path):
            dirs[:] = [
                d for d in dirs
                if d not in active_excludes
                and os.path.relpath(os.path.join(root, d), path).replace("\\", "/") not in active_excludes
            ]
            for filename in files:
                if not filename.endswith((".yaml", ".yml")):
                    continue
                rel_file = os.path.relpath(os.path.join(root, filename), path).replace("\\", "/")
                if filename in active_excludes or rel_file in active_excludes:
                    continue
                file_path = os.path.join(root, filename)
                findings.extend(scan_single_k8s_manifest(file_path))

    severity_order = {
        Severity.CRITICAL.value: 0, Severity.HIGH.value: 1,
        Severity.MEDIUM.value: 2, Severity.LOW.value: 3,
    }
    findings.sort(key=lambda f: (severity_order.get(f.severity, 9), f.file_path, f.line))
    return findings
