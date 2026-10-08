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
# K8S009  Host namespace sharing (net/pid/ipc)     CRITICAL
# K8S010  Dangerous service exposure (NodePort/LB) HIGH
# K8S011  Missing or unconfined Seccomp profile    MEDIUM
# K8S012  Missing NetworkPolicy for workload       MEDIUM
# K8S013  Plaintext secret in container env        HIGH
# K8S014  Default namespace usage                  LOW
# K8S015  Mutable or untagged container image      HIGH
# K8S016  Missing health probes (liveness/ready)   MEDIUM
# K8S017  Container runtime socket mount           CRITICAL
# K8S018  NET_RAW capability not dropped           MEDIUM
# K8S019  Insecure imagePullPolicy (Never)         HIGH
# K8S020  Default ServiceAccount assignment        LOW

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
    has_seccomp_profile = False
    is_service = False
    is_workload = False
    has_network_policy = False
    seen_liveness_probe = False
    seen_readiness_probe = False
    has_dropped_net_raw = False

    for raw in lines:
        stripped = raw.strip().lower()
        if re.match(r"^(containers|initcontainers)\s*:", stripped):
            in_containers_block = True
        if re.match(r"^\s*-\s*(name|image)\s*:", raw):
            in_containers_block = True
        if "automountserviceaccounttoken: false" in stripped:
            has_automount_false = True
        if "limits:" in stripped:
            seen_resources_limits = True
        if "requests:" in stripped:
            seen_resources_requests = True
        if "seccompprofile:" in stripped or "runtimedefault" in stripped:
            has_seccomp_profile = True
        if "livenessprobe:" in stripped:
            seen_liveness_probe = True
        if "readinessprobe:" in stripped:
            seen_readiness_probe = True
        if any(d in stripped for d in ("- all", "- net_raw", "['all']", "[\"all\"]", "['net_raw']", "[\"net_raw\"]")):
            has_dropped_net_raw = True
        if re.match(r"^\s*kind\s*:\s*service\b", stripped):
            is_service = True
        if re.match(r"^\s*kind\s*:\s*(deployment|statefulset|daemonset|pod|job|cronjob)\b", stripped):
            is_workload = True
        if re.match(r"^\s*kind\s*:\s*networkpolicy\b", stripped):
            has_network_policy = True

    cur_secret_env_name: Optional[str] = None

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

        # K8S009 — Host namespace sharing (hostNetwork, hostPID, hostIPC)
        for prop, name in [("hostnetwork", "hostNetwork"), ("hostpid", "hostPID"), ("hostipc", "hostIPC")]:
            if f"{prop}:" in line_lower and "true" in line_lower:
                if not _is_suppressed(raw, "K8S009"):
                    findings.append(_make_finding(
                        file_path, lineno, "K8S009", Severity.CRITICAL.value,
                        f"Host namespace sharing detected ({name}: true) — container isolation boundary broken",
                        f"Set {name}: false. Sharing host namespaces allows network sniffing, process tracing, or IPC manipulation.",
                        raw.rstrip(),
                    ))

        # K8S010 — Dangerous service exposure (NodePort / LoadBalancer)
        if is_service:
            if re.search(r"^\s*type\s*:\s*NodePort\b", raw, re.IGNORECASE):
                if not _is_suppressed(raw, "K8S010"):
                    findings.append(_make_finding(
                        file_path, lineno, "K8S010", Severity.HIGH.value,
                        "Dangerous service exposure: type: NodePort opens static port across all cluster nodes",
                        "Use ClusterIP with an Ingress controller and API gateway instead of exposing NodePorts directly.",
                        raw.rstrip(),
                    ))
            elif re.search(r"^\s*type\s*:\s*LoadBalancer\b", raw, re.IGNORECASE):
                if not _is_suppressed(raw, "K8S010"):
                    findings.append(_make_finding(
                        file_path, lineno, "K8S010", Severity.HIGH.value,
                        "Public service exposure: type: LoadBalancer provisions external cloud load balancer",
                        "Verify public accessibility requirement. Use internal load balancer annotations or ClusterIP with Ingress.",
                        raw.rstrip(),
                    ))

        # K8S011 — Seccomp profile explicitly set to Unconfined
        if "type:" in line_lower and "unconfined" in line_lower:
            if not _is_suppressed(raw, "K8S011"):
                findings.append(_make_finding(
                    file_path, lineno, "K8S011", Severity.MEDIUM.value,
                    "Seccomp profile set to Unconfined — disables standard kernel syscall filtering",
                    "Set securityContext.seccompProfile.type: RuntimeDefault to enforce standard syscall filters.",
                    raw.rstrip(),
                ))

        # K8S013 — Plaintext secret in container env
        env_match = re.search(
            r"^\s*-\s*name\s*:\s*['\"]?([A-Za-z0-9_]*(?:PASSWORD|SECRET|KEY|TOKEN|AUTH|PASSWD|CREDENTIAL)[A-Za-z0-9_]*)['\"]?",
            raw,
            re.IGNORECASE,
        )
        if env_match:
            cur_secret_env_name = env_match.group(1)
        elif cur_secret_env_name:
            val_match = re.search(r"^\s*value\s*:\s*['\"]?([^'\"\s#]+)['\"]?", raw)
            if val_match and "valuefrom" not in line_lower:
                val = val_match.group(1).strip()
                if val and not (val.startswith("{{") or val.startswith("$(") or val.startswith("${")):
                    if not _is_suppressed(raw, "K8S013"):
                        findings.append(_make_finding(
                            file_path, lineno, "K8S013", Severity.HIGH.value,
                            f"Plaintext secret detected in container env var '{cur_secret_env_name}'",
                            "Store sensitive credentials in Kubernetes Secrets and reference them using valueFrom.secretKeyRef.",
                            raw.rstrip(),
                        ))
                cur_secret_env_name = None
            elif re.match(r"^\s*-\s*name\s*:", raw) or re.match(r"^\s*[a-zA-Z]", raw) or "valuefrom:" in line_lower:
                cur_secret_env_name = None

        # K8S014 — Default namespace usage
        if re.search(r"^\s*namespace\s*:\s*['\"]?default['\"]?\s*(?:#.*)?$", raw, re.IGNORECASE):
            if not _is_suppressed(raw, "K8S014"):
                findings.append(_make_finding(
                    file_path, lineno, "K8S014", Severity.LOW.value,
                    "Explicit usage of 'default' namespace detected — lacks tenant isolation",
                    "Deploy workloads into dedicated, logically isolated namespaces instead of the default namespace.",
                    raw.rstrip(),
                ))

        # K8S015 — Mutable or untagged container image
        img_match = re.search(r"^\s*image\s*:\s*['\"]?([^'\"\s#]+)['\"]?", raw)
        if img_match:
            img_val = img_match.group(1).strip()
            if not (img_val.startswith("{{") or img_val.startswith("$")):
                last_segment = img_val.split("/")[-1]
                is_mutable = False
                if ":" in last_segment:
                    tag = last_segment.split(":", 1)[1].strip()
                    if tag.lower() in ("latest", ""):
                        is_mutable = True
                elif "@" not in last_segment:
                    is_mutable = True
                if is_mutable and not _is_suppressed(raw, "K8S015"):
                    findings.append(_make_finding(
                        file_path, lineno, "K8S015", Severity.HIGH.value,
                        f"Mutable or untagged container image '{img_val}' detected — supply-chain drift risk",
                        "Pin an immutable tag or digest (e.g. image: name:v1.2.3 or image: name@sha256:...) instead of ':latest' or untagged images.",
                        raw.rstrip(),
                    ))

        # K8S017 — Container runtime socket mount
        if any(sock in line_lower for sock in ("docker.sock", "containerd.sock", "crio.sock")):
            if not _is_suppressed(raw, "K8S017"):
                findings.append(_make_finding(
                    file_path, lineno, "K8S017", Severity.CRITICAL.value,
                    "Container runtime socket mounted into container — allows complete host and cluster takeover",
                    "Do not mount container runtime sockets (docker.sock, containerd.sock). Use unprivileged or rootless build tools.",
                    raw.rstrip(),
                ))

        # K8S019 — Insecure imagePullPolicy (Never)
        if re.search(r"^\s*imagepullpolicy\s*:\s*['\"]?never['\"]?", raw, re.IGNORECASE):
            if not _is_suppressed(raw, "K8S019"):
                findings.append(_make_finding(
                    file_path, lineno, "K8S019", Severity.HIGH.value,
                    "Insecure imagePullPolicy: Never prevents Kubernetes from fetching verified container image updates",
                    "Set imagePullPolicy: Always or IfNotPresent with immutable tags.",
                    raw.rstrip(),
                ))

        # K8S020 — Default ServiceAccount usage
        if re.search(r"^\s*serviceaccount(?:name)?\s*:\s*['\"]?default['\"]?\s*(?:#.*)?$", raw, re.IGNORECASE):
            if not _is_suppressed(raw, "K8S020"):
                findings.append(_make_finding(
                    file_path, lineno, "K8S020", Severity.LOW.value,
                    "Explicit assignment of 'default' ServiceAccount detected — lacks principle of least privilege",
                    "Create and bind dedicated ServiceAccounts with least-privilege RBAC roles for workloads.",
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

    # K8S011 — Missing Seccomp profile (document-level)
    if in_containers_block and not has_seccomp_profile:
        if not _is_suppressed(lines[0] if lines else "", "K8S011"):
            findings.append(_make_finding(
                file_path, 1, "K8S011", Severity.MEDIUM.value,
                "Missing Seccomp profile — container operates without syscall restriction filters",
                "Set securityContext.seccompProfile.type: RuntimeDefault in Pod or container securityContext.",
                "",
            ))

    # K8S012 — Missing NetworkPolicy definition for workload (document-level)
    if is_workload and not has_network_policy:
        if not _is_suppressed(lines[0] if lines else "", "K8S012"):
            findings.append(_make_finding(
                file_path, 1, "K8S012", Severity.MEDIUM.value,
                "Missing NetworkPolicy definition — pod network traffic is unrestricted by default",
                "Define a Kubernetes NetworkPolicy for this workload to isolate pod ingress and egress traffic.",
                "",
            ))

    # K8S016 — Missing health checks (document-level)
    if is_workload and in_containers_block and not (seen_liveness_probe and seen_readiness_probe):
        if not _is_suppressed(lines[0] if lines else "", "K8S016"):
            missing = []
            if not seen_liveness_probe:
                missing.append("livenessProbe")
            if not seen_readiness_probe:
                missing.append("readinessProbe")
            findings.append(_make_finding(
                file_path, 1, "K8S016", Severity.MEDIUM.value,
                f"Container missing health check probes ({' and '.join(missing)}) — availability and recovery risk",
                "Define both livenessProbe and readinessProbe for all workload containers to ensure zero-downtime rollouts and self-healing.",
                "",
            ))

    # K8S018 — NET_RAW capability not dropped (document-level)
    if is_workload and in_containers_block and not has_dropped_net_raw:
        if not _is_suppressed(lines[0] if lines else "", "K8S018"):
            findings.append(_make_finding(
                file_path, 1, "K8S018", Severity.MEDIUM.value,
                "Container does not drop NET_RAW capability — network spoofing and ARP poisoning risk (CIS 5.2.7)",
                "Drop NET_RAW or ALL capabilities under securityContext.capabilities.drop: ['ALL'].",
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
