"""
Terraform and OpenTofu Infrastructure-as-Code (IaC) Security Scanner.
Performs static analysis on .tf and .tfvars files without external binary dependencies.

Rules:
  TF001 (HIGH)     - Security group ingress allowing open 0.0.0.0/0 on sensitive ports (22, 3389, DBs)
  TF002 (CRITICAL) - Overly permissive IAM policy document with wildcard Action and Resource
  TF003 (HIGH)     - S3 bucket or cloud storage with public-read ACL or missing encryption
  TF004 (HIGH)     - Unencrypted database or storage volume (storage_encrypted / encrypted = false)
  TF005 (CRITICAL) - Publicly accessible database instance (publicly_accessible = true)
  TF006 (MEDIUM)   - S3 bucket public access block explicitly disabled
  TF007 (HIGH)     - Hardcoded plaintext credentials or secret keys in Terraform files
  TF008 (HIGH)     - Cloud storage container with public access enabled
"""

import os
import re
from typing import List, Optional
from maunprekshak.scanner.report import SASTFinding, Severity

EXCLUDE_DIRS = {
    "node_modules", ".git", "__pycache__", "venv", ".venv",
    "dist", "build", ".eggs", "site-packages", "tests", "test",
    "testing", "fixtures", ".terraform",
}

# Sensitive ports commonly targeted for exploitation
SENSITIVE_PORTS = {
    22: "SSH",
    3389: "RDP",
    5432: "PostgreSQL",
    3306: "MySQL",
    1433: "MSSQL",
    27017: "MongoDB",
    6379: "Redis",
    9200: "Elasticsearch",
}


def _is_suppressed(line: str, check_id: str) -> bool:
    """Check if a line contains an inline suppression comment."""
    line_lower = line.lower()
    if "#" not in line_lower and "//" not in line_lower:
        return False
    comment_part = line_lower[line_lower.find("#"):] if "#" in line_lower else line_lower[line_lower.find("//"):]
    if "maunprekshak: ignore" in comment_part or "maunprekshak:ignore" in comment_part:
        match = re.search(r"ignore(?:\[(.*?)\])?", comment_part)
        if match:
            rules_str = match.group(1)
            if not rules_str:
                return True
            rules = [r.strip().upper() for r in rules_str.split(",") if r.strip()]
            return check_id.upper() in rules
    if "nosec" in comment_part:
        if f"nosec: {check_id.lower()}" in comment_part or f"nosec:{check_id.lower()}" in comment_part:
            return True
        if "nosec:" not in comment_part:
            return True
    return False


def _make_finding(
    file_path: str,
    line: int,
    check_id: str,
    severity: str,
    description: str,
    recommendation: str,
    snippet: str,
) -> SASTFinding:
    return SASTFinding(
        file_path=file_path,
        line=line,
        col=1,
        check_id=check_id,
        severity=severity,
        description=description,
        recommendation=recommendation,
        code_snippet=snippet[:120].strip(),
    )


def scan_single_terraform_file(file_path: str) -> List[SASTFinding]:
    """Scan a single .tf or .tfvars file for IaC security misconfigurations."""
    findings: List[SASTFinding] = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except Exception:
        return findings

    # State tracking across multiline blocks
    in_security_group_or_ingress = False
    sg_from_port = None
    sg_to_port = None
    sg_port_line = None

    in_iam_policy = False
    has_wildcard_action = False
    has_wildcard_resource = False
    iam_start_line = None

    for idx, raw in enumerate(lines):
        lineno = idx + 1
        line = raw.strip()
        line_lower = line.lower()

        # ─── TF007: Hardcoded Plaintext Secrets in .tf / .tfvars ─────────────
        # Pattern: password = "plain" or secret_key = "plain" (excluding variable references like var.xyz)
        pwd_match = re.search(
            r"""(?:password|secret_key|admin_password|db_password|api_key)\s*=\s*["']([^"'\${}\s]{4,})["']""",
            line,
            re.IGNORECASE,
        )
        if pwd_match:
            val = pwd_match.group(1)
            # Exclude interpolations and common dummy words
            if not val.startswith(("${", "var.", "local.")) and val.lower() not in ("dummy", "change_me", "none", "null", "false", "true"):
                if not _is_suppressed(raw, "TF007"):
                    findings.append(_make_finding(
                        file_path, lineno, "TF007", Severity.HIGH.value,
                        "Hardcoded plaintext credential or secret detected in Terraform configuration",
                        "Store credentials in environment variables or an external secret manager (AWS Secrets Manager, Vault).",
                        raw,
                    ))

        # ─── TF003: S3 / Cloud Storage Public ACL ────────────────────────────
        if "acl" in line_lower and any(public_acl in line_lower for public_acl in ('"public-read"', '"public-read-write"', "'public-read'", "'public-read-write'")):
            if not _is_suppressed(raw, "TF003"):
                findings.append(_make_finding(
                    file_path, lineno, "TF003", Severity.HIGH.value,
                    "Cloud storage bucket configured with public-read or public-read-write ACL",
                    "Configure private bucket ACL: acl = \"private\" and enforce Public Access Block.",
                    raw,
                ))

        # ─── TF004: Unencrypted Storage or Database Volume ───────────────────
        if re.search(r"""(?:storage_encrypted|encrypted)\s*=\s*false\b""", line_lower):
            if not _is_suppressed(raw, "TF004"):
                findings.append(_make_finding(
                    file_path, lineno, "TF004", Severity.HIGH.value,
                    "Storage volume or database configured with encryption disabled (encrypted = false)",
                    "Enable at-rest encryption: encrypted = true or storage_encrypted = true with KMS key.",
                    raw,
                ))

        # ─── TF005: Publicly Accessible Database ─────────────────────────────
        if re.search(r"""publicly_accessible\s*=\s*true\b""", line_lower):
            if not _is_suppressed(raw, "TF005"):
                findings.append(_make_finding(
                    file_path, lineno, "TF005", Severity.CRITICAL.value,
                    "Database instance is configured as publicly accessible from the internet",
                    "Set publicly_accessible = false and deploy databases inside private subnets.",
                    raw,
                ))

        # ─── TF006: S3 Public Access Block Disabled ──────────────────────────
        if any(block_disabled in line_lower for block_disabled in (
            "block_public_acls = false",
            "block_public_policy = false",
            "ignore_public_acls = false",
            "restrict_public_buckets = false",
        )):
            if not _is_suppressed(raw, "TF006"):
                findings.append(_make_finding(
                    file_path, lineno, "TF006", Severity.MEDIUM.value,
                    "S3 Public Access Block protection explicitly disabled",
                    "Enable all public access blocks: block_public_acls = true, block_public_policy = true.",
                    raw,
                ))

        # ─── TF008: Storage Container Public Access ──────────────────────────
        if (
            'public_access_type = "container"' in line_lower
            or 'public_access_type = "blob"' in line_lower
            or 'container_access_type = "container"' in line_lower
            or 'container_access_type = "blob"' in line_lower
            or 'entity = "allusers"' in line_lower
            or 'entity = "allauthenticatedusers"' in line_lower
            or 'member = "allusers"' in line_lower
            or 'member = "allauthenticatedusers"' in line_lower
        ):
            if not _is_suppressed(raw, "TF008"):
                findings.append(_make_finding(
                    file_path, lineno, "TF008", Severity.HIGH.value,
                    "Cloud storage container or bucket configured with anonymous public access",
                    "Restrict access: remove public entities (allUsers) or set container_access_type = \"private\".",
                    raw,
                ))

        # ─── TF001: Security Group Open Ingress Tracking ─────────────────────
        if "ingress" in line_lower or "aws_security_group" in line_lower:
            in_security_group_or_ingress = True

        port_match = re.search(r"""(?:from_port|to_port)\s*=\s*(\d+)""", line_lower)
        if port_match:
            p = int(port_match.group(1))
            if "from_port" in line_lower:
                sg_from_port = p
            if "to_port" in line_lower:
                sg_to_port = p
            sg_port_line = lineno

        if 'cidr_blocks' in line_lower and ('"0.0.0.0/0"' in line or "'0.0.0.0/0'" in line):
            # Check if associated with sensitive port or open range
            is_sensitive = False
            port_name = "management/database"
            if sg_from_port is not None and sg_to_port is not None:
                for sport, sname in SENSITIVE_PORTS.items():
                    if sg_from_port <= sport <= sg_to_port:
                        is_sensitive = True
                        port_name = f"{sname} ({sport})"
                        break
                if sg_from_port == 0 and sg_to_port == 0:
                    is_sensitive = True
                    port_name = "ALL ports"
            elif in_security_group_or_ingress:
                is_sensitive = True

            if is_sensitive and not _is_suppressed(raw, "TF001"):
                findings.append(_make_finding(
                    file_path, lineno, "TF001", Severity.HIGH.value,
                    f"Security group ingress rule allows open 0.0.0.0/0 access on sensitive port {port_name}",
                    "Restrict CIDR blocks to specific authorized IP ranges or private VPC subnets.",
                    raw,
                ))
            # Reset port tracking after CIDR block check
            sg_from_port = None
            sg_to_port = None

        if line == "}" or line == "},":
            in_security_group_or_ingress = False

        # ─── TF002: Overly Permissive IAM Policy Tracking ────────────────────
        if "aws_iam_policy" in line_lower or "policy" in line_lower:
            in_iam_policy = True
            iam_start_line = lineno
            has_wildcard_action = False
            has_wildcard_resource = False

        if in_iam_policy:
            if re.search(r"""["']action["']\s*:\s*["']\*["']""", line_lower) or re.search(r"""actions?\s*=\s*\[\s*["']\*["']\s*\]""", line_lower):
                has_wildcard_action = True
            if re.search(r"""["']resource["']\s*:\s*["']\*["']""", line_lower) or re.search(r"""resources?\s*=\s*\[\s*["']\*["']\s*\]""", line_lower):
                has_wildcard_resource = True

            if has_wildcard_action and has_wildcard_resource:
                if not _is_suppressed(raw, "TF002"):
                    findings.append(_make_finding(
                        file_path, iam_start_line or lineno, "TF002", Severity.CRITICAL.value,
                        "IAM policy grants full administrative wildcard permissions (Action: *, Resource: *)",
                        "Follow the principle of least privilege. Grant only specific actions on specific resource ARNs.",
                        raw,
                    ))
                has_wildcard_action = False
                has_wildcard_resource = False
                in_iam_policy = False

    return findings


def scan_terraform(
    path: str,
    exclude: Optional[List[str]] = None,
    target_files: Optional[List[str]] = None,
) -> List[SASTFinding]:
    """
    Scan Terraform and OpenTofu files (*.tf, *.tfvars) in the project directory.

    Args:
        path: Absolute path to the project root directory.
        exclude: Optional list of additional directories or paths to exclude.
        target_files: Optional list of specific files to check.

    Returns:
        List of SASTFinding objects for IaC security issues.
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
            if not os.path.isfile(abs_path) or not abs_path.endswith((".tf", ".tfvars")):
                continue
            path_parts = set(abs_path.replace("\\", "/").split("/"))
            rel_file = os.path.relpath(abs_path, path).replace("\\", "/")
            bname = os.path.basename(abs_path)
            if path_parts & active_excludes or rel_file in active_excludes or bname in active_excludes:
                continue
            findings.extend(scan_single_terraform_file(abs_path))
    else:
        for root, dirs, files in os.walk(path):
            dirs[:] = [
                d for d in dirs
                if d not in active_excludes
                and os.path.relpath(os.path.join(root, d), path).replace("\\", "/") not in active_excludes
            ]
            for filename in files:
                if not filename.endswith((".tf", ".tfvars")):
                    continue
                rel_file = os.path.relpath(os.path.join(root, filename), path).replace("\\", "/")
                if filename in active_excludes or rel_file in active_excludes:
                    continue
                file_path = os.path.join(root, filename)
                findings.extend(scan_single_terraform_file(file_path))

    severity_order = {
        Severity.CRITICAL.value: 0, Severity.HIGH.value: 1,
        Severity.MEDIUM.value: 2, Severity.LOW.value: 3,
    }
    findings.sort(key=lambda f: (severity_order.get(f.severity, 9), f.file_path, f.line))
    return findings
