"""
Deterministic mechanical auto-fixing for safe SAST, IaC, and container anti-patterns.
Supports:
- MP012: yaml.load(data) -> yaml.safe_load(data)
- MP014: tempfile.mktemp(...) -> tempfile.NamedTemporaryFile(...).name
- MP015: verify=False -> verify=True
- MP023: tarfile.extractall() -> tarfile.extractall(filter='data')
- MP031: torch.load(...) -> torch.load(..., weights_only=True)
- MP033: os.chmod(..., 0o777) -> 0o700 / 0o666 -> 0o600
- MP036: yaml.unsafe_load(...) -> yaml.safe_load(...) / Loader=yaml.SafeLoader
- MP051: numpy.load(..., allow_pickle=True) -> allow_pickle=False
- K8S001: privileged: true -> privileged: false
- K8S006: allowPrivilegeEscalation: true -> allowPrivilegeEscalation: false
- K8S007: readOnlyRootFilesystem: false -> readOnlyRootFilesystem: true
- K8S009: hostNetwork/hostPID/hostIPC: true -> false
- TF004: storage_encrypted / encrypted = false -> true
- TF005: publicly_accessible = true -> false
- TF006: block_public_acls = false -> true
- DF002: Missing non-root USER -> inject USER 10001:10001
"""
import os
import re
from typing import List, Tuple, Set
from maunprekshak.scanner.report import SASTFinding, ScanResult, aggregate

FIXABLE_RULES = {
    "MP012", "MP014", "MP015", "MP023", "MP031", "MP033", "MP036",
    "MP051", "K8S001", "K8S006", "K8S007", "K8S009",
    "TF004", "TF005", "TF006", "DF002",
}


def fix_file_findings(file_path: str, findings: List[SASTFinding]) -> int:
    """
    Apply mechanical fixes to a specific file based on SAST findings.
    Returns the number of fixes applied.
    """
    if not os.path.isfile(file_path) or not findings:
        return 0

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except Exception:
        return 0

    applicable = [f for f in findings if f.check_id in FIXABLE_RULES]
    if not applicable:
        return 0

    # Sort descending by line number so fixes operate reliably
    applicable.sort(key=lambda x: x.line, reverse=True)

    applied = 0
    modified = False

    for finding in applicable:
        line_idx = finding.line - 1
        if 0 <= line_idx < len(lines):
            line = lines[line_idx]
            new_line = line

            if finding.check_id == "MP012":
                if "yaml.load(" in new_line:
                    new_line = new_line.replace("yaml.load(", "yaml.safe_load(")

            elif finding.check_id == "MP014":
                if "tempfile.mktemp(" in new_line:
                    new_line = re.sub(
                        r"tempfile\.mktemp\((.*?)\)",
                        r"tempfile.NamedTemporaryFile(\1).name",
                        new_line,
                    )

            elif finding.check_id == "MP015":
                if re.search(r"\bverify\s*=\s*False\b", new_line):
                    new_line = re.sub(r"\bverify\s*=\s*False\b", "verify=True", new_line)

            elif finding.check_id == "MP023":
                if ".extractall(" in new_line:
                    def _patch_extractall(match):
                        args = match.group(1).strip()
                        if not args:
                            return ".extractall(filter='data')"
                        elif "filter=" not in args:
                            return f".extractall({args}, filter='data')"
                        return match.group(0)

                    new_line = re.sub(
                        r"\.extractall\((.*?)\)",
                        _patch_extractall,
                        new_line,
                    )

            elif finding.check_id == "MP031":
                if "weights_only=False" in new_line or "weights_only = False" in new_line:
                    new_line = re.sub(r"\bweights_only\s*=\s*False\b", "weights_only=True", new_line)
                elif "torch.load(" in new_line:
                    def _patch_torch_load(match):
                        args = match.group(1).strip()
                        if not args:
                            return "torch.load(weights_only=True)"
                        elif "weights_only=" not in args:
                            return f"torch.load({args}, weights_only=True)"
                        return match.group(0)

                    new_line = re.sub(r"torch\.load\((.*?)\)", _patch_torch_load, new_line)

            elif finding.check_id == "MP033":
                if "0o777" in new_line:
                    new_line = re.sub(r"\b0o777\b", "0o700", new_line)
                elif "0o666" in new_line:
                    new_line = re.sub(r"\b0o666\b", "0o600", new_line)

            elif finding.check_id == "MP036":
                if "yaml.unsafe_load(" in new_line:
                    new_line = new_line.replace("yaml.unsafe_load(", "yaml.safe_load(")
                elif re.search(r"Loader\s*=\s*(?:yaml\.)?(?:UnsafeLoader|Loader|CLoader)\b", new_line):
                    new_line = re.sub(
                        r"Loader\s*=\s*(?:yaml\.)?(?:UnsafeLoader|Loader|CLoader)\b",
                        "Loader=yaml.SafeLoader",
                        new_line,
                    )

            elif finding.check_id == "MP051":
                if re.search(r"\ballow_pickle\s*=\s*(?:True|1)\b", new_line):
                    new_line = re.sub(r"\ballow_pickle\s*=\s*(?:True|1)\b", "allow_pickle=False", new_line)

            elif finding.check_id == "K8S001":
                if re.search(r"\bprivileged\s*:\s*true\b", new_line, re.IGNORECASE):
                    new_line = re.sub(r"(\bprivileged\s*:\s*)true\b", r"\1false", new_line, flags=re.IGNORECASE)

            elif finding.check_id == "K8S006":
                if re.search(r"\ballowPrivilegeEscalation\s*:\s*true\b", new_line, re.IGNORECASE):
                    new_line = re.sub(r"(\ballowPrivilegeEscalation\s*:\s*)true\b", r"\1false", new_line, flags=re.IGNORECASE)

            elif finding.check_id == "K8S007":
                if re.search(r"\breadOnlyRootFilesystem\s*:\s*false\b", new_line, re.IGNORECASE):
                    new_line = re.sub(r"(\breadOnlyRootFilesystem\s*:\s*)false\b", r"\1true", new_line, flags=re.IGNORECASE)

            elif finding.check_id == "K8S009":
                for prop in ("hostNetwork", "hostPID", "hostIPC"):
                    if re.search(rf"\b{prop}\s*:\s*true\b", new_line, re.IGNORECASE):
                        new_line = re.sub(rf"(\b{prop}\s*:\s*)true\b", r"\1false", new_line, flags=re.IGNORECASE)

            elif finding.check_id == "TF004":
                new_line = re.sub(
                    r"\b(storage_encrypted|encrypted)\s*=\s*false\b",
                    r"\1 = true",
                    new_line,
                    flags=re.IGNORECASE,
                )

            elif finding.check_id == "TF005":
                new_line = re.sub(
                    r"\bpublicly_accessible\s*=\s*true\b",
                    "publicly_accessible = false",
                    new_line,
                    flags=re.IGNORECASE,
                )

            elif finding.check_id == "TF006":
                new_line = re.sub(
                    r"\b(block_public_acls|block_public_policy|ignore_public_acls|restrict_public_buckets)\s*=\s*false\b",
                    r"\1 = true",
                    new_line,
                    flags=re.IGNORECASE,
                )

            elif finding.check_id == "DF002":
                if re.search(r"^\s*USER\s+(?:root|0)\b", new_line, re.IGNORECASE):
                    new_line = re.sub(r"^\s*USER\s+(?:root|0)\b", "USER 10001:10001", new_line, flags=re.IGNORECASE)
                else:
                    has_user = any(re.match(r"^\s*USER\s+", l, re.IGNORECASE) for l in lines)
                    if not has_user:
                        cmd_idx = next(
                            (i for i, l in enumerate(lines) if re.match(r"^\s*(CMD|ENTRYPOINT)\b", l, re.IGNORECASE)),
                            None,
                        )
                        if cmd_idx is not None:
                            lines.insert(cmd_idx, "USER 10001:10001\n")
                        else:
                            lines.append("USER 10001:10001\n")
                        applied += 1
                        modified = True

            if new_line != line:
                lines[line_idx] = new_line
                applied += 1
                modified = True

    if modified:
        try:
            with open(file_path, "w", encoding="utf-8") as f:
                f.writelines(lines)
        except Exception:
            return 0

    return applied


def apply_auto_fixes(scan_result: ScanResult) -> Tuple[int, ScanResult]:
    """
    Apply auto-fixes across all SAST findings in scan_result.
    Returns (total_fixes_applied, updated_scan_result).
    """
    fixable_findings = [s for s in scan_result.sast if s.check_id in FIXABLE_RULES]
    if not fixable_findings:
        return 0, scan_result

    by_file = {}
    for f in fixable_findings:
        by_file.setdefault(f.file_path, []).append(f)

    total_fixed = 0
    fixed_findings: Set[Tuple[str, int, str]] = set()
    for file_path, findings in by_file.items():
        count = fix_file_findings(file_path, findings)
        if count > 0:
            total_fixed += count
            for f in findings:
                fixed_findings.add((f.file_path, f.line, f.check_id))

    if total_fixed > 0:
        scan_result.sast = [
            s for s in scan_result.sast
            if (s.file_path, s.line, s.check_id) not in fixed_findings
        ]
        recalculated = aggregate(scan_result.deps, scan_result.secrets, scan_result.sast)
        scan_result.risk_score = recalculated.risk_score

    return total_fixed, scan_result


def fix_requirements_txt(req_file_path: str, dep_findings: list) -> int:
    """
    Automatically patch a requirements.txt file to upgrade vulnerable
    pinned dependencies to their minimum safe fix version from OSV findings.

    Args:
        req_file_path: Absolute path to requirements.txt file.
        dep_findings:  List of DepVulnerability objects with a non-empty fix_version.

    Returns:
        Number of dependency entries successfully patched.
    """
    if not os.path.isfile(req_file_path):
        return 0

    fixable = {
        dep.package.lower(): dep.fix_version
        for dep in dep_findings
        if dep.fix_version and dep.fix_version not in ("", "N/A", "unknown")
    }
    if not fixable:
        return 0

    try:
        with open(req_file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except Exception:
        return 0

    patched = 0
    new_lines = []

    for line in lines:
        stripped = line.strip()
        # Skip comments and blank lines
        if not stripped or stripped.startswith("#"):
            new_lines.append(line)
            continue

        # Parse package specifier: name==version or name>=version etc.
        match = re.match(
            r"^([A-Za-z0-9_\-\.]+)"      # package name
            r"\s*([=!<>~^]+)\s*"          # specifier operator
            r"([0-9][^\s#;]*)(.*)$",       # version + tail
            stripped,
        )
        if match:
            pkg_name = match.group(1)
            operator = match.group(2)
            _cur_version = match.group(3)
            tail = match.group(4)

            fix_ver = fixable.get(pkg_name.lower())
            if fix_ver and operator in ("==", "<="):
                # Replace pinned or capped version with the fixed version
                new_line = f"{pkg_name}>={fix_ver}{tail}\n"
                new_lines.append(new_line)
                patched += 1
                continue

        new_lines.append(line)

    if patched > 0:
        try:
            with open(req_file_path, "w", encoding="utf-8") as f:
                f.writelines(new_lines)
        except Exception:
            return 0

    return patched

