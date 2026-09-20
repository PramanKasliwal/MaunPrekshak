"""
Deterministic mechanical auto-fixing for safe SAST anti-patterns.
Supports:
- MP012: yaml.load(data) -> yaml.safe_load(data)
- MP023: tarfile.extractall() -> tarfile.extractall(filter='data')
- MP014: tempfile.mktemp(...) -> tempfile.NamedTemporaryFile(...).name
"""
import os
import re
from typing import List, Tuple, Set
from maunprekshak.scanner.report import SASTFinding, ScanResult, aggregate


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

    fixable_rules = {"MP012", "MP023", "MP014"}
    applicable = [f for f in findings if f.check_id in fixable_rules]
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
                # Replace yaml.load( with yaml.safe_load(
                if "yaml.load(" in new_line:
                    new_line = new_line.replace("yaml.load(", "yaml.safe_load(")

            elif finding.check_id == "MP014":
                # Replace tempfile.mktemp(...) with tempfile.NamedTemporaryFile(...).name
                if "tempfile.mktemp(" in new_line:
                    new_line = re.sub(
                        r"tempfile\.mktemp\((.*?)\)",
                        r"tempfile.NamedTemporaryFile(\1).name",
                        new_line,
                    )

            elif finding.check_id == "MP023":
                # Replace .extractall(...) with filter='data'
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
    fixable_rules = {"MP012", "MP023", "MP014"}
    fixable_findings = [s for s in scan_result.sast if s.check_id in fixable_rules]
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
