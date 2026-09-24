"""
MaunPrekshak — Core Data Models & Report Generation
All shared dataclasses, risk scoring, and output formatting live here.
"""
import json
import os
import re
import uuid
from dataclasses import dataclass, asdict, field
from typing import List, Optional
from enum import Enum
from maunprekshak import __version__


# ─── Enums ────────────────────────────────────────────────────────────────────

class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# ─── Dataclasses ──────────────────────────────────────────────────────────────

@dataclass
class DepVulnerability:
    """A CVE found in a Python dependency."""
    package: str
    version: str
    cve_id: str
    severity: str
    cvss_score: float
    description: str
    fix_version: str


@dataclass
class SecretFinding:
    """A hardcoded secret or credential found in source code."""
    file_path: str
    line: int           # Line number (1-indexed)
    secret_type: str
    masked_value: str
    severity: str

    # Backward-compat alias
    @property
    def line_number(self) -> int:
        return self.line


@dataclass
class SASTFinding:
    """A static analysis security finding."""
    file_path: str
    line: int           # Line number (1-indexed)
    col: int            # Column offset
    check_id: str       # e.g. MP001
    severity: str
    description: str
    recommendation: str
    code_snippet: str = ""

    # Backward-compat aliases
    @property
    def line_number(self) -> int:
        return self.line

    @property
    def col_offset(self) -> int:
        return self.col


@dataclass
class RiskScore:
    """Overall risk score for a scan."""
    score: int
    level: str  # LOW | MEDIUM | HIGH | CRITICAL


@dataclass
class ScanResult:
    """Complete result of a MaunPrekshak scan."""
    deps: List[DepVulnerability] = field(default_factory=list)
    secrets: List[SecretFinding] = field(default_factory=list)
    sast: List[SASTFinding] = field(default_factory=list)
    risk_score: Optional[RiskScore] = None
    ai_summary: Optional[str] = None

    @property
    def total_findings(self) -> int:
        return len(self.deps) + len(self.secrets) + len(self.sast)

    @property
    def critical_count(self) -> int:
        all_findings = list(self.deps) + list(self.secrets) + list(self.sast)
        return sum(1 for f in all_findings if getattr(f, "severity", "") == Severity.CRITICAL.value)

    @property
    def high_count(self) -> int:
        all_findings = list(self.deps) + list(self.secrets) + list(self.sast)
        return sum(1 for f in all_findings if getattr(f, "severity", "") == Severity.HIGH.value)

    @property
    def medium_count(self) -> int:
        all_findings = list(self.deps) + list(self.secrets) + list(self.sast)
        return sum(1 for f in all_findings if getattr(f, "severity", "") == Severity.MEDIUM.value)

    @property
    def low_count(self) -> int:
        all_findings = list(self.deps) + list(self.secrets) + list(self.sast)
        return sum(1 for f in all_findings if getattr(f, "severity", "") == Severity.LOW.value)


# ─── Aggregation & Scoring ────────────────────────────────────────────────────

def aggregate(
    deps: List[DepVulnerability],
    secrets: List[SecretFinding],
    sast: List[SASTFinding],
) -> ScanResult:
    """
    Aggregate all scanner findings and calculate overall risk score.

    Scoring:
        CRITICAL = 10 pts, HIGH = 5 pts, MEDIUM = 2 pts, LOW = 1 pt
    Levels:
        0–20 = LOW, 21–50 = MEDIUM, 51–99 = HIGH, 100+ = CRITICAL
    """
    score = 0
    score_map = {
        Severity.CRITICAL.value: 10,
        Severity.HIGH.value: 5,
        Severity.MEDIUM.value: 2,
        Severity.LOW.value: 1,
    }

    for item in list(deps) + list(secrets) + list(sast):
        sev = getattr(item, "severity", Severity.LOW.value)
        score += score_map.get(sev, 1)

    if score >= 100:
        level = "CRITICAL"
    elif score >= 51:
        level = "HIGH"
    elif score >= 21:
        level = "MEDIUM"
    else:
        level = "LOW"

    return ScanResult(
        deps=deps,
        secrets=secrets,
        sast=sast,
        risk_score=RiskScore(score=score, level=level),
    )


# ─── AI Summary ───────────────────────────────────────────────────────────────

from maunprekshak.scanner.ai import generate_ai_summary


# ─── Output Formatters ────────────────────────────────────────────────────────

def to_json(scan_result: ScanResult) -> str:
    """Serialize scan result to JSON string."""
    data = {
        "risk_score": asdict(scan_result.risk_score) if scan_result.risk_score else None,
        "ai_summary": scan_result.ai_summary,
        "summary": {
            "deps": len(scan_result.deps),
            "secrets": len(scan_result.secrets),
            "sast": len(scan_result.sast),
            "total": scan_result.total_findings,
        },
        "deps": [asdict(d) for d in scan_result.deps],
        "secrets": [
            {
                "file_path": s.file_path,
                "line": s.line,
                "secret_type": s.secret_type,
                "masked_value": s.masked_value,
                "severity": s.severity,
            }
            for s in scan_result.secrets
        ],
        "sast": [
            {
                "file_path": s.file_path,
                "line": s.line,
                "col": s.col,
                "check_id": s.check_id,
                "severity": s.severity,
                "description": s.description,
                "recommendation": s.recommendation,
                "code_snippet": s.code_snippet,
            }
            for s in scan_result.sast
        ],
    }
    return json.dumps(data, indent=2)


def to_markdown(scan_result: ScanResult) -> str:
    """Format scan result as a Markdown report."""
    md = "# मौन प्रेक्षक — MaunPrekshak Security Report\n\n"

    if scan_result.risk_score:
        md += f"**Overall Risk:** `{scan_result.risk_score.level}` (Score: {scan_result.risk_score.score})\n\n"

    md += f"| Module | Findings |\n|--------|----------|\n"
    md += f"| Dependencies | {len(scan_result.deps)} |\n"
    md += f"| Secrets | {len(scan_result.secrets)} |\n"
    md += f"| SAST | {len(scan_result.sast)} |\n\n"

    if scan_result.ai_summary:
        md += f"## AI Executive Summary\n\n{scan_result.ai_summary}\n\n"

    if scan_result.deps:
        md += "## Dependency Vulnerabilities\n\n"
        md += "| Package | Version | CVE | Severity | Description |\n"
        md += "|---------|---------|-----|----------|-------------|\n"
        for d in scan_result.deps:
            md += f"| {d.package} | {d.version} | {d.cve_id} | `{d.severity}` | {d.description[:60]}... |\n"
        md += "\n"

    if scan_result.secrets:
        md += "## Exposed Secrets\n\n"
        md += "| File | Line | Type | Value | Severity |\n"
        md += "|------|------|------|-------|----------|\n"
        for s in scan_result.secrets:
            md += f"| {os.path.basename(s.file_path)} | {s.line} | {s.secret_type} | `{s.masked_value}` | `{s.severity}` |\n"
        md += "\n"

    if scan_result.sast:
        md += "## SAST Findings\n\n"
        md += "| File | Line | Check | Severity | Description |\n"
        md += "|------|------|-------|----------|-------------|\n"
        for s in scan_result.sast:
            md += f"| {os.path.basename(s.file_path)} | {s.line} | {s.check_id} | `{s.severity}` | {s.description} |\n"
        md += "\n"

    return md


def to_pdf(scan_result: ScanResult, output_path: str) -> None:
    """
    Generate a PDF security report using reportlab.
    Falls back silently if reportlab is not installed.
    """
    try:
        from reportlab.pdfgen import canvas
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors

        c = canvas.Canvas(output_path, pagesize=A4)
        width, height = A4

        # Header
        c.setFont("Helvetica-Bold", 20)
        c.setFillColor(colors.HexColor("#1a1a2e"))
        c.drawString(50, height - 60, "MaunPrekshak Security Report")
        c.setFont("Helvetica", 11)
        c.setFillColor(colors.grey)
        c.drawString(50, height - 80, "मौन प्रेक्षक — The Silent Observer")

        # Risk score
        if scan_result.risk_score:
            color_map = {
                "CRITICAL": colors.red,
                "HIGH": colors.orangered,
                "MEDIUM": colors.orange,
                "LOW": colors.green,
            }
            c.setFont("Helvetica-Bold", 14)
            c.setFillColor(color_map.get(scan_result.risk_score.level, colors.black))
            c.drawString(50, height - 120,
                         f"Overall Risk: {scan_result.risk_score.level} (Score: {scan_result.risk_score.score})")

        # Summary table
        c.setFont("Helvetica", 12)
        c.setFillColor(colors.black)
        y = height - 160
        c.drawString(50, y, f"Dependency vulnerabilities: {len(scan_result.deps)}")
        c.drawString(50, y - 20, f"Exposed secrets: {len(scan_result.secrets)}")
        c.drawString(50, y - 40, f"SAST findings: {len(scan_result.sast)}")

        # AI Summary
        if scan_result.ai_summary:
            c.setFont("Helvetica-Bold", 12)
            c.drawString(50, y - 80, "AI Executive Summary:")
            c.setFont("Helvetica", 10)
            text = c.beginText(50, y - 100)
            for line in scan_result.ai_summary[:800].split("\n"):
                text.textLine(line[:100])
            c.drawText(text)

        c.save()

    except ImportError:
        print("[Warning] reportlab not installed — PDF generation skipped. Run: pip install reportlab")


def to_sarif(scan_result: ScanResult, project_root: str = ".") -> str:
    """
    Serialize scan result to OASIS SARIF 2.1.0 format.
    Compatible with GitHub Advanced Security / Code Scanning.
    """
    rules_dict = {}
    results_list = []

    level_map = {
        "CRITICAL": "error",
        "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "note",
    }

    root = os.path.abspath(project_root)

    def _relpath(p: str) -> str:
        try:
            rel = os.path.relpath(os.path.abspath(p), root)
            if rel.startswith(".."):
                return os.path.basename(p)
            return rel.replace("\\", "/")
        except Exception:
            return os.path.basename(p)

    # 1. Process SAST findings
    for s in scan_result.sast:
        rule_id = s.check_id
        if rule_id not in rules_dict:
            rules_dict[rule_id] = {
                "id": rule_id,
                "name": f"PythonSAST_{rule_id}",
                "shortDescription": {"text": s.description},
                "fullDescription": {
                    "text": f"{s.description}. Recommendation: {s.recommendation}"
                },
                "defaultConfiguration": {
                    "level": level_map.get(s.severity.upper(), "warning")
                },
                "helpUri": "https://github.com/PramanKasliwal/maunprekshak#static-code-analysis-sast",
            }

        rel_file = _relpath(s.file_path)
        start_line = max(1, s.line)
        start_col = max(1, getattr(s, "col", 1))

        results_list.append(
            {
                "ruleId": rule_id,
                "level": level_map.get(s.severity.upper(), "warning"),
                "message": {
                    "text": f"{s.description}: {s.recommendation}"
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": rel_file,
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": {
                                "startLine": start_line,
                                "startColumn": start_col,
                            },
                        }
                    }
                ],
            }
        )

    # 2. Process Secret findings
    for sec in scan_result.secrets:
        rule_id = f"MP-SECRET-{sec.secret_type.upper().replace(' ', '_').replace('/', '_')}"
        if rule_id not in rules_dict:
            rules_dict[rule_id] = {
                "id": rule_id,
                "name": "ExposedSecret",
                "shortDescription": {"text": f"Exposed secret: {sec.secret_type}"},
                "fullDescription": {
                    "text": f"Potential hardcoded credential or secret found: {sec.secret_type}. Immediately revoke and rotate this secret."
                },
                "defaultConfiguration": {"level": "error"},
                "helpUri": "https://github.com/PramanKasliwal/maunprekshak#secrets--credential-detection",
            }

        rel_file = _relpath(sec.file_path)
        start_line = max(1, sec.line)
        results_list.append(
            {
                "ruleId": rule_id,
                "level": level_map.get(sec.severity.upper(), "error"),
                "message": {
                    "text": f"Exposed {sec.secret_type} detected: {sec.masked_value}"
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": rel_file,
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": {
                                "startLine": start_line,
                                "startColumn": 1,
                            },
                        }
                    }
                ],
            }
        )

    # 3. Process Dependency findings
    for dep in scan_result.deps:
        rule_id = f"MP-DEP-{dep.package}"
        if rule_id not in rules_dict:
            rules_dict[rule_id] = {
                "id": rule_id,
                "name": "VulnerableDependency",
                "shortDescription": {"text": f"Vulnerable dependency: {dep.package}"},
                "fullDescription": {
                    "text": f"Package {dep.package} ({dep.version}) has known vulnerability {dep.cve_id}. {dep.description}"
                },
                "defaultConfiguration": {
                    "level": level_map.get(dep.severity.upper(), "error")
                },
                "helpUri": f"https://osv.dev/vulnerability/{dep.cve_id}" if dep.cve_id else "https://osv.dev",
            }

        msg = f"{dep.package}=={dep.version} is affected by {dep.cve_id}."
        if dep.fix_version:
            msg += f" Upgrade to >= {dep.fix_version}."

        results_list.append(
            {
                "ruleId": rule_id,
                "level": level_map.get(dep.severity.upper(), "error"),
                "message": {"text": msg},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": "requirements.txt",
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": {
                                "startLine": 1,
                                "startColumn": 1,
                            },
                        }
                    }
                ],
            }
        )

    sarif_data = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "MaunPrekshak",
                        "semanticVersion": __version__,
                        "informationUri": "https://github.com/PramanKasliwal/maunprekshak",
                        "rules": list(rules_dict.values()),
                    }
                },
                "results": results_list,
            }
        ],
    }

    return json.dumps(sarif_data, indent=2)


def to_cyclonedx(scan_result: ScanResult, project_name: str = "project") -> str:
    """
    Generate an OASIS CycloneDX 1.5 JSON Software Bill of Materials (SBOM).
    Includes all identified dependencies, purls, and linked vulnerability alerts.
    """
    from datetime import datetime, timezone

    components = []
    vulnerabilities = []
    seen_components = set()

    for dep in scan_result.deps:
        comp_key = (dep.package.lower(), dep.version)
        if "/" in dep.package and not dep.package.startswith("@"):
            purl = f"pkg:golang/{dep.package}@{dep.version}"
        elif dep.package.startswith("@") or any(ext in dep.package.lower() for ext in ("lodash", "react", "vue", "axios")):
            purl = f"pkg:npm/{dep.package}@{dep.version}"
        elif any(ext in dep.package.lower() for ext in ("serde", "tokio", "rand", "syn")):
            purl = f"pkg:cargo/{dep.package}@{dep.version}"
        else:
            purl = f"pkg:pypi/{dep.package}@{dep.version}"

        bom_ref = f"{dep.package}@{dep.version}"

        if comp_key not in seen_components:
            seen_components.add(comp_key)
            components.append({
                "type": "library",
                "bom-ref": bom_ref,
                "name": dep.package,
                "version": dep.version,
                "purl": purl,
            })

        if dep.cve_id:
            vulnerabilities.append({
                "bom-ref": f"vuln-{dep.cve_id}-{dep.package}",
                "id": dep.cve_id,
                "source": {
                    "name": "OSV",
                    "url": f"https://osv.dev/vulnerability/{dep.cve_id}",
                },
                "ratings": [
                    {
                        "source": {"name": "OSV"},
                        "score": dep.cvss_score,
                        "severity": dep.severity.lower(),
                        "method": "CVSSv3",
                    }
                ],
                "description": dep.description,
                "recommendation": f"Upgrade to {dep.fix_version}" if dep.fix_version else "Check upstream for patched release.",
                "affects": [
                    {
                        "ref": bom_ref,
                    }
                ],
            })

    cdx_data = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [
                {
                    "vendor": "MaunPrekshak",
                    "name": "maunprekshak",
                    "version": __version__,
                }
            ],
            "component": {
                "type": "application",
                "name": project_name,
            },
        },
        "components": components,
        "vulnerabilities": vulnerabilities,
    }
    return json.dumps(cdx_data, indent=2)


def to_spdx(scan_result: ScanResult, project_name: str = "project") -> str:
    """
    Generate a Linux Foundation SPDX 2.3 JSON Software Bill of Materials (SBOM).
    """
    from datetime import datetime, timezone

    packages = []
    seen = set()

    for dep in scan_result.deps:
        key = (dep.package.lower(), dep.version)
        if key in seen:
            continue
        seen.add(key)

        clean_pkg = re.sub(r"[^a-zA-Z0-9.-]", "-", dep.package)
        spdx_id = f"SPDXRef-Package-{clean_pkg}-{dep.version}"
        packages.append({
            "name": dep.package,
            "SPDXID": spdx_id,
            "versionInfo": dep.version,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "homepage": f"https://osv.dev/vulnerability/{dep.cve_id}" if dep.cve_id else "NOASSERTION",
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "copyrightText": "NOASSERTION",
        })

    spdx_data = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": project_name,
        "documentNamespace": f"https://spdx.org/spdxdocs/{project_name}-{uuid.uuid4()}",
        "creationInfo": {
            "created": datetime.now(timezone.utc).isoformat(),
            "creators": [f"Tool: MaunPrekshak-{__version__}"],
        },
        "packages": packages,
    }
    return json.dumps(spdx_data, indent=2)


def to_gitlab(scan_result: ScanResult, project_root: str = ".") -> str:
    """
    Generate a GitLab CI SAST report in the official GitLab SAST Report v15 schema.
    Compatible with GitLab Security & Compliance dashboards (gl-sast-report.json).
    """
    from datetime import datetime, timezone

    root = os.path.abspath(project_root)

    def _relpath(p: str) -> str:
        try:
            rel = os.path.relpath(os.path.abspath(p), root)
            return rel.replace("\\", "/") if not rel.startswith("..") else os.path.basename(p)
        except Exception:
            return os.path.basename(p)

    severity_map = {
        "CRITICAL": "Critical",
        "HIGH": "High",
        "MEDIUM": "Medium",
        "LOW": "Low",
        "INFO": "Info",
    }

    vulnerabilities = []

    for s in scan_result.sast:
        vuln_id = f"{s.check_id}-{os.path.basename(s.file_path)}-{s.line}"
        vulnerabilities.append({
            "id": vuln_id,
            "category": "sast",
            "name": s.check_id,
            "message": s.description,
            "description": f"{s.description}. {s.recommendation}",
            "cve": vuln_id,
            "severity": severity_map.get(s.severity.upper(), "Medium"),
            "confidence": "High",
            "solution": s.recommendation,
            "scanner": {
                "id": "maunprekshak",
                "name": "MaunPrekshak",
            },
            "location": {
                "file": _relpath(s.file_path),
                "start_line": s.line,
                "end_line": s.line,
            },
            "identifiers": [
                {
                    "type": "maunprekshak_rule_id",
                    "name": s.check_id,
                    "value": s.check_id,
                    "url": "https://github.com/PramanKasliwal/maunprekshak#static-code-analysis-sast",
                }
            ],
        })

    for sec in scan_result.secrets:
        vuln_id = f"SECRET-{os.path.basename(sec.file_path)}-{sec.line}"
        vulnerabilities.append({
            "id": vuln_id,
            "category": "sast",
            "name": sec.secret_type,
            "message": f"Exposed secret: {sec.secret_type}",
            "description": f"A credential of type '{sec.secret_type}' was detected at line {sec.line}.",
            "cve": vuln_id,
            "severity": severity_map.get(sec.severity.upper(), "High"),
            "confidence": "High",
            "solution": "Remove the credential from source code, rotate it immediately, and use environment variables or a secrets manager.",
            "scanner": {
                "id": "maunprekshak",
                "name": "MaunPrekshak",
            },
            "location": {
                "file": _relpath(sec.file_path),
                "start_line": sec.line,
                "end_line": sec.line,
            },
            "identifiers": [
                {
                    "type": "maunprekshak_secret_type",
                    "name": sec.secret_type,
                    "value": sec.secret_type,
                    "url": "https://github.com/PramanKasliwal/maunprekshak#secrets-detection",
                }
            ],
        })

    for dep in scan_result.deps:
        vuln_id = f"DEP-{dep.cve_id}-{dep.package}"
        vulnerabilities.append({
            "id": vuln_id,
            "category": "dependency_scanning",
            "name": dep.cve_id,
            "message": f"{dep.package} {dep.version} — {dep.cve_id}",
            "description": dep.description,
            "cve": dep.cve_id,
            "severity": severity_map.get(dep.severity.upper(), "High"),
            "confidence": "High",
            "solution": f"Upgrade {dep.package} to {dep.fix_version}." if dep.fix_version else "Check upstream for a patched release.",
            "scanner": {
                "id": "maunprekshak",
                "name": "MaunPrekshak",
            },
            "location": {
                "file": "requirements.txt",
                "start_line": 1,
                "end_line": 1,
                "dependency": {
                    "package": {"name": dep.package},
                    "version": dep.version,
                },
            },
            "identifiers": [
                {
                    "type": "cve",
                    "name": dep.cve_id,
                    "value": dep.cve_id,
                    "url": f"https://osv.dev/vulnerability/{dep.cve_id}",
                }
            ],
        })

    report = {
        "schema": "https://gitlab.com/gitlab-org/security-products/security-report-schemas/-/raw/master/dist/sast-report-format.json",
        "version": "15.0.6",
        "scan": {
            "scanner": {
                "id": "maunprekshak",
                "name": "MaunPrekshak",
                "url": "https://github.com/PramanKasliwal/maunprekshak",
                "vendor": {"name": "Praman Kasliwal"},
                "version": __version__,
            },
            "type": "sast",
            "start_time": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S"),
            "end_time": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S"),
            "status": "success",
        },
        "vulnerabilities": vulnerabilities,
    }
    return json.dumps(report, indent=2)


def format_github_annotations(scan_result: ScanResult, project_root: str = ".") -> str:
    """
    Format scan findings as GitHub Actions workflow commands for PR annotations.
    Emits ::error:: and ::warning:: commands that GitHub Actions renders as
    inline annotations on the Pull Request "Files Changed" tab.

    Automatically used when GITHUB_ACTIONS=true or --annotations flag is set.
    """
    root = os.path.abspath(project_root)

    def _relpath(p: str) -> str:
        try:
            rel = os.path.relpath(os.path.abspath(p), root)
            return rel.replace("\\", "/") if not rel.startswith("..") else os.path.basename(p)
        except Exception:
            return os.path.basename(p)

    lines_out = []

    for s in scan_result.sast:
        level = "error" if s.severity.upper() in ("CRITICAL", "HIGH") else "warning"
        rel_file = _relpath(s.file_path)
        # Sanitize title and message for GitHub Actions command format
        title = s.check_id.replace(",", " ").replace("\n", " ")
        msg = s.description.replace(",", " ").replace("\n", " ").replace("%", "%25")
        lines_out.append(
            f"::{level} file={rel_file},line={s.line},col={s.col + 1},title={title}::{msg}"
        )

    for sec in scan_result.secrets:
        rel_file = _relpath(sec.file_path)
        title = sec.secret_type.replace(",", " ").replace("\n", " ")
        msg = f"Exposed secret of type '{sec.secret_type}' detected. Remove and rotate immediately.".replace(",", " ")
        lines_out.append(
            f"::error file={rel_file},line={sec.line},col=1,title={title}::{msg}"
        )

    for dep in scan_result.deps:
        level = "error" if dep.severity.upper() in ("CRITICAL", "HIGH") else "warning"
        title = dep.cve_id.replace(",", " ")
        msg = f"{dep.package} {dep.version}: {dep.description[:120]}".replace(",", " ").replace("\n", " ")
        lines_out.append(
            f"::{level} title={title}::{msg}"
        )

    return "\n".join(lines_out)


def to_html(scan_result: ScanResult, project_name: str = "project") -> str:
    """
    Generate an interactive, standalone single-file HTML security audit report.
    100% offline and self-contained with zero external stylesheet or JavaScript dependencies.
    """
    import html
    from datetime import datetime, timezone

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    risk_level = scan_result.risk_score.level if scan_result.risk_score else "LOW"
    risk_score = scan_result.risk_score.score if scan_result.risk_score else 0

    level_colors = {
        "LOW": "#10b981",
        "MEDIUM": "#eab308",
        "HIGH": "#f97316",
        "CRITICAL": "#ef4444",
    }
    risk_color = level_colors.get(risk_level.upper(), "#10b981")

    # Metrics
    total = scan_result.total_findings
    crit_count = scan_result.critical_count
    high_count = scan_result.high_count
    med_count = scan_result.medium_count
    low_count = scan_result.low_count
    deps_count = len(scan_result.deps)
    secrets_count = len(scan_result.secrets)
    sast_count = len(scan_result.sast)

    # Build findings list
    all_findings_html = []

    # 1. Dependency Findings
    for dep in scan_result.deps:
        sev = dep.severity.upper()
        c = level_colors.get(sev, "#94a3b8")
        title = f"{html.escape(dep.package)} {html.escape(dep.version)} — {html.escape(dep.cve_id)}"
        fix_html = f"<div class='fix-box'><strong>Recommended Fix:</strong> Upgrade to &ge; {html.escape(dep.fix_version)}</div>" if dep.fix_version else ""
        card = f"""
        <div class="finding-card" data-severity="{sev.lower()}" data-category="deps" style="border-left-color: {c};">
            <div class="card-header">
                <span class="badge" style="background-color: {c};">{sev}</span>
                <span class="badge cat-badge">Dependency</span>
                <span class="badge id-badge">{html.escape(dep.cve_id)}</span>
                <span class="finding-title">{title}</span>
            </div>
            <div class="card-body">
                <p class="description">{html.escape(dep.description)}</p>
                <div class="location-box"><code>Package: {html.escape(dep.package)} | Installed Version: {html.escape(dep.version)} | CVSS: {dep.cvss_score}</code></div>
                {fix_html}
            </div>
        </div>
        """
        all_findings_html.append(card)

    # 2. Secret Findings
    for sec in scan_result.secrets:
        sev = sec.severity.upper()
        c = level_colors.get(sev, "#94a3b8")
        title = f"{html.escape(sec.secret_type)} in {html.escape(sec.file_path)}"
        card = f"""
        <div class="finding-card" data-severity="{sev.lower()}" data-category="secrets" style="border-left-color: {c};">
            <div class="card-header">
                <span class="badge" style="background-color: {c};">{sev}</span>
                <span class="badge cat-badge">Secret</span>
                <span class="finding-title">{title}</span>
            </div>
            <div class="card-body">
                <div class="location-box"><code>{html.escape(sec.file_path)}:{sec.line}</code></div>
                <div class="snippet-box"><code>Masked Secret: {html.escape(sec.masked_value)}</code></div>
                <div class="fix-box"><strong>Remediation:</strong> Immediately revoke this credential, rotate it with the provider, and store it in an environment secret manager.</div>
            </div>
        </div>
        """
        all_findings_html.append(card)

    # 3. SAST / Container / CI Findings
    for s in scan_result.sast:
        sev = s.severity.upper()
        c = level_colors.get(sev, "#94a3b8")
        title = f"{html.escape(s.check_id)}: {html.escape(s.description[:80])}"
        snippet_html = f"<div class='snippet-box'><code>{html.escape(s.code_snippet)}</code></div>" if s.code_snippet else ""
        card = f"""
        <div class="finding-card" data-severity="{sev.lower()}" data-category="sast" style="border-left-color: {c};">
            <div class="card-header">
                <span class="badge" style="background-color: {c};">{sev}</span>
                <span class="badge cat-badge">SAST</span>
                <span class="badge id-badge">{html.escape(s.check_id)}</span>
                <span class="finding-title">{title}</span>
            </div>
            <div class="card-body">
                <div class="location-box"><code>{html.escape(s.file_path)}:{s.line}:{s.col}</code></div>
                <p class="description">{html.escape(s.description)}</p>
                {snippet_html}
                <div class="fix-box"><strong>Recommendation:</strong> {html.escape(s.recommendation)}</div>
            </div>
        </div>
        """
        all_findings_html.append(card)

    findings_content = "\n".join(all_findings_html) if all_findings_html else "<div class='no-findings'>✓ Zero vulnerabilities detected. Clean security posture!</div>"

    ai_section = ""
    if scan_result.ai_summary:
        ai_section = f"""
        <div class="ai-box">
            <h3>🤖 AI Security Executive Summary</h3>
            <div class="ai-content">{html.escape(scan_result.ai_summary)}</div>
        </div>
        """

    html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MaunPrekshak Security Audit Report — {html.escape(project_name)}</title>
    <style>
        :root {{
            --bg-primary: #0f172a;
            --bg-secondary: #1e293b;
            --bg-card: #1e293b;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --border-color: #334155;
            --accent: #38bdf8;
            --crit: #ef4444;
            --high: #f97316;
            --med: #eab308;
            --low: #10b981;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-primary);
            color: var(--text-primary);
            padding: 2rem;
            line-height: 1.5;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 1.5rem;
            margin-bottom: 2rem;
            flex-wrap: wrap;
            gap: 1rem;
        }}
        .brand h1 {{ font-size: 1.75rem; font-weight: 700; color: #fff; }}
        .brand p {{ color: var(--text-secondary); font-size: 0.875rem; }}
        .risk-badge {{
            background-color: var(--bg-secondary);
            border: 2px solid {risk_color};
            border-radius: 8px;
            padding: 0.75rem 1.25rem;
            text-align: right;
        }}
        .risk-badge .level {{ font-size: 1.25rem; font-weight: bold; color: {risk_color}; }}
        .risk-badge .score {{ font-size: 0.875rem; color: var(--text-secondary); }}
        
        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }}
        .metric-card {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 1rem;
            text-align: center;
        }}
        .metric-card .val {{ font-size: 1.75rem; font-weight: bold; }}
        .metric-card .lbl {{ font-size: 0.75rem; text-transform: uppercase; color: var(--text-secondary); margin-top: 0.25rem; }}

        .controls {{
            display: flex;
            gap: 1rem;
            margin-bottom: 1.5rem;
            flex-wrap: wrap;
            align-items: center;
        }}
        .search-box {{
            flex: 1;
            min-width: 250px;
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            padding: 0.6rem 1rem;
            border-radius: 6px;
            color: #fff;
            font-size: 0.875rem;
        }}
        .btn-group {{ display: flex; gap: 0.5rem; flex-wrap: wrap; }}
        .filter-btn {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            color: var(--text-secondary);
            padding: 0.4rem 0.8rem;
            border-radius: 6px;
            cursor: pointer;
            font-size: 0.8rem;
            transition: all 0.2s;
        }}
        .filter-btn.active {{
            background: var(--accent);
            color: #0f172a;
            font-weight: bold;
            border-color: var(--accent);
        }}

        .findings-list {{ display: flex; flex-direction: column; gap: 1rem; }}
        .finding-card {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-left-width: 5px;
            border-radius: 6px;
            padding: 1.25rem;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
        }}
        .card-header {{ display: flex; align-items: center; gap: 0.75rem; margin-bottom: 0.75rem; flex-wrap: wrap; }}
        .badge {{
            font-size: 0.7rem;
            font-weight: bold;
            padding: 0.2rem 0.5rem;
            border-radius: 4px;
            color: #fff;
            text-transform: uppercase;
        }}
        .cat-badge {{ background: #475569; }}
        .id-badge {{ background: #334155; color: var(--accent); font-family: monospace; }}
        .finding-title {{ font-size: 1rem; font-weight: 600; color: #f1f5f9; }}
        .card-body {{ font-size: 0.875rem; color: #cbd5e1; }}
        .location-box {{ margin: 0.5rem 0; font-family: monospace; font-size: 0.8rem; color: #94a3b8; }}
        .snippet-box {{
            background: #090d16;
            border: 1px solid #1e293b;
            padding: 0.6rem;
            border-radius: 4px;
            margin: 0.5rem 0;
            overflow-x: auto;
            font-family: monospace;
            font-size: 0.8rem;
            color: #38bdf8;
        }}
        .fix-box {{
            background: rgba(16, 185, 129, 0.1);
            border: 1px solid rgba(16, 185, 129, 0.3);
            color: #6ee7b7;
            padding: 0.6rem 0.8rem;
            border-radius: 4px;
            margin-top: 0.75rem;
            font-size: 0.8rem;
        }}
        .no-findings {{
            text-align: center;
            padding: 3rem;
            background: var(--bg-secondary);
            border-radius: 8px;
            color: #10b981;
            font-size: 1.25rem;
            font-weight: 600;
        }}
        .ai-box {{
            background: #1e1b4b;
            border: 1px solid #4338ca;
            border-radius: 8px;
            padding: 1.25rem;
            margin-bottom: 2rem;
        }}
        .ai-box h3 {{ color: #a5b4fc; font-size: 1.1rem; margin-bottom: 0.5rem; }}
        .ai-content {{ white-space: pre-wrap; font-size: 0.875rem; color: #e0e7ff; }}
        footer {{
            margin-top: 3rem;
            text-align: center;
            font-size: 0.75rem;
            color: var(--text-secondary);
            border-top: 1px solid var(--border-color);
            padding-top: 1.5rem;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="brand">
                <h1>मौन प्रेक्षक — MaunPrekshak</h1>
                <p>The Silent Observer &bull; Audit Report for <strong>{html.escape(project_name)}</strong></p>
                <p style="font-size: 0.75rem; margin-top: 0.25rem;">Generated on {timestamp} &bull; Engine v{__version__}</p>
            </div>
            <div class="risk-badge">
                <div class="level">{risk_level} RISK</div>
                <div class="score">Composite Score: {risk_score}</div>
            </div>
        </header>

        {ai_section}

        <div class="metrics-grid">
            <div class="metric-card">
                <div class="val" style="color: #fff;">{total}</div>
                <div class="lbl">Total Issues</div>
            </div>
            <div class="metric-card">
                <div class="val" style="color: var(--crit);">{crit_count}</div>
                <div class="lbl">Critical</div>
            </div>
            <div class="metric-card">
                <div class="val" style="color: var(--high);">{high_count}</div>
                <div class="lbl">High</div>
            </div>
            <div class="metric-card">
                <div class="val" style="color: var(--med);">{med_count}</div>
                <div class="lbl">Medium</div>
            </div>
            <div class="metric-card">
                <div class="val" style="color: var(--low);">{low_count}</div>
                <div class="lbl">Low</div>
            </div>
            <div class="metric-card">
                <div class="val" style="color: var(--accent);">{secrets_count}</div>
                <div class="lbl">Secrets</div>
            </div>
            <div class="metric-card">
                <div class="val" style="color: var(--accent);">{deps_count}</div>
                <div class="lbl">Dependencies</div>
            </div>
            <div class="metric-card">
                <div class="val" style="color: var(--accent);">{sast_count}</div>
                <div class="lbl">SAST / CI</div>
            </div>
        </div>

        <div class="controls">
            <input type="text" id="searchInput" class="search-box" placeholder="Search by rule, package, file, or keyword...">
            <div class="btn-group" id="sevFilters">
                <button class="filter-btn active" data-sev="all">All</button>
                <button class="filter-btn" data-sev="critical">Critical</button>
                <button class="filter-btn" data-sev="high">High</button>
                <button class="filter-btn" data-sev="medium">Medium</button>
                <button class="filter-btn" data-sev="low">Low</button>
            </div>
            <div class="btn-group" id="catFilters">
                <button class="filter-btn active" data-cat="all">All Types</button>
                <button class="filter-btn" data-cat="secrets">Secrets</button>
                <button class="filter-btn" data-cat="deps">Dependencies</button>
                <button class="filter-btn" data-cat="sast">SAST</button>
            </div>
        </div>

        <div class="findings-list" id="findingsList">
            {findings_content}
        </div>

        <footer>
            MaunPrekshak Core &bull; Open-source Local-First Security Scanner &bull;
            <a href="https://github.com/PramanKasliwal/maunprekshak" style="color: var(--accent);" target="_blank">GitHub Repository</a>
        </footer>
    </div>

    <script>
        (function() {{
            const searchInput = document.getElementById('searchInput');
            const sevButtons = document.querySelectorAll('#sevFilters .filter-btn');
            const catButtons = document.querySelectorAll('#catFilters .filter-btn');
            const cards = document.querySelectorAll('.finding-card');

            let currentSev = 'all';
            let currentCat = 'all';
            let searchQuery = '';

            function updateCards() {{
                cards.forEach(card => {{
                    const sev = card.getAttribute('data-severity');
                    const cat = card.getAttribute('data-category');
                    const text = card.textContent.toLowerCase();

                    const matchSev = currentSev === 'all' || sev === currentSev;
                    const matchCat = currentCat === 'all' || cat === currentCat;
                    const matchSearch = !searchQuery || text.includes(searchQuery);

                    if (matchSev && matchCat && matchSearch) {{
                        card.style.display = 'block';
                    }} else {{
                        card.style.display = 'none';
                    }}
                }});
            }}

            searchInput.addEventListener('input', (e) => {{
                searchQuery = e.target.value.toLowerCase().trim();
                updateCards();
            }});

            sevButtons.forEach(btn => {{
                btn.addEventListener('click', () => {{
                    sevButtons.forEach(b => b.classList.remove('active'));
                    btn.classList.add('active');
                    currentSev = btn.getAttribute('data-sev');
                    updateCards();
                }});
            }});

            catButtons.forEach(btn => {{
                btn.addEventListener('click', () => {{
                    catButtons.forEach(b => b.classList.remove('active'));
                    btn.classList.add('active');
                    currentCat = btn.getAttribute('data-cat');
                    updateCards();
                }});
            }});
        }})();
    </script>
</body>
</html>
"""
    return html_template


