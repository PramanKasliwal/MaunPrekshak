"""
MaunPrekshak — Core Data Models & Report Generation
All shared dataclasses, risk scoring, and output formatting live here.
"""
import json
import os
from dataclasses import dataclass, asdict, field
from typing import List, Optional
from enum import Enum


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

def generate_ai_summary(scan_result: ScanResult) -> str:
    """
    Generate an AI-powered executive security summary using Gemini.
    Gracefully skips if GEMINI_API_KEY is not set.
    """
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        return "AI Summary skipped: set GEMINI_API_KEY to enable."

    try:
        import time
        from google import genai  # google-genai package

        client = genai.Client(api_key=api_key)

        prompt = f"""You are a senior application security engineer.
Analyze this Python project scan result and write a concise executive security summary.

Scan Results:
- Overall Risk: {scan_result.risk_score.level} (Score: {scan_result.risk_score.score})
- Dependency vulnerabilities: {len(scan_result.deps)}
- Exposed secrets/credentials: {len(scan_result.secrets)}
- SAST findings: {len(scan_result.sast)}

Top findings:
{_format_top_findings(scan_result)}

Write:
1. A 2-sentence executive summary
2. Top 3 most critical risks and why
3. Prioritized remediation steps (numbered)
Keep it under 300 words. Be direct and actionable."""

        # Retry up to 3 times with exponential backoff for transient 503 errors
        last_error = None
        for attempt, wait in enumerate([0, 5, 10]):
            try:
                if wait:
                    time.sleep(wait)
                response = client.models.generate_content(
                    model="gemini-3.7-flash",
                    contents=prompt,
                )
                return response.text
            except Exception as e:
                last_error = e
                err_str = str(e)
                # Only retry on 503 / rate limit errors
                if "503" not in err_str and "UNAVAILABLE" not in err_str and "429" not in err_str:
                    break

        return f"AI Summary unavailable (retried 3×): {last_error}"

    except Exception as e:
        return f"AI Summary unavailable: {str(e)}"


def _format_top_findings(scan_result: ScanResult) -> str:
    """Format top findings for the AI prompt."""
    lines = []
    for dep in scan_result.deps[:3]:
        lines.append(f"  - DEP {dep.severity}: {dep.package}=={dep.version} ({dep.cve_id})")
    for sec in scan_result.secrets[:3]:
        lines.append(f"  - SECRET {sec.severity}: {sec.secret_type} in {os.path.basename(sec.file_path)}:{sec.line}")
    for sast in scan_result.sast[:3]:
        lines.append(f"  - SAST {sast.severity}: {sast.description} in {os.path.basename(sast.file_path)}:{sast.line}")
    return "\n".join(lines) if lines else "  No findings."


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
                        "semanticVersion": "0.2.0",
                        "informationUri": "https://github.com/PramanKasliwal/maunprekshak",
                        "rules": list(rules_dict.values()),
                    }
                },
                "results": results_list,
            }
        ],
    }

    return json.dumps(sarif_data, indent=2)

