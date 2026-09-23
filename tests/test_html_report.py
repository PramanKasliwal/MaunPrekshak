"""
Tests for Standalone Interactive HTML Security Audit Report
"""
from maunprekshak.scanner.report import (
    ScanResult,
    DepVulnerability,
    SecretFinding,
    SASTFinding,
    RiskScore,
    to_html,
)


def test_html_report_clean_scan():
    result = ScanResult(
        deps=[],
        secrets=[],
        sast=[],
        risk_score=RiskScore(score=0, level="LOW"),
    )
    html_out = to_html(result, project_name="my-clean-app")

    assert "<!DOCTYPE html>" in html_out
    assert "my-clean-app" in html_out
    assert "LOW RISK" in html_out
    assert "Zero vulnerabilities detected" in html_out
    assert "Total Issues" in html_out
    # Verify no external CDN or stylesheet dependencies
    assert "https://cdn." not in html_out
    assert "https://cdnjs." not in html_out


def test_html_report_with_findings():
    result = ScanResult(
        deps=[
            DepVulnerability(
                package="requests",
                version="2.19.0",
                cve_id="CVE-2018-18074",
                severity="HIGH",
                cvss_score=7.5,
                description="Redirect credentials leak",
                fix_version="2.20.0",
            )
        ],
        secrets=[
            SecretFinding(
                file_path="src/config.py",
                line=12,
                secret_type="GitHub Token",
                masked_value="ghp_***abc1",
                severity="HIGH",
            )
        ],
        sast=[
            SASTFinding(
                file_path="src/app.py",
                line=45,
                col=4,
                check_id="GHA001",
                severity="HIGH",
                description="Script injection via context",
                recommendation="Use environment variables",
                code_snippet="run: echo ${{ github.event.issue.title }}",
            )
        ],
        risk_score=RiskScore(score=45, level="HIGH"),
        ai_summary="All 3 issues require urgent remediation before production deployment.",
    )
    html_out = to_html(result, project_name="vulnerable-demo")

    assert "vulnerable-demo" in html_out
    assert "HIGH RISK" in html_out
    assert "CVE-2018-18074" in html_out
    assert "GitHub Token" in html_out
    assert "GHA001" in html_out
    assert "AI Security Executive Summary" in html_out
    assert "urgent remediation" in html_out
    assert "data-severity=\"high\"" in html_out
    assert "data-category=\"deps\"" in html_out
    assert "data-category=\"secrets\"" in html_out
    assert "data-category=\"sast\"" in html_out
