"""
Unit tests for OASIS SARIF 2.1.0 output formatting.
"""
import json
import os
import pytest
from maunprekshak import __version__
from maunprekshak.scanner.report import (
    ScanResult,
    SASTFinding,
    SecretFinding,
    DepVulnerability,
    RiskScore,
    to_sarif,
)


def test_empty_scan_result_to_sarif():
    """Test that an empty scan result produces a valid SARIF structure."""
    res = ScanResult()
    sarif_str = to_sarif(res)
    data = json.loads(sarif_str)

    assert data["version"] == "2.1.0"
    assert "$schema" in data
    assert len(data["runs"]) == 1
    run = data["runs"][0]
    assert run["tool"]["driver"]["name"] == "MaunPrekshak"
    assert run["tool"]["driver"]["semanticVersion"] == __version__
    assert run["results"] == []


def test_sast_finding_sarif_mapping():
    """Test mapping of SAST findings to SARIF rules and results."""
    sast = SASTFinding(
        file_path="/tmp/myproject/app/views.py",
        line=42,
        col=10,
        check_id="MP001",
        severity="HIGH",
        description="Use of eval() detected",
        recommendation="Use ast.literal_eval() instead",
        code_snippet="eval(user_input)",
    )
    res = ScanResult(sast=[sast], risk_score=RiskScore(score=5, level="LOW"))
    sarif_str = to_sarif(res, project_root="/tmp/myproject")
    data = json.loads(sarif_str)

    run = data["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    assert any(r["id"] == "MP001" for r in rules)

    results = run["results"]
    assert len(results) == 1
    result = results[0]
    assert result["ruleId"] == "MP001"
    assert result["level"] == "error"  # HIGH maps to error
    assert "eval()" in result["message"]["text"]
    loc = result["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "app/views.py"
    assert loc["region"]["startLine"] == 42
    assert loc["region"]["startColumn"] == 10


def test_secret_finding_sarif_mapping():
    """Test mapping of secret findings to SARIF rules and results."""
    import secrets
    masked_value = "AKIA***" + secrets.token_hex(2)
    sec = SecretFinding(
        file_path="/tmp/myproject/config.py",
        line=15,
        secret_type="AWS Access Key ID",
        masked_value=masked_value,
        severity="CRITICAL",
    )
    res = ScanResult(secrets=[sec], risk_score=RiskScore(score=10, level="LOW"))
    sarif_str = to_sarif(res, project_root="/tmp/myproject")
    data = json.loads(sarif_str)

    run = data["runs"][0]
    assert len(run["results"]) == 1
    result = run["results"][0]
    assert result["level"] == "error"
    assert masked_value in result["message"]["text"]
    loc = result["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "config.py"
    assert loc["region"]["startLine"] == 15


def test_dep_vulnerability_sarif_mapping():
    """Test mapping of dependency vulnerabilities to SARIF."""
    dep = DepVulnerability(
        package="requests",
        version="2.25.0",
        cve_id="CVE-2023-32681",
        severity="MEDIUM",
        cvss_score=6.1,
        description="Information disclosure via redirect",
        fix_version="2.31.0",
    )
    res = ScanResult(deps=[dep], risk_score=RiskScore(score=2, level="LOW"))
    sarif_str = to_sarif(res)
    data = json.loads(sarif_str)

    run = data["runs"][0]
    assert len(run["results"]) == 1
    result = run["results"][0]
    assert result["level"] == "warning"  # MEDIUM maps to warning
    assert "CVE-2023-32681" in result["message"]["text"]
    assert "2.31.0" in result["message"]["text"]
