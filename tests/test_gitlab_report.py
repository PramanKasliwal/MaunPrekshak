"""
Unit tests for the GitLab CI SAST report formatter (to_gitlab).
"""
import json
import pytest
from maunprekshak.scanner.report import to_gitlab, ScanResult, SASTFinding, SecretFinding, DepVulnerability, aggregate


def _make_result() -> ScanResult:
    sast = [SASTFinding(
        file_path="/proj/app.py", line=10, col=4,
        check_id="MP001", severity="CRITICAL",
        description="eval() detected", recommendation="Use ast.literal_eval()",
        code_snippet="eval(user_input)",
    )]
    secrets = [SecretFinding(
        file_path="/proj/config.py", line=5,
        secret_type="AWS Access Key", masked_value="AKIA***MPLE", severity="HIGH",
    )]
    deps = [DepVulnerability(
        package="requests", version="2.25.0", cve_id="CVE-2023-32681",
        severity="HIGH", cvss_score=7.5, description="Proxy URL injection",
        fix_version="2.31.0",
    )]
    return aggregate(deps, secrets, sast)


class TestGitLabReport:
    def test_output_is_valid_json(self):
        result = _make_result()
        out = to_gitlab(result)
        data = json.loads(out)
        assert isinstance(data, dict)

    def test_schema_key_present(self):
        result = _make_result()
        data = json.loads(to_gitlab(result))
        assert "schema" in data
        assert "gitlab" in data["schema"].lower()

    def test_version_field_present(self):
        result = _make_result()
        data = json.loads(to_gitlab(result))
        assert "version" in data
        assert data["version"].startswith("15")

    def test_scan_section_present(self):
        result = _make_result()
        data = json.loads(to_gitlab(result))
        assert "scan" in data
        assert data["scan"]["type"] == "sast"
        assert data["scan"]["status"] == "success"

    def test_scanner_name_is_maunprekshak(self):
        result = _make_result()
        data = json.loads(to_gitlab(result))
        assert data["scan"]["scanner"]["name"] == "MaunPrekshak"

    def test_vulnerabilities_list_present(self):
        result = _make_result()
        data = json.loads(to_gitlab(result))
        assert "vulnerabilities" in data
        assert len(data["vulnerabilities"]) == 3  # 1 sast + 1 secret + 1 dep

    def test_sast_finding_has_location(self):
        result = _make_result()
        data = json.loads(to_gitlab(result))
        sast_vulns = [v for v in data["vulnerabilities"] if v.get("category") == "sast" and "MP001" in v.get("name", "")]
        assert sast_vulns
        assert "location" in sast_vulns[0]
        assert "start_line" in sast_vulns[0]["location"]

    def test_dep_finding_has_cve_identifier(self):
        result = _make_result()
        data = json.loads(to_gitlab(result))
        dep_vulns = [v for v in data["vulnerabilities"] if v.get("category") == "dependency_scanning"]
        assert dep_vulns
        identifiers = dep_vulns[0].get("identifiers", [])
        cve_ids = [i for i in identifiers if i.get("type") == "cve"]
        assert cve_ids

    def test_secret_finding_included(self):
        result = _make_result()
        data = json.loads(to_gitlab(result))
        secret_vulns = [v for v in data["vulnerabilities"] if "secret" in v.get("name", "").lower() or "AWS" in v.get("name", "")]
        assert secret_vulns

    def test_empty_result_produces_empty_vulnerabilities(self):
        result = aggregate([], [], [])
        data = json.loads(to_gitlab(result))
        assert data["vulnerabilities"] == []
