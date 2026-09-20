"""
Tests for CycloneDX 1.5 and SPDX 2.3 Software Bill of Materials (SBOM) generation.
"""
import json
import pytest
from maunprekshak.scanner.report import (
    ScanResult,
    DepVulnerability,
    RiskScore,
    to_cyclonedx,
    to_spdx,
)


@pytest.fixture
def mock_scan_result():
    deps = [
        DepVulnerability(
            package="requests",
            version="2.28.0",
            cve_id="CVE-2023-32681",
            severity="MEDIUM",
            cvss_score=6.1,
            description="Proxy-Authorization header leak",
            fix_version="2.31.0",
        ),
        DepVulnerability(
            package="lodash",
            version="4.17.20",
            cve_id="CVE-2021-23337",
            severity="HIGH",
            cvss_score=7.2,
            description="Command injection vulnerability",
            fix_version="4.17.21",
        ),
        DepVulnerability(
            package="serde",
            version="1.0.100",
            cve_id="",
            severity="LOW",
            cvss_score=0.0,
            description="Safe dependency",
            fix_version="",
        ),
        DepVulnerability(
            package="github.com/gin-gonic/gin",
            version="1.9.0",
            cve_id="",
            severity="LOW",
            cvss_score=0.0,
            description="Go web framework",
            fix_version="",
        ),
    ]
    return ScanResult(
        deps=deps,
        secrets=[],
        sast=[],
        risk_score=RiskScore(score=35, level="MEDIUM"),
    )


class TestCycloneDX:
    def test_cyclonedx_structure(self, mock_scan_result):
        raw_json = to_cyclonedx(mock_scan_result, project_name="my-app")
        data = json.loads(raw_json)

        assert data["bomFormat"] == "CycloneDX"
        assert data["specVersion"] == "1.5"
        assert data["version"] == 1
        assert "urn:uuid:" in data["serialNumber"]
        assert data["metadata"]["component"]["name"] == "my-app"
        assert data["metadata"]["tools"][0]["name"] == "maunprekshak"

    def test_cyclonedx_components_and_purls(self, mock_scan_result):
        data = json.loads(to_cyclonedx(mock_scan_result))
        components = {c["name"]: c for c in data["components"]}

        assert "requests" in components
        assert components["requests"]["purl"] == "pkg:pypi/requests@2.28.0"

        assert "lodash" in components
        assert components["lodash"]["purl"] == "pkg:npm/lodash@4.17.20"

        assert "serde" in components
        assert components["serde"]["purl"] == "pkg:cargo/serde@1.0.100"

        assert "github.com/gin-gonic/gin" in components
        assert components["github.com/gin-gonic/gin"]["purl"] == "pkg:golang/github.com/gin-gonic/gin@1.9.0"

    def test_cyclonedx_vulnerabilities(self, mock_scan_result):
        data = json.loads(to_cyclonedx(mock_scan_result))
        vulns = data.get("vulnerabilities", [])
        cve_ids = {v["id"] for v in vulns}

        assert "CVE-2023-32681" in cve_ids
        assert "CVE-2021-23337" in cve_ids
        assert len(vulns) == 2


class TestSPDX:
    def test_spdx_structure(self, mock_scan_result):
        raw_json = to_spdx(mock_scan_result, project_name="my-app")
        data = json.loads(raw_json)

        assert data["spdxVersion"] == "SPDX-2.3"
        assert data["dataLicense"] == "CC0-1.0"
        assert data["SPDXID"] == "SPDXRef-DOCUMENT"
        assert data["name"] == "my-app"
        assert "https://spdx.org/spdxdocs/my-app-" in data["documentNamespace"]
        assert any("MaunPrekshak" in creator for creator in data["creationInfo"]["creators"])

    def test_spdx_packages(self, mock_scan_result):
        data = json.loads(to_spdx(mock_scan_result))
        packages = {p["name"]: p for p in data["packages"]}

        assert len(packages) == 4
        assert "requests" in packages
        assert packages["requests"]["versionInfo"] == "2.28.0"
        assert "SPDXRef-Package-requests-2.28.0" == packages["requests"]["SPDXID"]
