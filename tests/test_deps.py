"""
Tests for MaunPrekshak Dependency Scanner
"""
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from maunprekshak.scanner.deps import (
    parse_requirements_file,
    parse_pyproject_toml,
    scan_dependencies,
)


# ─── Fixtures ─────────────────────────────────────────────────────────────────

SAMPLE_REQUIREMENTS = """\
requests==2.25.1
django==3.2.0
flask>=2.0.0
numpy
boto3==1.26.0
"""

SAMPLE_PYPROJECT = """\
[project]
name = "myapp"
version = "1.0.0"
dependencies = [
    "requests==2.25.1",
    "fastapi>=0.100.0",
    "pydantic==2.0.0",
]
"""

MOCK_OSV_RESPONSE = {
    "vulns": [
        {
            "id": "CVE-2023-32681",
            "summary": "Requests SSRF vulnerability",
            "severity": [{"score": "7.5", "type": "CVSS_V3"}],
            "affected": [
                {
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [
                                {"introduced": "0"},
                                {"fixed": "2.31.0"},
                            ],
                        }
                    ]
                }
            ],
        }
    ]
}


# ─── Tests ────────────────────────────────────────────────────────────────────

class TestParseRequirementsFile:
    def test_parses_pinned_versions(self, tmp_path):
        req_file = tmp_path / "requirements.txt"
        req_file.write_text(SAMPLE_REQUIREMENTS)
        packages = parse_requirements_file(str(req_file))
        assert ("requests", "2.25.1") in packages
        assert ("django", "3.2.0") in packages
        assert ("boto3", "1.26.0") in packages

    def test_skips_packages_without_version(self, tmp_path):
        req_file = tmp_path / "requirements.txt"
        req_file.write_text(SAMPLE_REQUIREMENTS)
        packages = parse_requirements_file(str(req_file))
        pkg_names = [p[0] for p in packages]
        # numpy has no pinned version — still included but version is empty
        assert "numpy" in pkg_names

    def test_handles_missing_file(self):
        packages = parse_requirements_file("/nonexistent/requirements.txt")
        assert packages == []

    def test_handles_comments_and_blank_lines(self, tmp_path):
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("# comment\n\nrequests==2.25.1\n")
        packages = parse_requirements_file(str(req_file))
        assert len(packages) == 1
        assert packages[0][0] == "requests"


class TestParsePyprojectToml:
    def test_parses_project_dependencies(self, tmp_path):
        toml_file = tmp_path / "pyproject.toml"
        toml_file.write_text(SAMPLE_PYPROJECT)
        packages = parse_pyproject_toml(str(toml_file))
        pkg_names = [p[0] for p in packages]
        assert "requests" in pkg_names
        assert "fastapi" in pkg_names
        assert "pydantic" in pkg_names

    def test_handles_missing_file(self):
        packages = parse_pyproject_toml("/nonexistent/pyproject.toml")
        assert packages == []


class TestScanDependencies:
    @pytest.mark.asyncio
    async def test_returns_vulnerability_for_known_cve(self, tmp_path):
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("requests==2.25.1\n")

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_response = MagicMock()
            mock_response.json.return_value = MOCK_OSV_RESPONSE
            mock_response.status_code = 200
            mock_post.return_value = mock_response

            vulns = await scan_dependencies(str(tmp_path))

        assert len(vulns) > 0
        assert vulns[0].package == "requests"
        assert vulns[0].cve_id == "CVE-2023-32681"
        assert vulns[0].severity in ("HIGH", "CRITICAL")

    @pytest.mark.asyncio
    async def test_returns_empty_for_safe_packages(self, tmp_path):
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("requests==999.0.0\n")

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_response = MagicMock()
            mock_response.json.return_value = {"vulns": []}
            mock_response.status_code = 200
            mock_post.return_value = mock_response

            vulns = await scan_dependencies(str(tmp_path))

        assert vulns == []

    @pytest.mark.asyncio
    async def test_handles_network_error_gracefully(self, tmp_path):
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("requests==2.25.1\n")

        with patch("httpx.AsyncClient.post", side_effect=Exception("Network error")):
            vulns = await scan_dependencies(str(tmp_path))

        # Should not raise — returns empty list on network failure
        assert isinstance(vulns, list)
