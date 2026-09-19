"""
Tests for MaunPrekshak Dependency Scanner
"""
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from maunprekshak.scanner.deps import (
    parse_requirements_file,
    parse_pyproject_toml,
    parse_poetry_lock,
    parse_pipfile_lock,
    parse_uv_lock,
    parse_package_json,
    parse_package_lock_json,
    parse_yarn_lock,
    parse_pnpm_lock_yaml,
    parse_go_mod,
    parse_go_sum,
    parse_cargo_toml,
    parse_cargo_lock,
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

    @pytest.mark.asyncio
    async def test_target_files_filters_dependency_scan(self, tmp_path):
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("requests==2.25.1\n")

        # When target_files does not include requirements.txt, scan is skipped
        vulns = await scan_dependencies(str(tmp_path), target_files=["other_file.py"])
        assert vulns == []


SAMPLE_POETRY_LOCK = """\
[[package]]
name = "cryptography"
version = "41.0.1"
description = "cryptography is a package"

[[package]]
name = "urllib3"
version = "1.26.15"
description = "HTTP library with thread-safe connection pooling"
"""

SAMPLE_PIPFILE_LOCK = """\
{
    "_meta": {"hash": {"sha256": "abcdef"}},
    "default": {
        "flask": {"version": "==2.2.5"}
    },
    "develop": {
        "pytest": {"version": "==7.4.0"}
    }
}
"""

SAMPLE_UV_LOCK = """\
version = 1

[[package]]
name = "httpx"
version = "0.27.0"

[[package]]
name = "certifi"
version = "2024.2.2"
"""


class TestLockfileParsers:
    def test_parse_poetry_lock(self, tmp_path):
        lock = tmp_path / "poetry.lock"
        lock.write_text(SAMPLE_POETRY_LOCK)
        packages = parse_poetry_lock(str(lock))
        assert ("cryptography", "41.0.1") in packages
        assert ("urllib3", "1.26.15") in packages

    def test_parse_pipfile_lock(self, tmp_path):
        lock = tmp_path / "Pipfile.lock"
        lock.write_text(SAMPLE_PIPFILE_LOCK)
        packages = parse_pipfile_lock(str(lock))
        assert ("flask", "2.2.5") in packages
        assert ("pytest", "7.4.0") in packages

    def test_parse_uv_lock(self, tmp_path):
        lock = tmp_path / "uv.lock"
        lock.write_text(SAMPLE_UV_LOCK)
        packages = parse_uv_lock(str(lock))
        assert ("httpx", "0.27.0") in packages
        assert ("certifi", "2024.2.2") in packages


SAMPLE_PACKAGE_JSON = """{
  "name": "my-app",
  "dependencies": {
    "axios": "^1.6.0",
    "express": "~4.18.2",
    "unpinned": "*"
  },
  "devDependencies": {
    "mocha": ">=10.2.0"
  }
}"""

SAMPLE_PACKAGE_LOCK_V1 = """{
  "name": "my-app",
  "lockfileVersion": 1,
  "dependencies": {
    "lodash": {
      "version": "4.17.20"
    }
  }
}"""

SAMPLE_PACKAGE_LOCK_V2 = """{
  "name": "my-app",
  "lockfileVersion": 2,
  "packages": {
    "": { "name": "my-app" },
    "node_modules/lodash": {
      "version": "4.17.21"
    },
    "node_modules/@types/node": {
      "version": "20.1.0"
    }
  }
}"""


class TestNPMParsers:
    def test_parse_package_json(self, tmp_path):
        pj = tmp_path / "package.json"
        pj.write_text(SAMPLE_PACKAGE_JSON)
        packages = parse_package_json(str(pj))
        assert ("axios", "1.6.0") in packages
        assert ("express", "4.18.2") in packages
        assert ("mocha", "10.2.0") in packages
        assert ("unpinned", "") in packages

    def test_parse_package_lock_v1(self, tmp_path):
        lock = tmp_path / "package-lock.json"
        lock.write_text(SAMPLE_PACKAGE_LOCK_V1)
        packages = parse_package_lock_json(str(lock))
        assert ("lodash", "4.17.20") in packages

    def test_parse_package_lock_v2(self, tmp_path):
        lock = tmp_path / "package-lock.json"
        lock.write_text(SAMPLE_PACKAGE_LOCK_V2)
        packages = parse_package_lock_json(str(lock))
        assert ("lodash", "4.17.21") in packages
        assert ("@types/node", "20.1.0") in packages

    @pytest.mark.asyncio
    async def test_scan_dependencies_with_package_json(self, tmp_path):
        pj = tmp_path / "package.json"
        pj.write_text('{"dependencies": {"lodash": "4.17.20"}}')

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_response = MagicMock()
            mock_response.json.return_value = {
                "vulns": [{
                    "id": "GHSA-p6mc-m468-83gw",
                    "summary": "Regular Expression Denial of Service in lodash",
                    "severity": [{"type": "CVSS_V3", "score": "7.5"}],
                    "affected": [{"ranges": [{"events": [{"fixed": "4.17.21"}]}]}]
                }]
            }
            mock_response.status_code = 200
            mock_post.return_value = mock_response

            vulns = await scan_dependencies(str(tmp_path))

        assert len(vulns) == 1
        assert vulns[0].package == "lodash"
        assert vulns[0].version == "4.17.20"
        assert vulns[0].severity == "HIGH"
        assert vulns[0].fix_version == "4.17.21"


SAMPLE_GO_MOD = """\
module github.com/myorg/myapp

go 1.21

require (
    github.com/gin-gonic/gin v1.9.1
    golang.org/x/crypto v0.14.0 // indirect
)

require github.com/stretchr/testify v1.8.4
"""

SAMPLE_GO_SUM = """\
github.com/gin-gonic/gin v1.9.1 h1:4+DT8OGDxFuAlghn14BO64v1BlPnEP31...
github.com/gin-gonic/gin v1.9.1/go.mod h1:DSCu05q...
golang.org/x/crypto v0.14.0 h1:wBqGXzWJW6...
golang.org/x/crypto v0.14.0/go.mod h1:1XG...
"""

SAMPLE_YARN_LOCK = """\
# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT DIRECTLY.
# yarn lockfile v1

"@babel/core@^7.0.0":
  version "7.24.0"
  resolved "https://registry.yarnpkg.com/@babel/core/-/core-7.24.0.tgz"

lodash@^4.17.15:
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"
"""

SAMPLE_PNPM_LOCK = """\
lockfileVersion: '6.0'

packages:
  /@babel/core@7.24.0:
    resolution: {integrity: sha512-mock}
  /lodash@4.17.21:
    resolution: {integrity: sha512-mock}
"""


class TestGoParsers:
    def test_parse_go_mod(self, tmp_path):
        gm = tmp_path / "go.mod"
        gm.write_text(SAMPLE_GO_MOD)
        packages = parse_go_mod(str(gm))
        assert ("github.com/gin-gonic/gin", "v1.9.1") in packages
        assert ("golang.org/x/crypto", "v0.14.0") in packages
        assert ("github.com/stretchr/testify", "v1.8.4") in packages

    def test_parse_go_sum(self, tmp_path):
        gs = tmp_path / "go.sum"
        gs.write_text(SAMPLE_GO_SUM)
        packages = parse_go_sum(str(gs))
        assert ("github.com/gin-gonic/gin", "v1.9.1") in packages
        assert ("golang.org/x/crypto", "v0.14.0") in packages

    @pytest.mark.asyncio
    async def test_scan_dependencies_with_go_mod(self, tmp_path):
        gm = tmp_path / "go.mod"
        gm.write_text("module test\ngo 1.21\nrequire github.com/gin-gonic/gin v1.9.0\n")

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_response = MagicMock()
            mock_response.json.return_value = {
                "vulns": [{
                    "id": "GO-2023-1988",
                    "summary": "Improper input validation in gin-gonic/gin",
                    "severity": [{"type": "CVSS_V3", "score": "8.0"}],
                    "affected": [{"ranges": [{"events": [{"fixed": "v1.9.1"}]}]}]
                }]
            }
            mock_response.status_code = 200
            mock_post.return_value = mock_response

            vulns = await scan_dependencies(str(tmp_path))

        assert len(vulns) == 1
        assert vulns[0].package == "github.com/gin-gonic/gin"
        assert vulns[0].version == "v1.9.0"
        assert vulns[0].severity == "HIGH"


class TestLockfileExpansion:
    def test_parse_yarn_lock(self, tmp_path):
        yl = tmp_path / "yarn.lock"
        yl.write_text(SAMPLE_YARN_LOCK)
        packages = parse_yarn_lock(str(yl))
        assert ("@babel/core", "7.24.0") in packages
        assert ("lodash", "4.17.21") in packages

    def test_parse_pnpm_lock_yaml(self, tmp_path):
        pl = tmp_path / "pnpm-lock.yaml"
        pl.write_text(SAMPLE_PNPM_LOCK)
        packages = parse_pnpm_lock_yaml(str(pl))
        assert ("@babel/core", "7.24.0") in packages
        assert ("lodash", "4.17.21") in packages


SAMPLE_CARGO_TOML = """\
[package]
name = "myapp"
version = "0.1.0"
edition = "2021"

[dependencies]
serde = "1.0.197"
tokio = { version = "1.35.0", features = ["full"] }

[dev-dependencies]
tempfile = "3.8.0"
"""

SAMPLE_CARGO_LOCK = """\
# This file is automatically @generated by Cargo.
# It is not intended for manual editing.
version = 3

[[package]]
name = "serde"
version = "1.0.197"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "tokio"
version = "1.35.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
"""


class TestCargoParsers:
    def test_parse_cargo_toml(self, tmp_path):
        ct = tmp_path / "Cargo.toml"
        ct.write_text(SAMPLE_CARGO_TOML)
        packages = parse_cargo_toml(str(ct))
        assert ("serde", "1.0.197") in packages
        assert ("tokio", "1.35.0") in packages
        assert ("tempfile", "3.8.0") in packages

    def test_parse_cargo_lock(self, tmp_path):
        cl = tmp_path / "Cargo.lock"
        cl.write_text(SAMPLE_CARGO_LOCK)
        packages = parse_cargo_lock(str(cl))
        assert ("serde", "1.0.197") in packages
        assert ("tokio", "1.35.0") in packages

    @pytest.mark.asyncio
    async def test_scan_dependencies_with_cargo_lock(self, tmp_path):
        cl = tmp_path / "Cargo.lock"
        cl.write_text("""\
version = 3

[[package]]
name = "serde"
version = "1.0.197"
source = "registry+https://github.com/rust-lang/crates.io-index"
""")

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_response = MagicMock()
            mock_response.json.return_value = {
                "vulns": [{
                    "id": "RUSTSEC-2023-0071",
                    "summary": "Flaw in serde deserialization",
                    "severity": [{"type": "CVSS_V3", "score": "7.5"}],
                    "affected": [{"ranges": [{"events": [{"fixed": "1.0.198"}]}]}]
                }]
            }
            mock_response.status_code = 200
            mock_post.return_value = mock_response

            vulns = await scan_dependencies(str(tmp_path))

        assert len(vulns) == 1
        assert vulns[0].package == "serde"
        assert vulns[0].version == "1.0.197"
        assert vulns[0].severity == "HIGH"
        assert vulns[0].fix_version == "1.0.198"


