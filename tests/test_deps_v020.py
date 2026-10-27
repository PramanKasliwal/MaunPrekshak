"""
Tests for MaunPrekshak Core v0.20.0 — Multi-Ecosystem SCA Phase 9 (Conda, Helm, OCaml opam).
"""
import os
import tempfile
import pytest
from unittest.mock import AsyncMock, patch

from maunprekshak.scanner.deps import (
    parse_conda_environment,
    parse_helm_chart,
    parse_opam_file,
    scan_dependencies,
)
from maunprekshak.scanner.report import DepVulnerability


def test_parse_conda_environment():
    content = """
name: ml_env
channels:
  - conda-forge
dependencies:
  - python=3.10.8
  - numpy=1.24.0
  - scipy>=1.10.0
  - flask==2.2.2
  - openssl
  - pip:
    - requests==2.31.0
    - urllib3>=1.26.5
"""
    with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as f:
        f.write(content)
        f.flush()
        temp_path = f.name

    try:
        packages = parse_conda_environment(temp_path)
        pkg_dict = dict(packages)
        assert pkg_dict["python"] == "3.10.8"
        assert pkg_dict["numpy"] == "1.24.0"
        assert pkg_dict["scipy"] == "1.10.0"
        assert pkg_dict["flask"] == "2.2.2"
        assert pkg_dict["openssl"] == ""
        assert pkg_dict["requests"] == "2.31.0"
        assert pkg_dict["urllib3"] == "1.26.5"
    finally:
        os.remove(temp_path)


def test_parse_helm_chart():
    content = """
apiVersion: v2
name: payment-service
version: 1.0.0
dependencies:
  - name: redis
    version: 17.0.1
    repository: https://charts.bitnami.com/bitnami
  - name: postgresql
    version: "12.1.0"
    repository: https://charts.bitnami.com/bitnami
  - name: rabbitmq
    version: '11.0.0'
"""
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
        f.write(content)
        f.flush()
        temp_path = f.name

    try:
        packages = parse_helm_chart(temp_path)
        pkg_dict = dict(packages)
        assert pkg_dict["redis"] == "17.0.1"
        assert pkg_dict["postgresql"] == "12.1.0"
        assert pkg_dict["rabbitmq"] == "11.0.0"
    finally:
        os.remove(temp_path)


def test_parse_opam_file():
    content = """
opam-version: "2.0"
name: "my-ocaml-app"
version: "0.1.0"
depends: [
  "ocaml" {>= "4.14.0"}
  "dune" {>= "3.0.0"}
  "base64" {= "3.5.1"}
  "cmdliner"
  "lwt" {>= "5.6.0" & < "6.0.0"}
]
build: [
  ["dune" "build" "-p" name "-j" jobs]
]
"""
    with tempfile.NamedTemporaryFile("w", suffix=".opam", delete=False) as f:
        f.write(content)
        f.flush()
        temp_path = f.name

    try:
        packages = parse_opam_file(temp_path)
        pkg_dict = dict(packages)
        assert pkg_dict["ocaml"] == "4.14.0"
        assert pkg_dict["dune"] == "3.0.0"
        assert pkg_dict["base64"] == "3.5.1"
        assert pkg_dict["cmdliner"] == ""
        assert pkg_dict["lwt"] == "5.6.0"
    finally:
        os.remove(temp_path)


@pytest.mark.asyncio
async def test_scan_dependencies_conda_helm_opam():
    with tempfile.TemporaryDirectory() as tmpdir:
        conda_file = os.path.join(tmpdir, "environment.yml")
        with open(conda_file, "w") as f:
            f.write("dependencies:\n  - numpy=1.24.0\n")

        helm_file = os.path.join(tmpdir, "Chart.yaml")
        with open(helm_file, "w") as f:
            f.write("dependencies:\n  - name: redis\n    version: 17.0.1\n")

        opam_file = os.path.join(tmpdir, "sample.opam")
        with open(opam_file, "w") as f:
            f.write('depends: [\n  "dune" {>= "3.0.0"}\n]\n')

        mock_vuln = DepVulnerability(
            package="redis",
            version="17.0.1",
            cve_id="BIT-redis-2025-46819",
            severity="HIGH",
            cvss_score=7.8,
            description="Redis vulnerability",
            fix_version="17.0.2",
        )

        with patch("maunprekshak.scanner.deps._query_osv", new_callable=AsyncMock) as mock_query:
            mock_query.return_value = [mock_vuln]
            findings = await scan_dependencies(tmpdir)
            assert len(findings) >= 1
            assert any(f.package == "redis" for f in findings)
            assert mock_query.call_count >= 3
