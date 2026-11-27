"""
Tests for MaunPrekshak Core v0.22.0 — Container Security Suite (DF019, DF020).
"""
import os
import tempfile
from maunprekshak.scanner.dockerfile import scan_single_dockerfile


def _scan_dockerfile_content(content: str):
    with tempfile.NamedTemporaryFile("w", suffix=".Dockerfile", delete=False) as f:
        f.write(content)
        f.flush()
        temp_path = f.name
    try:
        return scan_single_dockerfile(temp_path)
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


def test_df019_apt_get_missing_no_install_recommends():
    content = """
FROM ubuntu:22.04
USER appuser
RUN apt-get update && apt-get install -y curl python3-pip
RUN apt install -y git
"""
    findings = _scan_dockerfile_content(content)
    df019 = [f for f in findings if f.check_id == "DF019"]
    assert len(df019) == 2
    for f in df019:
        assert f.severity == "MEDIUM"
        assert "--no-install-recommends" in f.description


def test_df019_safe_with_no_install_recommends():
    content = """
FROM ubuntu:22.04
USER appuser
RUN apt-get update && apt-get install --no-install-recommends -y curl python3-pip
RUN apt-get install -y --no-install-recommends git
"""
    findings = _scan_dockerfile_content(content)
    df019 = [f for f in findings if f.check_id == "DF019"]
    assert len(df019) == 0


def test_df020_insecure_package_installer_flags():
    content = """
FROM python:3.11-slim
USER appuser
RUN pip install --trusted-host pypi.org requests
RUN pip install --trusted-host=files.pythonhosted.org flask
RUN npm install --unsafe-perm
RUN yarn install --ignore-engines
"""
    findings = _scan_dockerfile_content(content)
    df020 = [f for f in findings if f.check_id == "DF020"]
    assert len(df020) == 4
    for f in df020:
        assert f.severity == "HIGH"
        assert "insecure" in f.description.lower() or "integrity" in f.description.lower()


def test_df020_safe_flags():
    content = """
FROM python:3.11-slim
USER appuser
RUN pip install requests flask
RUN npm install
RUN yarn install --frozen-lockfile
"""
    findings = _scan_dockerfile_content(content)
    df020 = [f for f in findings if f.check_id == "DF020"]
    assert len(df020) == 0
