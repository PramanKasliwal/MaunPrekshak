import tempfile
import os
from maunprekshak.scanner.dockerfile import scan_single_dockerfile


def _scan_content(content: str):
    with tempfile.NamedTemporaryFile("w", suffix="Dockerfile", delete=False) as f:
        f.write(content)
        path = f.name
    try:
        return scan_single_dockerfile(path)
    finally:
        os.unlink(path)


def test_df011_chmod_permissive():
    dockerfile = """
FROM python:3.11-slim
USER appuser
RUN chmod 777 /app/data
"""
    findings = _scan_content(dockerfile)
    df011 = [f for f in findings if f.check_id == "DF011"]
    assert len(df011) == 1
    assert df011[0].severity == "HIGH"
    assert "chmod 777" in df011[0].description


def test_df011_chmod_safe():
    dockerfile = """
FROM python:3.11-slim
USER appuser
RUN chmod 755 /app/data
"""
    findings = _scan_content(dockerfile)
    df011 = [f for f in findings if f.check_id == "DF011"]
    assert len(df011) == 0


def test_df011_suppression():
    dockerfile = """
FROM python:3.11-slim
USER appuser
RUN chmod 777 /app/data # maunprekshak: ignore[DF011]
"""
    findings = _scan_content(dockerfile)
    df011 = [f for f in findings if f.check_id == "DF011"]
    assert len(df011) == 0


def test_df012_maintainer_deprecated():
    dockerfile = """
FROM python:3.11-slim
MAINTAINER Security Team <sec@example.com>
USER appuser
"""
    findings = _scan_content(dockerfile)
    df012 = [f for f in findings if f.check_id == "DF012"]
    assert len(df012) == 1
    assert df012[0].severity == "LOW"
    assert "MAINTAINER" in df012[0].description


def test_df012_label_safe():
    dockerfile = """
FROM python:3.11-slim
LABEL maintainer="Security Team <sec@example.com>"
USER appuser
"""
    findings = _scan_content(dockerfile)
    df012 = [f for f in findings if f.check_id == "DF012"]
    assert len(df012) == 0


def test_df012_suppression():
    dockerfile = """
FROM python:3.11-slim
MAINTAINER Legacy Team <dev@example.com> # maunprekshak: ignore[DF012]
USER appuser
"""
    findings = _scan_content(dockerfile)
    df012 = [f for f in findings if f.check_id == "DF012"]
    assert len(df012) == 0
