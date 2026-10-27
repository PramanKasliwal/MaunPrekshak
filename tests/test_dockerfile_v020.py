"""
Tests for MaunPrekshak Core v0.20.0 — Container Security Suite (DF015, DF016).
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
        os.remove(temp_path)


def test_df015_sensitive_dir_recursive_perms():
    content = """
FROM python:3.12-slim
USER appuser
RUN chmod -R 777 /etc
RUN chown -R appuser:appgroup /var
RUN chmod --recursive 755 /root
"""
    findings = _scan_dockerfile_content(content)
    df015 = [f for f in findings if f.check_id == "DF015"]
    assert len(df015) == 3
    for f in df015:
        assert f.severity == "HIGH"
        assert "sensitive system directory" in f.description.lower()


def test_df015_safe_app_dir_and_suppression():
    content = """
FROM python:3.12-slim
USER appuser
RUN chmod -R 755 /app/static
RUN chmod -R 700 /home/appuser
RUN chmod -R 777 /etc # nosec: DF015
"""
    findings = _scan_dockerfile_content(content)
    df015 = [f for f in findings if f.check_id == "DF015"]
    assert len(df015) == 0


def test_df016_pip_install_missing_no_cache_dir():
    content = """
FROM python:3.12-slim
USER appuser
RUN pip install flask requests
RUN pip3 install -r requirements.txt
"""
    findings = _scan_dockerfile_content(content)
    df016 = [f for f in findings if f.check_id == "DF016"]
    assert len(df016) == 2
    for f in df016:
        assert f.severity == "MEDIUM"
        assert "--no-cache-dir" in f.description


def test_df016_safe_with_no_cache_dir_and_suppression():
    content = """
FROM python:3.12-slim
USER appuser
RUN pip install --no-cache-dir -r requirements.txt
RUN pip3 install --no-cache-dir flask
RUN pip install requests # nosec: DF016
"""
    findings = _scan_dockerfile_content(content)
    df016 = [f for f in findings if f.check_id == "DF016"]
    assert len(df016) == 0
