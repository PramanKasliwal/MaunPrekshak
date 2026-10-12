"""
Tests for MaunPrekshak Core v0.17.0 — Dockerfile Container Security Scanner Phase 6.
Tests DF007 (sudo/su in RUN), DF008 (sensitive files copied), DF009 (apk/yum cache cleanup), DF010 (HEALTHCHECK NONE).
"""
import pytest
from maunprekshak.scanner.dockerfile import scan_dockerfiles


def write_dockerfile(tmp_path, filename, content):
    f = tmp_path / filename
    f.write_text(content)
    return str(tmp_path)


def test_df007_sudo_in_run(tmp_path):
    content = """FROM python:3.11-slim
RUN apt-get update && sudo apt-get install -y curl
USER appuser
CMD ["python", "app.py"]
"""
    path = write_dockerfile(tmp_path, "Dockerfile", content)
    findings = scan_dockerfiles(path)
    check_ids = [f.check_id for f in findings]
    assert "DF007" in check_ids


def test_df008_sensitive_file_copied(tmp_path):
    content = """FROM python:3.11-slim
COPY .env /app/.env
USER appuser
CMD ["python", "app.py"]
"""
    path = write_dockerfile(tmp_path, "Dockerfile", content)
    findings = scan_dockerfiles(path)
    check_ids = [f.check_id for f in findings]
    assert "DF008" in check_ids


def test_df008_ssh_key_copied(tmp_path):
    content = """FROM python:3.11-slim
COPY id_rsa /root/.ssh/id_rsa
USER appuser
CMD ["python", "app.py"]
"""
    path = write_dockerfile(tmp_path, "Dockerfile", content)
    findings = scan_dockerfiles(path)
    check_ids = [f.check_id for f in findings]
    assert "DF008" in check_ids


def test_df009_apk_without_no_cache(tmp_path):
    content = """FROM alpine:3.18
RUN apk add curl git
USER appuser
CMD ["sh"]
"""
    path = write_dockerfile(tmp_path, "Dockerfile", content)
    findings = scan_dockerfiles(path)
    check_ids = [f.check_id for f in findings]
    assert "DF009" in check_ids


def test_df009_apk_with_no_cache_passes(tmp_path):
    content = """FROM alpine:3.18
RUN apk add --no-cache curl git
USER appuser
CMD ["sh"]
"""
    path = write_dockerfile(tmp_path, "Dockerfile", content)
    findings = scan_dockerfiles(path)
    check_ids = [f.check_id for f in findings]
    assert "DF009" not in check_ids


def test_df010_healthcheck_none(tmp_path):
    content = """FROM python:3.11-slim
HEALTHCHECK NONE
USER appuser
CMD ["python", "app.py"]
"""
    path = write_dockerfile(tmp_path, "Dockerfile", content)
    findings = scan_dockerfiles(path)
    check_ids = [f.check_id for f in findings]
    assert "DF010" in check_ids


def test_df007_df008_suppression(tmp_path):
    content = """FROM python:3.11-slim
RUN sudo apt-get install -y curl # maunprekshak: ignore[DF007]
COPY .env /app/.env # maunprekshak: ignore[DF008]
USER appuser
CMD ["python", "app.py"]
"""
    path = write_dockerfile(tmp_path, "Dockerfile", content)
    findings = scan_dockerfiles(path)
    check_ids = [f.check_id for f in findings]
    assert "DF007" not in check_ids
    assert "DF008" not in check_ids
