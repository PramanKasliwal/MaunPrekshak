"""
Tests for Dockerfile Container Security Scanner (DF001 - DF006).
"""
import pytest
from maunprekshak.scanner.dockerfile import scan_dockerfiles


def write_dockerfile(tmp_path, filename, content):
    f = tmp_path / filename
    f.write_text(content)
    return str(tmp_path)


class TestDockerfileScanner:
    def test_df001_missing_user(self, tmp_path):
        content = """FROM python:3.11-slim
WORKDIR /app
COPY . .
CMD ["python", "app.py"]
"""
        path = write_dockerfile(tmp_path, "Dockerfile", content)
        findings = scan_dockerfiles(path)
        check_ids = [f.check_id for f in findings]
        assert "DF001" in check_ids

    def test_df001_with_user_passes(self, tmp_path):
        content = """FROM python:3.11-slim
WORKDIR /app
COPY . .
USER appuser
CMD ["python", "app.py"]
"""
        path = write_dockerfile(tmp_path, "Dockerfile", content)
        findings = scan_dockerfiles(path)
        check_ids = [f.check_id for f in findings]
        assert "DF001" not in check_ids

    def test_df002_unpinned_or_latest_image(self, tmp_path):
        content = """FROM python:latest
USER appuser
"""
        path = write_dockerfile(tmp_path, "Dockerfile", content)
        findings = scan_dockerfiles(path)
        check_ids = [f.check_id for f in findings]
        assert "DF002" in check_ids

    def test_df003_uncached_apt_get(self, tmp_path):
        content = """FROM python:3.11-slim
RUN apt-get update && apt-get install -y curl
USER appuser
"""
        path = write_dockerfile(tmp_path, "Dockerfile", content)
        findings = scan_dockerfiles(path)
        check_ids = [f.check_id for f in findings]
        assert "DF003" in check_ids

    def test_df004_sensitive_port_exposed(self, tmp_path):
        content = """FROM python:3.11-slim
EXPOSE 22
USER appuser
"""
        path = write_dockerfile(tmp_path, "Dockerfile", content)
        findings = scan_dockerfiles(path)
        check_ids = [f.check_id for f in findings]
        assert "DF004" in check_ids

    def test_df005_curl_piped_to_shell(self, tmp_path):
        content = """FROM python:3.11-slim
RUN curl -fsSL https://get.docker.com | sh
USER appuser
"""
        path = write_dockerfile(tmp_path, "Dockerfile", content)
        findings = scan_dockerfiles(path)
        check_ids = [f.check_id for f in findings]
        assert "DF005" in check_ids

    def test_df006_add_instruction_used(self, tmp_path):
        content = """FROM python:3.11-slim
ADD src/ /app/
USER appuser
"""
        path = write_dockerfile(tmp_path, "Dockerfile", content)
        findings = scan_dockerfiles(path)
        check_ids = [f.check_id for f in findings]
        assert "DF006" in check_ids

    def test_inline_suppression(self, tmp_path):
        content = """FROM python:latest # maunprekshak: ignore[DF002]
USER appuser
"""
        path = write_dockerfile(tmp_path, "Dockerfile", content)
        findings = scan_dockerfiles(path)
        check_ids = [f.check_id for f in findings]
        assert "DF002" not in check_ids

    def test_clean_dockerfile_no_findings(self, tmp_path):
        content = """FROM python:3.11.8-slim
WORKDIR /app
COPY requirements.txt .
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8080
USER 10001:10001
CMD ["python", "main.py"]
"""
        path = write_dockerfile(tmp_path, "Dockerfile", content)
        findings = scan_dockerfiles(path)
        assert len(findings) == 0
