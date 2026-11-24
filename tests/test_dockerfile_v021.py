"""
Tests for MaunPrekshak Core v0.21.0 — Container Security Suite (DF017, DF018).
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


def test_df017_sensitive_keys_certs_copy_add():
    content = """
FROM alpine:3.19
USER appuser
COPY id_rsa /root/.ssh/id_rsa
ADD server.key /etc/ssl/private/server.key
COPY cert.pem /app/certs/cert.pem
ADD client.pfx /app/certs/client.pfx
"""
    findings = _scan_dockerfile_content(content)
    df017 = [f for f in findings if f.check_id == "DF017"]
    assert len(df017) == 4
    for f in df017:
        assert f.severity == "CRITICAL"
        assert "cryptographic key or certificate" in f.description.lower()


def test_df017_safe_copy_and_suppression():
    content = """
FROM alpine:3.19
USER appuser
COPY package.json /app/
COPY server.js /app/
COPY cert.pem /app/certs/cert.pem # nosec: DF017
"""
    findings = _scan_dockerfile_content(content)
    df017 = [f for f in findings if f.check_id == "DF017"]
    assert len(df017) == 0


def test_df018_insecure_curl_wget_flags():
    content = """
FROM ubuntu:22.04
USER appuser
RUN curl -k https://example.com/install.sh -o install.sh
RUN curl --insecure https://packages.example.com/deb.key | apt-key add -
RUN wget --no-check-certificate https://example.com/binary.tar.gz
"""
    findings = _scan_dockerfile_content(content)
    df018 = [f for f in findings if f.check_id == "DF018"]
    assert len(df018) == 3
    for f in df018:
        assert f.severity == "HIGH"
        assert "tls verification disabled" in f.description.lower() or "tls certificate validation disabled" in f.description.lower()


def test_df018_safe_downloads_and_suppression():
    content = """
FROM ubuntu:22.04
USER appuser
RUN curl -sSL https://example.com/script.sh -o script.sh
RUN wget https://example.com/file.zip
RUN curl -k https://internal.corp/test # nosec: DF018
"""
    findings = _scan_dockerfile_content(content)
    df018 = [f for f in findings if f.check_id == "DF018"]
    assert len(df018) == 0
