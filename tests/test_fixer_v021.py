"""
Tests for MaunPrekshak Core v0.21.0 — Mechanical Auto-Fixing Suite (TF024, TF025, DF018, MP098).
"""
import os
import tempfile
from maunprekshak.scanner.report import SASTFinding, Severity
from maunprekshak.scanner.fixer import fix_file_findings


def test_fix_tf024_msk_kafka_tls():
    content = """resource "aws_msk_cluster" "kafka" {
  encryption_info {
    encryption_in_transit {
      client_broker = "PLAINTEXT"
    }
  }
}
"""
    with tempfile.NamedTemporaryFile("w", suffix=".tf", delete=False) as f:
        f.write(content)
        path = f.name
    try:
        findings = [
            SASTFinding(
                file_path=path, line=4, col=1, check_id="TF024",
                severity=Severity.HIGH.value, description="", recommendation="", code_snippet="",
            )
        ]
        applied = fix_file_findings(path, findings)
        assert applied == 1
        with open(path, "r") as f:
            fixed = f.read()
        assert 'client_broker = "TLS"' in fixed
    finally:
        os.unlink(path)


def test_fix_tf025_elasticache_encryption():
    content = """resource "aws_elasticache_replication_group" "redis" {
  at_rest_encryption_enabled = false
  transit_encryption_enabled = false
}
"""
    with tempfile.NamedTemporaryFile("w", suffix=".tf", delete=False) as f:
        f.write(content)
        path = f.name
    try:
        findings = [
            SASTFinding(
                file_path=path, line=2, col=1, check_id="TF025",
                severity=Severity.HIGH.value, description="", recommendation="", code_snippet="",
            ),
            SASTFinding(
                file_path=path, line=3, col=1, check_id="TF025",
                severity=Severity.HIGH.value, description="", recommendation="", code_snippet="",
            )
        ]
        applied = fix_file_findings(path, findings)
        assert applied == 2
        with open(path, "r") as f:
            fixed = f.read()
        assert "at_rest_encryption_enabled = true" in fixed
        assert "transit_encryption_enabled = true" in fixed
    finally:
        os.unlink(path)


def test_fix_df018_insecure_downloads():
    content = """FROM ubuntu:22.04
USER appuser
RUN curl -k https://example.com/install.sh
RUN curl --insecure https://packages.example.com/key.pub
RUN wget --no-check-certificate https://example.com/pkg.tar.gz
"""
    with tempfile.NamedTemporaryFile("w", suffix=".Dockerfile", delete=False) as f:
        f.write(content)
        path = f.name
    try:
        findings = [
            SASTFinding(
                file_path=path, line=3, col=1, check_id="DF018",
                severity=Severity.HIGH.value, description="", recommendation="", code_snippet="",
            ),
            SASTFinding(
                file_path=path, line=4, col=1, check_id="DF018",
                severity=Severity.HIGH.value, description="", recommendation="", code_snippet="",
            ),
            SASTFinding(
                file_path=path, line=5, col=1, check_id="DF018",
                severity=Severity.HIGH.value, description="", recommendation="", code_snippet="",
            )
        ]
        applied = fix_file_findings(path, findings)
        assert applied == 3
        with open(path, "r") as f:
            fixed = f.read()
        assert "-k" not in fixed
        assert "--insecure" not in fixed
        assert "--no-check-certificate" not in fixed
        assert "RUN curl https://example.com/install.sh" in fixed
        assert "RUN wget https://example.com/pkg.tar.gz" in fixed
    finally:
        os.unlink(path)


def test_fix_mp098_paramiko_auto_add_policy():
    content = """import paramiko
client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
"""
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
        f.write(content)
        path = f.name
    try:
        findings = [
            SASTFinding(
                file_path=path, line=3, col=1, check_id="MP098",
                severity=Severity.HIGH.value, description="", recommendation="", code_snippet="",
            )
        ]
        applied = fix_file_findings(path, findings)
        assert applied == 1
        with open(path, "r") as f:
            fixed = f.read()
        assert "client.set_missing_host_key_policy(paramiko.RejectPolicy())" in fixed
    finally:
        os.unlink(path)
