import tempfile
import os
from maunprekshak.scanner.report import SASTFinding, Severity
from maunprekshak.scanner.fixer import fix_file_findings


def test_fix_tf016_s3_versioning():
    content = """resource "aws_s3_bucket_versioning" "example" {
  bucket = aws_s3_bucket.example.id
  versioning_configuration {
    status = "Disabled"
  }
}
"""
    with tempfile.NamedTemporaryFile("w", suffix=".tf", delete=False) as f:
        f.write(content)
        path = f.name
    try:
        findings = [
            SASTFinding(
                file_path=path, line=4, col=1, check_id="TF016",
                severity=Severity.HIGH.value, description="", recommendation="", code_snippet="",
            )
        ]
        applied = fix_file_findings(path, findings)
        assert applied == 1
        with open(path, "r") as f:
            fixed = f.read()
        assert 'status = "Enabled"' in fixed
    finally:
        os.unlink(path)


def test_fix_tf017_ebs_encryption():
    content = """resource "aws_ebs_encryption_by_default" "example" {
  enabled = false
}
"""
    with tempfile.NamedTemporaryFile("w", suffix=".tf", delete=False) as f:
        f.write(content)
        path = f.name
    try:
        findings = [
            SASTFinding(
                file_path=path, line=2, col=1, check_id="TF017",
                severity=Severity.HIGH.value, description="", recommendation="", code_snippet="",
            )
        ]
        applied = fix_file_findings(path, findings)
        assert applied == 1
        with open(path, "r") as f:
            fixed = f.read()
        assert "enabled = true" in fixed
    finally:
        os.unlink(path)


def test_fix_df013_ssh_port_exposure():
    content = """FROM ubuntu:22.04
USER appuser
EXPOSE 22
CMD ["app"]
"""
    with tempfile.NamedTemporaryFile("w", suffix="Dockerfile", delete=False) as f:
        f.write(content)
        path = f.name
    try:
        findings = [
            SASTFinding(
                file_path=path, line=3, col=1, check_id="DF013",
                severity=Severity.HIGH.value, description="", recommendation="", code_snippet="",
            )
        ]
        applied = fix_file_findings(path, findings)
        assert applied == 1
        with open(path, "r") as f:
            fixed = f.read()
        assert "# EXPOSE 22 (SSH prohibited in container)" in fixed
    finally:
        os.unlink(path)


def test_fix_mp083_cors_credentials():
    content = """from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True)
"""
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
        f.write(content)
        path = f.name
    try:
        findings = [
            SASTFinding(
                file_path=path, line=5, col=1, check_id="MP083",
                severity=Severity.HIGH.value, description="", recommendation="", code_snippet="",
            )
        ]
        applied = fix_file_findings(path, findings)
        assert applied == 1
        with open(path, "r") as f:
            fixed = f.read()
        assert "allow_credentials=False" in fixed
    finally:
        os.unlink(path)
