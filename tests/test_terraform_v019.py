import tempfile
import os
from maunprekshak.scanner.terraform import scan_single_terraform_file


def test_tf015_insecure_alb_ssl_policy():
    content = """
resource "aws_lb_listener" "front_end" {
  load_balancer_arn = aws_lb.front_end.arn
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS-1-0"
  certificate_arn   = "arn:aws:acm:..."
}
"""
    with tempfile.NamedTemporaryFile("w", suffix=".tf", delete=False) as f:
        f.write(content)
        path = f.name

    try:
        findings = scan_single_terraform_file(path)
        check_ids = [f.check_id for f in findings]
        assert "TF015" in check_ids
    finally:
        os.unlink(path)


def test_tf015_suppression():
    content = """
resource "aws_lb_listener" "front_end" {
  ssl_policy = "ELBSecurityPolicy-TLS-1-0" # maunprekshak: ignore[TF015]
}
"""
    with tempfile.NamedTemporaryFile("w", suffix=".tf", delete=False) as f:
        f.write(content)
        path = f.name

    try:
        findings = scan_single_terraform_file(path)
        check_ids = [f.check_id for f in findings]
        assert "TF015" not in check_ids
    finally:
        os.unlink(path)


def test_tf016_s3_versioning_disabled():
    content = """
resource "aws_s3_bucket_versioning" "example" {
  bucket = aws_s3_bucket.example.id
  versioning_configuration {
    status = "Disabled"
  }
}

resource "aws_s3_bucket_versioning" "suspended" {
  bucket = aws_s3_bucket.suspended.id
  versioning_configuration {
    status = "Suspended"
  }
}
"""
    with tempfile.NamedTemporaryFile("w", suffix=".tf", delete=False) as f:
        f.write(content)
        path = f.name

    try:
        findings = scan_single_terraform_file(path)
        check_ids = [f.check_id for f in findings]
        assert "TF016" in check_ids
        tf016_findings = [f for f in findings if f.check_id == "TF016"]
        assert len(tf016_findings) == 2
    finally:
        os.unlink(path)


def test_tf016_suppression():
    content = """
resource "aws_s3_bucket_versioning" "example" {
  versioning_configuration {
    status = "Disabled" # nosec: TF016
  }
}
"""
    with tempfile.NamedTemporaryFile("w", suffix=".tf", delete=False) as f:
        f.write(content)
        path = f.name

    try:
        findings = scan_single_terraform_file(path)
        check_ids = [f.check_id for f in findings]
        assert "TF016" not in check_ids
    finally:
        os.unlink(path)


def test_tf017_ebs_encryption_disabled():
    content = """
resource "aws_ebs_encryption_by_default" "example" {
  enabled = false
}
"""
    with tempfile.NamedTemporaryFile("w", suffix=".tf", delete=False) as f:
        f.write(content)
        path = f.name

    try:
        findings = scan_single_terraform_file(path)
        check_ids = [f.check_id for f in findings]
        assert "TF017" in check_ids
    finally:
        os.unlink(path)


def test_tf018_sqs_sns_missing_kms():
    content = """
resource "aws_sqs_queue" "insecure" {
  name = "insecure-queue"
  kms_master_key_id = null
  sqs_managed_sse_enabled = false
}
"""
    with tempfile.NamedTemporaryFile("w", suffix=".tf", delete=False) as f:
        f.write(content)
        path = f.name

    try:
        findings = scan_single_terraform_file(path)
        check_ids = [f.check_id for f in findings]
        assert "TF018" in check_ids
    finally:
        os.unlink(path)
