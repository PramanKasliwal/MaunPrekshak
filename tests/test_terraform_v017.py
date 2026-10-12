"""
Tests for MaunPrekshak Core v0.17.0 — Terraform & OpenTofu Security Scanner Phase 6.
Tests TF009 (S3 bucket server-side encryption disabled) and TF010 (all protocols ingress open to world).
"""
import pytest
from maunprekshak.scanner.terraform import scan_single_terraform_file


def test_tf009_s3_encryption_disabled(tmp_path):
    tf_file = tmp_path / "s3_enc.tf"
    tf_file.write_text("""
resource "aws_s3_bucket_server_side_encryption_configuration" "bad" {
  bucket = "my-bucket"
  rule {
    bucket_key_enabled = false
  }
}
""")
    findings = scan_single_terraform_file(str(tf_file))
    check_ids = [f.check_id for f in findings]
    assert "TF009" in check_ids


def test_tf010_all_protocols_ingress_open(tmp_path):
    tf_file = tmp_path / "sg_all.tf"
    tf_file.write_text("""
resource "aws_security_group" "open_all" {
  name = "open_all"

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
""")
    findings = scan_single_terraform_file(str(tf_file))
    check_ids = [f.check_id for f in findings]
    assert "TF010" in check_ids
    tf010 = next(f for f in findings if f.check_id == "TF010")
    assert tf010.severity == "CRITICAL"


def test_tf009_tf010_suppression(tmp_path):
    tf_file = tmp_path / "suppressed.tf"
    tf_file.write_text("""
resource "aws_s3_bucket_server_side_encryption_configuration" "bad" {
  bucket = "my-bucket"
  rule {
    bucket_key_enabled = false # maunprekshak: ignore[TF009]
  }
}

resource "aws_security_group" "open_all" {
  name = "open_all"

  ingress {
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"] # maunprekshak: ignore[TF010]
  }
}
""")
    findings = scan_single_terraform_file(str(tf_file))
    check_ids = [f.check_id for f in findings]
    assert "TF009" not in check_ids
    assert "TF010" not in check_ids
