"""
Tests for MaunPrekshak Core v0.22.0 — Terraform & OpenTofu Suite (TF027–TF030).
"""
import os
import tempfile
from maunprekshak.scanner.terraform import scan_single_terraform_file


def _scan_tf_content(content: str):
    with tempfile.NamedTemporaryFile("w", suffix=".tf", delete=False) as f:
        f.write(content)
        f.flush()
        temp_path = f.name
    try:
        return scan_single_terraform_file(temp_path)
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


def test_tf027_cloudwatch_missing_kms():
    bad_tf = """
resource "aws_cloudwatch_log_group" "logs1" {
  name = "app-logs"
}

resource "aws_cloudwatch_log_group" "logs2" {
  name        = "api-logs"
  kms_key_id  = ""
}
"""
    findings = _scan_tf_content(bad_tf)
    tf027 = [f for f in findings if f.check_id == "TF027"]
    assert len(tf027) == 2
    for f in tf027:
        assert f.severity == "HIGH"
        assert "cloudwatch log group" in f.description.lower()
        assert "kms" in f.description.lower()


def test_tf027_safe():
    good_tf = """
resource "aws_cloudwatch_log_group" "logs" {
  name       = "app-logs"
  kms_key_id = "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
}
"""
    findings = _scan_tf_content(good_tf)
    tf027 = [f for f in findings if f.check_id == "TF027"]
    assert len(tf027) == 0


def test_tf028_ecr_missing_scan_or_immutable():
    bad_tf = """
resource "aws_ecr_repository" "repo1" {
  name = "backend-app"
}

resource "aws_ecr_repository" "repo2" {
  name                 = "frontend-app"
  image_tag_mutability = "MUTABLE"
  image_scanning_configuration {
    scan_on_push = false
  }
}
"""
    findings = _scan_tf_content(bad_tf)
    tf028 = [f for f in findings if f.check_id == "TF028"]
    assert len(tf028) == 3
    for f in tf028:
        assert f.severity == "HIGH"
        assert "ecr repository" in f.description.lower()


def test_tf028_safe():
    good_tf = """
resource "aws_ecr_repository" "repo" {
  name                 = "backend-app"
  image_tag_mutability = "IMMUTABLE"
  image_scanning_configuration {
    scan_on_push = true
  }
}
"""
    findings = _scan_tf_content(good_tf)
    tf028 = [f for f in findings if f.check_id == "TF028"]
    assert len(tf028) == 0


def test_tf029_redshift_unencrypted():
    bad_tf = """
resource "aws_redshift_cluster" "cluster1" {
  cluster_identifier = "analytics"
}

resource "aws_redshift_cluster" "cluster2" {
  cluster_identifier = "warehouse"
  encrypted          = false
}
"""
    findings = _scan_tf_content(bad_tf)
    tf029 = [f for f in findings if f.check_id == "TF029"]
    assert len(tf029) == 2
    for f in tf029:
        assert f.severity == "HIGH"
        assert "redshift" in f.description.lower()
        assert "encryption" in f.description.lower()


def test_tf029_safe():
    good_tf = """
resource "aws_redshift_cluster" "cluster" {
  cluster_identifier = "analytics"
  encrypted          = true
  kms_key_id         = "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
}
"""
    findings = _scan_tf_content(good_tf)
    tf029 = [f for f in findings if f.check_id == "TF029"]
    assert len(tf029) == 0


def test_tf030_cloudwatch_retention_unlimited():
    bad_tf = """
resource "aws_cloudwatch_log_group" "logs1" {
  name = "app-logs"
}

resource "aws_cloudwatch_log_group" "logs2" {
  name              = "api-logs"
  retention_in_days = 0
}
"""
    findings = _scan_tf_content(bad_tf)
    tf030 = [f for f in findings if f.check_id == "TF030"]
    assert len(tf030) == 2
    for f in tf030:
        assert f.severity == "MEDIUM"
        assert "retention_in_days" in f.description.lower() or "retention" in f.description.lower()


def test_tf030_safe():
    good_tf = """
resource "aws_cloudwatch_log_group" "logs" {
  name              = "app-logs"
  retention_in_days = 90
}
"""
    findings = _scan_tf_content(good_tf)
    tf030 = [f for f in findings if f.check_id == "TF030"]
    assert len(tf030) == 0
