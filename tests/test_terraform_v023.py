"""
Tests for MaunPrekshak Core v0.23.0 — Terraform & OpenTofu Suite (TF031–TF034).
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
        os.remove(temp_path)


def test_tf031_rds_deletion_protection_disabled():
    bad_tf = """
resource "aws_db_instance" "default" {
  allocated_storage   = 20
  engine              = "mysql"
  instance_class      = "db.t3.micro"
  deletion_protection = false
}
"""
    findings = _scan_tf_content(bad_tf)
    tf031 = [f for f in findings if f.check_id == "TF031"]
    assert len(tf031) == 1
    assert tf031[0].severity == "HIGH"
    assert "deletion protection disabled" in tf031[0].description.lower()


def test_tf031_safe_and_suppression():
    good_tf = """
resource "aws_db_instance" "default" {
  deletion_protection = true
}

resource "aws_rds_cluster" "aurora" {
  deletion_protection = false # nosec: TF031
}
"""
    findings = _scan_tf_content(good_tf)
    tf031 = [f for f in findings if f.check_id == "TF031"]
    assert len(tf031) == 0


def test_tf032_s3_mfa_delete_object_lock_disabled():
    bad_tf = """
resource "aws_s3_bucket_versioning" "example" {
  bucket = aws_s3_bucket.example.id
  versioning_configuration {
    status     = "Enabled"
    mfa_delete = "Disabled"
  }
}

resource "aws_s3_bucket" "unlocked" {
  bucket              = "my-bucket"
  object_lock_enabled = false
}
"""
    findings = _scan_tf_content(bad_tf)
    tf032 = [f for f in findings if f.check_id == "TF032"]
    assert len(tf032) == 2
    for f in tf032:
        assert f.severity == "HIGH"
        assert "mfa delete" in f.description.lower() or "object lock" in f.description.lower()


def test_tf032_safe_and_suppression():
    good_tf = """
resource "aws_s3_bucket_versioning" "example" {
  bucket = aws_s3_bucket.example.id
  versioning_configuration {
    status     = "Enabled"
    mfa_delete = "Enabled"
  }
}

resource "aws_s3_bucket" "unlocked" {
  bucket              = "my-bucket"
  object_lock_enabled = false # nosec: TF032
}
"""
    findings = _scan_tf_content(good_tf)
    tf032 = [f for f in findings if f.check_id == "TF032"]
    assert len(tf032) == 0


def test_tf033_api_gateway_cache_unencrypted():
    bad_tf = """
resource "aws_api_gateway_method_settings" "all" {
  rest_api_id = aws_api_gateway_rest_api.example.id
  stage_name  = aws_api_gateway_stage.example.stage_name
  method_path = "*/*"

  settings {
    caching_enabled      = true
    cache_data_encrypted = false
  }
}
"""
    findings = _scan_tf_content(bad_tf)
    tf033 = [f for f in findings if f.check_id == "TF033"]
    assert len(tf033) == 1
    assert tf033[0].severity == "HIGH"
    assert "cache data encryption is disabled" in tf033[0].description.lower()


def test_tf033_safe_and_suppression():
    good_tf = """
resource "aws_api_gateway_method_settings" "all" {
  settings {
    cache_data_encrypted = true
  }
}

resource "aws_api_gateway_method_settings" "legacy" {
  settings {
    cache_data_encrypted = false # nosec: TF033
  }
}
"""
    findings = _scan_tf_content(good_tf)
    tf033 = [f for f in findings if f.check_id == "TF033"]
    assert len(tf033) == 0


def test_tf034_vpc_flow_logs_traffic_type_not_all():
    bad_tf = """
resource "aws_flow_log" "example" {
  iam_role_arn    = aws_iam_role.example.arn
  log_destination = aws_cloudwatch_log_group.example.arn
  traffic_type    = "REJECT"
  vpc_id          = aws_vpc.example.id
}
"""
    findings = _scan_tf_content(bad_tf)
    tf034 = [f for f in findings if f.check_id == "TF034"]
    assert len(tf034) == 1
    assert tf034[0].severity == "MEDIUM"
    assert "traffic_type" in tf034[0].description.lower()


def test_tf034_safe_and_suppression():
    good_tf = """
resource "aws_flow_log" "example" {
  traffic_type = "ALL"
}

resource "aws_flow_log" "custom" {
  traffic_type = "REJECT" # nosec: TF034
}
"""
    findings = _scan_tf_content(good_tf)
    tf034 = [f for f in findings if f.check_id == "TF034"]
    assert len(tf034) == 0
