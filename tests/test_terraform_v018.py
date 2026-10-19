import tempfile
import os
from maunprekshak.scanner.terraform import scan_single_terraform_file


def _scan_tf(content: str):
    with tempfile.NamedTemporaryFile("w", suffix=".tf", delete=False) as f:
        f.write(content)
        path = f.name
    try:
        return scan_single_terraform_file(path)
    finally:
        os.unlink(path)


def test_tf011_cloudtrail_logging_disabled():
    tf = """
resource "aws_cloudtrail" "insecure_trail" {
  name           = "audit-trail"
  s3_bucket_name = "my-audit-bucket"
  enable_logging = false
}
"""
    findings = _scan_tf(tf)
    tf011 = [f for f in findings if f.check_id == "TF011"]
    assert len(tf011) == 1
    assert tf011[0].severity == "HIGH"
    assert "CloudTrail" in tf011[0].description


def test_tf011_multi_region_disabled():
    tf = """
resource "aws_cloudtrail" "single_region_trail" {
  name                  = "audit-trail"
  s3_bucket_name        = "my-audit-bucket"
  is_multi_region_trail = false
}
"""
    findings = _scan_tf(tf)
    tf011 = [f for f in findings if f.check_id == "TF011"]
    assert len(tf011) == 1


def test_tf011_safe_and_suppression():
    tf = """
resource "aws_cloudtrail" "secure_trail" {
  name                  = "audit-trail"
  enable_logging        = true
  is_multi_region_trail = true
}

resource "aws_cloudtrail" "suppressed_trail" {
  name           = "legacy-trail"
  enable_logging = false # maunprekshak: ignore[TF011]
}
"""
    findings = _scan_tf(tf)
    tf011 = [f for f in findings if f.check_id == "TF011"]
    assert len(tf011) == 0


def test_tf012_rds_missing_kms():
    tf = """
resource "aws_db_instance" "insecure_db" {
  allocated_storage = 20
  engine            = "postgres"
  instance_class    = "db.t3.micro"
}
"""
    findings = _scan_tf(tf)
    tf012 = [f for f in findings if f.check_id == "TF012"]
    assert len(tf012) == 1
    assert tf012[0].severity == "HIGH"


def test_tf012_rds_null_kms():
    tf = """
resource "aws_db_instance" "null_kms_db" {
  allocated_storage = 20
  engine            = "postgres"
  instance_class    = "db.t3.micro"
  kms_key_id        = null
}
"""
    findings = _scan_tf(tf)
    tf012 = [f for f in findings if f.check_id == "TF012"]
    assert len(tf012) >= 1


def test_tf012_rds_with_kms_safe():
    tf = """
resource "aws_db_instance" "secure_db" {
  allocated_storage = 20
  engine            = "postgres"
  instance_class    = "db.t3.micro"
  kms_key_id        = "arn:aws:kms:us-east-1:123456789012:key/abcd-1234"
}
"""
    findings = _scan_tf(tf)
    tf012 = [f for f in findings if f.check_id == "TF012"]
    assert len(tf012) == 0


def test_tf013_default_sg_rules():
    tf = """
resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.main.id

  ingress {
    protocol  = -1
    self      = true
    from_port = 0
    to_port   = 0
  }
}
"""
    findings = _scan_tf(tf)
    tf013 = [f for f in findings if f.check_id == "TF013"]
    assert len(tf013) == 1
    assert tf013[0].severity == "MEDIUM"


def test_tf013_default_sg_clean_safe():
    tf = """
resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.main.id
}
"""
    findings = _scan_tf(tf)
    tf013 = [f for f in findings if f.check_id == "TF013"]
    assert len(tf013) == 0


def test_tf014_eks_public_access_unrestricted():
    tf = """
resource "aws_eks_cluster" "insecure_cluster" {
  name     = "prod-eks"
  role_arn = aws_iam_role.cluster.arn

  vpc_config {
    endpoint_public_access = true
    public_access_cidrs    = ["0.0.0.0/0"]
  }
}
"""
    findings = _scan_tf(tf)
    tf014 = [f for f in findings if f.check_id == "TF014"]
    assert len(tf014) >= 1
    assert tf014[0].severity == "HIGH"


def test_tf014_eks_private_safe():
    tf = """
resource "aws_eks_cluster" "secure_cluster" {
  name     = "prod-eks"
  role_arn = aws_iam_role.cluster.arn

  vpc_config {
    endpoint_public_access = false
  }
}
"""
    findings = _scan_tf(tf)
    tf014 = [f for f in findings if f.check_id == "TF014"]
    assert len(tf014) == 0
