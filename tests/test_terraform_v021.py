"""
Tests for MaunPrekshak Core v0.21.0 — Terraform & OpenTofu Suite (TF023–TF026).
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


def test_tf023_secretsmanager_missing_kms():
    bad_tf = """
resource "aws_secretsmanager_secret" "secret1" {
  name        = "prod-db-creds"
  kms_key_id  = null
}

resource "aws_secretsmanager_secret" "secret2" {
  name        = "api-token"
  kms_key_id  = "aws/secretsmanager"
}

resource "aws_secretsmanager_secret" "secret3" {
  name        = "empty-key"
  kms_key_id  = ""
}
"""
    findings = _scan_tf_content(bad_tf)
    tf023 = [f for f in findings if f.check_id == "TF023"]
    assert len(tf023) == 3
    for f in tf023:
        assert f.severity == "HIGH"
        assert "secrets manager secret is unencrypted or encrypted with default aws key" in f.description.lower()


def test_tf023_safe_and_suppression():
    good_tf = """
resource "aws_secretsmanager_secret" "secret1" {
  name        = "prod-db-creds"
  kms_key_id  = "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
}

resource "aws_secretsmanager_secret" "secret2" {
  name        = "suppressed"
  kms_key_id  = null # nosec: TF023
}
"""
    findings = _scan_tf_content(good_tf)
    tf023 = [f for f in findings if f.check_id == "TF023"]
    assert len(tf023) == 0


def test_tf024_msk_kafka_unencrypted_client_broker():
    bad_tf = """
resource "aws_msk_cluster" "kafka1" {
  encryption_info {
    encryption_in_transit {
      client_broker = "PLAINTEXT"
    }
  }
}

resource "aws_msk_cluster" "kafka2" {
  encryption_info {
    encryption_in_transit {
      client_broker = "TLS_PLAINTEXT"
    }
  }
}
"""
    findings = _scan_tf_content(bad_tf)
    tf024 = [f for f in findings if f.check_id == "TF024"]
    assert len(tf024) == 2
    for f in tf024:
        assert f.severity == "HIGH"
        assert "msk kafka cluster allows unencrypted client-broker" in f.description.lower()


def test_tf024_safe_and_suppression():
    good_tf = """
resource "aws_msk_cluster" "kafka1" {
  encryption_info {
    encryption_in_transit {
      client_broker = "TLS"
    }
  }
}

resource "aws_msk_cluster" "kafka2" {
  encryption_info {
    encryption_in_transit {
      client_broker = "PLAINTEXT" # nosec: TF024
    }
  }
}
"""
    findings = _scan_tf_content(good_tf)
    tf024 = [f for f in findings if f.check_id == "TF024"]
    assert len(tf024) == 0


def test_tf025_elasticache_encryption_disabled():
    bad_tf = """
resource "aws_elasticache_replication_group" "redis1" {
  replication_group_id        = "redis-cluster"
  at_rest_encryption_enabled  = false
  transit_encryption_enabled  = false
}
"""
    findings = _scan_tf_content(bad_tf)
    tf025 = [f for f in findings if f.check_id == "TF025"]
    assert len(tf025) == 2
    for f in tf025:
        assert f.severity == "HIGH"
        assert "elasticache replication group has at-rest or in-transit encryption disabled" in f.description.lower()


def test_tf025_safe_and_suppression():
    good_tf = """
resource "aws_elasticache_replication_group" "redis" {
  replication_group_id        = "redis-cluster"
  at_rest_encryption_enabled  = true
  transit_encryption_enabled  = true
}

resource "aws_elasticache_replication_group" "suppressed" {
  replication_group_id        = "redis-cluster-dev"
  at_rest_encryption_enabled  = false # nosec: TF025
}
"""
    findings = _scan_tf_content(good_tf)
    tf025 = [f for f in findings if f.check_id == "TF025"]
    assert len(tf025) == 0


def test_tf026_sns_http_protocol():
    bad_tf = """
resource "aws_sns_topic_subscription" "user_updates_http" {
  topic_arn = aws_sns_topic.user_updates.arn
  protocol  = "http"
  endpoint  = "http://example.com/sns-endpoint"
}
"""
    findings = _scan_tf_content(bad_tf)
    tf026 = [f for f in findings if f.check_id == "TF026"]
    assert len(tf026) == 1
    assert tf026[0].severity == "MEDIUM"
    assert "unencrypted http endpoint" in tf026[0].description.lower()


def test_tf026_safe_and_suppression():
    good_tf = """
resource "aws_sns_topic_subscription" "user_updates_https" {
  topic_arn = aws_sns_topic.user_updates.arn
  protocol  = "https"
  endpoint  = "https://example.com/sns-endpoint"
}

resource "aws_sns_topic_subscription" "suppressed" {
  topic_arn = aws_sns_topic.user_updates.arn
  protocol  = "http" # nosec: TF026
  endpoint  = "http://example.com/sns-endpoint"
}
"""
    findings = _scan_tf_content(good_tf)
    tf026 = [f for f in findings if f.check_id == "TF026"]
    assert len(tf026) == 0
