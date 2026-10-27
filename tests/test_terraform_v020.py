"""
Tests for MaunPrekshak Core v0.20.0 — Terraform & OpenTofu Suite (TF019–TF022).
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


def test_tf019_cloudfront_viewer_protocol_policy():
    bad_tf = """
resource "aws_cloudfront_distribution" "s3_distribution" {
  default_cache_behavior {
    viewer_protocol_policy = "allow-all"
    target_origin_id       = "myOrigin"
  }
}
"""
    findings = _scan_tf_content(bad_tf)
    tf019 = [f for f in findings if f.check_id == "TF019"]
    assert len(tf019) == 1
    assert tf019[0].severity == "HIGH"
    assert "allow-all" in tf019[0].description


def test_tf019_safe_and_suppression():
    good_tf = """
resource "aws_cloudfront_distribution" "s3_distribution" {
  default_cache_behavior {
    viewer_protocol_policy = "redirect-to-https"
  }
  ordered_cache_behavior {
    viewer_protocol_policy = "allow-all" # nosec: TF019
  }
}
"""
    findings = _scan_tf_content(good_tf)
    tf019 = [f for f in findings if f.check_id == "TF019"]
    assert len(tf019) == 0


def test_tf020_opensearch_encryption_disabled():
    bad_tf = """
resource "aws_opensearch_domain" "example" {
  domain_name = "example-domain"

  encrypt_at_rest {
    enabled = false
  }

  node_to_node_encryption {
    enabled = false
  }
}
"""
    findings = _scan_tf_content(bad_tf)
    tf020 = [f for f in findings if f.check_id == "TF020"]
    assert len(tf020) == 2
    for f in tf020:
        assert f.severity == "HIGH"
        assert "opensearch" in f.description.lower()


def test_tf020_safe_and_suppression():
    good_tf = """
resource "aws_opensearch_domain" "example" {
  domain_name = "example-domain"

  encrypt_at_rest {
    enabled = true
  }

  node_to_node_encryption {
    enabled = false # nosec: TF020
  }
}
"""
    findings = _scan_tf_content(good_tf)
    tf020 = [f for f in findings if f.check_id == "TF020"]
    assert len(tf020) == 0


def test_tf021_api_gateway_authorization_none():
    bad_tf = """
resource "aws_api_gateway_method" "MyDemoMethod" {
  rest_api_id   = aws_api_gateway_rest_api.MyDemoAPI.id
  resource_id   = aws_api_gateway_resource.MyDemoResource.id
  http_method   = "GET"
  authorization = "NONE"
}
"""
    findings = _scan_tf_content(bad_tf)
    tf021 = [f for f in findings if f.check_id == "TF021"]
    assert len(tf021) == 1
    assert tf021[0].severity == "HIGH"
    assert "authorization disabled" in tf021[0].description.lower()


def test_tf021_safe_and_suppression():
    good_tf = """
resource "aws_api_gateway_method" "MyDemoMethod" {
  rest_api_id   = aws_api_gateway_rest_api.MyDemoAPI.id
  resource_id   = aws_api_gateway_resource.MyDemoResource.id
  http_method   = "GET"
  authorization = "AWS_IAM"
}

resource "aws_api_gateway_method" "LegacyMethod" {
  http_method   = "GET"
  authorization = "NONE" # nosec: TF021
}
"""
    findings = _scan_tf_content(good_tf)
    tf021 = [f for f in findings if f.check_id == "TF021"]
    assert len(tf021) == 0


def test_tf022_lambda_kms_key_unconfigured():
    bad_tf = """
resource "aws_lambda_function" "test_lambda" {
  filename      = "lambda_function_payload.zip"
  function_name = "lambda_function_name"
  role          = aws_iam_role.iam_for_lambda.arn
  handler       = "index.test"
  runtime       = "nodejs18.x"
  kms_key_arn   = null
}
"""
    findings = _scan_tf_content(bad_tf)
    tf022 = [f for f in findings if f.check_id == "TF022"]
    assert len(tf022) == 1
    assert tf022[0].severity == "MEDIUM"
    assert "kms_key_arn" in tf022[0].description


def test_tf022_safe_and_suppression():
    good_tf = """
resource "aws_lambda_function" "test_lambda" {
  function_name = "secure_lambda"
  kms_key_arn   = "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
}

resource "aws_lambda_function" "suppressed_lambda" {
  function_name = "test_lambda"
  kms_key_arn   = null # nosec: TF022
}
"""
    findings = _scan_tf_content(good_tf)
    tf022 = [f for f in findings if f.check_id == "TF022"]
    assert len(tf022) == 0
