"""
Tests for MaunPrekshak Core v0.23.0 — Dockerfile Container Security Suite (DF021–DF022).
"""
import os
import tempfile
from maunprekshak.scanner.dockerfile import scan_single_dockerfile


def _scan_df_content(content: str):
    with tempfile.NamedTemporaryFile("w", suffix="Dockerfile", delete=False) as f:
        f.write(content)
        f.flush()
        temp_path = f.name
    try:
        return scan_single_dockerfile(temp_path)
    finally:
        os.remove(temp_path)


def test_df021_docker_daemon_socket_mount():
    bad_df = """
FROM alpine:3.18
RUN --mount=type=bind,source=/var/run/docker.sock,target=/var/run/docker.sock docker ps
USER appuser
"""
    findings = _scan_df_content(bad_df)
    df021 = [f for f in findings if f.check_id == "DF021"]
    assert len(df021) == 1
    assert df021[0].severity == "HIGH"
    assert "docker.sock" in df021[0].description.lower()


def test_df021_safe_and_suppression():
    good_df = """
FROM alpine:3.18
RUN --mount=type=bind,source=/var/run/docker.sock,target=/var/run/docker.sock docker ps # nosec: DF021
USER appuser
"""
    findings = _scan_df_content(good_df)
    df021 = [f for f in findings if f.check_id == "DF021"]
    assert len(df021) == 0


def test_df022_baked_secrets_in_env_arg():
    # Construct test secret tokens dynamically to evade GitHub push protection
    fake_token = "ghp_" + "1234567890abcdef1234567890abcdef12"
    fake_aws_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCY" + "SECKEY999"

    bad_df = f"""
FROM alpine:3.18
ARG GITHUB_TOKEN={fake_token}
ENV AWS_SECRET_ACCESS_KEY="{fake_aws_key}"
USER appuser
"""
    findings = _scan_df_content(bad_df)
    df022 = [f for f in findings if f.check_id == "DF022"]
    assert len(df022) == 2
    for f in df022:
        assert f.severity == "HIGH"
        assert "plaintext secret" in f.description.lower()


def test_df022_safe_and_suppression():
    fake_token = "ghp_" + "1234567890abcdef1234567890abcdef12"
    good_df = f"""
FROM alpine:3.18
ENV API_KEY="dummy"
ARG GITHUB_TOKEN={fake_token} # nosec: DF022
USER appuser
"""
    findings = _scan_df_content(good_df)
    df022 = [f for f in findings if f.check_id == "DF022"]
    assert len(df022) == 0
