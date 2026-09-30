"""
Tests for MaunPrekshak Core v0.13.0 — CI/CD Webhook Notification Engine.
"""
from unittest.mock import MagicMock, patch
from maunprekshak.scanner.report import (
    ScanResult,
    DepVulnerability,
    SecretFinding,
    SASTFinding,
    RiskScore,
)
from maunprekshak.scanner.notify import (
    format_slack_payload,
    format_discord_payload,
    format_generic_payload,
    send_webhook_notification,
)


def _sample_scan_result():
    deps = [
        DepVulnerability(
            package="requests",
            version="2.25.1",
            cve_id="CVE-2023-32681",
            severity="MEDIUM",
            cvss_score=6.1,
            description="SSRF in requests",
            fix_version="2.31.0",
        )
    ]
    secrets = [
        SecretFinding(
            file_path="config.py",
            line=12,
            secret_type="AWS Access Key ID",
            masked_value="AKIA***1234",
            severity="HIGH",
        )
    ]
    sast = [
        SASTFinding(
            file_path="app.py",
            line=45,
            col=4,
            check_id="MP041",
            severity="HIGH",
            description="CORS wildcard with credentials",
            recommendation="Fix CORS",
            code_snippet="app.add_middleware(...)",
        )
    ]
    return ScanResult(
        deps=deps,
        secrets=secrets,
        sast=sast,
        risk_score=RiskScore(score=75, level="HIGH"),
    )


def test_format_slack_payload():
    result = _sample_scan_result()
    payload = format_slack_payload(result, status="failed", project_name="my-app")

    assert "text" in payload
    assert "blocks" in payload
    assert len(payload["blocks"]) >= 2
    # Verify top findings inclusion
    header_block = payload["blocks"][0]
    assert "FAILED" in header_block["text"]["text"]
    assert "🚨" in header_block["text"]["text"]


def test_format_discord_payload():
    result = _sample_scan_result()
    payload = format_discord_payload(result, status="failed", project_name="my-app")

    assert "embeds" in payload
    assert len(payload["embeds"]) == 1
    embed = payload["embeds"][0]
    assert embed["color"] == 0xE02424  # Red for failed
    assert any(f["name"] == "Status" and "FAILED" in f["value"] for f in embed["fields"])


def test_format_generic_payload():
    result = _sample_scan_result()
    payload = format_generic_payload(result, status="passed", project_name="my-app")

    assert payload["event"] == "maunprekshak_scan"
    assert payload["status"] == "passed"
    assert payload["risk_score"] == 75
    assert payload["risk_level"] == "HIGH"
    assert payload["total_findings"] == 3
    assert len(payload["top_findings"]) == 3


def test_send_webhook_notification_trigger_fail_skips_on_pass():
    result = _sample_scan_result()
    # When trigger="fail" and status="passed", no HTTP request should be sent
    sent = send_webhook_notification(
        "https://example.com/webhook",
        result,
        status="passed",
        trigger="fail",
    )
    assert sent is False


def test_send_webhook_notification_slack_dispatch():
    result = _sample_scan_result()
    mock_resp = MagicMock()
    mock_resp.status_code = 200

    with patch("httpx.Client.post", return_value=mock_resp) as mock_post:
        sent = send_webhook_notification(
            "https://hooks.slack.com/services/T123/B456/XYZ",
            result,
            status="failed",
            trigger="fail",
        )
        assert sent is True
        assert mock_post.called
        call_kwargs = mock_post.call_args[1]
        assert "blocks" in call_kwargs["json"]


def test_send_webhook_notification_discord_dispatch():
    result = _sample_scan_result()
    mock_resp = MagicMock()
    mock_resp.status_code = 204

    with patch("httpx.Client.post", return_value=mock_resp) as mock_post:
        sent = send_webhook_notification(
            "https://discord.com/api/webhooks/123/abc",
            result,
            status="failed",
            trigger="fail",
        )
        assert sent is True
        assert mock_post.called
        call_kwargs = mock_post.call_args[1]
        assert "embeds" in call_kwargs["json"]
