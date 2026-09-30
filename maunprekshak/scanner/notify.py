"""
MaunPrekshak — CI/CD Webhook & Alerting Engine
Dispatches security scan summaries to Slack, Discord, or generic incoming webhooks.
"""
import os
from typing import Dict, Any, Optional
import httpx
from maunprekshak.scanner.report import ScanResult


def format_slack_payload(result: ScanResult, status: str, project_name: str) -> Dict[str, Any]:
    """Format rich Slack Block Kit payload."""
    status_emoji = "🚨" if status.lower() == "failed" else "✅"
    title_text = f"{status_emoji} MaunPrekshak Scan {status.upper()}: {project_name}"

    summary_fields = [
        {"type": "mrkdwn", "text": f"*Status:*\n`{status.upper()}`"},
        {"type": "mrkdwn", "text": f"*Risk Level:*\n`{result.risk_score.level}` ({result.risk_score.score})"},
        {"type": "mrkdwn", "text": f"*Total Findings:*\n`{result.total_findings}`"},
        {"type": "mrkdwn", "text": f"*Breakdown:*\nSCA: {len(result.deps)} | Secrets: {len(result.secrets)} | SAST: {len(result.sast)}"},
    ]

    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": title_text, "emoji": True},
        },
        {
            "type": "section",
            "fields": summary_fields,
        },
    ]

    # Include up to 5 top findings
    top_findings = (result.deps + result.secrets + result.sast)[:5]
    if top_findings:
        findings_lines = []
        for f in top_findings:
            check_id = getattr(f, "check_id", getattr(f, "secret_type", getattr(f, "cve_id", "Finding")))
            file_loc = getattr(f, "file_path", getattr(f, "package", ""))
            line = getattr(f, "line", "")
            loc_str = f"{os.path.basename(file_loc)}:{line}" if line else os.path.basename(file_loc)
            findings_lines.append(f"• *[{f.severity}]* `{check_id}` in `{loc_str}`")

        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "*Top Findings:*\n" + "\n".join(findings_lines),
            },
        })

    return {
        "text": title_text,
        "blocks": blocks,
    }


def format_discord_payload(result: ScanResult, status: str, project_name: str) -> Dict[str, Any]:
    """Format Discord webhook embed payload."""
    is_failed = status.lower() == "failed"
    color = 0xE02424 if is_failed else 0x0E9F6E  # Red or Green

    fields = [
        {"name": "Status", "value": f"`{status.upper()}`", "inline": True},
        {"name": "Risk Level", "value": f"`{result.risk_score.level}` ({result.risk_score.score})", "inline": True},
        {"name": "Total Issues", "value": f"`{result.total_findings}`", "inline": True},
        {
            "name": "Categories",
            "value": f"Dependencies: {len(result.deps)} | Secrets: {len(result.secrets)} | SAST: {len(result.sast)}",
            "inline": False,
        },
    ]

    top_findings = (result.deps + result.secrets + result.sast)[:5]
    if top_findings:
        desc_lines = []
        for f in top_findings:
            check_id = getattr(f, "check_id", getattr(f, "secret_type", getattr(f, "cve_id", "Finding")))
            file_loc = getattr(f, "file_path", getattr(f, "package", ""))
            line = getattr(f, "line", "")
            loc_str = f"{os.path.basename(file_loc)}:{line}" if line else os.path.basename(file_loc)
            desc_lines.append(f"• **[{f.severity}]** `{check_id}` ({loc_str})")
        fields.append({
            "name": "Top Findings",
            "value": "\n".join(desc_lines),
            "inline": False,
        })

    embed = {
        "title": f"🛡️ MaunPrekshak Security Report — {project_name}",
        "color": color,
        "fields": fields,
    }

    return {
        "username": "MaunPrekshak",
        "embeds": [embed],
    }


def format_generic_payload(result: ScanResult, status: str, project_name: str) -> Dict[str, Any]:
    """Format structured JSON payload for generic webhooks / SIEM."""
    top_findings = []
    for f in (result.deps + result.secrets + result.sast)[:10]:
        top_findings.append({
            "rule": getattr(f, "check_id", getattr(f, "secret_type", getattr(f, "cve_id", "Finding"))),
            "severity": f.severity,
            "target": getattr(f, "file_path", getattr(f, "package", "")),
            "line": getattr(f, "line", None),
        })

    return {
        "event": "maunprekshak_scan",
        "status": status.lower(),
        "project": project_name,
        "risk_score": result.risk_score.score,
        "risk_level": result.risk_score.level,
        "total_findings": result.total_findings,
        "summary": {
            "deps": len(result.deps),
            "secrets": len(result.secrets),
            "sast": len(result.sast),
        },
        "top_findings": top_findings,
    }


def send_webhook_notification(
    webhook_url: str,
    result: ScanResult,
    status: str = "passed",
    trigger: str = "fail",
    project_root: str = ".",
) -> bool:
    """
    Send an HTTP POST webhook notification summarizing the scan result.

    Args:
        webhook_url: Target incoming webhook URL.
        result: The ScanResult object.
        status: "passed" or "failed".
        trigger: "fail" (only notify on failure) or "always" (notify on every run).
        project_root: Path to the scanned project.

    Returns:
        True if notification was sent successfully, False otherwise.
    """
    if not webhook_url:
        return False

    trigger_clean = trigger.strip().lower()
    if trigger_clean in ("fail", "failure", "failed") and status.lower() != "failed":
        return False

    project_name = os.path.basename(os.path.abspath(project_root)) or "project"

    url_lower = webhook_url.lower()
    if "hooks.slack.com" in url_lower:
        payload = format_slack_payload(result, status, project_name)
    elif "discord.com/api/webhooks" in url_lower or "discordapp.com" in url_lower:
        payload = format_discord_payload(result, status, project_name)
    else:
        payload = format_generic_payload(result, status, project_name)

    try:
        with httpx.Client(timeout=5.0) as client:
            resp = client.post(webhook_url, json=payload)
            return resp.status_code < 300
    except Exception:
        return False
