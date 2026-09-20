"""
Anthropic Claude AI provider implementation using built-in httpx.
"""
import os
import time
from typing import Optional
import httpx
from maunprekshak.scanner.report import ScanResult
from maunprekshak.scanner.ai.base import BaseAIProvider, format_prompt

DEFAULT_ANTHROPIC_MODEL = "claude-3-5-haiku-20241022"
DEFAULT_ANTHROPIC_BASE_URL = "https://api.anthropic.com/v1"


class AnthropicProvider(BaseAIProvider):
    """Anthropic Claude Messages API provider."""

    def generate_summary(
        self,
        scan_result: ScanResult,
        model: Optional[str] = None,
        base_url: Optional[str] = None,
    ) -> str:
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            return "AI Summary skipped: set ANTHROPIC_API_KEY to enable Anthropic Claude."

        resolved_base = (
            base_url
            or os.environ.get("ANTHROPIC_BASE_URL")
            or DEFAULT_ANTHROPIC_BASE_URL
        ).rstrip("/")

        target_model = model or DEFAULT_ANTHROPIC_MODEL
        prompt = format_prompt(scan_result)

        headers = {
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }

        payload = {
            "model": target_model,
            "max_tokens": 1024,
            "system": "You are a senior application security engineer reviewing project scan results.",
            "messages": [
                {"role": "user", "content": prompt}
            ],
        }

        endpoint = f"{resolved_base}/messages"
        last_error = None

        for attempt, wait in enumerate([0, 3, 7]):
            if wait:
                time.sleep(wait)
            try:
                with httpx.Client(timeout=45.0) as client:
                    resp = client.post(endpoint, json=payload, headers=headers)

                    if resp.status_code == 200:
                        data = resp.json()
                        content_blocks = data.get("content", [])
                        if content_blocks and "text" in content_blocks[0]:
                            return content_blocks[0]["text"].strip()
                        return "Anthropic summary returned an unexpected format."

                    # Check for rate limit or server overloaded (529) errors for retry
                    if resp.status_code in (429, 500, 502, 503, 504, 529):
                        last_error = f"HTTP {resp.status_code}: {resp.text}"
                        continue

                    # Non-retryable error
                    try:
                        err_json = resp.json()
                        err_msg = err_json.get("error", {}).get("message", resp.text)
                    except Exception:
                        err_msg = resp.text
                    return f"Anthropic API error ({resp.status_code}): {err_msg}"

            except Exception as e:
                last_error = str(e)

        return f"Anthropic AI summary unavailable (retried 3×): {last_error}"
