"""
OpenAI & OpenAI-compatible AI provider implementation using built-in httpx.
"""
import os
import time
from typing import Optional
import httpx
from maunprekshak.scanner.report import ScanResult
from maunprekshak.scanner.ai.base import BaseAIProvider, format_prompt

DEFAULT_OPENAI_MODEL = "gpt-4o-mini"
DEFAULT_OPENAI_BASE_URL = "https://api.openai.com/v1"


class OpenAIProvider(BaseAIProvider):
    """OpenAI and OpenAI-compatible Chat Completions provider."""

    def generate_summary(
        self,
        scan_result: ScanResult,
        model: Optional[str] = None,
        base_url: Optional[str] = None,
    ) -> str:
        api_key = os.environ.get("OPENAI_API_KEY")
        resolved_base = (
            base_url
            or os.environ.get("OPENAI_BASE_URL")
            or DEFAULT_OPENAI_BASE_URL
        ).rstrip("/")

        # If pointing to localhost / local model, api_key is optional
        is_local = "localhost" in resolved_base or "127.0.0.1" in resolved_base
        if not api_key and not is_local:
            return "AI Summary skipped: set OPENAI_API_KEY to enable OpenAI."

        target_model = model or DEFAULT_OPENAI_MODEL
        prompt = format_prompt(scan_result)

        headers = {
            "Content-Type": "application/json",
        }
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"

        payload = {
            "model": target_model,
            "messages": [
                {
                    "role": "system",
                    "content": "You are a senior application security engineer reviewing project scan results.",
                },
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.2,
            "max_tokens": 1000,
        }

        endpoint = f"{resolved_base}/chat/completions"
        last_error = None

        for attempt, wait in enumerate([0, 3, 7]):
            if wait:
                time.sleep(wait)
            try:
                with httpx.Client(timeout=45.0) as client:
                    resp = client.post(endpoint, json=payload, headers=headers)

                    if resp.status_code == 200:
                        data = resp.json()
                        choices = data.get("choices", [])
                        if choices and "message" in choices[0]:
                            return choices[0]["message"].get("content", "").strip()
                        return "OpenAI summary returned an unexpected format."

                    # Check for rate limit or server errors for retry
                    if resp.status_code in (429, 500, 502, 503, 504):
                        last_error = f"HTTP {resp.status_code}: {resp.text}"
                        continue

                    # Non-retryable error
                    try:
                        err_json = resp.json()
                        err_msg = err_json.get("error", {}).get("message", resp.text)
                    except Exception:
                        err_msg = resp.text
                    return f"OpenAI API error ({resp.status_code}): {err_msg}"

            except Exception as e:
                last_error = str(e)

        return f"OpenAI AI summary unavailable (retried 3×): {last_error}"
