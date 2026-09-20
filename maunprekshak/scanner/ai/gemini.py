"""
Google Gemini AI provider implementation using google-genai SDK.
"""
import os
import time
from typing import Optional
from maunprekshak.scanner.report import ScanResult
from maunprekshak.scanner.ai.base import BaseAIProvider, format_prompt

DEFAULT_GEMINI_MODEL = "gemini-2.5-flash"


class GeminiProvider(BaseAIProvider):
    """Google Gemini AI summary provider."""

    def generate_summary(
        self,
        scan_result: ScanResult,
        model: Optional[str] = None,
        base_url: Optional[str] = None,
    ) -> str:
        api_key = os.environ.get("GEMINI_API_KEY")
        if not api_key:
            return "AI Summary skipped: set GEMINI_API_KEY to enable Google Gemini."

        target_model = model or DEFAULT_GEMINI_MODEL

        try:
            from google import genai

            client = genai.Client(api_key=api_key)
            prompt = format_prompt(scan_result)

            last_error = None
            for attempt, wait in enumerate([0, 5, 10]):
                try:
                    if wait:
                        time.sleep(wait)
                    response = client.models.generate_content(
                        model=target_model,
                        contents=prompt,
                    )
                    return response.text
                except Exception as e:
                    last_error = e
                    err_str = str(e)
                    if "503" not in err_str and "UNAVAILABLE" not in err_str and "429" not in err_str:
                        break

            return f"Gemini AI summary unavailable (retried 3×): {last_error}"

        except ImportError:
            return "Google Gemini SDK not installed: install google-genai package."
        except Exception as e:
            return f"Gemini AI summary error: {str(e)}"
