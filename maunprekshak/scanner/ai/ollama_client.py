"""
Local offline LLM provider implementation for Ollama using built-in httpx.
"""
import os
from typing import Optional
import httpx
from maunprekshak.scanner.report import ScanResult
from maunprekshak.scanner.ai.base import BaseAIProvider, format_prompt

DEFAULT_OLLAMA_MODEL = "llama3.2"
DEFAULT_OLLAMA_HOST = "http://localhost:11434"


class OllamaProvider(BaseAIProvider):
    """Local Ollama AI summary provider (runs 100% offline)."""

    def generate_summary(
        self,
        scan_result: ScanResult,
        model: Optional[str] = None,
        base_url: Optional[str] = None,
    ) -> str:
        resolved_host = (
            base_url
            or os.environ.get("OLLAMA_HOST")
            or DEFAULT_OLLAMA_HOST
        ).rstrip("/")

        target_model = model or DEFAULT_OLLAMA_MODEL
        prompt = format_prompt(scan_result)

        # If base_url explicitly has /v1, use OpenAI-compatible endpoint
        if resolved_host.endswith("/v1"):
            endpoint = f"{resolved_host}/chat/completions"
            payload = {
                "model": target_model,
                "messages": [
                    {"role": "system", "content": "You are a senior application security engineer."},
                    {"role": "user", "content": prompt},
                ],
                "stream": False,
            }
            use_v1 = True
        else:
            endpoint = f"{resolved_host}/api/generate"
            payload = {
                "model": target_model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": 0.2,
                },
            }
            use_v1 = False

        try:
            with httpx.Client(timeout=60.0) as client:
                resp = client.post(endpoint, json=payload)

                if resp.status_code == 200:
                    data = resp.json()
                    if use_v1:
                        choices = data.get("choices", [])
                        if choices and "message" in choices[0]:
                            return choices[0]["message"].get("content", "").strip()
                    else:
                        return data.get("response", "").strip()

                return f"Ollama error ({resp.status_code}): {resp.text}"

        except httpx.ConnectError:
            return f"Ollama connection failed at {resolved_host}. Is Ollama running? Run `ollama serve`."
        except Exception as e:
            return f"Ollama AI summary error: {str(e)}"
