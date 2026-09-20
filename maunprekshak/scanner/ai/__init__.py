"""
Multi-Provider AI Remediation Engine for MaunPrekshak.
Supports Google Gemini, OpenAI, Anthropic Claude, and local Ollama / vLLM.
"""
import os
from typing import Optional, Dict, Type
from maunprekshak.scanner.report import ScanResult
from maunprekshak.scanner.ai.base import BaseAIProvider, format_prompt
from maunprekshak.scanner.ai.gemini import GeminiProvider
from maunprekshak.scanner.ai.openai_client import OpenAIProvider
from maunprekshak.scanner.ai.anthropic_client import AnthropicProvider
from maunprekshak.scanner.ai.ollama_client import OllamaProvider

PROVIDERS: Dict[str, Type[BaseAIProvider]] = {
    "gemini": GeminiProvider,
    "openai": OpenAIProvider,
    "anthropic": AnthropicProvider,
    "ollama": OllamaProvider,
}

PROVIDER_ALIASES = {
    "claude": "anthropic",
    "google": "gemini",
    "local": "ollama",
    "vllm": "openai",
    "groq": "openai",
}


def detect_provider() -> Optional[str]:
    """Auto-detect available AI provider based on environment variables."""
    if os.environ.get("GEMINI_API_KEY"):
        return "gemini"
    if os.environ.get("OPENAI_API_KEY"):
        return "openai"
    if os.environ.get("ANTHROPIC_API_KEY"):
        return "anthropic"
    if os.environ.get("OLLAMA_HOST") or os.environ.get("OPENAI_BASE_URL"):
        return "ollama" if os.environ.get("OLLAMA_HOST") else "openai"
    return None


def generate_ai_summary(
    scan_result: ScanResult,
    provider: str = "auto",
    model: Optional[str] = None,
    base_url: Optional[str] = None,
) -> str:
    """
    Generate an AI executive summary and remediation plan.
    Supports auto-detection and explicit provider selection:
    - "gemini": Google Gemini (via google-genai)
    - "openai": OpenAI Chat Completions (via httpx)
    - "anthropic": Anthropic Claude (via httpx)
    - "ollama": Local offline LLM (via httpx)
    """
    prov_name = (provider or "auto").lower().strip()

    if prov_name == "auto":
        detected = detect_provider()
        if not detected:
            return (
                "AI Summary skipped: set GEMINI_API_KEY, OPENAI_API_KEY, "
                "or ANTHROPIC_API_KEY to enable AI remediation advice."
            )
        prov_name = detected

    resolved_provider = PROVIDER_ALIASES.get(prov_name, prov_name)

    if resolved_provider not in PROVIDERS:
        valid = ", ".join(["auto", "gemini", "openai", "anthropic", "ollama"])
        return f"Unsupported AI provider '{provider}'. Supported providers: {valid}"

    provider_class = PROVIDERS[resolved_provider]
    provider_instance = provider_class()
    return provider_instance.generate_summary(scan_result, model=model, base_url=base_url)


__all__ = [
    "generate_ai_summary",
    "detect_provider",
    "BaseAIProvider",
    "GeminiProvider",
    "OpenAIProvider",
    "AnthropicProvider",
    "OllamaProvider",
    "format_prompt",
]
