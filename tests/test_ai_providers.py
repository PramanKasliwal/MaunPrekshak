"""
Unit tests for Multi-Provider AI Remediation Engine (Gemini, OpenAI, Anthropic, Ollama).
"""
import os
import pytest
from unittest.mock import patch, MagicMock
from maunprekshak.scanner.report import ScanResult, RiskScore
from maunprekshak.scanner.ai import (
    generate_ai_summary,
    detect_provider,
    BaseAIProvider,
    GeminiProvider,
    OpenAIProvider,
    AnthropicProvider,
    OllamaProvider,
    format_prompt,
)


@pytest.fixture
def empty_scan_result():
    return ScanResult(
        deps=[],
        secrets=[],
        sast=[],
        risk_score=RiskScore(score=0, level="LOW"),
    )


class TestProviderDetection:
    def test_detects_gemini(self, monkeypatch):
        monkeypatch.setenv("GEMINI_API_KEY", "test-gemini-key")
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.delenv("OLLAMA_HOST", raising=False)
        assert detect_provider() == "gemini"

    def test_detects_openai(self, monkeypatch):
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        monkeypatch.setenv("OPENAI_API_KEY", "test-openai-key")
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.delenv("OLLAMA_HOST", raising=False)
        assert detect_provider() == "openai"

    def test_detects_anthropic(self, monkeypatch):
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-anthropic-key")
        monkeypatch.delenv("OLLAMA_HOST", raising=False)
        assert detect_provider() == "anthropic"

    def test_detects_ollama(self, monkeypatch):
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.setenv("OLLAMA_HOST", "http://127.0.0.1:11434")
        assert detect_provider() == "ollama"

    def test_detects_none_when_empty(self, monkeypatch):
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.delenv("OLLAMA_HOST", raising=False)
        monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
        assert detect_provider() is None


class TestGenerateAISummaryDispatcher:
    def test_skipped_when_no_provider_and_no_keys(self, empty_scan_result, monkeypatch):
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.delenv("OLLAMA_HOST", raising=False)
        monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
        summary = generate_ai_summary(empty_scan_result, provider="auto")
        assert "AI Summary skipped" in summary

    def test_unsupported_provider(self, empty_scan_result):
        summary = generate_ai_summary(empty_scan_result, provider="unsupported_engine")
        assert "Unsupported AI provider 'unsupported_engine'" in summary


class TestOpenAIProvider:
    def test_missing_api_key_error(self, empty_scan_result, monkeypatch):
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
        provider = OpenAIProvider()
        result = provider.generate_summary(empty_scan_result)
        assert "set OPENAI_API_KEY" in result

    @patch("httpx.Client.post")
    def test_successful_openai_call(self, mock_post, empty_scan_result, monkeypatch):
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test123456")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "choices": [
                {
                    "message": {
                        "content": "### Executive Summary\nAll clear. No critical vulnerabilities found."
                    }
                }
            ]
        }
        mock_post.return_value = mock_resp

        provider = OpenAIProvider()
        summary = provider.generate_summary(empty_scan_result, model="gpt-4o-mini")

        assert "Executive Summary" in summary
        assert mock_post.called
        args, kwargs = mock_post.call_args
        assert args[0] == "https://api.openai.com/v1/chat/completions"
        assert kwargs["headers"]["Authorization"] == "Bearer sk-test123456"
        assert kwargs["json"]["model"] == "gpt-4o-mini"

    @patch("httpx.Client.post")
    def test_openai_api_error(self, mock_post, empty_scan_result, monkeypatch):
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test123456")
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_resp.text = "Unauthorized"
        mock_resp.json.return_value = {"error": {"message": "Incorrect API key provided"}}
        mock_post.return_value = mock_resp

        provider = OpenAIProvider()
        summary = provider.generate_summary(empty_scan_result)
        assert "OpenAI API error (401)" in summary
        assert "Incorrect API key provided" in summary


class TestAnthropicProvider:
    def test_missing_api_key_error(self, empty_scan_result, monkeypatch):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        provider = AnthropicProvider()
        result = provider.generate_summary(empty_scan_result)
        assert "set ANTHROPIC_API_KEY" in result

    @patch("httpx.Client.post")
    def test_successful_anthropic_call(self, mock_post, empty_scan_result, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test123456")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "content": [
                {
                    "text": "### Claude Security Assessment\nZero active vulnerabilities identified."
                }
            ]
        }
        mock_post.return_value = mock_resp

        provider = AnthropicProvider()
        summary = provider.generate_summary(empty_scan_result)

        assert "Claude Security Assessment" in summary
        assert mock_post.called
        args, kwargs = mock_post.call_args
        assert args[0] == "https://api.anthropic.com/v1/messages"
        assert kwargs["headers"]["x-api-key"] == "sk-ant-test123456"
        assert kwargs["headers"]["anthropic-version"] == "2023-06-01"
        assert kwargs["json"]["model"] == "claude-3-5-haiku-20241022"


class TestOllamaProvider:
    @patch("httpx.Client.post")
    def test_successful_ollama_native_generate(self, mock_post, empty_scan_result):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "response": "### Local LLM Assessment\nNo vulnerabilities detected."
        }
        mock_post.return_value = mock_resp

        provider = OllamaProvider()
        summary = provider.generate_summary(empty_scan_result, model="llama3.2")

        assert "Local LLM Assessment" in summary
        assert mock_post.called
        args, kwargs = mock_post.call_args
        assert args[0] == "http://localhost:11434/api/generate"
        assert kwargs["json"]["model"] == "llama3.2"

    @patch("httpx.Client.post")
    def test_successful_ollama_v1_endpoint(self, mock_post, empty_scan_result):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "choices": [
                {
                    "message": {
                        "content": "### Local v1 Summary\nSystem secure."
                    }
                }
            ]
        }
        mock_post.return_value = mock_resp

        provider = OllamaProvider()
        summary = provider.generate_summary(
            empty_scan_result,
            model="deepseek-r1",
            base_url="http://localhost:11434/v1",
        )

        assert "Local v1 Summary" in summary
        assert mock_post.called
        args, kwargs = mock_post.call_args
        assert args[0] == "http://localhost:11434/v1/chat/completions"


class TestGeminiProvider:
    def test_missing_api_key_error(self, empty_scan_result, monkeypatch):
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        provider = GeminiProvider()
        result = provider.generate_summary(empty_scan_result)
        assert "set GEMINI_API_KEY" in result
