"""
MaunPrekshak Configuration Management
Loads project-level configuration from .maunprekshak.toml or pyproject.toml
"""
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

try:
    import tomllib
except ImportError:
    try:
        import toml as tomllib  # Fallback
    except ImportError:
        tomllib = None  # type: ignore


@dataclass
class ScannerConfig:
    exclude: List[str] = field(
        default_factory=lambda: [
            "tests",
            "test",
            "testing",
            "fixtures",
            ".venv",
            "venv",
            "node_modules",
            ".git",
        ]
    )
    fail_on: str = "critical"
    no_ai: bool = False
    ignore_rules: List[str] = field(default_factory=list)
    ai_provider: str = "auto"
    ai_model: Optional[str] = None
    ai_base_url: Optional[str] = None


DEFAULT_CONFIG_TEMPLATE = """# MaunPrekshak Configuration File (.maunprekshak.toml)
# The Silent Observer — Python Security Scanner

[scanner]
# Directories to exclude from scans
exclude = [
    "tests",
    "test",
    "fixtures",
    ".venv",
    "venv",
    "node_modules",
    ".git",
]

# CI fail severity threshold: "critical", "high", "medium", or "low"
fail_on = "high"

# Disable AI remediation summaries (runs fully offline)
no_ai = false

# List of SAST check IDs to ignore (e.g. ["MP010"])
ignore_rules = []

[ai]
# AI provider: "auto", "gemini", "openai", "anthropic", "ollama"
provider = "auto"

# Model name override (optional)
# e.g. "gpt-4o-mini", "claude-3-5-haiku-20241022", "gemini-2.5-flash", "llama3.2"
# model = ""

# Custom API base URL (optional, e.g. "http://localhost:11434/v1" or private enterprise gateway)
# base_url = ""
"""


def load_config(root_path: Optional[str] = None) -> ScannerConfig:
    """
    Search for configuration in:
    1. .maunprekshak.toml in root_path (or current directory)
    2. pyproject.toml [tool.maunprekshak] in root_path (or current directory)
    3. Default settings
    """
    if tomllib is None:
        return ScannerConfig()

    search_dir = Path(root_path).resolve() if root_path else Path.cwd().resolve()
    if search_dir.is_file():
        search_dir = search_dir.parent

    # 1. Check for .maunprekshak.toml
    candidates = [
        search_dir / ".maunprekshak.toml",
        search_dir.parent / ".maunprekshak.toml",
    ]

    for config_file in candidates:
        if config_file.is_file():
            try:
                with open(config_file, "rb") as f:
                    data = tomllib.load(f)
                scanner_data = data.get("scanner", {})
                ai_data = data.get("ai", {})
                default_ex = ScannerConfig().exclude
                return ScannerConfig(
                    exclude=scanner_data.get("exclude", default_ex),
                    fail_on=scanner_data.get("fail_on", "critical"),
                    no_ai=scanner_data.get("no_ai", False),
                    ignore_rules=scanner_data.get("ignore_rules", []),
                    ai_provider=ai_data.get("provider", "auto"),
                    ai_model=ai_data.get("model", None),
                    ai_base_url=ai_data.get("base_url", None),
                )
            except Exception:
                pass

    # 2. Check pyproject.toml [tool.maunprekshak]
    pyproject_file = search_dir / "pyproject.toml"
    if not pyproject_file.is_file() and (search_dir.parent / "pyproject.toml").is_file():
        pyproject_file = search_dir.parent / "pyproject.toml"

    if pyproject_file.is_file():
        try:
            with open(pyproject_file, "rb") as f:
                data = tomllib.load(f)
            tool_data = data.get("tool", {}).get("maunprekshak", {})
            if tool_data:
                ai_data = tool_data.get("ai", {})
                default_ex = ScannerConfig().exclude
                return ScannerConfig(
                    exclude=tool_data.get("exclude", default_ex),
                    fail_on=tool_data.get("fail_on", "critical"),
                    no_ai=tool_data.get("no_ai", False),
                    ignore_rules=tool_data.get("ignore_rules", []),
                    ai_provider=ai_data.get("provider", "auto"),
                    ai_model=ai_data.get("model", None),
                    ai_base_url=ai_data.get("base_url", None),
                )
        except Exception:
            pass

    return ScannerConfig()
