# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.8.0] - 2026-09-20

### Added
- **Multi-Provider AI Remediation Engine**:
  - Unified AI architecture supporting **Google Gemini**, **OpenAI**, **Anthropic Claude**, and **Ollama (local/offline LLMs)** with zero new dependencies (powered by built-in `httpx`).
  - Automatic provider resolution based on environment variables (`GEMINI_API_KEY` -> `OPENAI_API_KEY` -> `ANTHROPIC_API_KEY` -> `OLLAMA_HOST`).
  - CLI flags: `--ai-provider`, `--ai-model`, and `--ai-base-url` for fine-grained engine control.
  - Configuration support via `[ai]` table in `.maunprekshak.toml` (`provider`, `model`, `base_url`).
  - Support for custom OpenAI-compatible endpoints (vLLM, Groq, LM Studio, enterprise proxies).

## [0.7.0] - 2026-09-20

### Added
- **Apache License 2.0 Relicensing**: Upgraded license terms to Apache-2.0 with patent grant protection and trademark safeguards.
- **Inline Code Suppression**:
  - Support for `# maunprekshak: ignore`, `# maunprekshak: ignore[MPxxx]`, and Bandit/flake8-compatible `# nosec`, `# nosec: MPxxx` across all SAST rules.
  - File-level suppression `# maunprekshak: disable-file` and `# maunprekshak: disable-file[MPxxx]`.
  - Inline secret suppression with `# maunprekshak: ignore`, `# nosec`, and `# maunprekshak: ignore-secret`.
- **Software Bill of Materials (SBOM)**:
  - OASIS CycloneDX 1.5 JSON SBOM generation via `--output cyclonedx`.
  - Linux Foundation SPDX 2.3 JSON SBOM generation via `--output spdx`.
  - Package URLs (purls) and OSV vulnerability links for PyPI, npm, Cargo, and Go modules.
- **Dockerfile Container Security Scanner**:
  - `DF001`: Root container user / missing `USER` instruction.
  - `DF002`: Unpinned or `:latest` base image tag.
  - `DF003`: Uncached package manager lists (`apt-get install` without cache purge).
  - `DF004`: Sensitive ports exposed (`EXPOSE 22`, `23`, `3389`).
  - `DF005`: Insecure shell execution (`curl` / `wget` piped to `sh` / `bash`).
  - `DF006`: Insecure archive extraction (`ADD` instead of `COPY`).
- **Deterministic Auto-Fixing (`--fix`)**:
  - Mechanical remediation of safe anti-patterns: `MP012` (`yaml.load` -> `yaml.safe_load`), `MP023` (`tar.extractall()` -> `filter='data'`), and `MP014` (`tempfile.mktemp()` -> `tempfile.NamedTemporaryFile().name`).
- **Native Git Pre-Commit Hook**:
  - 1-command installer via `mp hook install` and `mp hook uninstall` directly managing `.git/hooks/pre-commit` with automatic backup preservation.

## [0.6.1] - 2026-09-19

### Added
- Native Windows support with `python -m maunprekshak` entry point.
- 1-line PowerShell installer (`install.ps1`).
- Enhanced path normalization across Windows backslashes and POSIX forward slashes.

## [0.6.0] - 2026-09-19

### Added
- Rust Cargo SCA support (`Cargo.lock`, `Cargo.toml`, crates.io).
- SAST security checks: `MP027` (weak crypto IV/salt), `MP028` (missing cookie security flags), `MP029` (insecure pandas deserialization), `MP030` (Jinja2 SSTI).
- High-entropy secret patterns: GitLab PAT, GitHub Fine-Grained PAT, Discord Bot Token, HashiCorp Vault.
- `--baseline` JSON report suppression for managing legacy technical debt.
