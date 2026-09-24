# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.10.0] - 2026-09-24

### Added
- **Kubernetes & Helm Manifest Security Scanner** (`--only k8s`):
  - Eight new K8S001–K8S008 rules detecting privileged containers, missing resource limits/requests, root user execution, sensitive hostPath volume mounts, dangerous Linux capabilities, privilege escalation, writable root filesystems, and unrestricted service account token auto-mounting.
  - Heuristic K8s manifest detection (apiVersion + kind header) to avoid false positives on non-K8s YAML files.
  - Full inline suppression support via `# maunprekshak: ignore[K8S001]` and `# nosec` comments.
  - Integrated into the `scan_project()` orchestration pipeline alongside Dockerfile and GitHub Actions workflow scanning.

- **Five New SAST Rules (MP031–MP035)**:
  - **MP031** (CRITICAL): `torch.load()` without `weights_only=True` — arbitrary pickle deserialization / RCE risk in AI/ML pipelines.
  - **MP032** (HIGH): Regular Expression Denial of Service (ReDoS) — detects catastrophic nested quantifier patterns (`(a+)+`, `([a-z]+)*`, etc.) in `re.compile()`, `re.search()`, and related calls.
  - **MP033** (MEDIUM): World-writable `os.chmod()` with `0o777` — fully permissive file permission risk.
  - **MP034** (HIGH): LDAP injection — dynamic search filter construction via f-strings or `.format()` in `ldap`/`ldap3` search calls.
  - **MP035** (HIGH): XPath injection — dynamic XPath expression construction via f-strings or `+` concatenation in `etree.xpath()` / `etree.find()`.

- **GitHub Actions PR Annotations** (`--annotations`):
  - Emits `::error::` and `::warning::` workflow commands for inline Pull Request file annotations.
  - Auto-detected when `GITHUB_ACTIONS=true` environment variable is set; no explicit flag needed in CI.
  - CRITICAL/HIGH findings → `::error`, MEDIUM/LOW → `::warning`.

- **GitLab CI SAST Report Export** (`--output gitlab`):
  - Generates `gl-sast-report.json` in the official GitLab Security Dashboard v15 schema.
  - Includes SAST, secrets, and dependency findings with proper identifiers, severity mappings, and scanner metadata.
  - Compatible with GitLab Security & Compliance dashboards out-of-the-box.

- **Dependency Auto-Fix** (`--fix` extended):
  - `fix_requirements_txt()` in `scanner/fixer.py` automatically bumps vulnerable pinned (`==`) and capped (`<=`) dependency versions in `requirements.txt` to `>={fix_version}`.
  - Searches `requirements.txt`, `requirements/base.txt`, and `requirements/prod.txt`.
  - Preserves all comments, blank lines, and non-vulnerable dependencies untouched.

### Changed
- `--only` flag now accepts `k8s` / `kubernetes` to run only the Kubernetes manifest scanner.
- `--output` flag now accepts `gitlab` to produce GitLab CI SAST JSON reports.
- `--fix` flag now additionally patches `requirements.txt` dependency versions in addition to SAST auto-fixes (MP012, MP023, MP014).
- Version bumped from `0.9.0` → `0.10.0`.

### Fixed
- Self-scan: Added `nosec: MP032` suppression on the `_REDOS_PATTERNS` internal regex definition to prevent false-positive self-flagging.

## [0.9.0] - 2026-09-23

### Added
- **Custom Rule Engine**:
  - Define domain-specific secret regexes and SAST rules via `.maunprekshak-rules.yaml`, `.maunprekshak.toml`, or CLI flag `--rules-file`.
  - Supports custom secret patterns with configurable severity and masking.
  - Supports custom AST checks for banned function calls, banned module imports, and regex anti-patterns.
- **Git Commit History Secrets Scanner**:
  - Deep-scan past git commits for leaked tokens and credentials that were committed and subsequently removed (`--history`, `--commits <N>`).
  - Differentiates commit additions with commit SHA and file attribution.
- **Interactive Standalone HTML Security Audit Report**:
  - Single-file, 100% offline self-contained HTML audit dashboard via `--output html` / `--output-file <file.html>`.
  - Real-time client-side search, severity badges, risk breakdown metrics, dark-mode styling, and zero external CDN/script dependencies.
- **GitHub Actions CI/CD Security Scanner**:
  - `GHA001`: Script injection via untrusted GitHub event contexts in `run:` step (`${{ github.event.* }}`).
  - `GHA002`: Unpinned third-party actions using mutable branch tags (`@main`, `@master`).
  - `GHA003`: Dangerous `pull_request_target` trigger with checkout of untrusted PR head.
  - `GHA004`: Overly permissive workflow permissions (`permissions: write-all`).
  - `GHA005`: Plaintext secrets printed to workflow logs (`echo ... ${{ secrets.* }}`).
- **Community Code of Conduct**:
  - Contributor Covenant v2.1 added to repository (`CODE_OF_CONDUCT.md`).

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
