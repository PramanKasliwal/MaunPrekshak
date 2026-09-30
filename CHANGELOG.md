# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.13.0] - 2026-10-01

### Added
- **Web, API & Microservices SAST Suite (`MP041`–`MP048`)**:
  - Eight dedicated AST security rules targeting OWASP Top 10 API & Web security anti-patterns across FastAPI, Flask, Django, Starlette, and GraphQL:
    - **MP041** (HIGH): CORS misconfiguration pairing wildcard origin `*` with credentials enabled (`allow_credentials=True` or `supports_credentials=True`).
    - **MP042** (MEDIUM): Unvalidated open redirect vulnerabilities (`redirect(request.args.get('url'))`, `HttpResponseRedirect`, `RedirectResponse`).
    - **MP043** (HIGH): Insecure JWT validation allowing the `"none"` algorithm or disabling signature/expiration verification.
    - **MP044** (MEDIUM): CSRF protection explicitly disabled via `@csrf_exempt` or `@csrf.exempt` on state-changing endpoints.
    - **MP045** (HIGH): Path traversal vulnerabilities in file serving/downloads (`send_file(os.path.join(..., request.args.get(...)))`, `FileResponse`).
    - **MP046** (HIGH): Mass assignment / unrestricted dictionary unpacking of untrusted request payloads (`User(**request.json)`).
    - **MP047** (LOW): GraphQL schema introspection explicitly enabled in production settings.
    - **MP048** (MEDIUM): Untrusted HTTP Host header injection during URL and password reset link construction.
- **Multi-Ecosystem Software Composition Analysis (SCA) for Java & PHP**:
  - Native manifest parsing for Java: Maven (`pom.xml`), Gradle (`build.gradle`, `build.gradle.kts`), and Gradle lockfiles (`gradle.lockfile`).
  - Native manifest parsing for PHP: Composer lockfiles (`composer.lock`) and definitions (`composer.json`).
  - Concurrent asynchronous vulnerability querying against OSV.dev for `"Maven"` and `"Packagist"` ecosystems with CVSS scoring and minimum safe version resolution.
- **Enterprise Cloud & DevOps Secrets Detection (`MP-SEC-021`–`MP-SEC-026`)**:
  - High-confidence pattern matching for enterprise credentials:
    - GCP Service Account JSON private key definitions (`"type": "service_account"`).
    - Azure Storage Account connection strings (`DefaultEndpointsProtocol=https;...`).
    - Azure Shared Access Signature (SAS) tokens with embedded signatures.
    - GitHub Copilot and App User/Server tokens (`ghu_`, `ghs_`).
    - Kubernetes Service Account bearer tokens (`bearer eyJh...`).
    - Databricks Personal Access Tokens (`dapi...`).
- **CI/CD Webhook & Alerting Engine (`--notify-webhook`)**:
  - Added `--notify-webhook <url>` and `--notify-on <fail|always>` CLI flags and configuration options.
  - Automatically formats and dispatches rich Slack Block Kit alerts, Discord embed messages, or structured generic JSON payloads upon scan completion or CI failure.

## [0.12.0] - 2026-09-30

### Added & Enhanced
- **Expanded Mechanical Auto-Fixing Engine (`--fix` Phase 2)**:
  - Extends `--fix` from basic legacy rules to cover 11 automated security anti-patterns across Python SAST, Terraform IaC, and Dockerfile container configurations:
    - **MP031** (AI/ML): Automatically rewrites `torch.load(path)` and `torch.load(path, weights_only=False)` to `torch.load(path, weights_only=True)` preventing pickle-based remote code execution.
    - **MP036** (YAML): Automatically converts `yaml.unsafe_load()` to `yaml.safe_load()` and rewrites unsafe loaders (`Loader=yaml.Loader` / `UnsafeLoader`) to `Loader=yaml.SafeLoader`.
    - **MP033** (File Permissions): Tightens overly permissive `os.chmod()` modes: `0o777` → `0o700` and `0o666` → `0o600`.
    - **MP015** (Disabled SSL): Flips `verify=False` to `verify=True` in HTTP requests.
    - **TF004** (IaC): Enables encryption for databases/storage volumes (`storage_encrypted = false` / `encrypted = false` → `true`).
    - **TF005** (IaC): Disables public database accessibility in Terraform (`publicly_accessible = true` → `false`).
    - **TF006** (IaC): Automatically enables S3 Public Access Block protection (`block_public_* = false` → `true`).
    - **DF002** (Container): Injects unprivileged `USER 10001:10001` before `CMD` or `ENTRYPOINT` in Dockerfiles lacking a non-root user.
  - Fully idempotent and deterministic: safely runs in CI/CD pre-commit hooks and local developer workflows.

## [0.11.0] - 2026-09-29

### Added
- **Terraform & OpenTofu Infrastructure-as-Code (IaC) Scanner** (`--only tf`, `--only terraform`, or `--only iac`):
  - Zero-dependency static analysis engine for `.tf` and `.tfvars` files across AWS, GCP, and Azure cloud resources.
  - Eight dedicated IaC security rules (`TF001–TF008`):
    - **TF001** (HIGH): Security group ingress allowing open `0.0.0.0/0` on sensitive management and database ports (SSH 22, RDP 3389, Postgres 5432, MySQL 3306, MongoDB 27017, Redis 6379, etc.).
    - **TF002** (CRITICAL): Overly permissive IAM policy document granting full wildcard permissions (`Action: *`, `Resource: *`).
    - **TF003** (HIGH): S3 bucket or storage configured with public-read or public-read-write ACLs.
    - **TF004** (HIGH): Unencrypted database or storage volume (`storage_encrypted = false` / `encrypted = false`).
    - **TF005** (CRITICAL): Publicly accessible database instance (`publicly_accessible = true`).
    - **TF006** (MEDIUM): S3 Public Access Block protection explicitly disabled.
    - **TF007** (HIGH): Hardcoded plaintext credentials or secret keys in Terraform configurations.
    - **TF008** (HIGH): Cloud storage container or bucket configured with anonymous public access (`allUsers`, `container`, `blob`).
  - Supports inline comment suppression via `# maunprekshak: ignore[TFxxx]` and `# nosec`.
- **Five New SAST Security Rules (MP036–MP040)**:
  - **MP036** (HIGH): Unsafe YAML deserialization via `yaml.unsafe_load()` or explicit `Loader=yaml.Loader` / `UnsafeLoader` / `CLoader`.
  - **MP037** (HIGH): Blind SSRF in `httpx` and `aiohttp` outbound HTTP requests with dynamic unvalidated URLs.
  - **MP038** (CRITICAL): LLM Prompt Injection vector — dynamic f-string or `.format()` interpolation into system prompt / developer instruction context in OpenAI, Anthropic, Gemini, or LangChain call signatures.
  - **MP039** (HIGH): Insecure ML / Object deserialization via `joblib.load()` or `cloudpickle.load()` with untrusted model artifacts.
  - **MP040** (HIGH): Subshell command execution via `os.popen()` or `asyncio.create_subprocess_shell()` resulting in command injection vulnerabilities.
- **Modern Cloud & Developer Secret Detectors**:
  - Added native high-fidelity detection for PyPI API tokens (`pypi-...`), NPM access tokens (`npm_...`), OpenAI project keys (`sk-proj-...`), Anthropic admin keys (`sk-ant-admin...`), Postman API keys (`PMAK-...`), and Supabase service/anon tokens (`sbp_...`).
- **SonarQube & Code Climate CI/CD Report Exports**:
  - `--output sonarqube` (`--output-file sonar-issues.json`): Official SonarQube Generic Issue Import format for ingestion via `sonar.externalIssuesReportPaths`.
  - `--output codeclimate` (`--output-file codeclimate.json`): Official Code Climate issue format compatible with GitLab Code Quality, Code Climate CLI, and GitHub Code Scanning.

## [0.10.2] - 2026-09-26

### Fixed & Enhanced
- **Robust `--exclude` Path & File Filtering**:
  - Automatically normalizes exclusion patterns by stripping trailing slashes (`tests/` or `tests\\`) and relative path prefixes (`./tests/` or `./tests`), preventing shell tab-completion from silently bypassing exclusions.
  - Supports passing `--exclude` multiple times (e.g. `--exclude tests --exclude fixtures`), accumulating exclusions instead of overwriting previous flags.
  - Supports comma-separated exclusion strings (e.g. `--exclude "tests,fixtures,legacy"`).
  - Extended path filtering to match nested relative subpaths (e.g. `src/legacy`) as well as directory basenames across all scanners (SAST, secrets, Kubernetes, Dockerfiles, and CI workflows).
  - Added support for excluding specific files directly via `--exclude` (e.g. `--exclude bad_script.py` or `--exclude secrets.json`).
  - Added unit test suite covering trailing slashes, dot-slashes, multiple flags, and comma-separated exclusion syntax.

## [0.10.1] - 2026-09-24

### Fixed
- **GitHub Actions Annotations & Baseline Suppression**:
  - Fixed an issue where running `maunprekshak scan .` in GitHub Actions with non-console output formats (e.g., `--output json`, `--output sarif`) would output `::error::` annotations to stdout, corrupting structured machine-readable streams and breaking baseline suppression (`--baseline`).
  - GitHub Actions annotations auto-detection is now scoped to console output or when an output file is explicitly provided, preserving raw stdout for JSON/SARIF/GitLab export.
  - Added robust fallback parsing for `--baseline` JSON reports to handle leading or trailing text gracefully.
  - Removed erroneous `.pre-commit-config.yaml` file from `.github/workflows/` that caused spurious CI workflow failures.

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
