# MaunPrekshak — मौन प्रेक्षक

> *"The Silent Observer. Nothing hides from it."*

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![PyPI version](https://img.shields.io/pypi/v/maunprekshak.svg?color=green&logo=pypi&logoColor=white)](https://pypi.org/project/maunprekshak/)
[![PyPI Downloads](https://img.shields.io/pypi/dm/maunprekshak?color=blue&logo=pypi&logoColor=white)](https://pypistats.org/packages/maunprekshak)
[![CI Tests](https://github.com/PramanKasliwal/maunprekshak/actions/workflows/ci.yml/badge.svg)](https://github.com/PramanKasliwal/maunprekshak/actions)

**MaunPrekshak** (मौन = *Silent*, प्रेक्षक = *Observer*) is a fast, privacy-first Python security toolkit designed to catch vulnerabilities, exposed credentials, and insecure code patterns right in your terminal.

---

## ⚡ Highlights

- 🔍 **Dependency Vulnerabilities (SCA)**: Real-time CVE discovery against [OSV.dev](https://osv.dev) across Python (`poetry.lock`, `Pipfile.lock`, `uv.lock`, `requirements.txt`, `pyproject.toml`, `Pipfile`), JavaScript/Node.js (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `package.json`), Go modules (`go.sum`, `go.mod`), and Rust crates (`Cargo.lock`, `Cargo.toml`) for deep transitive dependency tracking. CI fails as soon as any finding meets the selected severity threshold.
- 🔑 **Entropy & Regex Secrets Detection**: 40+ high-precision regex detectors (including OpenAI `sk-proj-`, Anthropic `sk-ant-`, HuggingFace `hf_`, GitLab `glpat-`, GitHub Fine-Grained PAT `github_pat_`, Discord, HashiCorp Vault, AWS, Stripe) PLUS Shannon entropy token analysis ($H \ge 4.5$ Base64 / $H \ge 3.0$ Hex) for un-prefixed tokens and private keys, with zero false-positives for UUIDs, URLs, and dummy values.
- 🛡️ **Static Code Analysis (SAST)**: 30 AST security rules (MP001–MP030) covering code execution, SQL injection, disabled SSL/TLS verification, wildcard network binding (`0.0.0.0`), insecure `/tmp` file creation, unsafe deserialization, paramiko AutoAddPolicy SSH MitM, unverified JWT decoding, world-writable chmod permissions, legacy XML XXE parsers, tarfile Zip Slip (CVE-2007-4559), urllib SSRF, ECB cipher modes, dill bytecode execution, Jinja2/Mako SSTI, pandas.read_pickle code execution, missing secure cookie flags, and hardcoded cryptographic IV/salt.
- ⚡ **Git Staged, Diff & Baseline Scanning**: Fast pre-commit mode via `--staged`, diff checks via `--diff`, and legacy debt suppression via `--baseline`.
- 🎨 **Rich Terminal & SARIF Export**: Formatted console output with risk gauges, and standard OASIS SARIF 2.1.0, JSON, or Markdown export.
- 🔒 **100% Privacy & Local-First**: Scans run entirely on your local CPU. Your source code never leaves your machine.
- 🤖 **Optional AI Remediation**: Plug in your Google Gemini API key for instant root-cause analysis and remediation steps.

---

## 🚀 Quick Start

### Installation

```bash
pip install maunprekshak
```

### 🐧 Linux (1-Line Standalone Install — No Python Required)

```bash
curl -sSL https://raw.githubusercontent.com/PramanKasliwal/maunprekshak/main/install.sh | bash
```

### 🪟 Windows (1-Line PowerShell Install — Configures PATH Automatically)

```powershell
irm https://raw.githubusercontent.com/PramanKasliwal/maunprekshak/main/install.ps1 | iex
```

### 🐍 Via PyPI (Any OS)
```bash
pip install maunprekshak
# or using pipx (recommended for Windows & Ubuntu 24.04+)
pipx install maunprekshak
pipx ensurepath
```

> **Windows Tip**: If `mp` is not recognized after a standard `pip install`, run directly via the Python module:
> ```cmd
> python -m maunprekshak scan .
> # or using py launcher
> py -m maunprekshak scan .
> ```
> Or permanently add Python's `Scripts\` folder to your user PATH via PowerShell:
> ```powershell
> $scriptsDir = python -c "import sysconfig; print(sysconfig.get_path('scripts'))"
> [Environment]::SetEnvironmentVariable("PATH", "$([Environment]::GetEnvironmentVariable('PATH', 'User'));$scriptsDir", "User")
> ```

Basic Scan

Scan the current directory:

```bash
mp scan .
```

### Fast Scan without AI (No API Key Required)

```bash
mp scan . --no-ai
```

### Export Results to SARIF, SBOM, JSON, or Markdown

```bash
# Export standard OASIS SARIF 2.1.0 for GitHub Code Scanning
mp scan ./my-project --output sarif --output-file results.sarif

# Export OASIS CycloneDX 1.5 JSON SBOM
mp scan ./my-project --output cyclonedx --output-file bom.cdx.json

# Export Linux Foundation SPDX 2.3 JSON SBOM
mp scan ./my-project --output spdx --output-file bom.spdx.json

# Export as JSON for pipelines
mp scan ./my-project --output json > report.json

# Export formatted Markdown
mp scan ./my-project --output markdown > SECURITY.md
```

### Safe Mechanical Auto-Fixing (`--fix`)

Automatically patch safe, deterministic anti-patterns without breaking application logic:
- `MP012`: `yaml.load()` -> `yaml.safe_load()`
- `MP023`: `tar.extractall()` -> `tar.extractall(filter='data')` (prevents Zip Slip)
- `MP014`: `tempfile.mktemp()` -> `tempfile.NamedTemporaryFile().name`

```bash
mp scan . --fix
```

### Inline Code Suppression

Suppress specific false-positives or approved patterns directly in code comments:

```python
# Suppress all findings on this line:
result = eval(user_input)  # maunprekshak: ignore
# or Bandit / flake8 compatible:
result = eval(user_input)  # nosec

# Suppress specific rule ID:
result = eval(user_input)  # maunprekshak: ignore[MP001]
result = eval(user_input)  # nosec: MP001

# Disable entire file for a rule at the top of the file:
# maunprekshak: disable-file[MP001]
```

### CI/CD Mode (Exit with Non-Zero on Threshold Breach)

```bash
# Fail CI build if any CRITICAL issue is found
mp scan . --ci --fail-on critical

# Fail CI build on HIGH or CRITICAL issues
mp scan . --ci --fail-on high

# A single HIGH or CRITICAL finding is enough to fail; the risk score remains informational
```

---

## 🐙 GitHub Actions & Code Scanning (SARIF)

Run MaunPrekshak in your GitHub workflow and get native inline alerts in GitHub's **Security ➔ Code Scanning** tab:

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  maunprekshak:
    runs-on: ubuntu-latest
    permissions:
      security-events: write  # Needed for SARIF upload
      contents: read
    steps:
      - uses: actions/checkout@v4

      - name: Run MaunPrekshak Security Scan
        uses: PramanKasliwal/maunprekshak@v0.7.0
        with:
          fail-on: high
          output: sarif
          sarif-file: results.sarif

      - name: Upload to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
```

---

## 🪝 Native Git Pre-Commit Hook (1-Command Install)

Install MaunPrekshak directly into your repository's `.git/hooks/pre-commit` with a single command — no external dependencies needed:

```bash
# Install native pre-commit hook (automatically scans staged files before every commit)
mp hook install

# Uninstall hook and restore any previous backup
mp hook uninstall
```

Or using the standard `.pre-commit-config.yaml` framework:

```yaml
repos:
  - repo: https://github.com/PramanKasliwal/maunprekshak
    rev: v0.7.0
    hooks:
      - id: maunprekshak
        args: ["--staged", "--fail-on", "high"]
```

---

## ⚙️ Configuration File (`.maunprekshak.toml`)

Generate a starter configuration file with:

```bash
mp init
```

Or customize `.maunprekshak.toml` (or `[tool.maunprekshak]` in `pyproject.toml`):

```toml
[scanner]
# Directories to exclude from scans
exclude = ["tests", "fixtures", ".venv", "node_modules"]

# Default CI failure threshold: "critical", "high", "medium", or "low"
fail_on = "high"

# Disable Gemini AI remediation (fully offline)
no_ai = false

# Ignore specific SAST check IDs
ignore_rules = ["MP010"]
```

## 🖥️ Sample Console Output

```text
╭──────────────────────────────────────────────────────────────────────────────╮
│ Risk Level: HIGH (Score: 78)                                                 │
╰──────────────────────────────────────────────────────────────────────────────╯

┌──────────────────────────────────────────────────────────────────────────────┐
│                              Scan Summary                                    │
├──────────────┬──────────┬─────────┬────────┬───────┬────────────────────────┤
│ Module       │ CRITICAL │  HIGH   │ MEDIUM │  LOW  │ Total                  │
├──────────────┼──────────┼─────────┼────────┼───────┼────────────────────────┤
│ Dependencies │    1     │    2    │   0    │   0   │ 3 vulnerabilities      │
│ Secrets      │    1     │    1    │   0    │   0   │ 2 exposed credentials  │
│ SAST         │    0     │    3    │   4    │   1   │ 8 insecure patterns    │
└──────────────┴──────────┴─────────┴────────┴───────┴────────────────────────┘

Top Findings:
  [CRITICAL] CVE-2023-32681 — requests==2.25.1 (Fixed in 2.31.0)
  [HIGH]     AWS Access Key ID exposed in config.py:12
  [HIGH]     MP004: subprocess.run() called with shell=True in deploy.py:45
```

---

## 📖 CLI Command Reference

| Option | Default | Description |
| :--- | :---: | :--- |
| `path` | `.` | Directory or project path to scan |
| `--only` | `all` | Restrict scan to: `deps`, `secrets`, or `sast` |
| `--output` | `console` | Output format: `console`, `json`, `markdown`, `pdf`, `sarif`, `cyclonedx`, `spdx` |
| `--output-file` | `stdout` | Write report directly to a file |
| `--ci` | `false` | Compact machine-readable summary + exit code |
| `--fail-on` | `critical` | Fail when any finding reaches `critical`, `high`, `medium`, or `low` |
| `--no-ai` | `false` | Skip AI summary generation (instant execution) |
| `--exclude` | `None` | Comma-separated directories to exclude |
| `--staged` | `false` | Scan only git staged files (instant pre-commit mode) |
| `--diff` | `None` | Scan only files modified against a git ref (e.g. `HEAD~1`, `main`) |
| `--baseline` | `None` | Path to baseline JSON report to suppress existing findings |
| `--fix` | `false` | Automatically patch safe security anti-patterns (MP012, MP023, MP014) |
| `mp hook install` | — | Install native Git pre-commit hook into `.git/hooks/pre-commit` |
| `mp hook uninstall` | — | Uninstall native Git pre-commit hook and restore backups |

---

## 🤖 Bringing Your Own Gemini AI Key (Optional)

If you'd like AI-generated remediation summaries, set your Gemini API key in your environment or a `.env` file:

```bash
export GEMINI_API_KEY="AIzaSy..."
mp scan .
```

Get a free API key at [Google AI Studio](https://aistudio.google.com/app/apikey).

---

## 🤝 Contributing

We welcome community contributions! Please read our [CONTRIBUTING.md](CONTRIBUTING.md) to get started.

- Found a bug or missing a secret pattern? [Open an Issue](https://github.com/PramanKasliwal/maunprekshak/issues).
- Want to contribute a new SAST check? PRs are warmly welcomed!

---
 
## 🔒 Security Policy
 
We take security vulnerabilities seriously. Please review our [SECURITY.md](SECURITY.md) for details on supported versions and how to responsibly report vulnerabilities privately.
 
---

## 📄 License

Distributed under the **Apache License 2.0**. See [LICENSE](LICENSE) for details.

---

> *In ancient Sanskrit, मौन (Maun) signifies the all-knowing silence, and प्रेक्षक (Prekshak) is the ever-vigilant observer.*
> *MaunPrekshak protects your code quietly, thoroughly, and without compromise.*
