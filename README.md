# MaunPrekshak — मौन प्रेक्षक

> *"The Silent Observer. Nothing hides from it."*

[![License: MIT](https://img.shields.io/badge/License-MIT-purple.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![PyPI version](https://img.shields.io/pypi/v/maunprekshak.svg?color=green&logo=pypi&logoColor=white)](https://pypi.org/project/maunprekshak/)
[![PyPI Downloads](https://img.shields.io/pypi/dm/maunprekshak?color=blue&logo=pypi&logoColor=white)](https://pypistats.org/packages/maunprekshak)
[![CI Tests](https://github.com/PramanKasliwal/maunprekshak/actions/workflows/ci.yml/badge.svg)](https://github.com/PramanKasliwal/maunprekshak/actions)

**MaunPrekshak** (मौन = *Silent*, प्रेक्षक = *Observer*) is a fast, privacy-first Python security toolkit designed to catch vulnerabilities, exposed credentials, and insecure code patterns right in your terminal.

---

## ⚡ Highlights

- 🔍 **Dependency Vulnerabilities (SCA)**: Real-time CVE discovery against [OSV.dev](https://osv.dev) with lockfile parsing (`poetry.lock`, `Pipfile.lock`, `uv.lock`, `requirements.txt`, `pyproject.toml`, `Pipfile`) for deep transitive dependency tracking.
- 🔑 **Entropy & Regex Secrets Detection**: 40+ high-precision regex detectors PLUS Shannon entropy token analysis ($H \ge 4.5$ Base64 / $H \ge 3.0$ Hex) for un-prefixed tokens and private keys, with zero false-positives for UUIDs, URLs, and dummy values.
- 🛡️ **Static Code Analysis (SAST)**: 18 AST security rules (MP001–MP018) covering code execution, SQL injection, disabled SSL/TLS verification, wildcard network binding (`0.0.0.0`), insecure `/tmp` file creation, and unsafe deserialization.
- ⚡ **Git Staged & Diff Scanning**: Fast pre-commit mode via `--staged` and `--diff` checking only modified files in milliseconds.
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

### 🐍 Via PyPI (Any OS)
```bash
pip install maunprekshak
# or using pipx (recommended for Ubuntu 24.04+)
pipx install maunprekshak
```

Basic Scan

Scan the current directory:

```bash
mp scan .
```

### Fast Scan without AI (No API Key Required)

```bash
mp scan . --no-ai
```

### Export Results to SARIF, JSON, or Markdown

```bash
# Export standard OASIS SARIF 2.1.0 for GitHub Code Scanning
mp scan ./my-project --output sarif --output-file results.sarif

# Export as JSON for pipelines
mp scan ./my-project --output json > report.json

# Export formatted Markdown
mp scan ./my-project --output markdown > SECURITY.md
```

### CI/CD Mode (Exit with Non-Zero on Threshold Breach)

```bash
# Fail CI build if any CRITICAL issue is found
mp scan . --ci --fail-on critical

# Fail CI build on HIGH or CRITICAL issues
mp scan . --ci --fail-on high
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
        uses: PramanKasliwal/maunprekshak@v0.3.0
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

## 🪝 Pre-Commit Hook

Prevent secrets, leaked API keys, and AST flaws from ever reaching Git. Add to your `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/PramanKasliwal/maunprekshak
    rev: v0.3.0
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
| `--output` | `console` | Output format: `console`, `json`, `markdown`, `pdf`, `sarif` |
| `--output-file` | `stdout` | Write report directly to a file |
| `--ci` | `false` | Compact machine-readable summary + exit code |
| `--fail-on` | `critical` | Threshold: `critical`, `high`, `medium`, `low` |
| `--no-ai` | `false` | Skip AI summary generation (instant execution) |
| `--exclude` | `None` | Comma-separated directories to exclude |
| `--staged` | `false` | Scan only git staged files (instant pre-commit mode) |
| `--diff` | `None` | Scan only files modified against a git ref (e.g. `HEAD~1`, `main`) |

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

Distributed under the **MIT License**. See [LICENSE](LICENSE) for details.

---

> *In ancient Sanskrit, मौन (Maun) signifies the all-knowing silence, and प्रेक्षक (Prekshak) is the ever-vigilant observer.*
> *MaunPrekshak protects your code quietly, thoroughly, and without compromise.*
