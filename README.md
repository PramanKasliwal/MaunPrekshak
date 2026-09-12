# MaunPrekshak — मौन प्रेक्षक

> *"The Silent Observer. Nothing hides from it."*

[![License: MIT](https://img.shields.io/badge/License-MIT-purple.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![PyPI version](https://badge.fury.io/py/maunprekshak.svg)](https://badge.fury.io/py/maunprekshak)
[![CI Tests](https://github.com/PramanKasliwal/maunprekshak/actions/workflows/ci.yml/badge.svg)](https://github.com/PramanKasliwal/maunprekshak/actions)

**MaunPrekshak** (मौन = *Silent*, प्रेक्षक = *Observer*) is a fast, privacy-first Python security toolkit designed to catch vulnerabilities, exposed credentials, and insecure code patterns right in your terminal.

---

## ⚡ Highlights

- 🔍 **Dependency Vulnerabilities (SCA)**: Real-time CVE discovery against [OSV.dev](https://osv.dev) for `requirements.txt`, `pyproject.toml`, and `Pipfile`.
- 🔑 **Secrets & Credential Detection**: 40+ high-precision regex detectors for AWS keys, GCP keys, GitHub tokens, Stripe keys, RSA/SSH private keys, JWTs, and database URIs with false-positive suppression.
- 🛡️ **Static Code Analysis (SAST)**: Python AST visitor checking for `eval()`, `exec()`, `pickle.loads()`, `subprocess(..., shell=True)`, `yaml.load()`, insecure hashing (`MD5`/`SHA1`), and command injection.
- 🎨 **Rich Terminal UX**: Beautiful formatted console output, severity badges, and export to **JSON** or **Markdown**.
- 🔒 **100% Privacy & Local-First**: Scans run entirely on your local CPU. Your source code never leaves your computer.
- 🤖 **Optional AI Remediation**: Plug in your own Google Gemini API key to get an instant executive summary and tailored remediation steps.

---

## 🚀 Quick Start

### Installation

```bash
pip install maunprekshak
```

### Basic Scan

Scan the current directory:

```bash
mp scan .
```

### Fast Scan without AI (No API Key Required)

```bash
mp scan . --no-ai
```

### Export Results to JSON or Markdown

```bash
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
| `--output` | `console` | Output format: `console`, `json`, `markdown` |
| `--output-file` | `stdout` | Write report directly to a file |
| `--ci` | `false` | Compact machine-readable summary + exit code |
| `--fail-on` | `critical` | Threshold: `critical`, `high`, `medium`, `low` |
| `--no-ai` | `false` | Skip AI summary generation (instant execution) |
| `--exclude` | `None` | Comma-separated directories to exclude |

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

## 📄 License

Distributed under the **MIT License**. See [LICENSE](LICENSE) for details.

---

> *In ancient Sanskrit, मौन (Maun) signifies the all-knowing silence, and प्रेक्षक (Prekshak) is the ever-vigilant observer.*
> *MaunPrekshak protects your code quietly, thoroughly, and without compromise.*
