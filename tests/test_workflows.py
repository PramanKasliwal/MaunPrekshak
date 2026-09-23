"""
Tests for GitHub Actions CI/CD Workflow Security Scanner (GHA001-GHA005)
"""
import os
import tempfile
from maunprekshak.scanner.workflows import scan_single_workflow, scan_workflows


def test_gha001_script_injection():
    content = """
name: CI
on: [issues]
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - name: Process issue
        run: |
          echo "Title: ${{ github.event.issue.title }}"
"""
    with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as f:
        f.write(content)
        path = f.name
    try:
        findings = scan_single_workflow(path)
        assert any(f.check_id == "GHA001" and f.severity == "HIGH" for f in findings)
    finally:
        os.unlink(path)


def test_gha002_unpinned_action():
    content = """
name: Build
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@main
"""
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
        f.write(content)
        path = f.name
    try:
        findings = scan_single_workflow(path)
        assert any(f.check_id == "GHA002" and f.severity == "MEDIUM" for f in findings)
    finally:
        os.unlink(path)


def test_gha003_dangerous_pull_request_target():
    content = """
name: PR Target
on:
  pull_request_target:
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
        with:
          ref: ${{ github.event.pull_request.head.sha }}
"""
    with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as f:
        f.write(content)
        path = f.name
    try:
        findings = scan_single_workflow(path)
        assert any(f.check_id == "GHA003" and f.severity == "CRITICAL" for f in findings)
    finally:
        os.unlink(path)


def test_gha004_permissions_write_all():
    content = """
name: Deploy
on: [push]
permissions: write-all
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: echo "deploying"
"""
    with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as f:
        f.write(content)
        path = f.name
    try:
        findings = scan_single_workflow(path)
        assert any(f.check_id == "GHA004" and f.severity == "HIGH" for f in findings)
    finally:
        os.unlink(path)


def test_gha005_echo_secret():
    content = """
name: Build
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo "Key is ${{ secrets.API_TOKEN }}"
"""
    with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as f:
        f.write(content)
        path = f.name
    try:
        findings = scan_single_workflow(path)
        assert any(f.check_id == "GHA005" and f.severity == "HIGH" for f in findings)
    finally:
        os.unlink(path)


def test_workflow_inline_suppression():
    content = """
name: Build
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@main  # maunprekshak: ignore[GHA002]
"""
    with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as f:
        f.write(content)
        path = f.name
    try:
        findings = scan_single_workflow(path)
        assert len(findings) == 0
    finally:
        os.unlink(path)


def test_secure_workflow_no_findings():
    content = """
name: CI
on:
  pull_request:
    branches: [main]
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
      - name: Safe run
        env:
          TITLE: ${{ github.event.issue.title }}
        run: echo "Processing $TITLE"
"""
    with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as f:
        f.write(content)
        path = f.name
    try:
        findings = scan_single_workflow(path)
        assert len(findings) == 0
    finally:
        os.unlink(path)
