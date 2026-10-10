import os
import tempfile
import pytest
from maunprekshak.scanner.workflows import (
    scan_single_workflow,
    scan_single_gitlab_ci,
    scan_workflows,
)


def test_gha006_self_hosted_runner():
    content = """name: Self-Hosted Runner Test
on: [push]
jobs:
  build:
    runs-on: self-hosted
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@v4
"""
    with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as f:
        f.write(content)
        path = f.name
    try:
        findings = scan_single_workflow(path)
        ids = [f.check_id for f in findings]
        assert "GHA006" in ids
    finally:
        os.unlink(path)


def test_gha007_env_delimiter_injection():
    content = """name: GHA007 Test
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - name: Inject env
        run: echo "USER_INPUT=${{ github.event.issue.body }}" >> $GITHUB_ENV
"""
    with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as f:
        f.write(content)
        path = f.name
    try:
        findings = scan_single_workflow(path)
        ids = [f.check_id for f in findings]
        assert "GHA007" in ids
    finally:
        os.unlink(path)


def test_gha008_missing_job_timeout():
    content = """name: GHA008 Test
on: [push]
jobs:
  long_job:
    runs-on: ubuntu-latest
    timeout-minutes: 0
    steps:
      - uses: actions/checkout@v4
"""
    with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as f:
        f.write(content)
        path = f.name
    try:
        findings = scan_single_workflow(path)
        ids = [f.check_id for f in findings]
        assert "GHA008" in ids
    finally:
        os.unlink(path)


def test_glci001_untrusted_variable():
    content = """build-job:
  stage: build
  image: alpine:3.18
  script:
    - echo "Deploying commit $CI_COMMIT_MESSAGE"
"""
    with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as f:
        f.write(content)
        path = f.name
    try:
        findings = scan_single_gitlab_ci(path)
        ids = [f.check_id for f in findings]
        assert "GLCI001" in ids
    finally:
        os.unlink(path)


def test_glci002_dind_privileged():
    content = """docker-build:
  stage: build
  image: docker:24.0.5
  services:
    - docker:24.0.5-dind
  script:
    - docker build -t myapp .
"""
    with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as f:
        f.write(content)
        path = f.name
    try:
        findings = scan_single_gitlab_ci(path)
        ids = [f.check_id for f in findings]
        assert "GLCI002" in ids
    finally:
        os.unlink(path)


def test_glci003_unpinned_image():
    content = """test-job:
  stage: test
  image: alpine:latest
  script:
    - pytest
"""
    with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as f:
        f.write(content)
        path = f.name
    try:
        findings = scan_single_gitlab_ci(path)
        ids = [f.check_id for f in findings]
        assert "GLCI003" in ids
    finally:
        os.unlink(path)


def test_glci004_plaintext_credentials():
    content = """variables:
  DATABASE_PASSWORD: "SuperSecretPassword123!"
  APP_ENV: "production"

deploy:
  stage: deploy
  image: alpine:3.18
  script:
    - ./deploy.sh
"""
    with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as f:
        f.write(content)
        path = f.name
    try:
        findings = scan_single_gitlab_ci(path)
        ids = [f.check_id for f in findings]
        assert "GLCI004" in ids
    finally:
        os.unlink(path)
