"""
Tests for Git Commit History Secrets Scanner
"""
import os
import secrets
import shutil
import subprocess
import tempfile
import pytest
from maunprekshak.scanner.git_history import scan_git_history


@pytest.fixture
def git_repo_with_leaked_commit():
    """Create a temporary git repository with a committed and subsequently removed secret."""
    tmpdir = tempfile.mkdtemp(prefix="mp_test_git_")
    try:
        # Initialize git repo
        subprocess.run(["git", "init"], cwd=tmpdir, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=tmpdir, check=True)
        subprocess.run(["git", "config", "user.name", "Tester"], cwd=tmpdir, check=True)

        # Commit 1: Add a secret dynamically
        # Dynamic slack-like / gitlab-like token
        dyn_token = f"glpat-{secrets.token_urlsafe(24)[:22]}"
        secret_file = os.path.join(tmpdir, "config.py")
        with open(secret_file, "w") as f:
            f.write(f'GITLAB_AUTH = "{dyn_token}"\n')

        subprocess.run(["git", "add", "config.py"], cwd=tmpdir, check=True)
        subprocess.run(["git", "commit", "-m", "Add auth config"], cwd=tmpdir, check=True)

        # Commit 2: "Remove" the secret (replace with env var)
        with open(secret_file, "w") as f:
            f.write('GITLAB_AUTH = os.getenv("GITLAB_AUTH")\n')

        subprocess.run(["git", "add", "config.py"], cwd=tmpdir, check=True)
        subprocess.run(["git", "commit", "-m", "Refactor auth config to use env"], cwd=tmpdir, check=True)

        yield tmpdir
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_scan_git_history_detects_removed_secret(git_repo_with_leaked_commit):
    findings = scan_git_history(git_repo_with_leaked_commit, max_commits=10)
    assert len(findings) >= 1
    # Check that location includes commit and filename
    match = any("config.py" in f.file_path and "commit:" in f.file_path for f in findings)
    assert match


def test_scan_git_history_non_git_dir():
    empty_dir = tempfile.mkdtemp(prefix="mp_non_git_")
    try:
        findings = scan_git_history(empty_dir)
        assert findings == []
    finally:
        shutil.rmtree(empty_dir, ignore_errors=True)
