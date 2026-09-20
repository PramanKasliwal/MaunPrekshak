"""
Tests for 1-command native Git hook installer (mp hook install / uninstall).
"""
import os
import stat
import pytest
from typer.testing import CliRunner
from maunprekshak.cli.main import app

runner = CliRunner()


@pytest.fixture
def temp_git_repo(tmp_path):
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    (git_dir / "hooks").mkdir()
    return tmp_path


class TestGitHookCLI:
    def test_hook_install_success(self, temp_git_repo):
        result = runner.invoke(app, ["hook", "install", "--path", str(temp_git_repo)])
        assert result.exit_code == 0
        assert "Successfully installed MaunPrekshak pre-commit hook" in result.stdout

        hook_file = temp_git_repo / ".git" / "hooks" / "pre-commit"
        assert hook_file.exists()
        content = hook_file.read_text()
        assert "MaunPrekshak Git Pre-Commit Hook" in content
        assert "scan . --staged --ci --fail-on high --no-ai" in content

        # Check executable permissions
        file_mode = os.stat(hook_file).st_mode
        assert bool(file_mode & stat.S_IXUSR)

    def test_hook_install_backs_up_existing(self, temp_git_repo):
        hook_file = temp_git_repo / ".git" / "hooks" / "pre-commit"
        hook_file.write_text("#!/bin/sh\necho 'custom hook'\n")

        result = runner.invoke(app, ["hook", "install", "--path", str(temp_git_repo)])
        assert result.exit_code == 0
        assert "Existing pre-commit hook backed up" in result.stdout

        backup_file = temp_git_repo / ".git" / "hooks" / "pre-commit.maunprekshak.bak"
        assert backup_file.exists()
        assert "custom hook" in backup_file.read_text()

    def test_hook_uninstall_success_and_restores_backup(self, temp_git_repo):
        # 1. Custom hook exists
        hook_file = temp_git_repo / ".git" / "hooks" / "pre-commit"
        hook_file.write_text("#!/bin/sh\necho 'custom hook'\n")

        # 2. Install MaunPrekshak hook
        runner.invoke(app, ["hook", "install", "--path", str(temp_git_repo)])

        # 3. Uninstall MaunPrekshak hook
        result = runner.invoke(app, ["hook", "uninstall", "--path", str(temp_git_repo)])
        assert result.exit_code == 0
        assert "Removed MaunPrekshak pre-commit hook" in result.stdout
        assert "Restored original pre-commit hook" in result.stdout

        # Verify custom hook restored
        assert hook_file.exists()
        assert "custom hook" in hook_file.read_text()

    def test_hook_install_no_git_dir_fails(self, tmp_path):
        result = runner.invoke(app, ["hook", "install", "--path", str(tmp_path)])
        assert result.exit_code == 1
        assert "No .git repository found" in result.stdout

    def test_hook_uninstall_no_git_dir_fails(self, tmp_path):
        result = runner.invoke(app, ["hook", "uninstall", "--path", str(tmp_path)])
        assert result.exit_code == 1
        assert "No .git repository found" in result.stdout
