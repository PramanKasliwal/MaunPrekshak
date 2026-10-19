import os
import tempfile
import pytest
from unittest.mock import patch, AsyncMock
from maunprekshak.scanner.deps import (
    parse_github_actions_workflows,
    parse_julia_project,
    parse_julia_manifest,
    parse_brewfile,
    scan_dependencies,
)


def test_parse_github_actions_workflows():
    content = """
name: CI
on: [push, pull_request]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Setup Node
        uses: "actions/setup-node@v4"
      - uses: 'dawidd6/action-download-artifact@v5'
      - uses: ./.github/actions/local-action
      - uses: docker://alpine:3.18
"""
    with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as f:
        f.write(content)
        path = f.name

    try:
        packages = parse_github_actions_workflows(path)
        pkg_dict = dict(packages)
        assert "actions/checkout" in pkg_dict
        assert pkg_dict["actions/checkout"] == "v3"
        assert "actions/setup-node" in pkg_dict
        assert pkg_dict["actions/setup-node"] == "v4"
        assert "dawidd6/action-download-artifact" in pkg_dict
        assert pkg_dict["dawidd6/action-download-artifact"] == "v5"
        assert "./.github/actions/local-action" not in pkg_dict
        assert "docker://alpine:3.18" not in pkg_dict
    finally:
        os.unlink(path)


def test_parse_julia_project():
    content = """
name = "MyJuliaApp"
uuid = "12345678-1234-1234-1234-123456789abc"
authors = ["Test <test@example.com>"]
version = "0.1.0"

[deps]
HTTP = "cd3eb016-35fb-5094-929b-558a96fad6f3"
JSON = "682c06a0-de6a-54ab-a142-c8b1cf79cde6"
DataFrames = "a93c0a06-3247-5384-a95e-61021a45b8bd"

[compat]
HTTP = "2.3.0"
JSON = "~0.21"
"""
    with tempfile.NamedTemporaryFile("w", suffix="Project.toml", delete=False) as f:
        f.write(content)
        path = f.name

    try:
        packages = parse_julia_project(path)
        pkg_dict = dict(packages)
        assert "HTTP" in pkg_dict
        assert pkg_dict["HTTP"] == "2.3.0"
        assert "JSON" in pkg_dict
        assert pkg_dict["JSON"] == "0.21"
        assert "DataFrames" in pkg_dict
        assert pkg_dict["DataFrames"] == ""
    finally:
        os.unlink(path)


def test_parse_julia_manifest():
    content = """
# This file is machine-generated - editing it directly is not advised

julia_version = "1.10.0"
manifest_format = "2.0"
project_hash = "abc123"

[[deps.HTTP]]
deps = ["Base64", "Dates", "Logging"]
git-tree-sha1 = "fedcba9876543210"
uuid = "cd3eb016-35fb-5094-929b-558a96fad6f3"
version = "2.4.0"

[[deps.JSON]]
deps = ["Dates", "Unicode"]
git-tree-sha1 = "0123456789abcdef"
uuid = "682c06a0-de6a-54ab-a142-c8b1cf79cde6"
version = "0.21.4"
"""
    with tempfile.NamedTemporaryFile("w", suffix="Manifest.toml", delete=False) as f:
        f.write(content)
        path = f.name

    try:
        packages = parse_julia_manifest(path)
        pkg_dict = dict(packages)
        assert "HTTP" in pkg_dict
        assert pkg_dict["HTTP"] == "2.4.0"
        assert "JSON" in pkg_dict
        assert pkg_dict["JSON"] == "0.21.4"
    finally:
        os.unlink(path)


def test_parse_brewfile():
    content = """
tap "homebrew/core"
brew "git"
brew "node@18"
brew "openssl@3", version: "3.0.0"
cask "google-chrome"
"""
    with tempfile.NamedTemporaryFile("w", suffix="Brewfile", delete=False) as f:
        f.write(content)
        path = f.name

    try:
        packages = parse_brewfile(path)
        pkg_dict = dict(packages)
        assert "git" in pkg_dict
        assert "node@18" in pkg_dict
        assert pkg_dict["node@18"] == "18"
        assert "openssl@3" in pkg_dict
        assert pkg_dict["openssl@3"] == "3.0.0"
    finally:
        os.unlink(path)


@pytest.mark.asyncio
async def test_scan_dependencies_v019():
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create GitHub workflow
        wf_dir = os.path.join(tmpdir, ".github", "workflows")
        os.makedirs(wf_dir, exist_ok=True)
        with open(os.path.join(wf_dir, "test.yml"), "w") as f:
            f.write("steps:\n  - uses: dawidd6/action-download-artifact@v5\n")

        # Create Julia Project.toml
        with open(os.path.join(tmpdir, "Project.toml"), "w") as f:
            f.write("[deps]\nHTTP = \"cd3eb016-35fb-5094-929b-558a96fad6f3\"\n[compat]\nHTTP = \"2.3.0\"\n")

        # Create Brewfile
        with open(os.path.join(tmpdir, "Brewfile"), "w") as f:
            f.write('brew "node@18"\n')

        with patch("maunprekshak.scanner.deps._query_osv", new_callable=AsyncMock) as mock_osv:
            mock_osv.return_value = []
            await scan_dependencies(tmpdir)

            called_ecosystems = {call.args[2] for call in mock_osv.call_args_list}
            assert "GitHub Actions" in called_ecosystems
            assert "Julia" in called_ecosystems
            assert "Homebrew" in called_ecosystems
