"""
Tests for MaunPrekshak Core v0.15.0 — Multi-Ecosystem SCA Phase 4 (Ruby Gemfile & Elixir Mix).
"""
import os
import tempfile
import pytest
from unittest.mock import patch, AsyncMock

from maunprekshak.scanner.deps import (
    parse_gemfile,
    parse_gemfile_lock,
    parse_mix_exs,
    parse_mix_lock,
    scan_dependencies,
)
from maunprekshak.scanner.report import DepVulnerability, Severity


def test_parse_gemfile():
    gemfile_content = """
source 'https://rubygems.org'

gem 'rails', '~> 7.0.0'
gem 'pg', '>= 1.2.0'
gem "puma", "5.6.4"
gem "sass-rails"
# gem 'commented_out', '1.0.0'
"""
    with tempfile.NamedTemporaryFile("w", suffix="Gemfile", delete=False) as f:
        f.write(gemfile_content)
        fname = f.name
    try:
        pkgs = dict(parse_gemfile(fname))
        assert pkgs.get("rails") == "7.0.0"
        assert pkgs.get("pg") == "1.2.0"
        assert pkgs.get("puma") == "5.6.4"
        assert pkgs.get("sass-rails") == ""
        assert "commented_out" not in pkgs
    finally:
        os.unlink(fname)


def test_parse_gemfile_lock():
    lock_content = """GEM
  remote: https://rubygems.org/
  specs:
    actioncable (7.0.4)
      actionpack (= 7.0.4)
      activesupport (= 7.0.4)
    devise (4.8.1)
      bcrypt (~> 3.0)
    rails (7.0.4)
      actioncable (= 7.0.4)

PLATFORMS
  ruby

DEPENDENCIES
  devise (~> 4.8)
  rails (~> 7.0.4)

BUNDLED WITH
   2.3.7
"""
    with tempfile.NamedTemporaryFile("w", suffix="Gemfile.lock", delete=False) as f:
        f.write(lock_content)
        fname = f.name
    try:
        pkgs = dict(parse_gemfile_lock(fname))
        assert pkgs.get("actioncable") == "7.0.4"
        assert pkgs.get("devise") == "4.8.1"
        assert pkgs.get("rails") == "7.0.4"
    finally:
        os.unlink(fname)


def test_parse_mix_exs():
    mix_content = """defmodule MyApp.MixProject do
  use Mix.Project

  def project do
    [
      app: :my_app,
      version: "0.1.0",
      deps: deps()
    ]
  end

  defp deps do
    [
      {:phoenix, "~> 1.7.0"},
      {:ecto_sql, ">= 3.10.0"},
      {:jason, "~> 1.2"},
      {:plug_cowboy, "2.6.0"}
    ]
  end
end
"""
    with tempfile.NamedTemporaryFile("w", suffix="mix.exs", delete=False) as f:
        f.write(mix_content)
        fname = f.name
    try:
        pkgs = dict(parse_mix_exs(fname))
        assert pkgs.get("phoenix") == "1.7.0"
        assert pkgs.get("ecto_sql") == "3.10.0"
        assert pkgs.get("jason") == "1.2"
        assert pkgs.get("plug_cowboy") == "2.6.0"
    finally:
        os.unlink(fname)


def test_parse_mix_lock():
    lock_content = """%{
  "decimal": {:hex, :decimal, "2.1.1", "hash123", [:mix], [], "hexpm", "hash456"},
  "ecto": {:hex, :ecto, "3.10.3", "hash234", [:mix], [], "hexpm", "hash789"},
  "phoenix": {:hex, :phoenix, "1.7.7", "hash345", [:mix], [], "hexpm", "hash012"}
}
"""
    with tempfile.NamedTemporaryFile("w", suffix="mix.lock", delete=False) as f:
        f.write(lock_content)
        fname = f.name
    try:
        pkgs = dict(parse_mix_lock(fname))
        assert pkgs.get("decimal") == "2.1.1"
        assert pkgs.get("ecto") == "3.10.3"
        assert pkgs.get("phoenix") == "1.7.7"
    finally:
        os.unlink(fname)


@pytest.mark.asyncio
async def test_scan_dependencies_ruby(tmp_path):
    gemfile_lock = tmp_path / "Gemfile.lock"
    gemfile_lock.write_text("""GEM
  remote: https://rubygems.org/
  specs:
    rails (6.1.4)
      actioncable (= 6.1.4)
""")
    mock_vuln = DepVulnerability(
        package="rails",
        version="6.1.4",
        cve_id="CVE-2022-32224",
        severity=Severity.HIGH.value,
        cvss_score=8.1,
        description="Possible RCE in Active Record",
        fix_version="6.1.4.1",
    )
    with patch("maunprekshak.scanner.deps._query_osv", new=AsyncMock(return_value=[mock_vuln])) as mock_q:
        findings = await scan_dependencies(str(tmp_path))
        assert len(findings) == 1
        assert findings[0].package == "rails"
        assert findings[0].severity == "HIGH"
        mock_q.assert_any_call("rails", "6.1.4", "RubyGems")


@pytest.mark.asyncio
async def test_scan_dependencies_elixir(tmp_path):
    mix_lock = tmp_path / "mix.lock"
    mix_lock.write_text("""%{
  "phoenix": {:hex, :phoenix, "1.6.0", "hash", [:mix], [], "hexpm", "hash"}
}
""")
    mock_vuln = DepVulnerability(
        package="phoenix",
        version="1.6.0",
        cve_id="GHSA-xxxx-yyyy",
        severity=Severity.MEDIUM.value,
        cvss_score=6.5,
        description="XSS in Phoenix template rendering",
        fix_version="1.6.1",
    )
    with patch("maunprekshak.scanner.deps._query_osv", new=AsyncMock(return_value=[mock_vuln])) as mock_q:
        findings = await scan_dependencies(str(tmp_path))
        assert len(findings) == 1
        assert findings[0].package == "phoenix"
        assert findings[0].severity == "MEDIUM"
        mock_q.assert_any_call("phoenix", "1.6.0", "Hex")
