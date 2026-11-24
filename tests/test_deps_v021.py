"""
Tests for MaunPrekshak Core v0.21.0 — Multi-Ecosystem SCA Phase 10 (R renv.lock, Erlang rebar.lock, Gradle libs.versions.toml).
"""
import os
import tempfile
import pytest
from unittest.mock import AsyncMock, patch

from maunprekshak.scanner.deps import (
    parse_renv_lock,
    parse_rebar_lock,
    parse_gradle_version_catalog,
    scan_dependencies,
)
from maunprekshak.scanner.report import DepVulnerability


def test_parse_renv_lock():
    content = """{
  "R": {
    "Version": "4.3.1",
    "Repositories": [
      {
        "Name": "CRAN",
        "URL": "https://cloud.r-project.org"
      }
    ]
  },
  "Packages": {
    "ggplot2": {
      "Package": "ggplot2",
      "Version": "3.4.4",
      "Source": "Repository",
      "Repository": "CRAN"
    },
    "dplyr": {
      "Package": "dplyr",
      "Version": "1.1.3",
      "Source": "Repository",
      "Repository": "CRAN"
    },
    "jsonlite": {
      "Package": "jsonlite",
      "Version": "1.8.7",
      "Source": "Repository",
      "Repository": "CRAN"
    }
  }
}"""
    with tempfile.NamedTemporaryFile("w", suffix=".lock", delete=False) as f:
        f.write(content)
        f.flush()
        temp_path = f.name

    try:
        packages = parse_renv_lock(temp_path)
        pkg_dict = dict(packages)
        assert pkg_dict["ggplot2"] == "3.4.4"
        assert pkg_dict["dplyr"] == "1.1.3"
        assert pkg_dict["jsonlite"] == "1.8.7"
    finally:
        os.remove(temp_path)


def test_parse_rebar_lock():
    content = """{"1.2.0",
[{<<"cowboy">>,{pkg,<<"cowboy">>,<<"2.9.0">>},1},
 {<<"jason">>,{pkg,<<"jason">>,<<"1.4.0">>},0},
 {<<"telemetry">>,{pkg,<<"telemetry">>,<<"1.2.1">>},0}]}.
[
  {pkg_hash,[
    {<<"cowboy">>, <<"hash123">>},
    {<<"jason">>, <<"hash456">>},
    {<<"telemetry">>, <<"hash789">>}
  ]}
].
"""
    with tempfile.NamedTemporaryFile("w", suffix=".lock", delete=False) as f:
        f.write(content)
        f.flush()
        temp_path = f.name

    try:
        packages = parse_rebar_lock(temp_path)
        pkg_dict = dict(packages)
        assert pkg_dict["cowboy"] == "2.9.0"
        assert pkg_dict["jason"] == "1.4.0"
        assert pkg_dict["telemetry"] == "1.2.1"
    finally:
        os.remove(temp_path)


def test_parse_gradle_version_catalog():
    content = """
[versions]
groovy = "3.0.5"
checkstyle = "8.37"
okhttp = "4.12.0"

[libraries]
groovy-core = { module = "org.codehaus.groovy:groovy", version.ref = "groovy" }
checkstyle = { group = "com.puppycrawl.tools", name = "checkstyle", version.ref = "checkstyle" }
retrofit = { group = "com.squareup.retrofit2", name = "retrofit", version.ref = "" }
retro_fixed = { group = "com.squareup.retrofit2", name = "retrofit", version = "2.9.0" }
okhttp = { module = "com.squareup.okhttp3:okhttp", version.ref = "okhttp" }
gson = "com.google.code.gson:gson:2.10.1"

[plugins]
jmh = { id = "me.champeau.jmh", version = "0.6.5" }
"""
    with tempfile.NamedTemporaryFile("w", suffix=".versions.toml", delete=False) as f:
        f.write(content)
        f.flush()
        temp_path = f.name

    try:
        packages = parse_gradle_version_catalog(temp_path)
        pkg_dict = dict(packages)
        assert pkg_dict["org.codehaus.groovy:groovy"] == "3.0.5"
        assert pkg_dict["com.puppycrawl.tools:checkstyle"] == "8.37"
        assert pkg_dict["com.squareup.retrofit2:retrofit"] == "2.9.0"
        assert pkg_dict["com.squareup.okhttp3:okhttp"] == "4.12.0"
        assert pkg_dict["com.google.code.gson:gson"] == "2.10.1"
    finally:
        os.remove(temp_path)


@pytest.mark.asyncio
async def test_scan_dependencies_v021_ecosystems():
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create renv.lock
        renv_file = os.path.join(tmpdir, "renv.lock")
        with open(renv_file, "w") as f:
            f.write("""{
  "Packages": {
    "vuln-r-pkg": {
      "Version": "1.0.0"
    }
  }
}""")

        # Create rebar.lock
        rebar_file = os.path.join(tmpdir, "rebar.lock")
        with open(rebar_file, "w") as f:
            f.write("""{"1.2.0",
[{<<"vuln_hex_pkg">>,{pkg,<<"vuln_hex_pkg">>,<<"0.5.0">>},0}]}.
""")

        # Create gradle/libs.versions.toml
        gradle_dir = os.path.join(tmpdir, "gradle")
        os.makedirs(gradle_dir, exist_ok=True)
        catalog_file = os.path.join(gradle_dir, "libs.versions.toml")
        with open(catalog_file, "w") as f:
            f.write("""
[libraries]
vuln-maven = { group = "com.example", name = "vuln-lib", version = "1.2.3" }
""")

        mock_vuln = DepVulnerability(
            package="vuln-r-pkg",
            version="1.0.0",
            cve_id="GHSA-test-021",
            severity="HIGH",
            cvss_score=7.5,
            description="Vulnerable dependency test",
            fix_version="1.0.1",
        )

        with patch("maunprekshak.scanner.deps._query_osv", new_callable=AsyncMock) as mock_query:
            mock_query.return_value = [mock_vuln]
            findings = await scan_dependencies(tmpdir)
            assert len(findings) >= 1
            assert any(f.package == "vuln-r-pkg" for f in findings)
            assert mock_query.call_count >= 3
