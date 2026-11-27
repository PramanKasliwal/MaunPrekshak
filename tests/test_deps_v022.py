"""
Tests for MaunPrekshak Core v0.22.0 — Multi-Ecosystem SCA Phase 11 (Scala build.sbt, Clojure deps.edn & project.clj, Debian debian/control).
"""
import os
import tempfile
import pytest
from unittest.mock import AsyncMock, patch

from maunprekshak.scanner.deps import (
    parse_sbt_file,
    parse_clojure_deps_edn,
    parse_leiningen_project_clj,
    parse_debian_control,
    scan_dependencies,
)
from maunprekshak.scanner.report import DepVulnerability


def test_parse_sbt_file():
    content = """
    name := "my-scala-app"
    version := "0.1.0"
    scalaVersion := "2.13.10"

    libraryDependencies += "org.typelevel" %% "cats-core" % "2.9.0"
    libraryDependencies ++= Seq(
      "io.circe" %% "circe-core" % "0.14.3",
      "com.typesafe" % "config" % "1.4.2" % Test
    )
    """
    with tempfile.NamedTemporaryFile("w", suffix=".sbt", delete=False) as f:
        f.write(content)
        f.flush()
        temp_path = f.name

    try:
        packages = parse_sbt_file(temp_path)
        pkg_dict = dict(packages)
        assert pkg_dict["org.typelevel:cats-core"] == "2.9.0"
        assert pkg_dict["io.circe:circe-core"] == "0.14.3"
        assert pkg_dict["com.typesafe:config"] == "1.4.2"
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


def test_parse_clojure_deps_edn():
    content = """
    {:paths ["src"]
     :deps {org.clojure/clojure {:mvn/version "1.11.1"}
            ring/ring-core {:mvn/version "1.9.6"}
            cheshire/cheshire {:mvn/version "5.11.0"}}}
    """
    with tempfile.NamedTemporaryFile("w", suffix=".edn", delete=False) as f:
        f.write(content)
        f.flush()
        temp_path = f.name

    try:
        packages = parse_clojure_deps_edn(temp_path)
        pkg_dict = dict(packages)
        assert pkg_dict["org.clojure:clojure"] == "1.11.1"
        assert pkg_dict["ring:ring-core"] == "1.9.6"
        assert pkg_dict["cheshire:cheshire"] == "5.11.0"
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


def test_parse_leiningen_project_clj():
    content = """
    (defproject my-clj-app "0.1.0-SNAPSHOT"
      :description "Sample Clojure App"
      :dependencies [[org.clojure/clojure "1.10.3"]
                     [compojure "1.6.2"]
                     [hiccup/hiccup "2.0.0-alpha2"]])
    """
    with tempfile.NamedTemporaryFile("w", suffix=".clj", delete=False) as f:
        f.write(content)
        f.flush()
        temp_path = f.name

    try:
        packages = parse_leiningen_project_clj(temp_path)
        pkg_dict = dict(packages)
        assert pkg_dict["org.clojure:clojure"] == "1.10.3"
        assert pkg_dict["compojure:compojure"] == "1.6.2"
        assert pkg_dict["hiccup:hiccup"] == "2.0.0-alpha2"
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


def test_parse_debian_control():
    content = """
    Source: sample-pkg
    Section: utils
    Priority: optional
    Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
    Standards-Version: 4.6.0

    Package: sample-pkg
    Architecture: any
    Depends: libc6 (>= 2.31), libssl-dev (= 3.0.2), curl (>= 7.81.0), ${shlibs:Depends}
    Description: Sample Debian package description
    """
    with tempfile.NamedTemporaryFile("w", suffix="control", delete=False) as f:
        f.write(content)
        f.flush()
        temp_path = f.name

    try:
        packages = parse_debian_control(temp_path)
        pkg_dict = dict(packages)
        assert pkg_dict["libc6"] == "2.31"
        assert pkg_dict["libssl-dev"] == "3.0.2"
        assert pkg_dict["curl"] == "7.81.0"
        assert "${shlibs:Depends}" not in pkg_dict
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


@pytest.mark.asyncio
async def test_scan_dependencies_v022_integration():
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create build.sbt
        sbt_file = os.path.join(tmpdir, "build.sbt")
        with open(sbt_file, "w") as f:
            f.write('libraryDependencies += "com.vuln" % "vuln-scala" % "1.0.0"\n')

        # Create deps.edn
        deps_edn = os.path.join(tmpdir, "deps.edn")
        with open(deps_edn, "w") as f:
            f.write('{:deps {org.vuln/vuln-clj {:mvn/version "2.0.0"}}}\n')

        # Create project.clj
        proj_clj = os.path.join(tmpdir, "project.clj")
        with open(proj_clj, "w") as f:
            f.write('(defproject test "0.1" :dependencies [[lein-vuln "3.0.0"]])\n')

        # Create debian/control
        deb_dir = os.path.join(tmpdir, "debian")
        os.makedirs(deb_dir, exist_ok=True)
        control_file = os.path.join(deb_dir, "control")
        with open(control_file, "w") as f:
            f.write("Package: test-deb\nDepends: libssl-dev (>= 1.1.1)\n")

        mock_vuln = DepVulnerability(
            package="libssl-dev",
            version="1.1.1",
            cve_id="CVE-2022-0220",
            severity="HIGH",
            cvss_score=8.1,
            description="Vulnerable Debian libssl package",
            fix_version="1.1.1w-0ubuntu1",
        )

        with patch("maunprekshak.scanner.deps._query_osv", new_callable=AsyncMock) as mock_query:
            mock_query.return_value = [mock_vuln]
            findings = await scan_dependencies(tmpdir)
            assert len(findings) >= 1
            assert any(f.package == "libssl-dev" for f in findings)
            assert mock_query.call_count >= 4
