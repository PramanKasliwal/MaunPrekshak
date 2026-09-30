"""
Tests for MaunPrekshak Core v0.13.0 — Multi-Ecosystem SCA (Java & PHP).
"""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from maunprekshak.scanner.deps import (
    parse_pom_xml,
    parse_gradle_file,
    parse_gradle_lockfile,
    parse_composer_lock,
    parse_composer_json,
    scan_dependencies,
)


SAMPLE_POM_XML = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>demo-app</artifactId>
    <version>1.0.0</version>

    <properties>
        <log4j.version>2.14.1</log4j.version>
    </properties>

    <dependencies>
        <dependency>
            <groupId>org.apache.logging.log4j</groupId>
            <artifactId>log4j-core</artifactId>
            <version>${log4j.version}</version>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
            <version>2.5.4</version>
        </dependency>
    </dependencies>
</project>
"""

SAMPLE_BUILD_GRADLE = """
plugins {
    id 'java'
    id 'org.springframework.boot' version '2.7.0'
}

dependencies {
    implementation 'org.springframework.boot:spring-boot-starter-web:2.7.0'
    testImplementation 'org.junit.jupiter:junit-jupiter:5.8.2'
    implementation group: 'com.fasterxml.jackson.core', name: 'jackson-databind', version: '2.13.0'
}
"""

SAMPLE_GRADLE_LOCKFILE = """# This is a Gradle lockfile
org.springframework.boot:spring-boot-starter-web:2.7.0=compileClasspath,runtimeClasspath
org.yaml:snakeyaml:1.30=compileClasspath,runtimeClasspath
empty:line=
"""

SAMPLE_COMPOSER_LOCK = """{
    "_readme": ["This file locks the dependencies."],
    "packages": [
        {
            "name": "guzzlehttp/guzzle",
            "version": "7.4.5"
        },
        {
            "name": "laravel/framework",
            "version": "v9.19.0"
        }
    ],
    "packages-dev": [
        {
            "name": "phpunit/phpunit",
            "version": "9.5.10"
        }
    ]
}"""

SAMPLE_COMPOSER_JSON = """{
    "name": "my/project",
    "require": {
        "php": ">=8.1",
        "monolog/monolog": "^3.2.0",
        "ext-json": "*"
    },
    "require-dev": {
        "phpunit/phpunit": "~9.5.0"
    }
}"""


def test_parse_pom_xml(tmp_path):
    pom_file = tmp_path / "pom.xml"
    pom_file.write_text(SAMPLE_POM_XML)

    deps = parse_pom_xml(str(pom_file))
    dep_dict = dict(deps)
    assert "org.apache.logging.log4j:log4j-core" in dep_dict
    assert dep_dict["org.apache.logging.log4j:log4j-core"] == "2.14.1"
    assert "org.springframework.boot:spring-boot-starter-web" in dep_dict
    assert dep_dict["org.springframework.boot:spring-boot-starter-web"] == "2.5.4"


def test_parse_gradle_file(tmp_path):
    gradle_file = tmp_path / "build.gradle"
    gradle_file.write_text(SAMPLE_BUILD_GRADLE)

    deps = parse_gradle_file(str(gradle_file))
    dep_dict = dict(deps)
    assert dep_dict.get("org.springframework.boot:spring-boot-starter-web") == "2.7.0"
    assert dep_dict.get("org.junit.jupiter:junit-jupiter") == "5.8.2"
    assert dep_dict.get("com.fasterxml.jackson.core:jackson-databind") == "2.13.0"


def test_parse_gradle_lockfile(tmp_path):
    lock_file = tmp_path / "gradle.lockfile"
    lock_file.write_text(SAMPLE_GRADLE_LOCKFILE)

    deps = parse_gradle_lockfile(str(lock_file))
    dep_dict = dict(deps)
    assert dep_dict.get("org.springframework.boot:spring-boot-starter-web") == "2.7.0"
    assert dep_dict.get("org.yaml:snakeyaml") == "1.30"


def test_parse_composer_lock(tmp_path):
    lock_file = tmp_path / "composer.lock"
    lock_file.write_text(SAMPLE_COMPOSER_LOCK)

    deps = parse_composer_lock(str(lock_file))
    dep_dict = dict(deps)
    assert dep_dict.get("guzzlehttp/guzzle") == "7.4.5"
    assert dep_dict.get("laravel/framework") == "9.19.0"  # leading v stripped
    assert dep_dict.get("phpunit/phpunit") == "9.5.10"


def test_parse_composer_json(tmp_path):
    json_file = tmp_path / "composer.json"
    json_file.write_text(SAMPLE_COMPOSER_JSON)

    deps = parse_composer_json(str(json_file))
    dep_dict = dict(deps)
    assert "php" not in dep_dict
    assert "ext-json" not in dep_dict
    assert dep_dict.get("monolog/monolog") == "3.2.0"
    assert dep_dict.get("phpunit/phpunit") == "9.5.0"


@pytest.mark.asyncio
async def test_scan_dependencies_java_and_php(tmp_path):
    (tmp_path / "pom.xml").write_text(SAMPLE_POM_XML)
    (tmp_path / "composer.lock").write_text(SAMPLE_COMPOSER_LOCK)

    mock_vuln = {
        "id": "GHSA-jfh8-c2jp-5v3q",
        "summary": "Log4j Remote Code Execution",
        "severity": [{"score": "10.0", "type": "CVSS_V3"}],
        "affected": [
            {
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": "2.17.1"}],
                    }
                ]
            }
        ],
    }

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"vulns": [mock_vuln]}
        mock_resp.status_code = 200
        mock_post.return_value = mock_resp

        findings = await scan_dependencies(str(tmp_path))

        assert len(findings) > 0
        assert any("log4j-core" in f.package or "guzzle" in f.package for f in findings)
