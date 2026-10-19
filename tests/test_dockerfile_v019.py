import tempfile
import os
from maunprekshak.scanner.dockerfile import scan_single_dockerfile


def test_df013_ssh_exposed():
    content = """
FROM ubuntu:22.04
RUN apt-get update && apt-get install -y openssh-server
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]
"""
    with tempfile.NamedTemporaryFile("w", suffix="Dockerfile", delete=False) as f:
        f.write(content)
        path = f.name

    try:
        findings = scan_single_dockerfile(path)
        check_ids = [f.check_id for f in findings]
        assert "DF013" in check_ids
        df013_findings = [f for f in findings if f.check_id == "DF013"]
        assert len(df013_findings) >= 1
    finally:
        os.unlink(path)


def test_df013_suppression():
    content = """
FROM ubuntu:22.04
EXPOSE 22 # maunprekshak: ignore[DF013]
"""
    with tempfile.NamedTemporaryFile("w", suffix="Dockerfile", delete=False) as f:
        f.write(content)
        path = f.name

    try:
        findings = scan_single_dockerfile(path)
        check_ids = [f.check_id for f in findings]
        assert "DF013" not in check_ids
    finally:
        os.unlink(path)


def test_df014_curl_wget_piped_to_shell():
    content = """
FROM alpine:3.18
RUN curl -fsSL https://example.com/install.sh | sh
RUN wget -qO- https://example.com/setup.sh | bash
"""
    with tempfile.NamedTemporaryFile("w", suffix="Dockerfile", delete=False) as f:
        f.write(content)
        path = f.name

    try:
        findings = scan_single_dockerfile(path)
        check_ids = [f.check_id for f in findings]
        assert "DF014" in check_ids
        df014_findings = [f for f in findings if f.check_id == "DF014"]
        assert len(df014_findings) == 2
    finally:
        os.unlink(path)


def test_df014_suppression():
    content = """
FROM alpine:3.18
RUN curl -fsSL https://example.com/install.sh | sh # nosec: DF014
"""
    with tempfile.NamedTemporaryFile("w", suffix="Dockerfile", delete=False) as f:
        f.write(content)
        path = f.name

    try:
        findings = scan_single_dockerfile(path)
        check_ids = [f.check_id for f in findings]
        assert "DF014" not in check_ids
    finally:
        os.unlink(path)
