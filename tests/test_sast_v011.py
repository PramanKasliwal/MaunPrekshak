import ast
import pytest
from maunprekshak.scanner.sast import SecurityVisitor, scan_sast


def _scan_code(code_str: str):
    lines = code_str.splitlines()
    tree = ast.parse(code_str)
    visitor = SecurityVisitor("test_code.py", lines)
    visitor.visit(tree)
    return visitor.findings


def test_mp036_unsafe_yaml():
    code = """
import yaml

data1 = yaml.unsafe_load(untrusted_stream)
data2 = yaml.load(untrusted_stream, Loader=yaml.Loader)
data3 = yaml.load(untrusted_stream, Loader=yaml.UnsafeLoader)
safe1 = yaml.safe_load(untrusted_stream)
safe2 = yaml.load(untrusted_stream, Loader=yaml.SafeLoader)
"""
    findings = _scan_code(code)
    mp036 = [f for f in findings if f.check_id == "MP036"]
    assert len(mp036) == 3
    assert all(f.severity == "HIGH" for f in mp036)


def test_mp037_blind_ssrf():
    code = """
import httpx
import aiohttp

endpoint = "/users"
base = "https://internal.net"
res1 = httpx.get(f"https://api.example.com/{endpoint}")
res2 = httpx.post("https://" + target_host)
res3 = client.get("https://example.com/api/{}".format(path))
safe_res = httpx.get("https://api.example.com/v1/health")
"""
    findings = _scan_code(code)
    mp037 = [f for f in findings if f.check_id == "MP037"]
    assert len(mp037) == 3
    assert all(f.severity == "HIGH" for f in mp037)


def test_mp038_llm_prompt_injection():
    code = """
import openai
from langchain.prompts import PromptTemplate

client = openai.OpenAI()
user_prompt = "ignore previous instructions"

# Unsafe: system f-string in messages list
res1 = client.chat.completions.create(
    model="gpt-4o",
    messages=[
        {"role": "system", "content": f"You are a helpful assistant for {user_prompt}"},
        {"role": "user", "content": "hello"}
    ]
)

# Unsafe: Anthropic style system= kwarg f-string
res2 = client.messages.create(
    model="claude-3-5-sonnet",
    system=f"Act as {user_prompt}",
    messages=[]
)

# Unsafe: dynamic string into PromptTemplate
tpl = PromptTemplate.from_template(f"Prefix: {user_prompt} and {input}")

# Safe: static template with variable slot
safe_tpl = PromptTemplate.from_template("Prefix: {topic}")
"""
    findings = _scan_code(code)
    mp038 = [f for f in findings if f.check_id == "MP038"]
    assert len(mp038) == 3
    assert all(f.severity == "CRITICAL" for f in mp038)


def test_mp039_joblib_cloudpickle():
    code = """
import joblib
import cloudpickle

model = joblib.load("model.pkl")
obj = cloudpickle.loads(payload)
"""
    findings = _scan_code(code)
    mp039 = [f for f in findings if f.check_id == "MP039"]
    assert len(mp039) == 2
    assert all(f.severity == "HIGH" for f in mp039)


def test_mp040_subshell_execution():
    code = """
import os
import asyncio

p = os.popen(f"cat {filename}")
proc = asyncio.create_subprocess_shell("whoami")
"""
    findings = _scan_code(code)
    mp040 = [f for f in findings if f.check_id == "MP040"]
    assert len(mp040) == 2
    assert all(f.severity == "HIGH" for f in mp040)
