"""
Tests for MaunPrekshak Core v0.13.0 — Web, API & Microservices SAST Suite (MP041–MP048).
"""
import ast
import pytest
from maunprekshak.scanner.sast import SecurityVisitor


def _scan_code(code_str: str):
    lines = code_str.splitlines()
    tree = ast.parse(code_str)
    visitor = SecurityVisitor("test_code.py", lines)
    visitor.visit(tree)
    return visitor.findings


def test_mp041_cors_wildcard_credentials():
    code = """
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from flask_cors import CORS

app = FastAPI()

# Insecure FastAPI CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
)

# Insecure Flask-CORS
CORS(app, origins="*", supports_credentials=True)

# Safe FastAPI CORS
safe_app = FastAPI()
safe_app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://dashboard.example.com"],
    allow_credentials=True,
)
"""
    findings = _scan_code(code)
    mp041 = [f for f in findings if f.check_id == "MP041"]
    assert len(mp041) == 2
    assert all(f.severity == "HIGH" for f in mp041)


def test_mp042_open_redirect():
    code = """
from flask import redirect, request
from django.http import HttpResponseRedirect
from starlette.responses import RedirectResponse

def view1():
    return redirect(request.args.get('next'))

def view2():
    return HttpResponseRedirect(request.GET.get('url'))

def view3():
    return RedirectResponse(url=request.query_params.get('dest'))

def safe_view():
    return redirect('/home')
"""
    findings = _scan_code(code)
    mp042 = [f for f in findings if f.check_id == "MP042"]
    assert len(mp042) == 3
    assert all(f.severity == "MEDIUM" for f in mp042)


def test_mp043_jwt_insecure_validation():
    code = """
import jwt

token = "eyJhbGciOi..."

# Insecure: none algorithm
res1 = jwt.decode(token, key="secret", algorithms=["none"])

# Insecure: verify_signature False
res2 = jwt.decode(token, key="secret", options={"verify_signature": False})

# Safe: RS256
safe_res = jwt.decode(token, key="pubkey", algorithms=["RS256"])
"""
    findings = _scan_code(code)
    mp043 = [f for f in findings if f.check_id == "MP043"]
    assert len(mp043) == 2
    assert all(f.severity == "HIGH" for f in mp043)


def test_mp044_csrf_exempt():
    code = """
from django.views.decorators.csrf import csrf_exempt

@csrf_exempt
def unsafe_post_endpoint(request):
    return "ok"

@csrf_exempt
async def async_unsafe_endpoint(request):
    return "ok"

def safe_endpoint(request):
    return "ok"
"""
    findings = _scan_code(code)
    mp044 = [f for f in findings if f.check_id == "MP044"]
    assert len(mp044) == 2
    assert all(f.severity == "MEDIUM" for f in mp044)


def test_mp045_path_traversal_file_serving():
    code = """
import os
from flask import send_file, request
from fastapi.responses import FileResponse

BASE_DIR = "/var/www/uploads"

def download_flask():
    return send_file(os.path.join(BASE_DIR, request.args.get("file")))

def download_fastapi():
    return FileResponse(path=request.query_params.get("filename"))

def safe_download():
    return send_file("/var/www/uploads/report.pdf")
"""
    findings = _scan_code(code)
    mp045 = [f for f in findings if f.check_id == "MP045"]
    assert len(mp045) == 2
    assert all(f.severity == "HIGH" for f in mp045)


def test_mp046_mass_assignment():
    code = """
from flask import request

class User:
    def __init__(self, **kwargs):
        pass

def create_user():
    # Insecure mass assignment
    u1 = User(**request.json)
    u2 = User(**request.get_json())
    u3 = User(**request.form)

    # Safe: controlled dictionary
    clean_data = {"name": "Alice"}
    u_safe = User(**clean_data)
"""
    findings = _scan_code(code)
    mp046 = [f for f in findings if f.check_id == "MP046"]
    assert len(mp046) == 3
    assert all(f.severity == "HIGH" for f in mp046)


def test_mp047_graphql_introspection():
    code = """
from graphene_django.views import GraphQLView

# Insecure call
view = GraphQLView.as_view(graphiql=True, introspection=True)

# Insecure assignment
GRAPHQL_INTROSPECTION = True

# Safe
safe_view = GraphQLView.as_view(graphiql=False, introspection=False)
"""
    findings = _scan_code(code)
    mp047 = [f for f in findings if f.check_id == "MP047"]
    assert len(mp047) == 2
    assert all(f.severity == "LOW" for f in mp047)


def test_mp048_host_header_injection():
    code = """
from flask import request
from urllib.parse import urljoin

def send_reset():
    # Insecure f-string URL construction with request.host
    reset_url1 = f"https://{request.host}/reset-password?token=abc"
    reset_url2 = f"http://{request.headers.get('host')}/activate"

    # Insecure urljoin
    reset_url3 = urljoin(request.host, "/callback")

    # Safe static URL
    safe_url = f"https://auth.company.com/reset?user={user_id}"
"""
    findings = _scan_code(code)
    mp048 = [f for f in findings if f.check_id == "MP048"]
    assert len(mp048) == 3
    assert all(f.severity == "MEDIUM" for f in mp048)
