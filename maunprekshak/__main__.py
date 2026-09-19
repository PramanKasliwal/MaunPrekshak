"""
MaunPrekshak — Module Execution Entrypoint
Enables running the scanner via `python -m maunprekshak`.
"""
from maunprekshak.cli.main import app

if __name__ == "__main__":
    app()
