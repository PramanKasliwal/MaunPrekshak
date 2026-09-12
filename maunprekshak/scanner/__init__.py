import asyncio
from typing import List, Optional
from maunprekshak.scanner.report import ScanResult, aggregate
from maunprekshak.scanner.deps import scan_dependencies
from maunprekshak.scanner.secrets import scan_secrets
from maunprekshak.scanner.sast import scan_sast

def scan_project(path: str) -> ScanResult:
    """
    Orchestrate the scanning of dependencies, secrets, and SAST.
    
    Args:
        path: Path to the project root directory
        
    Returns:
        A unified ScanResult containing all findings.
    """
    # Run synchronously for ease of use, wrapping async functions where needed
    deps = asyncio.run(scan_dependencies(path))
    secrets = scan_secrets(path)
    sast = scan_sast(path)
    
    return aggregate(deps, secrets, sast)
