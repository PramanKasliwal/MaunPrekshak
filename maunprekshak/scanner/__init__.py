import asyncio
from typing import List, Optional
from maunprekshak.scanner.report import ScanResult, aggregate
from maunprekshak.scanner.deps import scan_dependencies
from maunprekshak.scanner.secrets import scan_secrets
from maunprekshak.scanner.sast import scan_sast

def scan_project(
    path: str,
    exclude: Optional[List[str]] = None,
    only: Optional[str] = None,
) -> ScanResult:
    """
    Orchestrate the scanning of dependencies, secrets, and SAST.
    
    Args:
        path: Path to the project root directory
        exclude: Optional list of directories to exclude
        only: Run only a specific module ('deps', 'secrets', 'sast')
        
    Returns:
        A unified ScanResult containing all findings.
    """
    deps = []
    secrets = []
    sast = []

    if only is None or only == "deps":
        deps = asyncio.run(scan_dependencies(path))

    if only is None or only == "secrets":
        secrets = scan_secrets(path, exclude=exclude)

    if only is None or only == "sast":
        sast = scan_sast(path, exclude=exclude)

    return aggregate(deps, secrets, sast)
