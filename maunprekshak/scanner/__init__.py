import asyncio
from concurrent.futures import ThreadPoolExecutor
from typing import List, Optional
from maunprekshak.scanner.report import ScanResult, aggregate
from maunprekshak.scanner.deps import scan_dependencies
from maunprekshak.scanner.secrets import scan_secrets
from maunprekshak.scanner.sast import scan_sast


async def scan_project_async(
    path: str,
    exclude: Optional[List[str]] = None,
    only: Optional[str] = None,
    target_files: Optional[List[str]] = None,
) -> ScanResult:
    """
    Asynchronously orchestrate scanning of dependencies, secrets, and SAST.
    Ideal for async servers (e.g. FastAPI).
    """
    deps = []
    secrets = []
    sast = []

    if only is None or only == "deps":
        deps = await scan_dependencies(path, target_files=target_files)

    if only is None or only == "secrets":
        secrets = scan_secrets(path, exclude=exclude, target_files=target_files)

    if only is None or only == "sast":
        sast = scan_sast(path, exclude=exclude, target_files=target_files)

    return aggregate(deps, secrets, sast)


def scan_project(
    path: str,
    exclude: Optional[List[str]] = None,
    only: Optional[str] = None,
    target_files: Optional[List[str]] = None,
) -> ScanResult:
    """
    Synchronous entrypoint for CLI. Safe to call from both CLI and async contexts.
    """
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        with ThreadPoolExecutor(max_workers=1) as executor:
            return executor.submit(
                lambda: asyncio.run(
                    scan_project_async(path, exclude=exclude, only=only, target_files=target_files)
                )
            ).result()

    return asyncio.run(
        scan_project_async(path, exclude=exclude, only=only, target_files=target_files)
    )
