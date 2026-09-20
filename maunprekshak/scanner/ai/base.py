"""
Base abstraction for AI summary providers.
"""
import os
from abc import ABC, abstractmethod
from typing import Optional
from maunprekshak.scanner.report import ScanResult


def format_prompt(scan_result: ScanResult) -> str:
    """Format scan results into a concise structured prompt for AI models."""
    lines = []
    for dep in scan_result.deps[:3]:
        lines.append(f"  - DEP {dep.severity}: {dep.package}=={dep.version} ({dep.cve_id})")
    for sec in scan_result.secrets[:3]:
        lines.append(f"  - SECRET {sec.severity}: {sec.secret_type} in {os.path.basename(sec.file_path)}:{sec.line}")
    for sast in scan_result.sast[:3]:
        lines.append(f"  - SAST {sast.severity}: {sast.description} in {os.path.basename(sast.file_path)}:{sast.line}")
    top_findings = "\n".join(lines) if lines else "  No findings."

    score_level = scan_result.risk_score.level if scan_result.risk_score else "UNKNOWN"
    score_val = scan_result.risk_score.score if scan_result.risk_score else 0

    return f"""You are a senior application security engineer.
Analyze this project scan result and write a concise executive security summary.

Scan Results:
- Overall Risk: {score_level} (Score: {score_val})
- Dependency vulnerabilities: {len(scan_result.deps)}
- Exposed secrets/credentials: {len(scan_result.secrets)}
- SAST findings: {len(scan_result.sast)}

Top findings:
{top_findings}

Write:
1. A 2-sentence executive summary
2. Top 3 most critical risks and why
3. Prioritized remediation steps (numbered)
Keep it under 300 words. Be direct and actionable."""


class BaseAIProvider(ABC):
    """Abstract base class for AI summary providers."""

    @abstractmethod
    def generate_summary(
        self,
        scan_result: ScanResult,
        model: Optional[str] = None,
        base_url: Optional[str] = None,
    ) -> str:
        """
        Generate an executive summary from scan results.
        Returns a markdown-formatted string summary or informative error message.
        """
        pass
