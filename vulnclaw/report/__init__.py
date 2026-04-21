"""VulnClaw Report Module — structured report generation with vulnerability verification."""

from vulnclaw.report.filter import ReportContentFilter, filter_report_content
from vulnclaw.report.generator import (
    generate_persistent_cycle_report,
    generate_report,
    generate_report_from_file,
)
from vulnclaw.report.poc_builder import generate_single_poc, generate_pocs
from vulnclaw.report.verifier import (
    PoCGenerator,
    VerificationResult,
    VerificationStatus,
    VerifiedFinding,
    VerifierExecutor,
    VulnerabilityVerifier,
)

__all__ = [
    # Generator
    "generate_report",
    "generate_report_from_file",
    "generate_persistent_cycle_report",
    # Verifier
    "VulnerabilityVerifier",
    "VerifiedFinding",
    "VerificationStatus",
    "VerificationResult",
    "PoCGenerator",
    "VerifierExecutor",
    # Filter
    "ReportContentFilter",
    "filter_report_content",
    # PoC
    "generate_pocs",
    "generate_single_poc",
]
