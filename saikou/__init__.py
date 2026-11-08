"""Saikou - prove that a security fix is real, not just claimed.

The engine is standard-library only:

    from saikou import scan_transformation
    findings = scan_transformation(before, after, language="python")
    blocked = any(f.severity.value == "hard_fail" for f in findings)

Command line: `saikou verify BEFORE AFTER`, `saikou diff --base REF`,
`saikou harden FILE`, `saikou selftest`.
"""

from .engine import (
    Claim,
    Contract,
    Detection,
    EvidenceLedger,
    Finding,
    LANGUAGES,
    Provenance,
    Severity,
    SurfaceDiff,
    THREAT_CHOICES,
    TIER_MEANING,
    Tier,
    __version__,
    assemble_ledger,
    checks_run,
    detect_language,
    diff_python_surface,
    language_for_path,
    normalise_language,
    normalise_threats,
    run_analyser,
    scan_transformation,
)

__all__ = [
    "Claim", "Contract", "Detection", "EvidenceLedger", "Finding", "LANGUAGES", "Provenance",
    "Severity", "SurfaceDiff", "THREAT_CHOICES", "TIER_MEANING", "Tier", "__version__",
    "assemble_ledger", "checks_run", "detect_language", "diff_python_surface",
    "language_for_path", "normalise_language", "normalise_threats", "run_analyser",
    "scan_transformation",
]
