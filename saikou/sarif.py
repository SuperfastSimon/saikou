"""SARIF 2.1.0 output, for GitHub code scanning and other SARIF consumers."""

from __future__ import annotations

import hashlib
from typing import Dict, List, Sequence

from .engine import Severity, __version__
from .verify import FileReport, provenance_of

RULE_HELP: Dict[str, str] = {
    "suppression_introduced": "An analyser suppression (nosec, noqa, eslint-disable, ...) was "
                              "added. Silencing an analyser is not a fix.",
    "findings_suppressed_not_fixed": "An analyser finding is now hidden by a suppression "
                                     "instead of being fixed.",
    "elided_output": "Code was replaced by an elision marker such as 'rest unchanged'.",
    "analyser_config_touched": "Analyser configuration changed; suppression moved out of band.",
    "cosmetic_only_change": "Only comments or whitespace changed; no executable behaviour did.",
    "no_change": "The output is identical to the input; nothing was fixed.",
    "parse_failure": "The output does not parse; it cannot be verified or imported.",
    "guard_computed_but_unused": "A validation/sanitisation result is computed but never used.",
    "js_guard_computed_but_unused": "A validation/sanitisation result is computed but never used.",
    "js_async_guard_in_boolean": "An async guard is tested without await; a Promise is "
                                 "always truthy.",
    "js_floating_guard_promise": "An async guard's Promise is floated; the code continues "
                                 "before it resolves.",
    "shared_sink_injection_path": "An interpolated string reaches a raw sink through a wrapper.",
    "body_gutted": "A function or class body was reduced to '...' or 'pass'.",
    "api_break": "Public symbols were removed or changed incompatibly.",
    "must_preserve_violated": "A symbol marked must-preserve was altered.",
    "hardcoded_secret_material": "A secret-like name is assigned a literal value.",
}


def _fingerprint(path: str, check: str, detail: str) -> str:
    return hashlib.sha256(f"{path}|{check}|{detail}".encode("utf-8")).hexdigest()[:32]


def to_sarif(reports: Sequence[FileReport]) -> dict:
    rules: Dict[str, dict] = {}
    results: List[dict] = []
    for report in reports:
        for f in report.findings:
            if f.check not in rules:
                rules[f.check] = {
                    "id": f.check, "name": f.check,
                    "shortDescription": {"text": RULE_HELP.get(f.check, f.check.replace("_", " "))},
                    "properties": {"provenance": provenance_of(f.check)},
                }
            results.append({
                "ruleId": f.check,
                "level": "error" if f.severity is Severity.HARD_FAIL else "warning",
                "message": {"text": f"[{provenance_of(f.check)}] {f.detail}"},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": report.path.replace("\\", "/")},
                    "region": {"startLine": max(1, int(f.line or 1))},
                }}],
                "partialFingerprints": {
                    "saikouFinding/v1": _fingerprint(report.path, f.check, f.detail)},
                "properties": {"verificationTier": report.tier.value},
            })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "Saikou", "version": __version__,
                "informationUri": "https://saikou.tech",
                "rules": [rules[k] for k in sorted(rules)],
            }},
            "results": results,
        }],
    }
