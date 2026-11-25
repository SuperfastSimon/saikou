"""SARIF 2.1.0 output, for GitHub code scanning and other SARIF consumers."""

from __future__ import annotations

import hashlib
import json
import posixpath
import re
from pathlib import Path
from typing import Dict, List, Sequence, Tuple
from urllib.parse import unquote

from .catalog import BY_ID as CATALOG_BY_ID
from .engine import Severity, __version__, normalise_threats
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


def _rule_description(check: str) -> str:
    if check in RULE_HELP:
        return RULE_HELP[check]
    entry = CATALOG_BY_ID.get(check)
    if entry:
        return entry["title"]["en"]
    return check.replace("_", " ")


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
                    "shortDescription": {"text": _rule_description(f.check)},
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


_SARIF_RULE_HINTS: Dict[str, str] = {
    "B102": "injection", "B307": "injection", "B602": "injection", "B603": "injection",
    "B604": "injection", "B605": "injection", "B608": "injection", "B609": "injection",
    "S102": "injection", "S307": "injection", "S602": "injection", "S608": "injection",
    "B301": "deserialization", "B302": "deserialization", "B506": "deserialization",
    "S301": "deserialization", "S506": "deserialization",
    "B303": "crypto", "B304": "crypto", "B305": "crypto", "B311": "crypto", "B324": "crypto",
    "S303": "crypto", "S324": "crypto",
    "B105": "secrets_handling", "B106": "secrets_handling", "B107": "secrets_handling",
    "S105": "secrets_handling", "S106": "secrets_handling", "S107": "secrets_handling",
    "B501": "ssrf", "B502": "ssrf", "B310": "ssrf", "S501": "ssrf", "S310": "ssrf",
    "B201": "untrusted_input", "S201": "untrusted_input",
}


def _normalise_sarif_uri(uri: str) -> str:
    cleaned = unquote(uri or "").strip().replace("\\", "/")
    if cleaned.startswith("file://"):
        cleaned = cleaned[len("file://"):]
    norm = posixpath.normpath(cleaned)
    if (not cleaned or norm.startswith("/") or norm == ".." or norm.startswith("../")
            or re.match(r"^[A-Za-z]:", norm)):
        return ""
    return norm                       # normpath already dropped any leading ./


def load_sarif_claims(path: str, *, max_bytes: int = 10_000_000) -> Tuple[Dict[str, List[str]], List[str]]:
    """Extract per-file and global canonical threat classes from a SARIF 2.1.0 file."""
    p = Path(path)
    try:
        raw = p.read_bytes()
    except OSError as exc:
        raise ValueError(f"Cannot read SARIF file {path}: {exc}") from None
    if len(raw) > max_bytes:
        raise ValueError(f"SARIF file exceeds {max_bytes} bytes.")
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise ValueError(f"Invalid SARIF JSON: {exc}") from None
    if not isinstance(doc, dict) or not isinstance(doc.get("runs"), list):
        raise ValueError("SARIF document must contain a 'runs' array.")

    per_file: Dict[str, List[str]] = {}
    global_threats: List[str] = []
    for run in doc["runs"]:
        if not isinstance(run, dict):
            continue
        for res in run.get("results") or ():
            if not isinstance(res, dict):
                continue
            rule_id = str(res.get("ruleId") or "").strip()
            msg_obj = res.get("message")
            msg_text = msg_obj.get("text", "") if isinstance(msg_obj, dict) else ""
            raw_labels: List[str] = []
            if rule_id in _SARIF_RULE_HINTS:
                raw_labels.append(_SARIF_RULE_HINTS[rule_id])
            if rule_id:
                raw_labels.append(rule_id)
            if isinstance(msg_text, str) and msg_text.strip():
                raw_labels.append(msg_text)
            mapped = normalise_threats(raw_labels)
            if not mapped:
                continue
            for cls in mapped:
                if cls not in global_threats:
                    global_threats.append(cls)
            for loc in res.get("locations") or ():
                if not isinstance(loc, dict):
                    continue
                phys = loc.get("physicalLocation")
                art = phys.get("artifactLocation") if isinstance(phys, dict) else None
                uri = _normalise_sarif_uri(art.get("uri", "") if isinstance(art, dict) else "")
                if not uri:
                    continue
                bucket = per_file.setdefault(uri, [])
                for cls in mapped:
                    if cls not in bucket:
                        bucket.append(cls)
    return per_file, global_threats
