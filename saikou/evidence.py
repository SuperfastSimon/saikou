"""Deterministic, optionally HMAC-signed Evidence Bundles for audit trails (stdlib only).

Produces a tamper-evident JSON record of what Saikou checked, how each finding was
established, and what was not checked. With a key from the environment (never CLI argv)
it adds an HMAC-SHA256 seal: tamper-evident for anyone without the key, but a shared-key HMAC,
not a public-key signature.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any, Dict, Optional, Sequence, Tuple

from . import catalog
from .engine import __version__, utc_now
from .verify import FileReport

EVIDENCE_SCHEMA = "saikou.evidence/v1"
MIN_SIGNING_KEY_LEN = 16

COMPLIANCE_MAPPING = {
    "standards": [
        {
            "framework": "NIS2 Directive (EU 2022/2555)",
            "control": "Art. 21(2)(e)",
            "scope": "Supporting evidence of independent fix verification during development "
                     "and vulnerability handling. Not a compliance certification.",
        },
        {
            "framework": "ISO/IEC 27001:2022",
            "control": "A.8.25 - A.8.28",
            "scope": "Supporting evidence for secure development life cycle and secure coding "
                     "verification. Not an audit certificate.",
        },
    ],
    "disclaimer": "Reports what Saikou checked and how it was established. It does not certify "
                  "that the code is secure or compliant with any regulation. The optional HMAC seal "
                  "uses a shared key and is not a public-key signature.",
}


def _canonical_bytes(payload: Dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def build_evidence_bundle(
    reports: Sequence[FileReport],
    mode: str,
    *,
    base_sha: str = "",
    skipped: Sequence[str] = (),
    file_hashes: Optional[Dict[str, Tuple[str, str]]] = None,
    signing_key: Optional[str] = None,
) -> Dict[str, Any]:
    """Assemble a canonical Evidence Bundle, optionally signed with HMAC-SHA256."""
    if signing_key is not None and len(signing_key) < MIN_SIGNING_KEY_LEN:
        raise ValueError(f"Signing key must be at least {MIN_SIGNING_KEY_LEN} characters.")

    hashes = file_hashes or {}
    file_entries = []
    for rep in reports:
        entry = rep.as_dict()
        pair = hashes.get(rep.path)
        if pair is not None:
            entry["before_sha256"], entry["after_sha256"] = pair
        file_entries.append(entry)

    payload: Dict[str, Any] = {
        "schema": EVIDENCE_SCHEMA,
        "saikou_version": __version__,
        "issued_at": utc_now(),
        "mode": mode,
        "base_sha": base_sha,
        "blocked": any(r.blocked for r in reports),
        "files": file_entries,
        "skipped": list(skipped),
        "limits": catalog.LIMITS,
        "compliance_mapping": COMPLIANCE_MAPPING,
    }
    canonical = _canonical_bytes(payload)
    digest = hashlib.sha256(canonical).hexdigest()
    bundle: Dict[str, Any] = dict(payload)
    bundle["digest_sha256"] = digest

    if signing_key:
        key_bytes = signing_key.encode("utf-8")
        sig = hmac.new(key_bytes, canonical, hashlib.sha256).hexdigest()
        bundle["signature"] = {
            "algorithm": "hmac-sha256",
            # keyed, so the id says which key signed without being a guessable hash of the key
            "key_id": hmac.new(key_bytes, b"saikou.evidence/key-id", hashlib.sha256).hexdigest()[:16],
            "value": sig,
            "note": "Shared-key HMAC: shows the bundle was not changed by anyone without the key. "
                    "Anyone holding the key can produce a valid bundle; this is not a public-key "
                    "signature and gives no non-repudiation.",
        }
    return bundle


def verify_evidence_bundle(
    bundle: Dict[str, Any],
    *,
    signing_key: Optional[str] = None,
) -> Tuple[bool, str]:
    """Verify digest integrity and, when present, the HMAC-SHA256 signature."""
    if not isinstance(bundle, dict) or bundle.get("schema") != EVIDENCE_SCHEMA:
        return False, "Unknown or malformed evidence bundle schema."
    expected_digest = bundle.get("digest_sha256")
    if not isinstance(expected_digest, str) or not expected_digest:
        return False, "Missing digest_sha256."

    payload = {k: v for k, v in bundle.items() if k not in ("digest_sha256", "signature")}
    canonical = _canonical_bytes(payload)
    actual_digest = hashlib.sha256(canonical).hexdigest()
    if not hmac.compare_digest(actual_digest, expected_digest):
        return False, "digest_sha256 mismatch: bundle content was altered."

    sig_obj = bundle.get("signature")
    if sig_obj is not None:
        if not signing_key:
            return False, "Bundle is signed but no signing_key was provided."
        if not isinstance(sig_obj, dict) or sig_obj.get("algorithm") != "hmac-sha256":
            return False, "Unsupported or malformed signature block."
        expected_sig = sig_obj.get("value")
        if not isinstance(expected_sig, str):
            return False, "Missing signature value."
        actual_sig = hmac.new(signing_key.encode("utf-8"), canonical, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(actual_sig, expected_sig):
            return False, "HMAC signature mismatch."
    return True, "ok"
