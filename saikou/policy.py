"""Repository policy file (`.saikou.toml`) with fail-closed, time-bounded waivers (stdlib only)."""

from __future__ import annotations

import ast
import fnmatch
import re
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from .engine import Finding, Severity, normalise_threats
from .verify import FileReport

try:
    import tomllib  # Python 3.11+
except ImportError:  # pragma: no cover - Python 3.9/3.10 fallback
    tomllib = None  # type: ignore[assignment]

MAX_POLICY_BYTES = 200_000


class PolicyError(ValueError):
    """Raised when `.saikou.toml` is malformed or violates fail-closed waiver rules."""


@dataclass(frozen=True)
class Waiver:
    check: str
    path: str
    reason: str
    owner: str
    expires: date


@dataclass
class Policy:
    strict_api: bool = False
    warn_only: List[str] = field(default_factory=list)
    must_preserve: List[str] = field(default_factory=list)
    exclude_paths: List[str] = field(default_factory=list)
    claimed_threats: List[str] = field(default_factory=list)
    waivers: List[Waiver] = field(default_factory=list)


def norm_path(path: str) -> str:
    """Repository-relative POSIX path: backslashes to slashes, leading `./` segments dropped.

    Only whole `./` segments go: `.github/x.py` keeps its dot (str.lstrip("./") would not)."""
    p = path.replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    return p


def _strip_comment(line: str) -> str:
    """Drop a trailing `# comment`, but not a `#` inside a quoted string."""
    quote = ""
    for i, ch in enumerate(line):
        if quote:
            if ch == quote:
                quote = ""
        elif ch in "\"'":
            quote = ch
        elif ch == "#":
            return line[:i]
    return line


def _fallback_parse_toml(text: str) -> Dict[str, Any]:
    """Minimal TOML subset parser for Python 3.9/3.10 ([policy] and [[waivers]])."""
    root: Dict[str, Any] = {}
    current: Dict[str, Any] = root
    for raw in text.splitlines():
        line = _strip_comment(raw).strip()
        if not line:
            continue
        if line.startswith("[[") and line.endswith("]]"):
            name = line[2:-2].strip()
            lst = root.setdefault(name, [])
            if not isinstance(lst, list):
                raise PolicyError(f"Duplicate table name {name!r}.")
            item: Dict[str, Any] = {}
            lst.append(item)
            current = item
            continue
        if line.startswith("[") and line.endswith("]"):
            name = line[1:-1].strip()
            tbl = root.setdefault(name, {})
            if not isinstance(tbl, dict):
                raise PolicyError(f"Duplicate table name {name!r}.")
            current = tbl
            continue
        if "=" not in line:
            raise PolicyError(f"Invalid TOML line: {line[:60]}")
        key, _, val = line.partition("=")
        key, val = key.strip(), val.strip()
        if val == "true":
            parsed: Any = True
        elif val == "false":
            parsed = False
        elif re.fullmatch(r"\d{4}-\d{2}-\d{2}", val):
            try:
                parsed = date.fromisoformat(val)       # TOML local date, as tomllib returns it
            except ValueError as exc:
                raise PolicyError(f"Invalid date for {key!r}: {exc}") from None
        else:
            try:
                parsed = ast.literal_eval(val)
            except (SyntaxError, ValueError) as exc:
                raise PolicyError(f"Invalid TOML value for {key!r}: {exc}") from None
        current[key] = parsed
    return root


def _parse_toml(raw: bytes) -> Dict[str, Any]:
    if len(raw) > MAX_POLICY_BYTES:
        raise PolicyError(f"Policy file exceeds {MAX_POLICY_BYTES} bytes.")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PolicyError(f"Policy file is not UTF-8: {exc}") from None
    if tomllib is not None:
        try:
            return tomllib.loads(text)
        except ValueError as exc:
            raise PolicyError(f"Invalid TOML syntax: {exc}") from None
    return _fallback_parse_toml(text)


def _str_list(tbl: Dict[str, Any], key: str) -> List[str]:
    val = tbl.get(key, [])
    if not isinstance(val, list) or not all(isinstance(x, str) and x.strip() for x in val):
        raise PolicyError(f"policy.{key} must be a list of non-empty strings.")
    return [x.strip() for x in val]


def load_policy(path: str) -> Policy:
    """Load and strictly validate a `.saikou.toml` policy file from disk."""
    try:
        raw = Path(path).read_bytes()
    except OSError as exc:
        raise PolicyError(f"Cannot read policy file {path}: {exc}") from None
    return parse_policy(raw)


def parse_policy(raw: bytes) -> Policy:
    """Strictly validate policy bytes (from disk, or from a commit via `git show`)."""
    data = _parse_toml(raw)
    pol_tbl = data.get("policy", {})
    if not isinstance(pol_tbl, dict):
        raise PolicyError("[policy] must be a table.")
    strict_api = pol_tbl.get("strict_api", False)
    if not isinstance(strict_api, bool):
        raise PolicyError("policy.strict_api must be a boolean.")

    waivers_raw = data.get("waivers", [])
    if not isinstance(waivers_raw, list):
        raise PolicyError("[[waivers]] must be an array of tables.")
    waivers: List[Waiver] = []
    for idx, item in enumerate(waivers_raw):
        if not isinstance(item, dict):
            raise PolicyError(f"waivers[{idx}] must be a table.")
        for req in ("check", "path", "reason", "owner"):
            val = item.get(req)
            if not isinstance(val, str) or not val.strip():
                raise PolicyError(f"waivers[{idx}].{req} is required and must be a non-empty string.")
        exp = item.get("expires")
        if isinstance(exp, date) and not isinstance(exp, datetime):
            exp_date = exp                                  # TOML local date: expires = 2027-06-01
        elif isinstance(exp, str) and re.fullmatch(r"\d{4}-\d{2}-\d{2}", exp.strip()):
            try:
                exp_date = date.fromisoformat(exp.strip())
            except ValueError as exc:
                raise PolicyError(f"waivers[{idx}].expires is not a valid date: {exc}") from None
        else:
            raise PolicyError(f"waivers[{idx}].expires is required as a date (YYYY-MM-DD), "
                              f"got {exp!r}.")
        waivers.append(Waiver(
            check=item["check"].strip(),
            path=norm_path(item["path"].strip()),
            reason=item["reason"].strip(),
            owner=item["owner"].strip(),
            expires=exp_date,
        ))

    return Policy(
        strict_api=strict_api,
        warn_only=_str_list(pol_tbl, "warn_only"),
        must_preserve=_str_list(pol_tbl, "must_preserve"),
        exclude_paths=[norm_path(p) for p in _str_list(pol_tbl, "exclude_paths")],
        claimed_threats=normalise_threats(_str_list(pol_tbl, "claimed_threats")),
        waivers=waivers,
    )


def apply_waivers(reports: Sequence[FileReport], pol: Policy,
                  *, today: Optional[date] = None) -> List[str]:
    """Demote hard fails matched by active, unexpired waivers; report expired waivers as notes."""
    ref_day = today or date.today()
    notes: List[str] = []
    active: List[Waiver] = []
    for w in pol.waivers:
        if w.expires < ref_day:
            notes.append(
                f"policy waiver expired on {w.expires.isoformat()} "
                f"({w.check} on {w.path}, owner={w.owner}); ignored.")
        else:
            active.append(w)

    if not active:
        return notes

    for rep in reports:
        rel = norm_path(rep.path)
        updated: List[Finding] = []
        for f in rep.findings:
            matched: Optional[Waiver] = None
            if f.severity is Severity.HARD_FAIL:
                for w in active:
                    if w.check == f.check and fnmatch.fnmatch(rel, w.path):
                        matched = w
                        break
            if matched is not None:
                updated.append(Finding(
                    f.check, Severity.WARN,
                    f"[waived until {matched.expires.isoformat()} by {matched.owner}: "
                    f"{matched.reason}] {f.detail}",
                    f.line, f.excerpt,
                ))
            else:
                updated.append(f)
        rep.findings = updated
    return notes
