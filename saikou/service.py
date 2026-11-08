"""The request/response logic shared by the hosted API (saikou.api) and the local app
(saikou.server). Plain dicts in, plain dicts out, stdlib only - so both front doors behave
identically and are validated in one place.

Local-only operations (git, providers, harden-with-write) are kept here too but are only
wired up by saikou.server; the hosted API never touches the file system.
"""

from __future__ import annotations

import difflib
import functools
import http.client
import json
import os
import re
import secrets
import shutil
import stat
import tempfile
import threading
import urllib.error
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from . import catalog
from .engine import (
    LANGUAGES,
    THREAT_CHOICES,
    Contract,
    __version__,
    detect_language,
    language_for_path,
    normalise_language,
    normalise_threats,
)
from .sarif import to_sarif
from .verify import (
    FileReport,
    GitError,
    changed_files,
    config_weakening,
    is_analyser_config,
    unreadable_report,
    verify_pair,
)

READING_GUIDE = ("No score. Each finding says how it was established (tool / parser / "
                 "mechanical). Absence of a finding is not evidence of a fix.")
MODES = ("verify", "gate")

# The contract values `saikou harden`, the hosted API and the intake questions accept. The
# first of each is the default. Anything else is refused: the engine compares exactly, so an
# unknown compat value would silently drop the strict_api gate.
COMPAT_CHOICES = ("strict_api", "allow_signature_changes", "rewrite_freely")
DEPENDENCY_CHOICES = ("stdlib_only", "existing_only", "may_add")
ERROR_POLICY_CHOICES = ("fail_closed", "preserve_current")


class ServiceError(Exception):
    """A request problem with an HTTP-ish status and a stable machine code."""

    def __init__(self, status: int, code: str, message: str,
                 headers: Optional[Dict[str, str]] = None) -> None:
        super().__init__(message)
        self.status, self.code, self.message = status, code, message
        self.headers = headers

    def as_dict(self) -> dict:
        return {"error": {"code": self.code, "message": self.message}}


@dataclass
class Limits:
    max_chars: int = 60_000          # per file
    max_files: int = 50
    max_total_chars: int = 400_000

    @classmethod
    def from_env(cls) -> "Limits":
        def _int(name: str, default: int) -> int:
            try:
                return max(1000, int(os.getenv(name, default)))
            except ValueError:
                return default
        return cls(_int("MAX_INPUT_CHARS", cls.max_chars), cls.max_files,
                   _int("MAX_TOTAL_CHARS", cls.max_total_chars))


# ---------------------------------------------------------------------------------------
# input helpers
# ---------------------------------------------------------------------------------------

def _need_obj(body: Any) -> Dict[str, Any]:
    if not isinstance(body, dict):
        raise ServiceError(422, "bad_request", "Request body must be a JSON object.")
    return body


def _str(body: dict, key: str, *, max_len: int, required: bool = False, default: str = "") -> str:
    value = body.get(key, default)
    if value is None:
        value = default
    if not isinstance(value, str):
        raise ServiceError(422, "bad_field", f"'{key}' must be a string.")
    if required and not value.strip():
        raise ServiceError(422, "missing_field", f"'{key}' is required.")
    if len(value) > max_len:
        raise ServiceError(413, "too_large", f"'{key}' is {len(value)} characters; the limit is {max_len}.")
    return value


def _bool(body: dict, key: str, default: bool = False) -> bool:
    value = body.get(key, default)
    if not isinstance(value, bool):
        raise ServiceError(422, "bad_field", f"'{key}' must be true or false.")
    return value


def _strs(body: dict, key: str, *, max_items: int, max_len: int = 200) -> List[str]:
    value = body.get(key) or []
    if not isinstance(value, list) or len(value) > max_items:
        raise ServiceError(422, "bad_field", f"'{key}' must be a list of at most {max_items} strings.")
    out = []
    for item in value:
        if not isinstance(item, str) or not item.strip() or len(item) > max_len:
            raise ServiceError(422, "bad_field", f"'{key}' must contain non-empty strings of at most {max_len} characters.")
        out.append(item.strip())
    return out


def _mode(body: dict, default: str) -> str:
    mode = body.get("mode", default)
    if mode not in MODES:
        raise ServiceError(422, "bad_field", f"'mode' must be one of {list(MODES)}.")
    return mode


def _choice(body: dict, key: str, choices: Sequence[str]) -> str:
    """One of a fixed set of values; missing or empty means the first one (the default)."""
    value = body.get(key)
    if value is None or value == "":
        return choices[0]
    if not isinstance(value, str) or value not in choices:
        raise ServiceError(422, "bad_field", f"'{key}' must be one of {list(choices)}.")
    return value


def _threats(body: dict) -> List[str]:
    raw = _strs(body, "claimed_threats", max_items=len(THREAT_CHOICES) * 2)
    mapped = normalise_threats(raw)
    if raw and not mapped:
        raise ServiceError(422, "bad_field", "None of claimed_threats map to a known threat class. "
                           "Valid: " + ", ".join(THREAT_CHOICES))
    return mapped


def _resolve_language(body: dict, path: str, code: str) -> str:
    explicit = body.get("language")
    if explicit:
        if not isinstance(explicit, str):
            raise ServiceError(422, "bad_field", "'language' must be a string.")
        lang = normalise_language(explicit)
        if lang == "unknown" and explicit.strip().lower() not in ("unknown", ""):
            raise ServiceError(422, "bad_field", f"Unknown language {explicit!r}. Known: "
                               + ", ".join(sorted(k for k in LANGUAGES if k != "unknown")))
        return lang
    lang = language_for_path(path)
    return lang if lang != "unknown" else detect_language(code).language


# ---------------------------------------------------------------------------------------
# output helpers
# ---------------------------------------------------------------------------------------

def _enrich(report: FileReport, mode: str) -> dict:
    data = report.as_dict()
    hard, warn = len(report.hard_fails), len(report.warnings)
    data["counts"] = {"hard_fail": hard, "warn": warn}
    data["tier_meaning"] = catalog.TIER_MEANING.get(report.tier.value, {})
    data["not_checked"] = [{"id": c["id"], "title": c["title"]}
                           for c in catalog.not_checked(report.language, mode)]
    return data


def _envelope(reports: Sequence[FileReport], mode: str, skipped: Sequence[str] = (),
              fmt: str = "json") -> dict:
    if fmt == "sarif":
        return to_sarif(list(reports))
    return {
        "saikou": __version__, "mode": mode,
        "blocked": any(r.blocked for r in reports),
        "files": [_enrich(r, mode) for r in reports],
        "skipped": list(skipped),
        "limits": catalog.LIMITS,
        "reading_guide": READING_GUIDE,
    }


def _format(body: dict) -> str:
    fmt = body.get("format", "json")
    if fmt not in ("json", "sarif"):
        raise ServiceError(422, "bad_field", "'format' must be 'json' or 'sarif'.")
    return fmt


def _analyser_ok() -> bool:
    return shutil.which("bandit") is not None


# ---------------------------------------------------------------------------------------
# public operations
# ---------------------------------------------------------------------------------------

def health() -> dict:
    return {"status": "ok", "version": __version__}


def checks() -> dict:
    return {"version": __version__, "checks": catalog.CHECKS,
            "provenance": catalog.PROVENANCE_MEANING, "tiers": catalog.TIER_MEANING,
            "limits": catalog.LIMITS, "threat_classes": THREAT_CHOICES,
            "languages": sorted(k for k in LANGUAGES if k != "unknown"),
            "modes": list(MODES)}


def _one(body: dict, limits: Limits, mode: str, *,
         path_default: str = "input") -> Callable[[], FileReport]:
    """Validate one pair and return its verification, to run once every input is valid."""
    path = _str(body, "path", max_len=300, default=path_default) or path_default
    before = _str(body, "before", max_len=limits.max_chars)
    after = _str(body, "after", max_len=limits.max_chars, required=True)
    lang = _resolve_language(body, path, after or before)
    use_analyser = _bool(body, "analyser")
    if mode == "gate" and is_analyser_config(path):
        return functools.partial(config_weakening, path, before, after,
                                 "modified" if before else "added")
    return functools.partial(
        verify_pair, before, after, path=path, language=lang, claimed_threats=_threats(body),
        strict_api=_bool(body, "strict_api"), must_preserve=_strs(body, "must_preserve", max_items=200),
        expect_change=(mode == "verify"), run_tools=use_analyser and _analyser_ok(),
        warn_only=_strs(body, "warn_only", max_items=40),
        change="verify" if mode == "verify" else ("modified" if before else "added"))


def verify(body: Any, limits: Optional[Limits] = None) -> dict:
    """One before/after pair. mode 'verify' = judge a claimed fix; 'gate' = judge a change."""
    body = _need_obj(body)
    limits = limits or Limits.from_env()
    mode = _mode(body, "verify")
    fmt = _format(body)
    report = _one(body, limits, mode)()
    out = _envelope([report], mode, fmt=fmt)
    if isinstance(out, dict) and "files" in out and _bool(body, "analyser") and not _analyser_ok():
        out["notes"] = ["Analyser evidence was requested but bandit is not installed; none was collected."]
    return out


def verify_batch(body: Any, limits: Optional[Limits] = None) -> dict:
    """Many file pairs in one request (CI without installing anything)."""
    body = _need_obj(body)
    limits = limits or Limits.from_env()
    mode = _mode(body, "gate")
    fmt = _format(body)
    files = body.get("files")
    if not isinstance(files, list) or not files:
        raise ServiceError(422, "missing_field", "'files' must be a non-empty list of {path, before, after}.")
    if len(files) > limits.max_files:
        raise ServiceError(413, "too_many_files", f"At most {limits.max_files} files per request.")
    total = 0
    common = {k: body[k] for k in ("claimed_threats", "strict_api", "must_preserve", "analyser",
                                   "warn_only", "language") if k in body}
    jobs: List[Callable[[], FileReport]] = []
    skipped: List[str] = []
    for i, item in enumerate(files):
        if not isinstance(item, dict):
            raise ServiceError(422, "bad_field", f"files[{i}] must be an object with path, before and after.")
        for key in ("before", "after"):
            if item.get(key) is not None and not isinstance(item[key], str):
                raise ServiceError(422, "bad_field", f"files[{i}].{key} must be a string.")
        total += len(item.get("before") or "") + len(item.get("after") or "")
        if total > limits.max_total_chars:
            raise ServiceError(413, "too_large", f"Total input exceeds {limits.max_total_chars} characters.")
        merged = {**common, **item}
        path = _str(merged, "path", max_len=300, required=True)
        lang = language_for_path(path)
        if lang == "unknown" and not is_analyser_config(path) and not merged.get("language"):
            skipped.append(f"{path}: language not recognised")
            continue
        jobs.append(_one(merged, limits, mode))
    # Verification runs only after every file and option passed validation.
    return _envelope([job() for job in jobs], mode, skipped, fmt=fmt)


# ---- local-only operations ---------------------------------------------------------------

_REF = re.compile(r"^[A-Za-z0-9_./@^~{}:\-]+$")


def _ref(value: str, name: str) -> str:
    if value.startswith("-") or not _REF.match(value):
        raise ServiceError(422, "bad_field", f"'{name}' is not a valid git ref.")
    return value


def git_diff(body: Any, limits: Optional[Limits] = None) -> dict:
    """Gate the changes in a local git repository (local app only)."""
    body = _need_obj(body)
    mode = "gate"
    fmt = _format(body)
    repo = _str(body, "repo", max_len=500, required=True)
    if not os.path.isdir(os.path.join(repo, ".git")) and not os.path.isfile(os.path.join(repo, ".git")):
        raise ServiceError(422, "not_a_repo", "That folder is not a git repository (no .git).")
    base = _ref(_str(body, "base", max_len=200, default="HEAD") or "HEAD", "base")
    head = _str(body, "head", max_len=200)
    head = _ref(head, "head") if head else None
    staged = _bool(body, "staged")
    no_merge_base = _bool(body, "no_merge_base")
    paths = _strs(body, "paths", max_items=50, max_len=300)
    if any(p.startswith("-") for p in paths):
        raise ServiceError(422, "bad_field", "Paths must not start with '-'.")
    # Every option is read once and checked before git runs or any file is verified.
    threats = _threats(body)
    strict_api = _bool(body, "strict_api")
    must_preserve = _strs(body, "must_preserve", max_items=200)
    run_tools = _bool(body, "analyser") and _analyser_ok()
    warn_only = _strs(body, "warn_only", max_items=40)
    try:
        sha, files, skipped = changed_files(base, head=head, staged=staged,
                                            merge_base=not no_merge_base,
                                            paths=paths, cwd=repo)
    except GitError as exc:
        raise ServiceError(422, "git_error", str(exc)[:300]) from None
    if len(files) > 200:
        raise ServiceError(413, "too_many_files", f"{len(files)} files changed; limit is 200. Narrow with paths.")
    reports: List[FileReport] = []
    for cf in files:
        if cf.unreadable:
            reports.append(unreadable_report(cf, warn_only))
            continue
        if is_analyser_config(cf.path):
            reports.append(config_weakening(cf.path, cf.before, cf.after, cf.change))
            continue
        lang = language_for_path(cf.path)
        if lang == "unknown":
            skipped.append(f"{cf.path}: language not recognised")
            continue
        reports.append(verify_pair(
            cf.before, cf.after, path=cf.path, language=lang, claimed_threats=threats,
            strict_api=strict_api, must_preserve=must_preserve,
            expect_change=False, run_tools=run_tools, warn_only=warn_only, change=cf.change))
    out = _envelope(reports, mode, skipped, fmt=fmt)
    if isinstance(out, dict) and "files" in out:
        out["base"] = sha
    return out


def _local_models(url: str) -> Dict[str, Any]:
    """Installed models of a local Ollama: this machine only, no proxy, no redirect."""
    from .llm import _DIRECT, _MAX_BODY, LLMError, checked_endpoint

    try:
        checked, loopback = checked_endpoint(url)
    except LLMError:
        return {"reachable": False, "models": []}
    if not loopback:
        return {"reachable": False, "models": [], "not_local": True}
    root = checked.rsplit("/v1", 1)[0]
    try:
        with _DIRECT.open(f"{root}/api/tags", timeout=2) as resp:
            names = [m.get("name", "") for m in json.loads(resp.read(_MAX_BODY).decode("utf-8")).get("models", [])]
        return {"reachable": True, "models": sorted(n for n in names if n and "cloud" not in n)}
    except (urllib.error.URLError, OSError, ValueError, AttributeError, TypeError, RecursionError,
            http.client.HTTPException):
        return {"reachable": False, "models": []}


def providers() -> dict:
    """Which model providers are usable here. Never returns a key, only whether one is set."""
    from .llm import PROVIDERS

    out = []
    for name, preset in PROVIDERS.items():
        base = os.getenv(preset["url_env"], preset["base_url"]).rstrip("/")
        entry = {"id": name, "base_url": base, "key_env": preset["key_env"],
                 "key_set": bool(os.getenv(preset["key_env"])) or name == "local",
                 "default_model": os.getenv(preset["model_env"], preset["model"]),
                 "strict_schema": bool(preset["structured"])}
        if name == "local":
            entry.update(_local_models(base))
        out.append(entry)
    return {"providers": out, "analyser_available": _analyser_ok(), "threat_classes": THREAT_CHOICES}


def harden(body: Any) -> dict:
    """Ask a model for a hardened version, verify it, optionally write it (local app only)."""
    from .llm import PROVIDERS, LLMConfig, LLMError, run_hardening

    body = _need_obj(body)
    limits = Limits.from_env()
    code = _str(body, "code", max_len=limits.max_chars, required=True)
    path = _str(body, "path", max_len=500)
    provider = _str(body, "provider", max_len=40, default="openai") or "openai"
    if provider not in PROVIDERS:
        raise ServiceError(422, "bad_field", f"Unknown provider; choose from {sorted(PROVIDERS)}.")
    lang = _resolve_language(body, path or "input", code)
    model = _str(body, "model", max_len=200)
    # Every input is checked before the model is asked, so no paid call is spent on a
    # request that would then be refused for its input.
    contract = Contract(
        threat_model=_threats({"claimed_threats": body.get("threats")}),
        compat=_choice(body, "compat", COMPAT_CHOICES),
        dependencies=_choice(body, "dependencies", DEPENDENCY_CHOICES),
        error_policy=_choice(body, "error_policy", ERROR_POLICY_CHOICES),
        must_preserve=_strs(body, "must_preserve", max_items=200), notes=_str(body, "notes", max_len=4000))
    run_tools = _bool(body, "analyser") and _analyser_ok()
    write = _bool(body, "write")
    if write:                                   # checked again just before writing
        _unchanged_text(path, code)
    try:
        config = LLMConfig.from_env(provider=provider, model=model or None)
    except LLMError as exc:
        raise ServiceError(422, "provider_error", str(exc)) from None
    try:
        result = run_hardening(code, lang, contract, config, run_tools=run_tools)
    except LLMError as exc:
        raise ServiceError(502, "model_error", str(exc)) from None
    out = result.as_dict()
    name = os.path.basename(path) if path else "input"
    out.update({"provider": provider, "model": config.model, "written": False,
                # Shown for rejected output too, labelled as rejected, so the user can decide.
                "diff": "\n".join(difflib.unified_diff(
                    code.splitlines(), result.proposed.splitlines(),
                    fromfile=f"a/{name}", tofile=f"b/{name}", lineterm=""))})
    if not result.blocked:
        out["result_id"] = _keep_verified(code, result.proposed)
    if write:
        if result.blocked:
            raise ServiceError(409, "blocked", "Verification blocked this output; nothing was written.")
        _write_verified(path, code, result.proposed)
        out["written"] = True
    return out


# Verified hardening results, so the app can write exactly the output the user reviewed
# instead of asking the model again. Only output that passed verification is kept.
_VERIFIED: "OrderedDict[str, Tuple[str, str]]" = OrderedDict()
_VERIFIED_MAX = 20
_verified_lock = threading.Lock()


def _keep_verified(code: str, proposed: str) -> str:
    result_id = secrets.token_urlsafe(16)
    with _verified_lock:
        _VERIFIED[result_id] = (code, proposed)
        while len(_VERIFIED) > _VERIFIED_MAX:
            _VERIFIED.popitem(last=False)
    return result_id


_NOT_UTF8 = ("That file is not UTF-8 text. Saikou only opens and writes UTF-8 files: "
             "writing any other encoding back as UTF-8 would change characters in it.")


def _utf8(raw: bytes) -> str:
    """Strict: a byte that is not UTF-8 is refused, never replaced."""
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ServiceError(422, "not_utf8", _NOT_UTF8) from None


def _unchanged_text(path: str, code: str) -> str:
    """The file's current text, if it still holds `code`; otherwise a ServiceError."""
    if not path or not os.path.isfile(path):
        raise ServiceError(422, "bad_field", "'path' must be an existing file to write to.")
    with open(path, "rb") as fh:
        current = _utf8(fh.read())
    # Compare content, not line-ending style: browsers and text-mode reads turn CRLF into LF.
    if current.replace("\r\n", "\n") != code.replace("\r\n", "\n"):
        raise ServiceError(409, "file_changed", "The file changed since it was loaded; reload it before writing.")
    return current


def _replace_file(target: str, data: bytes) -> None:
    """Write `data` to a temporary file next to `target`, then swap it in with os.replace:
    a failure part-way leaves the old file as it was, never an empty or half one."""
    folder = os.path.dirname(target) or "."
    fd, tmp = tempfile.mkstemp(prefix="." + os.path.basename(target) + ".", suffix=".saikou-tmp",
                               dir=folder)
    os.close(fd)
    try:
        with open(tmp, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        try:
            shutil.copymode(target, tmp)        # mkstemp makes the file private (0600)
        except OSError:
            pass                                # content still lands; only the mode is lost
        os.replace(tmp, target)
    except BaseException:
        try:
            os.chmod(tmp, stat.S_IREAD | stat.S_IWRITE)   # a read-only copy cannot be removed on Windows
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _write_verified(path: str, code: str, proposed: str) -> None:
    # Through a symlink to its target, as an in-place write would; os.replace on the link
    # itself would turn it into a plain file.
    target = os.path.realpath(path) if path else path
    current = _unchanged_text(target, code)
    proposed = proposed.replace("\r\n", "\n")
    if "\r\n" in current:                       # keep the file's own line-ending style
        proposed = proposed.replace("\n", "\r\n")
    try:
        data = proposed.encode("utf-8")         # before the file is touched
    except UnicodeEncodeError:
        raise ServiceError(422, "not_encodable", "The result holds characters that cannot be "
                           "written as UTF-8; the file was not changed.") from None
    try:
        _replace_file(target, data)
    except OSError as exc:
        raise ServiceError(500, "write_failed", f"Could not write the file "
                           f"({exc.strerror or type(exc).__name__}); it was not changed.") from None


def write_result(body: Any) -> dict:
    """Write a verified hardening result, exactly as reviewed, to the file it came from
    (local app only). The file must still hold the code that was hardened."""
    body = _need_obj(body)
    result_id = _str(body, "result_id", max_len=100, required=True)
    path = _str(body, "path", max_len=500, required=True)
    with _verified_lock:
        entry = _VERIFIED.get(result_id)
    if entry is None:
        raise ServiceError(404, "result_not_found", "That result is no longer available; "
                           "run Harden again.")
    _write_verified(path, *entry)
    with _verified_lock:
        _VERIFIED.pop(result_id, None)
    return {"written": True, "path": path}


def read_file(body: Any) -> dict:
    """Read a text file by path so the local app can open it (local app only)."""
    body = _need_obj(body)
    path = _str(body, "path", max_len=500, required=True)
    if not os.path.isfile(path):
        raise ServiceError(404, "not_found", "No such file.")
    limits = Limits.from_env()
    if os.path.getsize(path) > limits.max_chars * 4:
        raise ServiceError(413, "too_large", "File is too large to load.")
    with open(path, "rb") as fh:
        raw = fh.read()
    if b"\x00" in raw[:8192]:
        raise ServiceError(422, "binary", "That looks like a binary file.")
    text = _utf8(raw)
    if len(text) > limits.max_chars:
        raise ServiceError(413, "too_large", f"File has {len(text)} characters; the limit is {limits.max_chars}.")
    return {"path": path, "content": text, "language": language_for_path(path)}
