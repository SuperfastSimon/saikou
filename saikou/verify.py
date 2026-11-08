"""Per-file verification and git change collection (standard library only)."""

from __future__ import annotations

import codecs
import difflib
import posixpath
import re
import subprocess
from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Sequence, Tuple

from .engine import (
    _SECURITY_RULE_NAMES,
    LANGUAGES,
    Finding,
    Severity,
    Tier,
    checks_run,
    diff_python_surface,
    language_for_file,
    language_for_path,
    normalise_language,
    normalise_threats,
    run_analyser,
    scan_transformation,
)

# How each check is established. Mirrors the ledger's provenance vocabulary so
# a reader always knows whether a line was parsed, counted, or tool-reported.
_PARSER_CHECKS = {
    "cosmetic_only_change", "parse_failure", "parse_skipped", "body_gutted",
    "guard_computed_but_unused", "shared_sink_injection_path", "api_break",
    "must_preserve_violated", "hardcoded_secret_material",
}
_TOOL_CHECKS = {"findings_suppressed_not_fixed", "new_analyser_findings"}


def provenance_of(check: str) -> str:
    if check in _TOOL_CHECKS:
        return "tool"
    if check in _PARSER_CHECKS or check.startswith("sink_"):
        return "parser"
    return "mechanical"


@dataclass
class FileReport:
    path: str
    language: str
    tier: Tier
    change: str                      # "verify" | "added" | "modified"
    findings: List[Finding] = field(default_factory=list)
    checks: List[str] = field(default_factory=list)
    api: Optional[dict] = None
    analyser: Optional[dict] = None

    @property
    def hard_fails(self) -> List[Finding]:
        return [f for f in self.findings if f.severity is Severity.HARD_FAIL]

    @property
    def warnings(self) -> List[Finding]:
        return [f for f in self.findings if f.severity is not Severity.HARD_FAIL]

    @property
    def blocked(self) -> bool:
        return bool(self.hard_fails)

    def as_dict(self) -> dict:
        return {
            "path": self.path, "language": self.language,
            "verification_tier": self.tier.value, "change": self.change,
            "blocked": self.blocked,
            "findings": [dict(f.as_dict(), provenance=provenance_of(f.check))
                         for f in self.findings],
            "checks_run": self.checks, "api_surface": self.api, "analyser": self.analyser,
        }


_TEST_DIRS = {"test", "tests", "testing"}
_TEST_FILE = re.compile(r"(?:test_.*|.*_test|conftest|tests)\.py")


def is_test_path(path: str) -> bool:
    """True for a repository-relative file under a test/tests/testing folder, and
    for test_*.py, *_test.py, conftest.py and tests.py (pytest's default file
    patterns). An absolute path, or one that climbs out with `..`, is never a
    test path: `/home/runner/work/test/app.py` and `tests/../app.py` are not tests."""
    norm = posixpath.normpath(path.replace("\\", "/"))
    if (not path or norm.startswith("/") or norm == ".." or norm.startswith("../")
            or re.match(r"[A-Za-z]:", norm)):
        return False
    parts = [p.lower() for p in norm.split("/") if p not in ("", ".")]
    if not parts:
        return False
    return any(p in _TEST_DIRS for p in parts[:-1]) or bool(_TEST_FILE.fullmatch(parts[-1]))


# Credential formats that are never fixture data. A literal like this still
# blocks, whatever file it is in.
_LIVE_CREDENTIAL = re.compile(
    r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b|\bgh[pousr]_[A-Za-z0-9]{36,}|\bgithub_pat_[A-Za-z0-9_]{22,}|"
    r"\bxox[abprs]-[A-Za-z0-9-]{10,}|\b[rs]k_live_[A-Za-z0-9]{16,}|\bAIza[0-9A-Za-z_-]{35}|"
    r"\bsk-(?:ant|proj)-[A-Za-z0-9_-]{20,}|-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----")


def _demote_test_secrets(findings: List[Finding], after: str) -> List[Finding]:
    """Gating only: a literal credential in a test file is almost always fixture
    data (`TOKEN = "t0ken-for-tests"`), so it warns instead of blocking the change.
    A recognisable provider key or private key still blocks."""
    lines = after.splitlines()

    def live(f: Finding) -> bool:
        if not f.line:
            return True                     # cannot inspect the value: keep blocking
        return bool(_LIVE_CREDENTIAL.search("\n".join(lines[f.line - 1:f.line + 3])))

    return [Finding(f.check, Severity.WARN,
                    "In a test file, so treated as fixture data and not blocking. If this is a "
                    "real credential, remove it and rotate it. " + f.detail, f.line, f.excerpt)
            if f.check == "hardcoded_secret_material" and f.severity is Severity.HARD_FAIL
            and not live(f) else f
            for f in findings]


def verify_pair(before: str, after: str, *, path: str, language: Optional[str] = None,
                claimed_threats: Sequence[str] = (), strict_api: bool = False,
                must_preserve: Sequence[str] = (), expect_change: bool = True,
                run_tools: bool = False, warn_only: Iterable[str] = (),
                change: str = "verify") -> FileReport:
    """Verify one before/after pair and return a report (no score, ever). Without
    `language`, the extension decides, else the `#!` line of `after`, else that of `before`."""
    lang = normalise_language(language) if language else language_for_file(path, after, before)
    _, tier = LANGUAGES[lang]
    claimed = normalise_threats(claimed_threats)
    findings = scan_transformation(before, after, language=lang, claimed_threats=claimed,
                                   expect_change=expect_change,
                                   expect_full_module=expect_change)
    if not expect_change and is_test_path(path):
        findings = _demote_test_secrets(findings, after)
    checks = checks_run(lang, expect_change=expect_change)
    report = FileReport(path, lang, tier, change, findings, checks)

    if lang == "python" and before.strip():
        diff = diff_python_surface(before, after)
        if diff.too_deep and not any(f.check == "parse_failure" for f in findings):
            # The scan got through, this deeper call did not: still not analysed.
            findings.append(Finding("parse_failure", Severity.HARD_FAIL, diff.parse_error or ""))
        if diff.parsed:
            report.api = diff.as_dict()
            checks.append("api-surface")
            if strict_api and diff.breaks_api:
                findings.append(Finding(
                    "api_break", Severity.HARD_FAIL,
                    f"--strict-api: {len(diff.removed)} public symbol(s) removed and "
                    f"{len(diff.changed)} signature(s) changed incompatibly."))
            violated = sorted({s for s in must_preserve
                               if any(r["name"] == s for r in diff.removed)
                               or any(c["name"] == s for c in diff.changed)})
            if violated:
                findings.append(Finding("must_preserve_violated", Severity.HARD_FAIL,
                                        "Symbols marked must-preserve were altered: "
                                        + ", ".join(violated)))

    if run_tools and lang == "python":
        b, a = run_analyser(before, lang), run_analyser(after, lang)
        if b.available and a.available:
            checks.append("bandit-twice")
            newly_suppressed = sorted(set(a.suppressed) - set(b.suppressed))
            introduced = sorted(set(a.findings) - set(b.findings))
            removed = sorted(set(b.findings) - set(a.findings))
            report.analyser = {"tool": "bandit --ignore-nosec", "removed": removed,
                               "introduced": introduced, "newly_suppressed": newly_suppressed}
            if newly_suppressed:
                findings.append(Finding(
                    "findings_suppressed_not_fixed", Severity.HARD_FAIL,
                    f"{len(newly_suppressed)} analyser finding(s) are newly hidden by "
                    f"suppressions: {'; '.join(newly_suppressed[:5])}"))
            if introduced:
                findings.append(Finding("new_analyser_findings", Severity.WARN,
                                        f"{len(introduced)} bandit finding(s) not present "
                                        f"before: {'; '.join(introduced[:5])}"))
        else:
            report.analyser = {"tool": "bandit", "available": False,
                               "note": (b.error or a.error or "unavailable")
                               + ". No analyser evidence was collected."}

    report.findings = _demote(findings, warn_only)
    return report


def _demote(findings: List[Finding], warn_only: Iterable[str]) -> List[Finding]:
    demote = set(warn_only)
    return [Finding(f.check, Severity.WARN, f"[demoted by --warn-only] {f.detail}", f.line,
                    f.excerpt) if f.check in demote and f.severity is Severity.HARD_FAIL else f
            for f in findings]


# ---------------------------------------------------------------------------
# analyser configuration changes (out-of-band suppression)
# ---------------------------------------------------------------------------

# Files whose only purpose is to exclude/ignore security findings.
_IGNORE_FILES = {".semgrepignore", ".gitleaksignore", ".trivyignore", ".snyk"}
_SECURITY_CONFIGS = {".bandit", "bandit.yaml", "bandit.yml", ".semgrep.yml", ".semgrep.yaml",
                     ".gitleaks.toml", "codeql-config.yml", "codeql-config.yaml"}
_SECTIONED = {"pyproject.toml", "setup.cfg", "tox.ini", ".flake8", "ruff.toml", ".ruff.toml",
              ".pylintrc", "pylintrc"}
_OTHER = {"sonar-project.properties", ".golangci.yml", ".golangci.yaml", "checkstyle.xml"}
_WEAKEN = re.compile(r"(?i)\b(?:skips?|exclude[sd]?|exclusions?|ignores?|ignored|disabled?|"
                     r"severity|confidence|nosec|baseline|per-file-ignores|extend-ignore|"
                     r"allowlist|whitelist|paths-ignore|off)\b")
_S_CODES = re.compile(r"""(?:["'\s,=\[]|^)S\d{0,3}(?:["'\s,\]]|$)""")


def _basename(path: str) -> str:
    return path.replace("\\", "/").rsplit("/", 1)[-1]


def is_analyser_config(path: str) -> bool:
    name = _basename(path)
    return (name in _IGNORE_FILES or name in _SECURITY_CONFIGS or name in _SECTIONED
            or name in _OTHER or name.startswith(".eslintrc")
            or name.startswith("eslint.config."))


def _added_lines(before: str, after: str) -> List[Tuple[int, str]]:
    a_lines = after.splitlines()
    sm = difflib.SequenceMatcher(None, before.splitlines(), a_lines, autojunk=False)
    added: List[Tuple[int, str]] = []
    for tag, _i1, _i2, j1, j2 in sm.get_opcodes():
        if tag in ("insert", "replace"):
            added += [(j + 1, a_lines[j]) for j in range(j1, j2)]
    return added


def _section_at(lines: List[str], line_no: int) -> str:
    for text in reversed(lines[:line_no]):
        m = re.match(r"\s*\[([^\]]+)\]", text)
        if m:
            return m.group(1).strip().lower()
    return ""


def config_weakening(path: str, before: str, after: str, change: str) -> FileReport:
    """Hard-fail changes that weaken a SECURITY analyser's configuration; warn on
    changes that relax style/type linters. Comments and unrelated keys are quiet."""
    name = _basename(path)
    after_lines = after.splitlines()
    findings: List[Finding] = []

    def hard(line: int, text: str, why: str) -> None:
        findings.append(Finding("analyser_config_weakened", Severity.HARD_FAIL,
                                f"{why} Suppression moved out of band is still suppression.",
                                line, text.strip()[:120]))

    def warn(line: int, text: str, why: str) -> None:
        findings.append(Finding("linter_config_relaxed", Severity.WARN, why, line,
                                text.strip()[:120]))

    for line, text in _added_lines(before, after):
        stripped = text.strip()
        if not stripped or stripped.startswith(("#", "//", ";")):
            continue
        if name in _IGNORE_FILES:
            hard(line, text, f"New entry in {name}, a file that exists to ignore findings.")
        elif name in _SECURITY_CONFIGS:
            if _WEAKEN.search(text):
                hard(line, text, f"Security analyser configuration in {name} now skips or "
                                 f"excludes more.")
        elif name in _SECTIONED:
            section = _section_at(after_lines, line)
            if not _WEAKEN.search(text) and not section.endswith(("ignores", "ignore")):
                continue
            if re.search(r"bandit|semgrep|codeql", section):
                hard(line, text, f"[{section}] in {name}: a security analyser now skips or "
                                 f"excludes more.")
            elif re.search(r"ruff|flake8", section) and (_S_CODES.search(text)
                                                          or "bandit" in text.lower()):
                codes = set(re.findall(r"\bS\d{3}\b", text))
                if codes and codes <= {"S101"}:
                    # assert-used, routinely allowed for test folders
                    warn(line, text, f"[{section}] in {name}: S101 (assert) ignored.")
                else:
                    hard(line, text, f"[{section}] in {name}: security (S/bandit) rules are "
                                     f"now ignored.")
            elif re.search(r"ruff|flake8|pylint|mypy|pyright|pycodestyle|isort", section):
                warn(line, text, f"[{section}] in {name}: a style/type linter was relaxed.")
        elif name.startswith(".eslintrc") or name.startswith("eslint.config."):
            if _SECURITY_RULE_NAMES.search(text) and re.search(r"""(?i)["']?(?:off|0)["']?""", text):
                hard(line, text, f"A security lint rule is switched off in {name}.")
            elif _WEAKEN.search(text):
                warn(line, text, f"ESLint configuration relaxed in {name}.")
        elif name == "sonar-project.properties":
            if re.search(r"sonar\.(?:exclusions|issue\.ignore)", text):
                hard(line, text, "Sonar now excludes or ignores more.")
        elif name.startswith(".golangci"):
            if "gosec" in text and _WEAKEN.search(text):
                hard(line, text, f"gosec is disabled or excluded in {name}.")
            elif _WEAKEN.search(text):
                warn(line, text, f"golangci-lint configuration relaxed in {name}.")
        elif _WEAKEN.search(text):
            warn(line, text, f"Lint configuration relaxed in {name}.")
    return FileReport(path, "config", Tier.STRUCTURAL, change, findings,
                      ["analyser-config-diff"])


# ---------------------------------------------------------------------------
# git
# ---------------------------------------------------------------------------

class GitError(RuntimeError):
    pass


MAX_FILE_BYTES = 1_000_000


def _git(args: Sequence[str], cwd: Optional[str] = None) -> bytes:
    try:
        proc = subprocess.run(["git", *args], cwd=cwd, capture_output=True, timeout=120)
    except FileNotFoundError:
        raise GitError("git is not installed or not on PATH") from None
    except subprocess.TimeoutExpired:
        raise GitError("git timed out") from None
    if proc.returncode != 0:
        raise GitError(proc.stderr.decode("utf-8", "replace").strip() or f"git {args[0]} failed")
    return proc.stdout


_BOMS = ((codecs.BOM_UTF32_LE, "utf-32"), (codecs.BOM_UTF32_BE, "utf-32"),
         (codecs.BOM_UTF16_LE, "utf-16"), (codecs.BOM_UTF16_BE, "utf-16"))
_REGULAR = ("100644", "100755")


def _decode(data: bytes) -> Optional[str]:
    """Text, or None for content that is not text or is over the size limit. UTF-16 and
    UTF-32 with a byte-order mark are text, so their NUL bytes do not count."""
    if len(data) > MAX_FILE_BYTES:
        return None
    for bom, codec in _BOMS:
        if data.startswith(bom):
            return data.decode(codec, "replace")
    if b"\x00" in data[:8192]:
        return None
    return data.decode("utf-8", "replace")


def _not_text(data: bytes) -> str:
    return (f"more than {MAX_FILE_BYTES} bytes" if len(data) > MAX_FILE_BYTES
            else "a NUL byte in the first 8 KB")


@dataclass
class ChangedFile:
    path: str
    change: str              # "added" | "modified"
    before: Optional[str]    # None (both sides) when the new content could not be checked
    after: Optional[str]
    unreadable: str = ""     # why not; such a file is reported with unreadable_report()
    language: str = ""       # from the extension or the `#!` line ("" = not determined)


def unreadable_report(cf: ChangedFile, warn_only: Iterable[str] = ()) -> FileReport:
    """Gating: a changed file Saikou would check, whose new content it could not read.

    It blocks rather than being skipped: one NUL byte in a comment, padding past the size
    limit, or a symlink in place of the file used to let the change through unchecked. The
    tier is `asserted`, because nothing was parsed."""
    lang = ("config" if is_analyser_config(cf.path)
            else cf.language or language_for_path(cf.path))
    what = "file" if lang == "unknown" else f"{lang} file"
    findings = [Finding(
        "content_not_checked", Severity.HARD_FAIL,
        f"Not checked: {cf.unreadable}. Skipping a changed {what} would let the change through "
        "unchecked, so it blocks. If the file is meant to be like this (a vendored bundle, "
        f"say), leave it out of the check with a pathspec: -- . ':(exclude){cf.path}'.")]
    return FileReport(cf.path, lang, Tier.ASSERTED, cf.change, _demote(findings, warn_only),
                      ["content-readable"])


def changed_files(base: str, *, head: Optional[str] = None, staged: bool = False,
                  merge_base: bool = True, paths: Sequence[str] = (),
                  cwd: Optional[str] = None,
                  include_unknown: bool = False) -> Tuple[str, List[ChangedFile], List[str]]:
    """Files added, modified or changed in type between `base` and HEAD, the index, or the
    work tree.

    Returns (resolved base sha, files, notes). With `merge_base` the comparison starts at
    the merge base, which is what a pull request shows. Deleted files are skipped: there is
    nothing left to verify. The language comes from the extension or, when that is not
    recognised, from the `#!` line of the new version, else of the old one (an executable
    script without an extension); it is returned in `language`. A file in a checked
    language or an analyser config file (any file with `include_unknown`) whose new content
    cannot be checked - not text, over the size limit, unreadable, or now a symlink or
    submodule - is returned with `unreadable` set and no content, so the caller reports it
    as blocking; other such files are skipped with a note. When only the old version is not
    text, the new one is checked as if the file were new, so everything in it counts as
    introduced.
    """
    ref = (head or "HEAD") if merge_base else base
    base_sha = _git(["rev-parse", "--verify", base + "^{commit}"], cwd).decode().strip()
    if merge_base:
        base_sha = _git(["merge-base", base_sha, ref], cwd).decode().strip()

    # --raw gives the file modes, so a symlink replaced by a file (status T) is seen too.
    args = ["diff", "--raw", "-z", "--no-renames", "--diff-filter=AMT"]
    if staged:
        args.append("--cached")
    args.append(base_sha)
    if head:
        args.append(head)
    if paths:
        args += ["--", *paths]
    raw = _git(args, cwd).split(b"\x00")
    entries = []
    for i in range(0, len(raw) - 1, 2):
        meta = raw[i].decode().lstrip(":").split()
        if len(meta) == 5:
            old_mode, new_mode, _, _, status = meta
            entries.append((old_mode, new_mode, status[0], raw[i + 1].decode("utf-8", "replace")))

    files: List[ChangedFile] = []
    notes: List[str] = []
    for old_mode, new_mode, status, path in entries:
        change = "added" if status == "A" else "modified"
        before_bytes = (b"" if status == "A" or old_mode not in _REGULAR
                        else _git(["show", f"{base_sha}:{path}"], cwd))
        always = include_unknown or is_analyser_config(path)
        if new_mode not in _REGULAR:
            kind = "a symbolic link" if new_mode == "120000" else "a submodule"
            lang = language_for_file(path, before_bytes)
            if always or lang != "unknown":
                files.append(ChangedFile(path, change, None, None, f"the path is now {kind}",
                                         language=lang))
            else:
                notes.append(f"{path}: {kind}, not a file")
            continue
        if head:
            after_bytes = _git(["show", f"{head}:{path}"], cwd)
        elif staged:
            after_bytes = _git(["show", f":{path}"], cwd)
        else:
            root = _git(["rev-parse", "--show-toplevel"], cwd).decode().strip()
            try:
                with open(f"{root}/{path}", "rb") as fh:
                    after_bytes = fh.read()
            except OSError:
                lang = language_for_file(path, before_bytes)
                if always or lang != "unknown":
                    files.append(ChangedFile(path, change, None, None,
                                             "unreadable in the work tree", language=lang))
                else:
                    notes.append(f"{path}: unreadable in the work tree")
                continue
        # The `#!` line is read from the raw bytes, as the kernel does, so a NUL byte further
        # down or padding past the size limit cannot make a script look unknown.
        lang = language_for_file(path, after_bytes, before_bytes)
        after_text = _decode(after_bytes)
        if after_text is None:
            if always or lang != "unknown":
                files.append(ChangedFile(path, change, None, None,
                                         f"the new version has {_not_text(after_bytes)}",
                                         language=lang))
            else:
                notes.append(f"{path}: binary or larger than {MAX_FILE_BYTES} bytes")
            continue
        before_text = _decode(before_bytes)
        if before_text is None:
            notes.append(f"{path}: the old version has {_not_text(before_bytes)}; the new "
                         "version was checked as if the file were new")
            before_text = ""
        files.append(ChangedFile(path, change, before_text, after_text, language=lang))
    return base_sha, files, notes
