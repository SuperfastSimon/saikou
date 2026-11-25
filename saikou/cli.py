"""saikou - command line.

    saikou verify BEFORE AFTER        verify one claimed fix (exit 1 if it is fake)
    saikou diff --base origin/main    gate a change set (exit 1 on introduced evasions)
    saikou harden FILE                bring-your-own-key hardening, verified before writing
    saikou selftest                   run the engine's own checks
    saikou ui                         the local app in your browser (127.0.0.1 only)

Exit codes: 0 = no hard fail, 1 = at least one hard fail, 2 = usage or runtime error.
"""

from __future__ import annotations

import argparse
import difflib
import json
import os
import sys
from typing import List, Optional, Sequence

from .engine import (
    THREAT_CHOICES,
    Contract,
    Severity,
    __version__,
    _selftest,
    detect_language,
    language_for_file,
    normalise_language,
    normalise_threats,
)
from .verify import (
    FileReport,
    GitError,
    changed_files,
    config_weakening,
    is_analyser_config,
    provenance_of,
    unreadable_report,
    verify_pair,
)

EXIT_OK, EXIT_BLOCKED, EXIT_ERROR = 0, 1, 2

READING_GUIDE = ("No score. Each finding says how it was established (tool / parser / "
                 "mechanical). Absence of a finding is not evidence of a fix.")


def _read(path: str) -> str:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()


def _csv(value: Optional[str]) -> List[str]:
    return [v.strip() for v in (value or "").split(",") if v.strip()]


def _threats(value: Optional[str]) -> List[str]:
    raw = _csv(value)
    mapped = normalise_threats(raw)
    if raw and not mapped:
        raise SystemExit(_usage_error(
            f"--claimed-threats: none of {raw!r} map to a known threat class. Valid: "
            + ", ".join(THREAT_CHOICES)))
    return mapped


def _usage_error(msg: str) -> int:
    print(f"saikou: error: {msg}", file=sys.stderr)
    return EXIT_ERROR


# ---------------------------------------------------------------------------
# rendering
# ---------------------------------------------------------------------------

def render_text(reports: Sequence[FileReport], mode: str, notes: Sequence[str] = ()) -> str:
    lines: List[str] = []
    for r in reports:
        state = "BLOCKED" if r.blocked else "ok"
        lines.append(f"{state:<8}{r.path}  [{r.language} · {r.tier.value} · {r.change}]")
        for f in sorted(r.findings, key=lambda x: (x.severity is not Severity.HARD_FAIL,
                                                   x.line or 0)):
            sev = "HARD FAIL" if f.severity is Severity.HARD_FAIL else "warn"
            where = f" L{f.line}" if f.line else ""
            lines.append(f"  {sev:<9} [{provenance_of(f.check)}] {f.check}{where}: {f.detail}")
        if r.api and (r.api.get("removed") or r.api.get("changed_signature")):
            lines.append(f"  api       removed={[s['name'] for s in r.api['removed']]} "
                         f"changed={[c['name'] for c in r.api['changed_signature']]}")
    for note in notes:
        lines.append(f"skipped  {note}")
    hard = sum(len(r.hard_fails) for r in reports)
    warn = sum(len(r.warnings) for r in reports)
    blocked = sum(1 for r in reports if r.blocked)
    lines.append("")
    lines.append(f"saikou {mode}: {len(reports)} file(s), {blocked} blocked, "
                 f"{hard} hard fail(s), {warn} warning(s).")
    lines.append(READING_GUIDE)
    return "\n".join(lines)


def render_json(reports: Sequence[FileReport], mode: str, notes: Sequence[str] = ()) -> str:
    return json.dumps({
        "saikou": __version__, "mode": mode,
        "blocked": any(r.blocked for r in reports),
        "files": [r.as_dict() for r in reports], "skipped": list(notes),
        "reading_guide": READING_GUIDE,
    }, indent=2)


def render_markdown(reports: Sequence[FileReport], mode: str) -> str:
    blocked = [r for r in reports if r.blocked]
    head = "### Saikou: " + (f"{len(blocked)} file(s) blocked" if blocked
                             else "no introduced evasions found")
    out = [head, "", f"Checked {len(reports)} file(s) in `{mode}` mode. {READING_GUIDE}", ""]
    rows = [(r, f) for r in reports for f in r.findings]
    if rows:
        out += ["| Severity | File | Check | How established | Detail |",
                "|---|---|---|---|---|"]
        for r, f in sorted(rows, key=lambda rf: rf[1].severity is not Severity.HARD_FAIL):
            sev = "**hard fail**" if f.severity is Severity.HARD_FAIL else "warning"
            loc = f"{r.path}:{f.line}" if f.line else r.path
            detail = f.detail.replace("|", "\\|").replace("\n", " ")[:220]
            out.append(f"| {sev} | `{loc}` | `{f.check}` | {provenance_of(f.check)} | {detail} |")
    return "\n".join(out) + "\n"


PR_COMMENT_MARKER = "<!-- saikou-verify-comment -->"


def render_pr_comment(reports: Sequence[FileReport], mode: str) -> str:
    return PR_COMMENT_MARKER + "\n" + render_markdown(reports, mode)


def _emit(reports: List[FileReport], args: argparse.Namespace, mode: str,
          notes: Sequence[str] = (), *, base_sha: str = "",
          file_hashes: Optional[dict] = None) -> int:
    if args.format == "json":
        print(render_json(reports, mode, notes))
    elif args.format == "sarif":
        from .sarif import to_sarif
        print(json.dumps(to_sarif(reports), indent=2))
    else:
        print(render_text(reports, mode, notes))
    if getattr(args, "sarif_file", None):
        from .sarif import to_sarif
        with open(args.sarif_file, "w", encoding="utf-8") as fh:
            json.dump(to_sarif(reports), fh, indent=2)
    if getattr(args, "summary", None):
        with open(args.summary, "a", encoding="utf-8") as fh:
            fh.write(render_markdown(reports, mode))
    if getattr(args, "pr_comment_file", None):
        with open(args.pr_comment_file, "w", encoding="utf-8") as fh:
            fh.write(render_pr_comment(reports, mode))
    if getattr(args, "evidence_file", None):
        from .evidence import build_evidence_bundle
        signing_key = os.getenv("SAIKOU_SIGNING_KEY") or None
        try:
            bundle = build_evidence_bundle(
                reports, mode, base_sha=base_sha, skipped=notes,
                file_hashes=file_hashes, signing_key=signing_key)
        except ValueError as exc:
            return _usage_error(str(exc))
        with open(args.evidence_file, "w", encoding="utf-8") as fh:
            json.dump(bundle, fh, indent=2)
    return EXIT_BLOCKED if any(r.blocked for r in reports) else EXIT_OK


# ---------------------------------------------------------------------------
# commands
# ---------------------------------------------------------------------------

def _load_cli_policy(args: argparse.Namespace):
    path = getattr(args, "policy", None)
    if not path:
        return None
    from .policy import PolicyError, load_policy
    try:
        return load_policy(path)
    except PolicyError as exc:
        raise SystemExit(_usage_error(f"--policy: {exc}"))


def _load_base_policy(args: argparse.Namespace, base_sha: str):
    """In change gating the policy comes from the BASE commit, never from the change itself:
    otherwise a pull request could add `exclude_paths = ["*"]` or a waiver and pass its own gate.
    Returns (policy or None, notes)."""
    path = getattr(args, "policy", None)
    if not path:
        return None, []
    from .policy import PolicyError, parse_policy
    from .verify import _git
    rel = os.path.relpath(path) if os.path.isabs(path) else path
    rel = rel.replace("\\", "/")
    spec = rel if rel.startswith(("./", "../")) else "./" + rel
    try:
        raw = _git(["show", f"{base_sha}:{spec}"])
    except GitError:
        return None, [f"--policy {path}: not in base commit {base_sha[:12]}, so not applied "
                      f"(a policy takes effect once it is merged)"]
    try:
        return parse_policy(raw), [f"policy {path} read from base commit {base_sha[:12]}"]
    except PolicyError as exc:
        raise SystemExit(_usage_error(f"--policy (base commit {base_sha[:12]}): {exc}"))


def _load_cli_sarif(args: argparse.Namespace):
    path = getattr(args, "from_sarif", None)
    if not path:
        return {}, []
    from .sarif import load_sarif_claims
    try:
        return load_sarif_claims(path)
    except ValueError as exc:
        raise SystemExit(_usage_error(f"--from-sarif: {exc}"))


def cmd_verify(args: argparse.Namespace) -> int:
    from .engine import sha256
    from .policy import apply_waivers, norm_path

    try:
        before, after = _read(args.before), _read(args.after)
    except OSError as exc:
        return _usage_error(str(exc))
    pol = _load_cli_policy(args)
    sarif_map, sarif_global = _load_cli_sarif(args)
    norm_after = norm_path(args.after)
    claimed = list(_threats(args.claimed_threats))
    for cls in (sarif_map.get(norm_after) or sarif_global) + (pol.claimed_threats if pol else []):
        if cls not in claimed:
            claimed.append(cls)
    strict_api = args.strict_api or (pol.strict_api if pol else False)
    must_preserve = _csv(args.must_preserve) + (pol.must_preserve if pol else [])
    warn_only = _csv(args.warn_only) + (pol.warn_only if pol else [])
    report = verify_pair(
        before, after, path=args.after, language=args.language or None,
        claimed_threats=claimed, strict_api=strict_api,
        must_preserve=must_preserve, expect_change=True,
        run_tools=args.analyser, warn_only=warn_only)
    if not args.language and report.language == "unknown":
        # The AFTER name may be a temp file; fall back to the BEFORE extension.
        report = verify_pair(
            before, after, path=args.before, claimed_threats=claimed,
            strict_api=strict_api, must_preserve=must_preserve,
            expect_change=True, run_tools=args.analyser, warn_only=warn_only)
    notes = apply_waivers([report], pol) if pol else []
    hashes = {report.path: (sha256(before), sha256(after))}
    return _emit([report], args, "verify", notes, file_hashes=hashes)


def cmd_diff(args: argparse.Namespace) -> int:
    import fnmatch
    from .engine import sha256
    from .policy import apply_waivers, norm_path

    sarif_map, _ = _load_cli_sarif(args)
    try:
        base_sha, files, notes = changed_files(
            args.base, head=args.head or None, staged=args.staged,
            merge_base=not args.no_merge_base, paths=args.paths,
            include_unknown=args.include_unknown)
    except GitError as exc:
        return _usage_error(f"git: {exc}")
    pol, pol_notes = _load_base_policy(args, base_sha)
    notes = list(notes) + pol_notes
    base_claimed = list(_threats(args.claimed_threats))
    if pol:
        for cls in pol.claimed_threats:
            if cls not in base_claimed:
                base_claimed.append(cls)
    strict_api = args.strict_api or (pol.strict_api if pol else False)
    must_preserve = _csv(args.must_preserve) + (pol.must_preserve if pol else [])
    warn_only = _csv(args.warn_only) + (pol.warn_only if pol else [])
    reports: List[FileReport] = []
    file_hashes: dict = {}
    for cf in files:
        rel = norm_path(cf.path)
        if pol and any(fnmatch.fnmatch(rel, pat) for pat in pol.exclude_paths):
            notes.append(f"{cf.path}: excluded by policy")
            continue
        if cf.unreadable:
            reports.append(unreadable_report(cf, warn_only))
            continue
        if is_analyser_config(cf.path):
            reports.append(config_weakening(cf.path, cf.before, cf.after, cf.change, warn_only))
            file_hashes[cf.path] = (sha256(cf.before or ""), sha256(cf.after or ""))
            continue
        file_claimed = list(base_claimed)
        for cls in sarif_map.get(rel, ()):
            if cls not in file_claimed:
                file_claimed.append(cls)
        report = verify_pair(
            cf.before, cf.after, path=cf.path, language=cf.language or None,
            claimed_threats=file_claimed,
            strict_api=strict_api, must_preserve=must_preserve,
            expect_change=False, run_tools=args.analyser, warn_only=warn_only,
            change=cf.change)
        if report.language == "unknown" and not args.include_unknown:
            notes.append(f"{cf.path}: language not recognised (use --include-unknown)")
            continue
        reports.append(report)
        file_hashes[cf.path] = (sha256(cf.before or ""), sha256(cf.after or ""))
    if pol:
        notes.extend(apply_waivers(reports, pol))
    return _emit(reports, args, f"diff {base_sha[:12]}", notes,
                 base_sha=base_sha, file_hashes=file_hashes)


def cmd_harden(args: argparse.Namespace) -> int:
    from .llm import PROVIDERS, LLMConfig, LLMError, checked_endpoint, load_env_file, run_hardening

    try:
        with open(args.file, "rb") as fh:
            original = fh.read()
        # Strict, unlike _read: this file may be rewritten, and a byte replaced here would be
        # lost for good. Newlines as text mode reads them, without a byte-order mark; both go
        # back on write.
        current_text = original.decode("utf-8")
        code = current_text[current_text.startswith(chr(0xFEFF)):].replace("\r\n", "\n").replace("\r", "\n")
    except UnicodeDecodeError:
        return _usage_error(f"{args.file} is not UTF-8. saikou harden rewrites only UTF-8 files, "
                            f"so that no character is lost; convert it first.")
    except OSError as exc:
        return _usage_error(str(exc))
    # Names only are ever tracked; values stay in the env. Keys and model names only: an
    # endpoint never comes from a .env file.
    load_env_file(args.env_file, allow=[args.api_key_env] if args.api_key_env else ())
    provider = args.provider or os.getenv("LLM_PROVIDER") or "openai"
    if provider not in PROVIDERS:
        return _usage_error(f"unknown provider {provider!r}; choose from {sorted(PROVIDERS)}")
    try:
        config = LLMConfig.from_env(api_key_env=args.api_key_env, provider=provider,
                                    base_url=args.base_url, model=args.model)
    except LLMError as exc:
        return _usage_error(str(exc))
    if args.model:
        config.model = args.model
    contract = Contract(threat_model=_threats(args.threat), compat=args.compat,
                        dependencies=args.dependencies, error_policy=args.error_policy,
                        must_preserve=_csv(args.must_preserve), notes=args.notes or "")
    # Language from --language, else the file extension or `#!` line, else a content guess.
    # (Passing the raw path used to resolve to "unknown", which silently skipped every Python
    # check.)
    language = (normalise_language(args.language) if args.language
                else language_for_file(args.file, code))
    if language == "unknown":
        language = detect_language(code).language
    try:                                  # check the endpoint before naming it
        endpoint, loopback = checked_endpoint(config.base_url)
    except LLMError as exc:
        return _usage_error(str(exc))
    where = ("locally on this machine; nothing leaves it" if loopback
             else f"at {endpoint} (your key, that provider's data terms)")
    print(f"saikou harden: asking {config.model} {where} ...", file=sys.stderr)
    try:
        result = run_hardening(code, language, contract, config, run_tools=not args.no_analyser)
    except LLMError as exc:
        return _usage_error(f"model call failed: {exc}")

    if args.format == "json":
        print(json.dumps(result.as_dict(), indent=2))
    else:
        led = result.ledger
        print(f"{'REJECTED' if result.blocked else 'VERIFIED'}  {args.file}  "
              f"[{result.language} · {result.tier.value}]")
        for f in led.findings:
            sev = "HARD FAIL" if f.severity is Severity.HARD_FAIL else "warn"
            where = f" L{f.line}" if f.line else ""
            print(f"  {sev:<9} [{provenance_of(f.check)}] {f.check}{where}: {f.detail}")
        for c in led.claims:
            if c.provenance.value == "model":
                print(f"  model     (unverified) {c.statement}")
        print("")
        diff = difflib.unified_diff(code.splitlines(True), result.proposed.splitlines(True),
                                    fromfile=f"a/{args.file}",
                                    tofile=f"b/{args.file}" + (" (REJECTED)" if result.blocked else ""))
        sys.stdout.writelines(diff)
        print("")
        print(READING_GUIDE)

    if result.blocked:
        print("Not written: verification blocked this output. The diff above is the "
              "rejected attempt, shown so you can decide.", file=sys.stderr)
        return EXIT_BLOCKED
    if args.write:
        from .service import _replace_file, text_in_file_style

        target = os.path.realpath(args.file)     # through a symlink, as an in-place write would
        try:
            with open(target, "rb") as fh:
                changed = fh.read() != original
            if changed:
                print(f"Not written: {args.file} changed while the model was working. Run "
                      f"saikou harden again on the new version.", file=sys.stderr)
                return EXIT_ERROR
            _replace_file(target, text_in_file_style(current_text, result.proposed).encode("utf-8"))
        except (OSError, UnicodeEncodeError) as exc:
            print(f"Not written: {type(exc).__name__}: {exc}. The file is as it was.",
                  file=sys.stderr)
            return EXIT_ERROR
        print(f"Written: {args.file}", file=sys.stderr)
    else:
        print("Dry run: re-run with --write to apply this verified change.", file=sys.stderr)
    return EXIT_OK


def cmd_selftest(_args: argparse.Namespace) -> int:
    return _selftest()


def cmd_mcp(_args: argparse.Namespace) -> int:
    from .mcp import serve_stdio
    return serve_stdio()


def cmd_ui(args: argparse.Namespace) -> int:
    from .llm import load_env_file
    from .server import serve

    load_env_file(args.env_file)          # provider keys for Harden; values are never shown
    try:
        return serve(port=args.port, open_browser=not args.no_browser, repo=args.repo,
                     verbose=args.verbose)
    except OSError as exc:
        return _usage_error(f"cannot listen on 127.0.0.1:{args.port}: {exc}")


# ---------------------------------------------------------------------------
# parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="saikou", description="Prove that a security fix is real, not just claimed.",
        epilog=READING_GUIDE)
    p.add_argument("--version", action="version", version=f"saikou {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    def common(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--claimed-threats", metavar="T,T",
                        help="threat classes the change claims to fix; a surviving sink of a "
                             "claimed class is a hard fail (" + ", ".join(THREAT_CHOICES) + ")")
        sp.add_argument("--strict-api", action="store_true",
                        help="treat removed or incompatibly changed public API as a hard fail")
        sp.add_argument("--must-preserve", metavar="SYM,SYM",
                        help="public symbols that must not change at all")
        sp.add_argument("--analyser", action="store_true",
                        help="also run bandit twice (normal and --ignore-nosec) for Python")
        sp.add_argument("--warn-only", metavar="CHECK,CHECK",
                        help="downgrade these checks from hard fail to warning")
        sp.add_argument("--format", choices=("text", "json", "sarif"), default="text")
        sp.add_argument("--sarif-file", metavar="PATH", help="also write SARIF 2.1.0 here")
        sp.add_argument("--summary", metavar="PATH",
                        help="append a Markdown summary (e.g. $GITHUB_STEP_SUMMARY)")
        sp.add_argument("--from-sarif", metavar="PATH",
                        help="derive per-file claimed threats from an existing SARIF 2.1.0 report")
        sp.add_argument("--policy", metavar="PATH",
                        help="repository policy and time-bounded waivers (.saikou.toml); in diff mode read "
                             "from the base commit, so a change cannot loosen its own gate")
        sp.add_argument("--evidence-file", metavar="PATH",
                        help="write an Evidence Bundle JSON; with SAIKOU_SIGNING_KEY set it carries a shared-key HMAC-SHA256 seal (tamper-evident, not a public-key signature)")
        sp.add_argument("--pr-comment-file", metavar="PATH",
                        help="write a sticky pull-request Markdown comment with marker")

    v = sub.add_parser("verify", help="verify one claimed fix: BEFORE vs AFTER")
    v.add_argument("before")
    v.add_argument("after")
    v.add_argument("--language", help="override language detection (default: file extension)")
    common(v)
    v.set_defaults(func=cmd_verify)

    d = sub.add_parser("diff", help="gate a git change set (pull request or local changes)")
    d.add_argument("--base", default="HEAD", help="base ref (default: HEAD)")
    d.add_argument("--head", help="head ref (default: the work tree, or the index with --staged)")
    d.add_argument("--staged", action="store_true", help="compare the index (pre-commit)")
    d.add_argument("--no-merge-base", action="store_true",
                   help="compare against BASE itself instead of the merge base")
    d.add_argument("--include-unknown", action="store_true",
                   help="also check files whose language is not recognised (by extension, "
                        "or by the #! line of a script without one)")
    d.add_argument("paths", nargs="*", help="limit to these paths")
    common(d)
    d.set_defaults(func=cmd_diff)

    h = sub.add_parser("harden", help="bring-your-own-key hardening, verified before writing")
    h.add_argument("file")
    h.add_argument("--language")
    h.add_argument("--threat", metavar="T,T", help="threat model (" + ", ".join(THREAT_CHOICES) + ")")
    h.add_argument("--compat", default="strict_api",
                   choices=("strict_api", "allow_signature_changes", "rewrite_freely"))
    h.add_argument("--dependencies", default="stdlib_only",
                   choices=("stdlib_only", "existing_only", "may_add"))
    h.add_argument("--error-policy", default="fail_closed",
                   choices=("fail_closed", "preserve_current"))
    h.add_argument("--must-preserve", metavar="SYM,SYM")
    h.add_argument("--notes", help="extra context for the model (treated as data)")
    h.add_argument("--provider", choices=sorted(("openai", "ollama", "local")),
                   help="openai = any OpenAI-compatible endpoint (default; $LLM_PROVIDER); "
                        "ollama = Ollama cloud, key in OLLAMA_API_KEY; "
                        "local = a model on this machine via Ollama, no key "
                        "(OLLAMA_LOCAL_API_KEY only if your local server needs one)")
    h.add_argument("--model", help="model id (default per provider; see OLLAMA_MODEL / "
                                   "OLLAMA_LOCAL_MODEL / LLM_MODEL)")
    h.add_argument("--base-url", help="override the endpoint (OpenAI-compatible, .../v1)")
    h.add_argument("--api-key-env", default=None,
                   help="NAME of the environment variable holding your key (never the key); "
                        "default depends on the provider")
    h.add_argument("--env-file", default=".env",
                   help="dotenv-style file with keys and model names (default ./.env; real "
                        "environment variables win over it; an endpoint is never read from it)")
    h.add_argument("--no-analyser", action="store_true", help="skip the bandit runs")
    h.add_argument("--write", action="store_true",
                   help="write the result in place - only ever when verification passed")
    h.add_argument("--format", choices=("text", "json"), default="text")
    h.set_defaults(func=cmd_harden)

    s = sub.add_parser("selftest", help="run the engine's own checks (no network)")
    s.set_defaults(func=cmd_selftest)

    m = sub.add_parser("mcp", help="run read-only MCP JSON-RPC 2.0 server over stdio")
    m.set_defaults(func=cmd_mcp)

    u = sub.add_parser("ui", help="open the local app in your browser (127.0.0.1 only)")
    u.add_argument("--port", type=int, default=0, help="port to listen on (default: a free one)")
    u.add_argument("--no-browser", action="store_true", help="print the link, do not open it")
    u.add_argument("--repo", metavar="PATH",
                   help="git repository for the Gate screen (default: the current folder)")
    u.add_argument("--env-file", default=".env",
                   help="dotenv-style file with provider keys and model names (default ./.env; "
                        "an endpoint is never read from it)")
    u.add_argument("--verbose", action="store_true", help="log every request to stderr")
    u.set_defaults(func=cmd_ui)
    return p


def main(argv: Optional[Sequence[str]] = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except (OSError, ValueError):
            pass
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except SystemExit as exc:
        return int(exc.code or 0)
    except KeyboardInterrupt:
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
