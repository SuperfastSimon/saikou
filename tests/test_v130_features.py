"""Frozen acceptance tests for Saikou v1.3.0 (all 5 features + security boundaries)."""

import hashlib
import io
import json
import os
import shutil
import subprocess
import tempfile
from datetime import date, timedelta
from pathlib import Path

import pytest

from saikou import cli, evidence, mcp, policy, sarif, treesitter
from saikou.engine import Finding, Severity, Tier
from saikou.verify import FileReport, verify_pair


# ---- 1. SARIF input (--from-sarif) -----------------------------------------------------

def test_load_sarif_claims_maps_rules_per_file():
    payload = {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "bandit"}},
            "results": [
                {
                    "ruleId": "B602",
                    "message": {"text": "subprocess call with shell=True identified"},
                    "locations": [{"physicalLocation": {"artifactLocation": {"uri": "src/run.py"}}}],
                },
                {
                    "ruleId": "B303",
                    "message": {"text": "Use of insecure MD5 hash function"},
                    "locations": [{"physicalLocation": {"artifactLocation": {"uri": "./src/auth.py"}}}],
                },
            ],
        }],
    }
    with tempfile.NamedTemporaryFile("w", suffix=".sarif", delete=False, encoding="utf-8") as fh:
        json.dump(payload, fh)
        path = fh.name
    try:
        per_file, global_threats = sarif.load_sarif_claims(path)
        assert "injection" in per_file["src/run.py"]
        assert "crypto" in per_file["src/auth.py"]
        assert "injection" in global_threats and "crypto" in global_threats
    finally:
        os.unlink(path)


def test_load_sarif_claims_rejects_traversal_and_oversized():
    bad = {
        "version": "2.1.0",
        "runs": [{
            "results": [{
                "ruleId": "B602",
                "message": {"text": "shell injection"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": "../escape.py"}}}],
            }],
        }],
    }
    with tempfile.NamedTemporaryFile("w", suffix=".sarif", delete=False, encoding="utf-8") as fh:
        json.dump(bad, fh)
        path = fh.name
    try:
        per_file, _ = sarif.load_sarif_claims(path)
        assert "../escape.py" not in per_file
        try:
            sarif.load_sarif_claims(path, max_bytes=10)
            assert False, "Expected ValueError on oversized SARIF"
        except ValueError:
            pass
    finally:
        os.unlink(path)


# ---- 2. Optional saikou[treesitter] extra ----------------------------------------------

def test_treesitter_graceful_fallback_when_unavailable():
    # In stdlib-only environment without tree_sitter installed, fallback must be clean
    if not treesitter.available("javascript"):
        rep = verify_pair(
            "function f(x) { return x; }\n",
            "function f(x) { const safe = sanitize(x); return x; }\n",
            path="app.js",
            language="javascript",
        )
        assert rep.tier is Tier.STRUCTURAL
        assert any(f.check == "js_guard_computed_but_unused" for f in rep.findings)


def test_treesitter_ast_path_with_stub_parser():
    class _FakeNode:
        def __init__(self, ntype, text, line, children=()):
            self.type = ntype
            self.text = text.encode("utf-8")
            self.start_point = (line - 1, 0)
            self.children = list(children)

    class _FakeTree:
        def __init__(self, root):
            self.root_node = root

    class _FakeParser:
        def parse(self, raw: bytes):
            decl = _FakeNode("variable_declarator", "safe = sanitize(x)", 2, [
                _FakeNode("identifier", "safe", 2),
                _FakeNode("call_expression", "sanitize(x)", 2),
            ])
            root = _FakeNode("program", raw.decode("utf-8"), 1, [decl])
            return _FakeTree(root)

    code = "function f(x) {\n  const safe = sanitize(x);\n  return x;\n}\n"
    findings, used_ast = treesitter.js_ts_ast_checks(code, "javascript", parser_override=_FakeParser())
    assert used_ast is True
    assert any(f.check == "js_guard_computed_but_unused" and f.line == 2 for f in findings), findings


# ---- 3. Signed Evidence Bundles --------------------------------------------------------

def test_evidence_bundle_sign_verify_and_tamper_detection():
    rep = FileReport("app.py", "python", Tier.AST_VERIFIED, "verify", [], ["suppression-delta"])
    key = "test-signing-key-at-least-16-bytes"
    bundle = evidence.build_evidence_bundle(
        [rep], "verify", base_sha="abc123",
        file_hashes={"app.py": ("sha_before", "sha_after")},
        signing_key=key,
    )
    assert bundle["schema"] == "saikou.evidence/v1"
    assert key not in json.dumps(bundle)
    assert bundle["signature"]["algorithm"] == "hmac-sha256"
    ok, msg = evidence.verify_evidence_bundle(bundle, signing_key=key)
    assert ok, msg

    # Wrong key fails
    ok_wrong, _ = evidence.verify_evidence_bundle(bundle, signing_key="different-signing-key-16-bytes")
    assert not ok_wrong

    # Tampering with payload fails
    tampered = json.loads(json.dumps(bundle))
    tampered["blocked"] = True
    ok_tamp, _ = evidence.verify_evidence_bundle(tampered, signing_key=key)
    assert not ok_tamp


def test_evidence_bundle_rejects_short_signing_key():
    rep = FileReport("app.py", "python", Tier.AST_VERIFIED, "verify", [], [])
    try:
        evidence.build_evidence_bundle([rep], "verify", signing_key="short")
        assert False, "Expected ValueError on short signing key"
    except ValueError:
        pass


# ---- 4. MCP Server & Sticky PR Comment -------------------------------------------------

def test_mcp_initialize_list_and_verify_call():
    req1 = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    req2 = json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
    req3 = json.dumps({
        "jsonrpc": "2.0", "id": 3, "method": "tools/call",
        "params": {
            "name": "saikou_verify",
            "arguments": {
                "path": "a.py",
                "before": "import subprocess\nsubprocess.run(c, shell=True)\n",
                "after": "import subprocess\nsubprocess.run(c, shell=True)  # nosec B602\n",
            },
        },
    })
    req4 = "not valid json"
    inp = io.StringIO("\n".join([req1, req2, req3, req4]) + "\n")
    out = io.StringIO()
    mcp.serve_stdio(inp, out)
    lines = [json.loads(ln) for ln in out.getvalue().splitlines() if ln.strip()]
    assert len(lines) == 4
    assert lines[0]["result"]["serverInfo"]["name"] == "saikou"
    tool_names = {t["name"] for t in lines[1]["result"]["tools"]}
    assert tool_names == {"saikou_verify", "saikou_verify_batch", "saikou_checks"}
    verify_payload = json.loads(lines[2]["result"]["content"][0]["text"])
    assert verify_payload["blocked"] is True
    assert lines[3]["error"]["code"] == -32700


def test_render_pr_comment_contains_sticky_marker():
    rep = FileReport("a.py", "python", Tier.AST_VERIFIED, "diff",
                     [Finding("sink_shell_true", Severity.HARD_FAIL, "shell=True", 10)], [])
    md = cli.render_pr_comment([rep], "diff abc123")
    assert "<!-- saikou-verify-comment -->" in md
    assert "sink_shell_true" in md


# ---- 5. Policy File (.saikou.toml) -----------------------------------------------------

def test_policy_active_and_expired_waivers():
    future = (date.today() + timedelta(days=30)).isoformat()
    past = (date.today() - timedelta(days=5)).isoformat()
    toml_text = (
        '[policy]\n'
        'strict_api = true\n'
        'warn_only = ["size_collapse"]\n'
        'must_preserve = ["public_fn"]\n\n'
        '[[waivers]]\n'
        'check = "sink_shell_true"\n'
        'path = "scripts/build.py"\n'
        'reason = "Controlled internal build script"\n'
        'owner = "sec-team"\n'
        f'expires = "{future}"\n\n'
        '[[waivers]]\n'
        'check = "sink_debug_true"\n'
        'path = "app.py"\n'
        'reason = "Temporary debug"\n'
        'owner = "dev"\n'
        f'expires = "{past}"\n'
    )
    with tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False, encoding="utf-8") as fh:
        fh.write(toml_text)
        p = fh.name
    try:
        pol = policy.load_policy(p)
        assert pol.strict_api is True
        assert pol.warn_only == ["size_collapse"]
        assert pol.must_preserve == ["public_fn"]

        rep_active = FileReport("scripts/build.py", "python", Tier.AST_VERIFIED, "modified",
                                [Finding("sink_shell_true", Severity.HARD_FAIL, "shell=True", 4)], [])
        rep_expired = FileReport("app.py", "python", Tier.AST_VERIFIED, "modified",
                                 [Finding("sink_debug_true", Severity.HARD_FAIL, "debug=True", 8)], [])
        notes = policy.apply_waivers([rep_active, rep_expired], pol)
        assert not rep_active.blocked
        assert rep_active.warnings and "[waived" in rep_active.warnings[0].detail
        assert rep_expired.blocked, "Expired waiver must NOT demote a hard fail"
        assert any("expired" in n.lower() for n in notes)
    finally:
        os.unlink(p)


def test_policy_rejects_waiver_without_reason_or_expires():
    bad = '[[waivers]]\ncheck = "sink_shell_true"\npath = "a.py"\n'
    with tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False, encoding="utf-8") as fh:
        fh.write(bad)
        p = fh.name
    try:
        try:
            policy.load_policy(p)
            assert False, "Expected PolicyError for incomplete waiver"
        except policy.PolicyError:
            pass
    finally:
        os.unlink(p)


# ---- 1.3.0 review fixes ----------------------------------------------------------------

needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")

_SAFE = "import subprocess\n\ndef run(x):\n    return subprocess.run([x])\n"
# the fake fix is assembled from parts: a literal marker in this file would be counted by the dogfood run
_FAKE = ("import subprocess\n\ndef run(x):\n    return subprocess.run(x, shell=True)  # "
         + "no" + "sec\n")


def _commit(repo: Path, files: dict) -> None:
    for name, text in files.items():
        (repo / name).parent.mkdir(parents=True, exist_ok=True)
        (repo / name).write_text(text, encoding="utf-8")
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-q", "-m", "c"], cwd=repo, check=True, capture_output=True)


@pytest.fixture
def two_commits(tmp_path, monkeypatch):
    def make(base: dict, change: dict) -> Path:
        for args in (["init", "-q", "-b", "main"], ["config", "user.email", "t@example.invalid"],
                     ["config", "user.name", "t"], ["config", "commit.gpgsign", "false"]):
            subprocess.run(["git", *args], cwd=tmp_path, check=True, capture_output=True)
        _commit(tmp_path, base)
        _commit(tmp_path, change)
        monkeypatch.chdir(tmp_path)
        return tmp_path
    return make


@needs_git
def test_diff_policy_added_by_the_change_cannot_loosen_its_own_gate(two_commits, capsys):
    two_commits({"app.py": _SAFE},
                {"app.py": _FAKE, ".saikou.toml": '[policy]\nexclude_paths = ["*"]\n'})
    code = cli.main(["diff", "--base", "HEAD~1", "--head", "HEAD", "--policy", ".saikou.toml"])
    out = capsys.readouterr().out
    assert code == 1
    assert "not in base commit" in out


@needs_git
def test_diff_policy_from_base_excludes_a_dot_directory(two_commits, capsys):
    two_commits({".github/s.py": _SAFE, ".saikou.toml": '[policy]\nexclude_paths = ["./.github/*"]\n'},
                {".github/s.py": _FAKE})
    code = cli.main(["diff", "--base", "HEAD~1", "--head", "HEAD", "--policy", ".saikou.toml"])
    out = capsys.readouterr().out
    assert code == 0, out
    assert "excluded by policy" in out and "read from base commit" in out


def test_norm_path_keeps_a_leading_dot():
    assert policy.norm_path("./.github/x.py") == ".github/x.py"
    assert policy.norm_path(".\\.eslintrc.js") == ".eslintrc.js"
    assert sarif._normalise_sarif_uri("./.github/a.py") == ".github/a.py"


def test_policy_accepts_a_toml_date_and_a_hash_inside_a_string():
    text = ('[[waivers]]\ncheck = "sink_shell_true"\npath = "a.py"\n'
            'reason = "build script, see #12"  # trailing comment\nowner = "sec"\n'
            'expires = 2027-06-01\n')
    pol = policy.parse_policy(text.encode())
    assert pol.waivers[0].expires == date(2027, 6, 1)
    assert pol.waivers[0].reason == "build script, see #12"
    fallback = policy._fallback_parse_toml(text)          # the Python 3.9/3.10 path
    assert fallback["waivers"][0]["expires"] == date(2027, 6, 1)
    assert fallback["waivers"][0]["reason"] == "build script, see #12"


class _Node:
    def __init__(self, ntype, text, line, children=()):
        self.type, self.text = ntype, text.encode("utf-8")
        self.start_point, self.children = (line - 1, 0), list(children)


class _Parser:
    def __init__(self, nodes):
        self.nodes = nodes

    def parse(self, raw):
        return type("T", (), {"root_node": _Node("program", raw.decode(), 1, self.nodes)})()


def test_treesitter_async_check_reads_only_the_condition():
    nodes = [
        _Node("function_declaration", "async function save(x) { return x; }", 1),
        _Node("if_statement", "if (ok) save(x);", 3),                 # body, not condition
        _Node("if_statement", "if (api.save(1)) { go(); }", 4),       # another object's method
        _Node("if_statement", "if (save(x)) { go(); }", 5),           # the real thing
        _Node("if_statement", "if (this.save(x)) { go(); }", 6),      # own method: real too
    ]
    findings, used = treesitter.js_ts_ast_checks("x", "javascript", parser_override=_Parser(nodes))
    assert used
    assert sorted(f.line for f in findings if f.check == "js_async_guard_in_boolean") == [5, 6]


def test_treesitter_findings_already_in_before_do_not_block(monkeypatch):
    def fake(code, _lang, **_kw):
        return ([Finding("js_async_guard_in_boolean", Severity.HARD_FAIL, "'g' is async", 1)]
                if "PATTERN" in code else []), True
    monkeypatch.setattr(treesitter, "available", lambda _lang: True)
    monkeypatch.setattr(treesitter, "js_ts_ast_checks", fake)
    old = verify_pair("let a = 1; // PATTERN\n", "let a = 1; // PATTERN\nlet b = 2;\n",
                      path="a.js", expect_change=False, change="modified")
    assert not old.blocked and old.tier is Tier.STRUCTURAL
    new = verify_pair("let a = 1;\n", "let a = 1; // PATTERN\n",
                      path="a.js", expect_change=False, change="modified")
    assert new.blocked


def test_treesitter_run_keeps_the_js_tier_structural(monkeypatch):
    monkeypatch.setattr(treesitter, "available", lambda _lang: True)
    monkeypatch.setattr(treesitter, "js_ts_ast_checks", lambda _code, _lang, **_kw: ([], True))
    rep = verify_pair("let a = 1;\n", "let a = 2;\n", path="a.js", expect_change=False, change="modified")
    assert rep.tier is Tier.STRUCTURAL
    assert "treesitter-js-ts-ast" in rep.checks


def test_mcp_never_replies_to_a_notification():
    assert mcp.handle_request(json.dumps({"jsonrpc": "2.0", "method": "notifications/cancelled"})) is None
    assert mcp.handle_request(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"})) is None


def test_evidence_key_id_is_not_a_plain_hash_of_the_key():
    key = "test-signing-key-at-least-16-bytes"
    rep = FileReport("app.py", "python", Tier.AST_VERIFIED, "verify", [], [])
    bundle = evidence.build_evidence_bundle([rep], "verify", signing_key=key)
    assert bundle["signature"]["key_id"] != hashlib.sha256(key.encode()).hexdigest()[:16]
    assert evidence.verify_evidence_bundle(bundle, signing_key=key)[0]


def test_action_posts_the_sticky_comment_it_writes():
    action = (Path(__file__).resolve().parents[1] / "action.yml").read_text(encoding="utf-8")
    assert "--pr-comment-file saikou-pr-comment.md" in action
    assert "body=@saikou-pr-comment.md" in action and "issues/comments" in action
    assert cli.PR_COMMENT_MARKER in action


def test_hmac_seal_states_it_is_not_a_public_key_signature():
    key = "test-signing-key-at-least-16-bytes"
    rep = FileReport("app.py", "python", Tier.AST_VERIFIED, "verify", [], [])
    bundle = evidence.build_evidence_bundle([rep], "verify", signing_key=key)
    assert "not a public-key signature" in bundle["signature"]["note"]


def test_banned_list_refuses_non_repudiation_wording():
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "check_site", Path(__file__).resolve().parents[1] / "scripts" / "check_site.py")
    check_site = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(check_site)
    assert check_site.banned_claims("x.html", "cryptographically signed evidence")
    assert check_site.banned_claims("x.html", "onweerlegbaar bewijs")
