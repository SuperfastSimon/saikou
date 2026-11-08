"""saikou.service: the logic shared by the hosted API and the local app. No network."""

import argparse
import errno
import json
import os
import shutil
import stat
import subprocess

import pytest

from saikou import cli, engine, llm, service
from saikou.service import Limits, ServiceError

FAKE_BEFORE = "import subprocess\n\ndef run(cmd):\n    return subprocess.call(cmd, shell=True)\n"
FAKE_AFTER = ("import subprocess\n\ndef run(cmd):\n"
              "    return subprocess.call(cmd, shell=True)  # nosec\n")
REAL_AFTER = ("import shlex\nimport subprocess\n\ndef run(cmd):\n"
              "    return subprocess.call(shlex.split(cmd))\n")


def _codes(fn, body, **kw):
    with pytest.raises(ServiceError) as err:
        fn(body, **kw)
    return err.value.status, err.value.code


def test_verify_blocks_fake_and_passes_real():
    fake = service.verify({"path": "svc.py", "before": FAKE_BEFORE, "after": FAKE_AFTER,
                           "claimed_threats": ["injection"]})
    assert fake["blocked"] is True and fake["mode"] == "verify"
    f = fake["files"][0]
    assert f["language"] == "python" and f["counts"]["hard_fail"] >= 2
    assert "en" in f["tier_meaning"] and fake["limits"]
    real = service.verify({"path": "svc.py", "before": FAKE_BEFORE, "after": REAL_AFTER,
                           "claimed_threats": ["injection"]})
    assert real["blocked"] is False


def test_verify_reports_what_was_not_checked_for_js():
    out = service.verify({"path": "a.js", "before": "a();\n", "after": "b();\n"})
    ids = {c["id"] for c in out["files"][0]["not_checked"]}
    assert "sink_shell_true" in ids


def test_gate_mode_judges_config_files():
    out = service.verify({"mode": "gate", "path": "pyproject.toml",
                          "before": "[tool.bandit]\n", "after": "[tool.bandit]\nskips = [\"B602\"]\n"})
    assert out["blocked"] is True
    assert out["files"][0]["findings"][0]["check"] == "analyser_config_weakened"


def test_sarif_format():
    out = service.verify({"path": "svc.py", "before": FAKE_BEFORE, "after": FAKE_AFTER,
                          "format": "sarif"})
    assert out["version"] == "2.1.0" and out["runs"][0]["results"]


@pytest.mark.parametrize("body,expected", [
    ({"before": "x"}, (422, "missing_field")),
    ("not an object", (422, "bad_request")),
    ({"after": "x", "mode": "nope"}, (422, "bad_field")),
    ({"after": "x", "claimed_threats": ["zzz"]}, (422, "bad_field")),
    ({"after": "x", "language": "cobol"}, (422, "bad_field")),
    ({"after": "x", "strict_api": "yes"}, (422, "bad_field")),
    ({"after": 5}, (422, "bad_field")),
])
def test_verify_rejects_bad_input(body, expected):
    assert _codes(service.verify, body) == expected


def test_verify_enforces_size_limit():
    assert _codes(service.verify, {"after": "x" * 2001}, limits=Limits(max_chars=2000)) == (413, "too_large")


def test_batch_mixes_files_and_skips_unknown_languages():
    out = service.verify_batch({"files": [
        {"path": "svc.py", "before": FAKE_BEFORE, "after": FAKE_AFTER},
        {"path": "README.md", "before": "a", "after": "b"},
        {"path": "web/app.ts", "before": "a();\n", "after": "a();\nb();\n"},
    ]})
    assert out["mode"] == "gate" and out["blocked"] is True
    assert [f["path"] for f in out["files"]] == ["svc.py", "web/app.ts"]
    assert out["skipped"] == ["README.md: language not recognised"]


def test_batch_limits():
    assert _codes(service.verify_batch, {"files": []}) == (422, "missing_field")
    many = {"files": [{"path": f"f{i}.py", "after": "x = 1\n"} for i in range(3)]}
    assert _codes(service.verify_batch, many, limits=Limits(max_files=2)) == (413, "too_many_files")


@pytest.mark.parametrize("item", [
    {"path": "a.py", "before": 1, "after": "x = 1\n"},
    {"path": "a.py", "before": "x = 1\n", "after": 2},
    {"path": "a.py", "before": True, "after": "x = 1\n"},
    {"path": "a.py", "after": 1.5},
])
def test_batch_refuses_non_string_before_or_after(item):
    """Review finding 11: len() ran before the type check, so a number was a TypeError (500)."""
    assert _codes(service.verify_batch, {"files": [item]}) == (422, "bad_field")


def test_batch_refuses_an_entry_that_is_not_an_object():
    assert _codes(service.verify_batch, {"files": ["a.py"]}) == (422, "bad_field")


@pytest.fixture
def no_verification(monkeypatch):
    """Records every verification that starts; a test asserts none did."""
    started = []

    def record(*args, **kwargs):
        started.append(kwargs.get("path"))
        raise AssertionError("verification ran before the input was validated")

    monkeypatch.setattr(service, "verify_pair", record)
    monkeypatch.setattr(service, "config_weakening", record)
    return started


def test_format_is_checked_before_any_verification(no_verification):
    """Review finding 18: 'format' was checked only after every file had been verified."""
    one = {"path": "svc.py", "before": FAKE_BEFORE, "after": FAKE_AFTER, "format": "xml"}
    assert _codes(service.verify, one) == (422, "bad_field")
    batch = {"format": "xml", "files": [{"path": f"f{i}.py", "after": "x = 1\n"} for i in range(3)]}
    assert _codes(service.verify_batch, batch) == (422, "bad_field")
    assert no_verification == []


def test_batch_checks_every_file_before_verifying_any(no_verification):
    files = [{"path": "a.py", "after": "x = 1\n"}, {"path": "pyproject.toml", "after": "[tool.bandit]\n"},
             {"path": "b.py", "after": "x = 2\n", "claimed_threats": ["zzz"]}]
    assert _codes(service.verify_batch, {"files": files}) == (422, "bad_field")
    assert no_verification == []


def test_git_diff_checks_its_options_before_running_git(tmp_path, monkeypatch, no_verification):
    (tmp_path / ".git").mkdir()
    ran = []
    monkeypatch.setattr(service, "changed_files", lambda *a, **k: ran.append(1) or ("0" * 40, [], []))
    for bad in ({"format": "xml"}, {"strict_api": "yes"}, {"warn_only": "x"},
                {"must_preserve": [""]}, {"analyser": 1}):
        assert _codes(service.git_diff, {"repo": str(tmp_path), **bad}) == (422, "bad_field"), bad
    assert ran == [] and no_verification == []


def test_checks_catalogue_is_served():
    out = service.checks()
    assert len(out["checks"]) > 30 and "injection" in out["threat_classes"]
    assert set(out["provenance"]) == {"tool", "parser", "mechanical"}


def test_read_file(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n")
    (tmp_path / "b.bin").write_bytes(bytes([0, 1, 2, 3]))
    assert service.read_file({"path": str(tmp_path / "a.py")})["language"] == "python"
    assert _codes(service.read_file, {"path": str(tmp_path / "b.bin")}) == (422, "binary")
    assert _codes(service.read_file, {"path": str(tmp_path / "nope.py")}) == (404, "not_found")


# "# cafe" with an e-acute in cp1252: one byte (0xE9) that is not valid UTF-8 on its own.
CP1252_LINE = ("# caf" + chr(0xE9) + "\n").encode("cp1252")


def test_read_file_refuses_a_file_that_is_not_utf8(tmp_path):
    """Review finding 9: the bytes were replaced by U+FFFD, and a write then stored those."""
    path = tmp_path / "latin.py"
    path.write_bytes(CP1252_LINE)
    assert _codes(service.read_file, {"path": str(path)}) == (422, "not_utf8")
    utf8 = tmp_path / "utf8.py"
    utf8.write_bytes(("# caf" + chr(0xE9) + "\n").encode("utf-8"))
    assert service.read_file({"path": str(utf8)})["content"] == "# caf" + chr(0xE9) + "\n"


def test_providers_never_leak_keys(monkeypatch):
    monkeypatch.setenv("OLLAMA_API_KEY", "very-secret-key-value-42")
    monkeypatch.setattr(service, "_local_models", lambda url: {"reachable": False, "models": []})
    out = service.providers()
    assert "very-secret-key-value-42" not in json.dumps(out)
    ollama = next(p for p in out["providers"] if p["id"] == "ollama")
    assert ollama["key_set"] is True and ollama["strict_schema"] is False


# ---- harden (model call stubbed) ----------------------------------------------------------

def _reply(code: str) -> dict:
    payload = {"hardened_code": code, "changes": [], "assumptions": [],
               "deferred_defects": [{"issue": "x", "why_not_fixed": "y", "operating_limitation": "z"}]}
    return {"choices": [{"finish_reason": "stop", "message": {"content": json.dumps(payload)}}]}


@pytest.fixture
def target(tmp_path, monkeypatch):
    monkeypatch.setenv("LLM_API_KEY", "test-key-not-real")
    path = tmp_path / "svc.py"
    path.write_text(FAKE_BEFORE)
    return path


def _harden(target, **extra):
    return {"code": target.read_text(), "path": str(target), "provider": "openai",
            "threats": ["injection"], **extra}


def test_harden_writes_only_verified_output(target, monkeypatch):
    monkeypatch.setattr(llm, "_post", lambda *a, **k: _reply(REAL_AFTER))
    out = service.harden(_harden(target))
    assert out["status"] == "verified" and out["written"] is False
    assert target.read_text() == FAKE_BEFORE
    out = service.harden(_harden(target, write=True))
    assert out["written"] is True and target.read_text() == REAL_AFTER


def test_harden_never_writes_blocked_output(target, monkeypatch):
    monkeypatch.setattr(llm, "_post", lambda *a, **k: _reply(FAKE_AFTER))
    assert _codes(service.harden, _harden(target, write=True)) == (409, "blocked")
    assert target.read_text() == FAKE_BEFORE


def test_harden_refuses_to_overwrite_a_file_that_changed(target, monkeypatch):
    monkeypatch.setattr(llm, "_post", lambda *a, **k: _reply(REAL_AFTER))
    body = _harden(target, write=True)
    target.write_text(FAKE_BEFORE + "# edited elsewhere\n")
    assert _codes(service.harden, body) == (409, "file_changed")


def test_rejected_output_gets_no_result_id(target, monkeypatch):
    monkeypatch.setattr(llm, "_post", lambda *a, **k: _reply(FAKE_AFTER))
    out = service.harden(_harden(target))
    assert out["status"] == "rejected" and "result_id" not in out
    assert "+    return subprocess.call(cmd, shell=True)  # nosec" in out["diff"]


def test_write_result_refuses_a_file_that_changed(target, monkeypatch):
    monkeypatch.setattr(llm, "_post", lambda *a, **k: _reply(REAL_AFTER))
    rid = service.harden(_harden(target))["result_id"]
    target.write_text(FAKE_BEFORE + "# edited elsewhere\n")
    assert _codes(service.write_result, {"result_id": rid, "path": str(target)}) == (409, "file_changed")
    assert _codes(service.write_result, {"result_id": "nope", "path": str(target)}) == (404, "result_not_found")


def test_harden_unknown_provider():
    assert _codes(service.harden, {"code": "x = 1\n", "provider": "nope"}) == (422, "bad_field")


@pytest.fixture
def model_calls(target, monkeypatch):
    """A model that would answer with a verified fix; the list records every call."""
    calls = []

    def answer(*args, **kwargs):
        calls.append(1)
        return _reply(REAL_AFTER)

    monkeypatch.setattr(llm, "_post", answer)
    return calls


@pytest.mark.parametrize("key,value", [
    ("compat", "strict"), ("compat", "Strict_API"), ("compat", "strict_api\n"), ("compat", 5),
    ("dependencies", "anything"), ("error_policy", "fail_open"),
])
def test_harden_refuses_an_unknown_contract_value(target, model_calls, key, value):
    """Review finding 7: an unknown compat value silently switched off the API-break gate."""
    assert _codes(service.harden, _harden(target, **{key: value})) == (422, "bad_field")
    assert model_calls == []


def test_harden_contract_defaults(target, model_calls):
    for empty in ({}, {"compat": "", "dependencies": None, "error_policy": ""}):
        out = service.harden(_harden(target, **empty))
        assert out["status"] == "verified"
    assert len(model_calls) == 2


def test_contract_values_match_the_cli_and_the_intake_questions():
    harden = next(a for a in cli.build_parser()._actions
                  if isinstance(a, argparse._SubParsersAction)).choices["harden"]
    choices = {a.dest: tuple(a.choices) for a in harden._actions if a.choices}
    assert choices["compat"] == service.COMPAT_CHOICES
    assert choices["dependencies"] == service.DEPENDENCY_CHOICES
    assert choices["error_policy"] == service.ERROR_POLICY_CHOICES
    defaults = {a.dest: a.default for a in harden._actions}
    assert (defaults["compat"], defaults["dependencies"], defaults["error_policy"]) == (
        service.COMPAT_CHOICES[0], service.DEPENDENCY_CHOICES[0], service.ERROR_POLICY_CHOICES[0])
    det = engine.detect_language("def f():\n    return 1\n", "python")
    asked = {q["id"]: tuple(q["options"]) for q in engine.build_questions(det, None)
             if q["kind"] == "single" and q["id"] != "language"}
    assert asked == {"compat": service.COMPAT_CHOICES, "dependencies": service.DEPENDENCY_CHOICES,
                     "error_policy": service.ERROR_POLICY_CHOICES}
    contract = engine.Contract()
    assert (contract.compat, contract.dependencies, contract.error_policy) == (
        service.COMPAT_CHOICES[0], service.DEPENDENCY_CHOICES[0], service.ERROR_POLICY_CHOICES[0])


def test_harden_checks_write_before_asking_the_model(target, model_calls, tmp_path):
    assert _codes(service.harden, _harden(target, write="yes")) == (422, "bad_field")
    missing = {**_harden(target, write=True), "path": str(tmp_path / "gone.py")}
    assert _codes(service.harden, missing) == (422, "bad_field")
    loaded = _harden(target, write=True)
    target.write_text(FAKE_BEFORE + "# edited elsewhere\n")
    assert _codes(service.harden, loaded) == (409, "file_changed")
    assert model_calls == []


# ---- writing back (local app) ---------------------------------------------------------------

@pytest.fixture
def latin(tmp_path, monkeypatch):
    """A cp1252 file, and the text the old read_file handed to the app for it."""
    monkeypatch.setenv("LLM_API_KEY", "test-key-not-real")
    path = tmp_path / "latin.py"
    raw = FAKE_BEFORE.encode() + CP1252_LINE
    path.write_bytes(raw)
    return path, raw, raw.decode("utf-8", "replace")


def test_harden_never_writes_over_a_file_that_is_not_utf8(latin, monkeypatch):
    """Review finding 9: the e-acute byte became ef bf bd after Harden + write."""
    path, raw, loaded = latin
    calls = []
    monkeypatch.setattr(llm, "_post", lambda *a, **k: calls.append(1) or _reply(
        REAL_AFTER + loaded[len(FAKE_BEFORE):]))
    body = {"code": loaded, "path": str(path), "provider": "openai", "threats": ["injection"]}
    assert _codes(service.harden, {**body, "write": True}) == (422, "not_utf8")
    assert path.read_bytes() == raw and calls == []
    rid = service.harden(body)["result_id"]
    assert _codes(service.write_result, {"result_id": rid, "path": str(path)}) == (422, "not_utf8")
    assert path.read_bytes() == raw


def _disk_full_open(monkeypatch):
    """Files opened for writing in saikou.service write half their data, then fail."""
    real_open = open

    class HalfWritten:
        def __init__(self, fh):
            self._fh = fh

        def write(self, data):
            self._fh.write(data[: len(data) // 2])
            self._fh.flush()
            raise OSError(errno.ENOSPC, "No space left on device")

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            self._fh.close()
            return False

        def __getattr__(self, name):
            return getattr(self._fh, name)

    def fake_open(file, mode="r", *args, **kwargs):
        fh = real_open(file, mode, *args, **kwargs)
        return HalfWritten(fh) if "w" in mode else fh

    monkeypatch.setattr(service, "open", fake_open, raising=False)


def test_a_failed_write_leaves_the_file_as_it_was(target, monkeypatch):
    """Review finding 16: open(path, "w") emptied the file first; a full disk left it empty."""
    monkeypatch.setattr(llm, "_post", lambda *a, **k: _reply(REAL_AFTER))
    rid = service.harden(_harden(target))["result_id"]
    _disk_full_open(monkeypatch)
    with pytest.raises((ServiceError, OSError)) as err:
        service.write_result({"result_id": rid, "path": str(target)})
    assert target.read_text() == FAKE_BEFORE
    assert sorted(os.listdir(target.parent)) == ["svc.py"]
    assert isinstance(err.value, ServiceError) and err.value.code == "write_failed"


def test_a_failed_replace_leaves_the_file_and_no_temporary_file(target, monkeypatch):
    def refuse(src, dst):
        raise PermissionError(errno.EACCES, "Access is denied")

    monkeypatch.setattr(service.os, "replace", refuse)
    with pytest.raises(ServiceError) as err:
        service._write_verified(str(target), FAKE_BEFORE, REAL_AFTER)
    assert err.value.code == "write_failed"
    assert target.read_text() == FAKE_BEFORE
    assert sorted(os.listdir(target.parent)) == ["svc.py"]


def test_output_that_cannot_be_encoded_never_touches_the_file(target):
    # A lone surrogate can come out of json.loads; the bytes are made before the file is opened.
    with pytest.raises(ServiceError) as err:
        service._write_verified(str(target), FAKE_BEFORE, "x = '" + chr(0xD800) + "'\n")
    assert err.value.code == "not_encodable"
    assert target.read_text() == FAKE_BEFORE
    assert sorted(os.listdir(target.parent)) == ["svc.py"]


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
def test_write_keeps_the_file_mode(target):
    target.chmod(0o640)
    service._write_verified(str(target), FAKE_BEFORE, REAL_AFTER)
    assert target.read_text() == REAL_AFTER
    assert stat.S_IMODE(target.stat().st_mode) == 0o640


def test_write_goes_through_a_symlink(target, tmp_path):
    link = tmp_path / "link.py"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("cannot create symlinks here")
    service._write_verified(str(link), FAKE_BEFORE, REAL_AFTER)
    assert link.is_symlink() and target.read_text() == REAL_AFTER


# ---- git (local app) ------------------------------------------------------------------------

needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")


@needs_git
def test_git_diff_gates_working_tree(tmp_path):
    def git(*args):
        subprocess.run(["git", *args], cwd=tmp_path, check=True, capture_output=True)
    git("init", "-q", "-b", "main")
    git("config", "user.email", "t@example.invalid")
    git("config", "user.name", "t")
    git("config", "commit.gpgsign", "false")
    (tmp_path / "svc.py").write_text(FAKE_BEFORE)
    git("add", ".")
    git("commit", "-q", "-m", "base")
    (tmp_path / "svc.py").write_text(FAKE_AFTER)
    out = service.git_diff({"repo": str(tmp_path), "base": "HEAD"})
    assert out["blocked"] is True and out["base"]
    assert _codes(service.git_diff, {"repo": str(tmp_path), "base": "--output=x"}) == (422, "bad_field")
    assert _codes(service.git_diff, {"repo": str(tmp_path / "nope")}) == (422, "not_a_repo")
    # A checked file the gate cannot read as text blocks in the local app too.
    (tmp_path / "svc.py").write_bytes(b"# \x00\n" + FAKE_AFTER.encode())
    out = service.git_diff({"repo": str(tmp_path), "base": "HEAD"})
    assert out["blocked"] is True
    assert [f["check"] for f in out["files"][0]["findings"]] == ["content_not_checked"]
    out = service.git_diff({"repo": str(tmp_path), "base": "HEAD", "warn_only": ["content_not_checked"]})
    assert out["blocked"] is False


def test_harden_write_keeps_crlf_files_crlf(tmp_path, monkeypatch):
    monkeypatch.setenv("LLM_API_KEY", "test-key-not-real")
    monkeypatch.setattr(llm, "_post", lambda *a, **k: _reply(REAL_AFTER))
    path = tmp_path / "win.py"
    path.write_bytes(FAKE_BEFORE.replace("\n", "\r\n").encode())
    out = service.harden({"code": FAKE_BEFORE, "path": str(path), "provider": "openai",
                          "threats": ["injection"], "write": True})
    assert out["written"] is True
    assert path.read_bytes() == REAL_AFTER.replace("\n", "\r\n").encode()


# ---- code that nests too deeply to parse or analyse (finding 8) --------------------------

DEEP = "x = " + "+".join(["1"] * 20_000) + "\n"      # 40,004 characters, under the limit


def test_too_deep_code_is_a_blocking_parse_failure_not_an_error(engine_ast_raises):
    engine_ast_raises("parse", RecursionError)
    for body in ({"path": "deep.py", "before": "x = 1\n", "after": "x = 2\n"},
                 {"path": "deep.py", "after": "x = 2\n", "mode": "gate"}):
        out = service.verify(body)
        findings = out["files"][0]["findings"]
        assert out["blocked"] is True and [f["check"] for f in findings] == ["parse_failure"]
        assert "nests too deeply" in findings[0]["detail"]
    batch = service.verify_batch({"files": [{"path": "deep.py", "after": "x = 2\n"}]})
    assert batch["blocked"] is True


def test_real_deep_expression_is_answered_not_raised():
    import ast

    try:
        ast.parse(DEEP)
        pytest.skip("this interpreter parses the expression")
    except RecursionError:
        pass
    assert len(DEEP) < Limits().max_chars
    out = service.verify({"path": "deep.py", "before": "x = 1\n", "after": DEEP})
    assert out["blocked"] is True
    assert [f["check"] for f in out["files"][0]["findings"]] == ["parse_failure"]
