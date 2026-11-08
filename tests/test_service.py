"""saikou.service: the logic shared by the hosted API and the local app. No network."""

import json
import shutil
import subprocess

import pytest

from saikou import llm, service
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
