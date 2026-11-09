"""`saikou harden` with the model call stubbed - no network, no key needed."""

import json
from pathlib import Path

import pytest

from saikou import llm
from saikou.cli import EXIT_BLOCKED, EXIT_ERROR, EXIT_OK, main

ORIGINAL = "import subprocess\n\ndef run(cmd):\n    return subprocess.call(cmd, shell=True)\n"
FAKE = ("import subprocess\n\ndef run(cmd):\n"
        "    return subprocess.call(cmd, shell=True)  # nosec - validated upstream\n")
REAL = ("import shlex\nimport subprocess\n\ndef run(cmd):\n"
        "    return subprocess.call(shlex.split(cmd))\n")


def _reply(code: str) -> dict:
    payload = {"hardened_code": code,
               "changes": [{"threat": "command injection", "what_changed": "x", "why": "y"}],
               "deferred_defects": [{"issue": "none", "why_not_fixed": "n/a",
                                     "operating_limitation": "n/a"}],
               "assumptions": []}
    return {"choices": [{"finish_reason": "stop",
                         "message": {"content": json.dumps(payload)}}]}


@pytest.fixture
def target(tmp_path, monkeypatch):
    path = tmp_path / "svc.py"
    path.write_text(ORIGINAL)
    monkeypatch.setenv("TEST_KEY", "sk-test-not-real")
    return path


def _harden(path: Path, *extra: str) -> int:
    return main(["harden", str(path), "--api-key-env", "TEST_KEY", "--threat", "injection",
                 "--no-analyser", *extra])


def test_fake_hardening_is_never_written(target, monkeypatch):
    monkeypatch.setattr(llm, "_post", lambda *a, **k: _reply(FAKE))
    assert _harden(target, "--write") == EXIT_BLOCKED
    assert target.read_text() == ORIGINAL


def test_real_hardening_written_only_with_write(target, monkeypatch):
    monkeypatch.setattr(llm, "_post", lambda *a, **k: _reply(REAL))
    assert _harden(target) == EXIT_OK
    assert target.read_text() == ORIGINAL          # dry run by default
    assert _harden(target, "--write") == EXIT_OK
    assert target.read_text() == REAL


def test_truncated_reply_is_an_error_not_a_result(target, monkeypatch):
    reply = _reply(REAL)
    reply["choices"][0]["finish_reason"] = "length"
    monkeypatch.setattr(llm, "_post", lambda *a, **k: reply)
    assert _harden(target, "--write") == EXIT_ERROR
    assert target.read_text() == ORIGINAL


def test_missing_key_is_usage_error(target, monkeypatch):
    monkeypatch.delenv("TEST_KEY")
    assert _harden(target) == EXIT_ERROR


def test_non_object_json_rejected(monkeypatch):
    monkeypatch.setattr(llm, "_post", lambda *a, **k: {"choices": [
        {"finish_reason": "stop", "message": {"content": "[1, 2]"}}]})
    with pytest.raises(llm.LLMError):
        llm.call_llm([], {}, llm.LLMConfig(api_key="k"))


def test_plain_http_refused_except_localhost():
    with pytest.raises(llm.LLMError):
        llm.call_llm([], {}, llm.LLMConfig(api_key="k", base_url="http://example.com/v1"))


def test_harden_detects_language_from_the_file_extension(target, monkeypatch, capsys):
    """Regression: the raw path used to be passed as the language, giving tier 'asserted'
    and silently skipping every Python check."""
    survivor = ORIGINAL.replace("def run", "def run").rstrip("\n") + "\n# reviewed\n"
    monkeypatch.setattr(llm, "_post", lambda *a, **k: _reply(survivor))
    # shell=True survives while injection is claimed: only the Python sink check can catch it.
    assert _harden(target, "--format", "json") == EXIT_BLOCKED
    import json as _json
    out = _json.loads(capsys.readouterr().out)
    assert out["language"] == "python" and out["verification_tier"] == "ast_verified"
    assert any(f["check"] == "sink_shell_true" for f in out["evidence_ledger"]["findings"])


def test_harden_falls_back_to_content_when_extension_is_unknown(tmp_path, monkeypatch, capsys):
    path = tmp_path / "script.txt"
    path.write_text(ORIGINAL)
    monkeypatch.setenv("TEST_KEY", "sk-test-not-real")
    monkeypatch.setattr(llm, "_post", lambda *a, **k: _reply(REAL))
    main(["harden", str(path), "--api-key-env", "TEST_KEY", "--threat", "injection",
          "--no-analyser", "--format", "json"])
    import json as _json
    assert _json.loads(capsys.readouterr().out)["language"] == "python"


# ---- --write: the same guarantees as the local app (review 9 and 16, CLI path) ---------------

def test_a_file_that_is_not_utf8_is_refused_before_the_model_is_asked(target, monkeypatch, capsys):
    raw = "# café\n".encode("cp1252") + ORIGINAL.encode()
    target.write_bytes(raw)
    calls = []
    monkeypatch.setattr(llm, "_post", lambda *a, **k: calls.append(1) or _reply(REAL))
    assert _harden(target, "--write") == EXIT_ERROR
    assert "not UTF-8" in capsys.readouterr().err
    assert calls == [] and target.read_bytes() == raw


def test_a_failed_write_leaves_the_file_as_it_was(target, monkeypatch, capsys):
    monkeypatch.setattr(llm, "_post", lambda *a, **k: _reply(REAL))

    def full(*_a, **_k):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr("saikou.service.os.replace", full)
    assert _harden(target, "--write") == EXIT_ERROR
    assert "Not written" in capsys.readouterr().err
    assert target.read_text() == ORIGINAL
    assert [p.name for p in target.parent.iterdir()] == ["svc.py"]     # no temporary file left


def test_a_file_changed_during_the_model_call_is_not_overwritten(target, monkeypatch, capsys):
    newer = ORIGINAL + "# edited meanwhile\n"

    def edit_then_answer(*_a, **_k):
        target.write_text(newer)
        return _reply(REAL)

    monkeypatch.setattr(llm, "_post", edit_then_answer)
    assert _harden(target, "--write") == EXIT_ERROR
    assert "changed while" in capsys.readouterr().err
    assert target.read_text() == newer


def test_write_keeps_going_through_a_symlink(target, monkeypatch):
    link = target.parent / "link.py"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("this machine cannot create symbolic links")
    monkeypatch.setattr(llm, "_post", lambda *a, **k: _reply(REAL))
    assert _harden(link, "--write") == EXIT_OK
    assert link.is_symlink() and target.read_text() == REAL
