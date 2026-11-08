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
