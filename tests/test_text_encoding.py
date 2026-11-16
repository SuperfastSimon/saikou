"""Byte-order marks and line endings: checks must see through them, writes must keep them.

Found by the attack round on 1.2.1: a UTF-8 byte-order mark at the start of a Python file
made every parser check read the file as "does not parse", so a new eval() or shell=True
and a no-op "fix" all passed.
"""

import json
import subprocess

from saikou import llm, service
from saikou.cli import EXIT_OK, main

BOM = chr(0xFEFF)
ORIG = "import subprocess\n\ndef run(cmd):\n    return subprocess.call(cmd, shell=True)\n"
REAL = "import shlex\nimport subprocess\n\ndef run(cmd):\n    return subprocess.call(shlex.split(cmd))\n"
NOOP = "import subprocess\n\ndef run(cmd):\n    cmd = str(cmd)\n    return subprocess.call(cmd, shell=True)\n"
NEWBAD = "import subprocess\n\ndef run(cmd):\n    eval(cmd)\n    return subprocess.call(cmd, shell=True)\n"


def _reply(code: str) -> dict:
    payload = {"hardened_code": code,
               "changes": [{"threat": "command injection", "what_changed": "x", "why": "y"}],
               "deferred_defects": [{"issue": "none", "why_not_fixed": "n/a", "operating_limitation": "n/a"}],
               "assumptions": []}
    return {"choices": [{"finish_reason": "stop", "message": {"content": json.dumps(payload)}}]}


def _checks(out: dict) -> set:
    return {f["check"] for f in out["files"][0]["findings"] if f["severity"] == "hard_fail"}


def test_a_bom_does_not_switch_off_the_gate():
    out = service.verify({"mode": "gate", "path": "svc.py", "before": BOM + "x = 1\n", "after": BOM + NEWBAD})
    assert out["blocked"] is True
    assert {"sink_dynamic_exec", "sink_shell_true"} <= _checks(out)


def test_a_bom_does_not_let_a_no_op_fix_through():
    out = service.verify({"mode": "verify", "path": "svc.py", "before": BOM + ORIG, "after": BOM + NOOP,
                          "claimed_threats": ["injection"]})
    assert out["blocked"] is True and "sink_shell_true" in _checks(out)


def test_a_bom_does_not_switch_off_the_git_gate(tmp_path):
    def git(*a):
        subprocess.run(["git", *a], cwd=tmp_path, check=True, capture_output=True)
    git("init", "-q")
    git("config", "user.email", "t@example.com")
    git("config", "user.name", "t")
    git("config", "core.autocrlf", "false")
    (tmp_path / "a.py").write_bytes(b"\xef\xbb\xbfx = 1\n")
    git("add", ".")
    git("commit", "-qm", "base")
    (tmp_path / "a.py").write_bytes(b"\xef\xbb\xbf" + NEWBAD.encode())
    compile((tmp_path / "a.py").read_bytes(), "a.py", "exec")          # it really runs
    assert service.git_diff({"repo": str(tmp_path)})["blocked"] is True


def _harden_write(path, monkeypatch) -> int:
    monkeypatch.setenv("TEST_KEY", "sk-test-not-real")
    monkeypatch.setattr(llm, "_post", lambda *a, **k: _reply(REAL))
    return main(["harden", str(path), "--api-key-env", "TEST_KEY", "--threat", "injection",
                 "--no-analyser", "--write"])


def test_cli_write_keeps_a_bom_and_crlf(tmp_path, monkeypatch):
    p = tmp_path / "svc.py"
    p.write_bytes(b"\xef\xbb\xbf" + ORIG.replace("\n", "\r\n").encode())
    assert _harden_write(p, monkeypatch) == EXIT_OK
    assert p.read_bytes() == b"\xef\xbb\xbf" + REAL.replace("\n", "\r\n").encode()


def test_cli_write_keeps_lf(tmp_path, monkeypatch):
    p = tmp_path / "svc.py"
    p.write_bytes(ORIG.encode())
    assert _harden_write(p, monkeypatch) == EXIT_OK
    assert p.read_bytes() == REAL.encode()


def test_the_local_app_writes_a_file_with_lone_cr_and_keeps_it(tmp_path, monkeypatch):
    p = tmp_path / "svc.py"
    p.write_bytes(ORIG.replace("\n", "\r").encode())          # classic Mac line endings
    monkeypatch.setenv("LLM_API_KEY", "sk-test-not-real")
    monkeypatch.setattr(llm, "_post", lambda *a, **k: _reply(REAL))
    # a browser textarea hands the text back with \n
    out = service.harden({"code": ORIG, "path": str(p), "threats": ["injection"], "write": True})
    assert out["written"] is True
    assert p.read_bytes() == REAL.replace("\n", "\r").encode()


def test_the_local_app_keeps_a_bom(tmp_path, monkeypatch):
    p = tmp_path / "svc.py"
    p.write_bytes(b"\xef\xbb\xbf" + ORIG.encode())
    monkeypatch.setenv("LLM_API_KEY", "sk-test-not-real")
    monkeypatch.setattr(llm, "_post", lambda *a, **k: _reply(REAL))
    text = service.read_file({"path": str(p)})["content"]
    out = service.harden({"code": text, "path": str(p), "threats": ["injection"], "write": True})
    assert out["written"] is True and out["status"] == "verified"
    assert p.read_bytes() == b"\xef\xbb\xbf" + REAL.encode()
