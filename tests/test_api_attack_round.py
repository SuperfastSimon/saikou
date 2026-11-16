"""Hosted API and model-call fixes from the attack round on 1.2.1; each test failed there."""
import asyncio, importlib, io, json, subprocess, time, urllib.error

import pytest
from fastapi.testclient import TestClient

from saikou import llm

ORIG = "import subprocess\n\ndef run(cmd):\n    return subprocess.call(cmd, shell=True)\n"
REAL = "import shlex\nimport subprocess\n\ndef run(cmd):\n    return subprocess.call(shlex.split(cmd))\n"
NOOP = "import subprocess\n\ndef run(cmd):\n    cmd = str(cmd)\n    return subprocess.call(cmd, shell=True)\n"
NEWBAD = "import subprocess\n\ndef run(cmd):\n    eval(cmd)\n    return subprocess.call(cmd, shell=True)\n"


def _reply(code):
    payload = {"hardened_code": code,
               "changes": [{"threat": "command injection", "what_changed": "x", "why": "y"}],
               "deferred_defects": [{"issue": "none", "why_not_fixed": "n/a", "operating_limitation": "n/a"}],
               "assumptions": []}
    return {"choices": [{"finish_reason": "stop", "message": {"content": json.dumps(payload)}}]}


def _load(monkeypatch, **env):
    for key in ("API_TOKENS", "ENVIRONMENT", "RATE_LIMIT_PER_MINUTE", "MAX_BODY_BYTES",
                "PLAYGROUND", "LLM_API_KEY", "MAX_SESSIONS", "SESSION_TTL_S"):
        monkeypatch.delenv(key, raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    import saikou.api as api
    return importlib.reload(api)


def H(t):
    return {"Authorization": "Bearer " + t}



# ---- 3. retry loop ---------------------------------------------------------------------

def _seq(monkeypatch, retries, items):
    calls = []
    it = iter(items)

    def post(url, payload, key, t):
        calls.append(payload["response_format"]["type"])
        x = next(it)
        if isinstance(x, Exception):
            raise x
        return x
    monkeypatch.setattr(llm, "_post", post)
    monkeypatch.setattr(llm.time, "sleep", lambda s: None)
    cfg = llm.LLMConfig(base_url="https://api.example.com/v1", model="m", api_key="k", retries=retries)
    return calls, cfg


def E(code):
    return urllib.error.HTTPError("u", code, "x", {}, io.BytesIO(b""))


def test_json_mode_switch_does_not_cost_an_attempt_with_retries_2(monkeypatch):
    # without the 400 the caller gets 3 attempts (retries=2); after the switch the plain-JSON
    # request must still get its 3 attempts
    calls, cfg = _seq(monkeypatch, 2, [E(400), E(503), E(503), _reply(REAL)])
    out = llm.call_llm([{"role": "user", "content": "x"}], {}, cfg)
    assert out["hardened_code"] == REAL and calls == ["json_schema"] + ["json_object"] * 3


def test_json_mode_switch_does_not_cost_an_attempt_with_retries_1(monkeypatch):
    calls, cfg = _seq(monkeypatch, 1, [E(400), urllib.error.URLError("reset"), _reply(REAL)])
    out = llm.call_llm([{"role": "user", "content": "x"}], {}, cfg)
    assert out["hardened_code"] == REAL


# ---- 4. hosted sessions ----------------------------------------------------------------

def _alive(api, sid):
    return asyncio.run(api._sessions.get(sid)) is not None


def test_each_token_keeps_at_least_one_session_when_tokens_exceed_max(monkeypatch):
    api = _load(monkeypatch, API_TOKENS="a,b,c", MAX_SESSIONS="2")
    c = TestClient(api.app)
    ids = [c.post("/harden/intake", json={"code": ORIG}, headers=H(t)).json()["session_id"] for t in "abc"]
    assert [_alive(api, s) for s in ids] == [True, True, True]


def test_ttl_sanity(monkeypatch):
    api = _load(monkeypatch, API_TOKENS="a", SESSION_TTL_S="1")
    c = TestClient(api.app)
    sid = c.post("/harden/intake", json={"code": ORIG}, headers=H("a")).json()["session_id"]
    time.sleep(1.3)
    assert not _alive(api, sid)


def test_another_token_cannot_spend_my_session(monkeypatch):
    api = _load(monkeypatch, API_TOKENS="a,b", LLM_API_KEY="sk-test-not-real")
    monkeypatch.setattr(llm, "_post", lambda *a, **k: _reply(REAL))
    c = TestClient(api.app)
    sid = c.post("/harden/intake", json={"code": ORIG}, headers=H("a")).json()["session_id"]
    r = c.post("/harden/apply", json={"session_id": sid}, headers=H("b"))
    assert r.status_code == 404, r.text[:200]


def test_apply_refuses_unknown_language_before_the_model_and_keeps_the_session(monkeypatch):
    api = _load(monkeypatch, API_TOKENS="a", LLM_API_KEY="sk-test-not-real")
    calls = []
    monkeypatch.setattr(llm, "_post", lambda *a, **k: calls.append(1) or _reply(NOOP))
    c = TestClient(api.app)
    sid = c.post("/harden/intake", json={"code": ORIG}, headers=H("a")).json()["session_id"]
    r = c.post("/harden/apply", json={"session_id": sid, "contract": {"language": "klingon"}}, headers=H("a"))
    assert (r.status_code, calls, _alive(api, sid)) == (422, [], True), (r.json().get("status"), r.json().get("verification_tier"))


# ---- 5. hosted error handling ----------------------------------------------------------

def test_deeply_nested_json_is_a_client_error_not_500(monkeypatch):
    c = TestClient(_load(monkeypatch, API_TOKENS="a").app, raise_server_exceptions=False)
    r = c.post("/v1/verify", content=b"[" * 100000, headers=H("a"))
    assert r.status_code == 400, r.text


def test_unauthenticated_malformed_json_is_401(monkeypatch):
    c = TestClient(_load(monkeypatch, API_TOKENS="a").app)
    r = c.post("/harden/intake", content=b"{", headers={"content-type": "application/json"})
    assert r.status_code == 401, r.text


def test_lowercase_bearer_scheme_is_accepted(monkeypatch):
    c = TestClient(_load(monkeypatch, API_TOKENS="a").app)
    r = c.post("/v1/verify", json={"after": "x = 1\n", "path": "a.py"}, headers={"Authorization": "bearer a"})
    assert r.status_code == 200, r.text
