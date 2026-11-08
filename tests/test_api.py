"""Hosted HTTP service: fails closed, one error shape, capped bodies, no local operations."""

import asyncio
import collections
import importlib
import logging
import threading
import time

import pytest

pytest.importorskip("httpx")
TestClient = pytest.importorskip("fastapi.testclient").TestClient

CODE = "import subprocess\n\ndef run(cmd):\n    return subprocess.call(cmd, shell=True)\n"
FAKE = CODE.replace("shell=True)", "shell=True)  # nosec")
REAL = "import shlex\nimport subprocess\n\ndef run(cmd):\n    return subprocess.call(shlex.split(cmd))\n"
TOKEN = "t0ken-for-tests"
AUTH = {"Authorization": f"Bearer {TOKEN}"}


def _load(monkeypatch, **env):
    for key in ("API_TOKENS", "ENVIRONMENT", "RATE_LIMIT_PER_MINUTE", "MAX_BODY_BYTES",
                "PLAYGROUND", "LLM_API_KEY", "MAX_SESSIONS", "SESSION_TTL_S"):
        monkeypatch.delenv(key, raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    import saikou.api as api
    return importlib.reload(api)


@pytest.fixture
def client(monkeypatch):
    return TestClient(_load(monkeypatch, API_TOKENS=TOKEN).app)


def _err(resp, status, code):
    assert resp.status_code == status, resp.text
    assert resp.json()["error"]["code"] == code
    assert resp.json()["error"]["message"]


def test_refuses_without_tokens_in_production(monkeypatch):
    api = _load(monkeypatch)
    client = TestClient(api.app)
    _err(client.post("/harden/intake", json={"code": CODE}), 503, "not_configured")
    _err(client.post("/v1/verify", json={"after": CODE}), 503, "not_configured")
    assert client.get("/openapi.json").status_code == 404
    assert client.get("/healthz").json()["status"] == "ok"


def test_dev_mode_serves_without_tokens(monkeypatch):
    client = TestClient(_load(monkeypatch, ENVIRONMENT="dev").app)
    assert client.post("/v1/verify", json={"path": "a.py", "after": CODE}).status_code == 200


def test_requires_bearer_token(client):
    resp = client.post("/harden/intake", json={"code": CODE})
    _err(resp, 401, "unauthorized")
    assert resp.headers["WWW-Authenticate"] == "Bearer"
    _err(client.post("/v1/verify", json={"after": CODE},
                     headers={"Authorization": "Bearer wrong"}), 401, "unauthorized")
    ok = client.post("/harden/intake", json={"code": CODE}, headers=AUTH)
    assert ok.status_code == 200 and ok.json()["detected"]["language"] == "python"


def test_verify_blocks_fake_and_passes_real(client):
    body = {"path": "svc.py", "before": CODE, "claimed_threats": ["injection"]}
    fake = client.post("/v1/verify", json={**body, "after": FAKE}, headers=AUTH)
    assert fake.status_code == 200 and fake.json()["blocked"] is True
    assert fake.headers["Cache-Control"] == "no-store"
    real = client.post("/v1/verify", json={**body, "after": REAL}, headers=AUTH)
    assert real.json()["blocked"] is False
    # A Python report says which checks did not apply: the JavaScript-only ones.
    assert all(c["id"].startswith("js_") for c in real.json()["files"][0]["not_checked"])


def test_verify_batch_and_sarif(client):
    out = client.post("/v1/verify/batch", headers=AUTH, json={"files": [
        {"path": "svc.py", "before": CODE, "after": FAKE},
        {"path": "notes.txt", "before": "a", "after": "b"}]}).json()
    assert out["blocked"] is True and out["skipped"] == ["notes.txt: language not recognised"]
    sarif = client.post("/v1/verify", headers=AUTH, json={"path": "svc.py", "before": CODE,
                                                          "after": FAKE, "format": "sarif"})
    assert sarif.json()["version"] == "2.1.0"


def test_service_errors_use_one_envelope(client):
    _err(client.post("/v1/verify", json={"before": "x"}, headers=AUTH), 422, "missing_field")
    _err(client.post("/v1/verify", json={"after": "x", "claimed_threats": ["zzz"]},
                     headers=AUTH), 422, "bad_field")
    _err(client.post("/v1/verify", content=b"{not json", headers=AUTH), 400, "bad_json")
    _err(client.post("/v1/verify/batch", json={"files": []}, headers=AUTH), 422, "missing_field")
    _err(client.post("/harden/intake", json={"code": ""}, headers=AUTH), 422, "bad_request")
    _err(client.get("/v1/nope"), 404, "not_found")


def test_body_is_capped(monkeypatch):
    client = TestClient(_load(monkeypatch, API_TOKENS=TOKEN, MAX_BODY_BYTES="10000").app)
    big = {"path": "a.py", "after": "x = 1\n" * 3000}
    _err(client.post("/v1/verify", json=big, headers=AUTH), 413, "body_too_large")
    # A chunked upload declares no Content-Length; the stream itself is counted.
    chunks = iter([b'{"after": "', b"x" * 6000, b"y" * 6000, b'"}'])
    _err(client.post("/v1/verify", content=chunks, headers=AUTH), 413, "body_too_large")
    chunks = iter([b'{"code": "', b"x" * 6000, b"y" * 6000, b'"}'])
    _err(client.post("/harden/intake", content=chunks,
                     headers={**AUTH, "Content-Type": "application/json"}), 413, "body_too_large")


def test_rate_limited(monkeypatch):
    api = _load(monkeypatch, API_TOKENS=TOKEN, RATE_LIMIT_PER_MINUTE="2")
    client = TestClient(api.app)
    codes = [client.post("/harden/intake", json={"code": CODE}, headers=AUTH).status_code
             for _ in range(2)]
    assert codes == [200, 200]
    resp = client.post("/v1/verify", json={"after": CODE}, headers=AUTH)
    _err(resp, 429, "rate_limited")
    assert int(resp.headers["Retry-After"]) >= 1


def test_session_is_single_use(monkeypatch):
    api = _load(monkeypatch, API_TOKENS=TOKEN, LLM_API_KEY="test-key-not-real")
    from saikou import llm
    monkeypatch.setattr(llm, "_post", lambda *a, **k: {"choices": [{
        "finish_reason": "stop", "message": {"content":
            '{"hardened_code": "import shlex, subprocess\\n\\ndef run(cmd):\\n'
            '    return subprocess.call(shlex.split(cmd))\\n", "changes": [], '
            '"deferred_defects": [], "assumptions": []}'}}]})
    monkeypatch.setattr(api, "run_hardening",
                        lambda code, lang, contract, config: llm.run_hardening(
                            code, lang, contract, config, run_tools=False))
    client = TestClient(api.app)
    sid = client.post("/harden/intake", json={"code": CODE}, headers=AUTH).json()["session_id"]
    first = client.post("/harden/apply", json={"session_id": sid,
                                               "contract": {"threat_model": ["injection"]}},
                        headers=AUTH)
    assert first.status_code == 200, first.text
    assert first.json()["status"] == "verified"
    _err(client.post("/harden/apply", json={"session_id": sid}, headers=AUTH),
         404, "session_not_found")


def test_a_provider_error_reaches_the_caller_without_the_providers_words(monkeypatch):
    """Review finding 19: the caller does not own this server's key or provider account."""
    import io
    import json
    import urllib.error

    key = "sk-proj-Q7hT2mVx9LpZ4nRb8cWk3yJd6fGs1aEu5oPi0qXz7wN2VbqZ"
    api = _load(monkeypatch, API_TOKENS=TOKEN, LLM_API_KEY=key)
    from saikou import llm

    def boom(url, payload, api_key, timeout):
        body = json.dumps({"error": {"message": "Incorrect API key provided: sk-proj-Q7hT"
                                                "****VbqZ in organization org-Operator123."}})
        raise urllib.error.HTTPError(url, 401, "Unauthorized", {}, io.BytesIO(body.encode()))

    monkeypatch.setattr(llm, "_post", boom)
    monkeypatch.setattr(api, "run_hardening",
                        lambda code, lang, contract, config: llm.run_hardening(
                            code, lang, contract, config, run_tools=False))
    client = TestClient(api.app)
    sid = client.post("/harden/intake", json={"code": CODE}, headers=AUTH).json()["session_id"]
    resp = client.post("/harden/apply", json={"session_id": sid}, headers=AUTH)
    _err(resp, 502, "model_error")
    assert resp.json()["error"]["message"] == "Provider returned HTTP 401."
    for word in ("VbqZ", "Q7hT", "Incorrect", "org-Operator123"):
        assert word not in resp.text


def test_a_bad_model_setting_is_not_quoted_to_the_caller(monkeypatch):
    api = _load(monkeypatch, API_TOKENS=TOKEN, LLM_API_KEY="test-key-not-real",
                LLM_TIMEOUT_S="operator-only-value")
    client = TestClient(api.app)
    sid = client.post("/harden/intake", json={"code": CODE}, headers=AUTH).json()["session_id"]
    resp = client.post("/harden/apply", json={"session_id": sid}, headers=AUTH)
    _err(resp, 503, "model_not_configured")
    assert "operator-only-value" not in resp.text and "LLM_TIMEOUT_S" not in resp.text


def test_apply_without_a_model_key_keeps_the_session(client):
    sid = client.post("/harden/intake", json={"code": CODE}, headers=AUTH).json()["session_id"]
    _err(client.post("/harden/apply", json={"session_id": sid}, headers=AUTH),
         503, "model_not_configured")


def test_hosted_service_has_no_local_operations(client):
    paths = {getattr(r, "path", "") for r in client.app.routes}
    assert paths == {"/healthz", "/v1/checks", "/v1/verify", "/v1/verify/batch",
                     "/harden/intake", "/harden/apply", "/", "/assets/{name}"}
    for path in ("/api/git/diff", "/api/file/read", "/api/harden", "/api/providers"):
        assert client.post(path, json={}, headers=AUTH).status_code in (404, 405)


def test_checks_are_public(client):
    out = client.get("/v1/checks").json()
    assert len(out["checks"]) > 30 and set(out["provenance"]) == {"tool", "parser", "mechanical"}


def test_playground_is_the_web_app_in_hosted_mode(client):
    page = client.get("/")
    assert page.status_code == 200 and 'data-mode="hosted"' in page.text
    assert "script-src 'self'" in page.headers["Content-Security-Policy"]
    assert client.get("/assets/app.js").status_code == 200
    assert client.get("/assets/api.py").status_code == 404
    assert client.get("/assets/..%2Fapi.py").status_code == 404


def test_playground_can_be_switched_off(monkeypatch):
    client = TestClient(_load(monkeypatch, API_TOKENS=TOKEN, PLAYGROUND="0").app)
    assert client.get("/").status_code == 404


# ---- review batch C: every error keeps the documented shape ----------------------------------

def test_a_non_ascii_authorization_header_is_a_401(client):
    """Review finding 10: compare_digest refused the non-ASCII str, so this was a 500."""
    for value in (b"Bearer " + bytes([0xE9]), ("Bearer " + chr(0xE9) * 3).encode("utf-8"),
                  b"Basic " + bytes([0xFF, 0xFE])):
        resp = client.post("/v1/verify", json={"after": CODE}, headers={"Authorization": value})
        _err(resp, 401, "unauthorized")
        assert resp.headers["WWW-Authenticate"] == "Bearer"


def test_a_non_ascii_token_can_be_used(monkeypatch):
    token = "t" + chr(0xF6) + "ken-for-tests"
    client = TestClient(_load(monkeypatch, API_TOKENS=token).app)
    ok = client.post("/v1/verify", json={"path": "a.py", "after": CODE},
                     headers={"Authorization": ("Bearer " + token).encode("utf-8")})
    assert ok.status_code == 200, ok.text
    _err(client.post("/v1/verify", json={"after": CODE}, headers=AUTH), 401, "unauthorized")


def test_batch_with_a_non_string_before_is_a_422(client):
    """Review finding 11: through the API this was a 500 text/plain."""
    resp = client.post("/v1/verify/batch", headers=AUTH,
                       json={"files": [{"path": "a.py", "before": 1, "after": "x = 1"}]})
    _err(resp, 422, "bad_field")


def test_an_unknown_format_is_a_422(client):
    for path, body in (("/v1/verify", {"after": CODE, "format": "xml"}),
                       ("/v1/verify/batch", {"files": [{"path": "a.py", "after": CODE}], "format": "xml"})):
        _err(client.post(path, json=body, headers=AUTH), 422, "bad_field")


def test_an_unexpected_error_is_a_json_500_without_details(monkeypatch, caplog):
    """Review finding 12: an unexpected exception gave a text/plain 500."""
    api = _load(monkeypatch, API_TOKENS=TOKEN)
    from saikou import service

    def boom(*_args, **_kwargs):
        raise RuntimeError("sentinel-internal-detail at C:/srv/secret/path.py")

    monkeypatch.setattr(service, "verify", boom)
    client = TestClient(api.app, raise_server_exceptions=False)
    with caplog.at_level(logging.ERROR, logger="saikou.api"):
        resp = client.post("/v1/verify", json={"after": CODE}, headers=AUTH)
    _err(resp, 500, "internal_error")
    assert resp.headers["content-type"].startswith("application/json")
    for leak in ("sentinel", "RuntimeError", "Traceback", "secret"):
        assert leak not in resp.text
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["Cache-Control"] == "no-store"
    request_id = resp.headers["X-Request-ID"]
    logged = [r for r in caplog.records if r.name == "saikou.api"]
    assert logged and logged[0].exc_info and request_id in logged[0].getMessage()
    assert "sentinel-internal-detail" in caplog.text


def test_contract_values_match_the_service(monkeypatch):
    """The hosted contract accepts exactly the values the local app and the CLI accept."""
    api = _load(monkeypatch, API_TOKENS=TOKEN)
    from saikou import service
    for field, choices in (("compat", service.COMPAT_CHOICES),
                           ("dependencies", service.DEPENDENCY_CHOICES),
                           ("error_policy", service.ERROR_POLICY_CHOICES)):
        for value in choices:
            assert getattr(api.ContractBody(**{field: value}), field) == value
        assert getattr(api.ContractBody(), field) == choices[0]
        client = TestClient(api.app)
        # A trailing newline must not slip past the pattern: the engine compares exactly.
        for bad in (choices[0].upper(), choices[0] + "\n", " " + choices[0], "strict"):
            _err(client.post("/harden/apply", headers=AUTH,
                             json={"session_id": "x" * 20, "contract": {field: bad}}),
                 422, "bad_request")


def _stub_model(monkeypatch, api):
    from saikou import llm
    monkeypatch.setattr(llm, "_post", lambda *a, **k: {"choices": [{
        "finish_reason": "stop", "message": {"content":
            '{"hardened_code": "import shlex, subprocess\\n\\ndef run(cmd):\\n'
            '    return subprocess.call(shlex.split(cmd))\\n", "changes": [], '
            '"deferred_defects": [], "assumptions": []}'}}]})
    monkeypatch.setattr(api, "run_hardening",
                        lambda code, lang, contract, config: llm.run_hardening(
                            code, lang, contract, config, run_tools=False))


def test_one_token_cannot_push_out_another_tokens_session(monkeypatch):
    """Review finding 14: the oldest session of anyone was evicted when the store was full."""
    api = _load(monkeypatch, API_TOKENS="token-a-for-tests,token-b-for-tests", MAX_SESSIONS="10",
                RATE_LIMIT_PER_MINUTE="1000", LLM_API_KEY="test-key-not-real")
    _stub_model(monkeypatch, api)
    client = TestClient(api.app)
    a = {"Authorization": "Bearer token-a-for-tests"}
    b = {"Authorization": "Bearer token-b-for-tests"}
    mine = client.post("/harden/intake", json={"code": CODE}, headers=a).json()["session_id"]
    flood = [client.post("/harden/intake", json={"code": CODE}, headers=b).json()["session_id"]
             for _ in range(25)]
    assert len(api._sessions._data) <= 10
    ok = client.post("/harden/apply", json={"session_id": mine}, headers=a)
    assert ok.status_code == 200, ok.text
    # B's share is half the store: its own oldest intakes made room, its newest are kept.
    _err(client.post("/harden/apply", json={"session_id": flood[0]}, headers=b),
         404, "session_not_found")
    assert client.post("/harden/apply", json={"session_id": flood[-1]}, headers=b).status_code == 200


def test_a_full_store_takes_from_the_largest_holder():
    from saikou.engine import Session, SessionStore, detect_language

    store = SessionStore(1800, max_entries=4)
    det = detect_language("x = 1\n", "python")

    async def fill():
        now = time.time()
        small = await store.put(Session("a", det, now), owner="small")
        big = [await store.put(Session("b", det, now + i + 1), owner="big") for i in range(6)]
        return small, big

    small, big = asyncio.run(fill())
    assert len(store._data) == 4
    assert small in store._data and big[-1] in store._data and big[0] not in store._data


def test_rate_limit_holds_under_concurrent_requests(monkeypatch):
    """Review finding 15: two threads could both pass the check before either appended."""
    api = _load(monkeypatch, API_TOKENS=TOKEN, RATE_LIMIT_PER_MINUTE="1")
    barrier = threading.Barrier(2, timeout=1.0)

    class Racy(collections.deque):
        # Each thread reads the length, then waits for the other: without a lock both read
        # the empty window before either appends, the moment the race needs. With the lock
        # the wait times out and the second thread reads the first one's entry.
        def __len__(self):
            seen = super().__len__()
            try:
                barrier.wait()
            except threading.BrokenBarrierError:
                pass
            return seen

    api._hits["caller"] = Racy()
    results = []

    def hit():
        try:
            results.append(api.rate_limit("caller"))
        except api.ServiceError as exc:
            results.append(exc.status)

    threads = [threading.Thread(target=hit) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(10)
    assert sorted(results, key=str) == [429, "caller"]
