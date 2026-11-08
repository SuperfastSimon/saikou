"""Hosted HTTP service: fails closed, one error shape, capped bodies, no local operations."""

import importlib

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
                "PLAYGROUND", "LLM_API_KEY"):
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
