"""Provider presets: OpenAI-compatible, Ollama cloud, and a local Ollama. No network."""

import json

import pytest

from saikou import llm
from saikou.cli import EXIT_ERROR, EXIT_OK, main
from saikou.engine import HARDEN_SCHEMA

MESSAGES = [{"role": "user", "content": "x"}]
REPLY = {"choices": [{"finish_reason": "stop", "message": {"content": json.dumps({
    "hardened_code": "import shlex\nimport subprocess\n\ndef run(cmd):\n"
                     "    return subprocess.call(shlex.split(cmd))\n",
    "changes": [], "deferred_defects": [], "assumptions": []})}}]}


# Names a foreign .env must never set. Each is set and then removed through monkeypatch, so
# a regression that does set one is undone after the test instead of leaking into the next.
FOREIGN = ("OLLAMA_BASE_URL", "LLM_BASE_URL", "OLLAMA_LOCAL_URL", "LLM_PROVIDER", "HTTPS_PROXY",
           "https_proxy", "HTTP_PROXY", "ALL_PROXY", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE",
           "PYTHONPATH", "GIT_CONFIG_COUNT", "GIT_CONFIG_KEY_0", "GIT_CONFIG_VALUE_0", "MY_KEY")


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for name in ("OLLAMA_API_KEY", "OLLAMA_LOCAL_API_KEY", "OLLAMA_MODEL", "OLLAMA_LOCAL_MODEL",
                 "LLM_API_KEY",
                 "LLM_MODEL", "LLM_TIMEOUT_S", "LLM_MAX_OUTPUT_TOKENS") + FOREIGN:
        monkeypatch.setenv(name, "")
        monkeypatch.delenv(name)
    monkeypatch.setattr(llm, "_ENDPOINTS_IN_FILE", {})


def _capture(monkeypatch):
    seen = {}

    def fake_post(url, payload, api_key, timeout):
        seen.update(url=url, payload=payload, api_key=api_key, timeout=timeout)
        return REPLY

    monkeypatch.setattr(llm, "_post", fake_post)
    return seen


def test_ollama_cloud_uses_json_mode_and_prompts_the_schema(monkeypatch):
    monkeypatch.setenv("OLLAMA_API_KEY", "test-key-not-real")
    seen = _capture(monkeypatch)
    config = llm.LLMConfig.from_env(provider="ollama")
    assert config.base_url == "https://ollama.com/v1" and config.model == "gpt-oss:120b"
    llm.call_llm(MESSAGES, HARDEN_SCHEMA, config)
    assert seen["url"] == "https://ollama.com/v1/chat/completions"
    assert seen["api_key"] == "test-key-not-real"
    assert seen["payload"]["response_format"] == {"type": "json_object"}
    assert "hardened_code" in seen["payload"]["messages"][-1]["content"]   # schema in the prompt


def test_openai_preset_keeps_strict_schema(monkeypatch):
    monkeypatch.setenv("LLM_API_KEY", "test-key-not-real")
    seen = _capture(monkeypatch)
    llm.call_llm(MESSAGES, HARDEN_SCHEMA, llm.LLMConfig.from_env())
    assert seen["payload"]["response_format"]["type"] == "json_schema"
    assert seen["url"] == "https://api.openai.com/v1/chat/completions"


def test_missing_ollama_key_names_the_variable(monkeypatch):
    _capture(monkeypatch)
    with pytest.raises(llm.LLMError, match="OLLAMA_API_KEY"):
        llm.call_llm(MESSAGES, HARDEN_SCHEMA, llm.LLMConfig.from_env(provider="ollama"))


def test_key_never_appears_in_repr_or_errors(monkeypatch):
    monkeypatch.setenv("OLLAMA_API_KEY", "super-secret-value-123")
    config = llm.LLMConfig.from_env(provider="ollama")
    assert "super-secret-value-123" not in repr(config) and "super-secret" not in str(config)

    def boom(*a, **k):
        raise OSError("connection refused")
    monkeypatch.setattr(llm, "_post", boom)
    with pytest.raises(llm.LLMError) as err:
        llm.call_llm(MESSAGES, HARDEN_SCHEMA, config)
    assert "super-secret-value-123" not in str(err.value)


def test_local_provider_needs_no_key_and_picks_an_installed_model(monkeypatch):
    seen = _capture(monkeypatch)

    class FakeResp:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self, n=-1): return json.dumps({"models": [
            {"name": "gpt-oss:120b-cloud"}, {"name": "qwen2.5-coder:3b"}]}).encode()

    monkeypatch.setattr(llm._DIRECT, "open", lambda *a, **k: FakeResp())
    config = llm.LLMConfig.from_env(provider="local")
    assert config.model == "qwen2.5-coder:3b" and config.timeout_s == 300
    llm.call_llm(MESSAGES, HARDEN_SCHEMA, config)
    assert seen["url"] == "http://localhost:11434/v1/chat/completions"
    assert seen["payload"]["response_format"] == {"type": "json_object"}


def test_local_provider_explains_when_ollama_is_down(monkeypatch):
    def down(*a, **k):
        raise llm.urllib.error.URLError("refused")
    monkeypatch.setattr(llm._DIRECT, "open", down)
    with pytest.raises(llm.LLMError, match="ollama serve"):
        llm.LLMConfig.from_env(provider="local")


def test_unknown_provider_rejected():
    with pytest.raises(llm.LLMError):
        llm.LLMConfig.from_env(provider="nope")


def test_env_file_loads_names_only_and_never_overrides(tmp_path, monkeypatch):
    f = tmp_path / ".env"
    f.write_text("# comment\nOLLAMA_API_KEY='abc123'\nexport OLLAMA_MODEL=kimi-k2.7-code\n"
                 "LLM_TIMEOUT_S=\nBAD LINE\nLLM_MODEL=from-file\n")
    monkeypatch.setenv("LLM_MODEL", "from-real-env")
    loaded = llm.load_env_file(str(f))
    assert sorted(loaded) == ["OLLAMA_API_KEY", "OLLAMA_MODEL"]       # names, not values
    import os
    assert os.environ["OLLAMA_API_KEY"] == "abc123"                  # quotes stripped
    assert os.environ["LLM_MODEL"] == "from-real-env"                # real env wins
    monkeypatch.delenv("OLLAMA_API_KEY"); monkeypatch.delenv("OLLAMA_MODEL")


def test_missing_env_file_is_not_an_error(tmp_path):
    assert llm.load_env_file(str(tmp_path / "nope.env")) == []


def test_cli_harden_with_ollama_reads_the_key_from_dotenv(tmp_path, monkeypatch):
    target = tmp_path / "svc.py"
    target.write_text("import subprocess\n\ndef run(cmd):\n    return subprocess.call(cmd, shell=True)\n")
    (tmp_path / ".env").write_text("OLLAMA_API_KEY=from-dotenv-not-real\n")
    monkeypatch.chdir(tmp_path)
    seen = _capture(monkeypatch)
    code = main(["harden", str(target), "--provider", "ollama", "--threat", "injection",
                 "--no-analyser"])
    assert code == EXIT_OK and seen["api_key"] == "from-dotenv-not-real"
    monkeypatch.delenv("OLLAMA_API_KEY", raising=False)


def test_cli_harden_ollama_without_key_is_a_clear_error(tmp_path, monkeypatch, capsys):
    target = tmp_path / "svc.py"
    target.write_text("x = 1\n")
    monkeypatch.chdir(tmp_path)
    assert main(["harden", str(target), "--provider", "ollama", "--no-analyser"]) == EXIT_ERROR
    assert "OLLAMA_API_KEY" in capsys.readouterr().err


def test_http_errors_show_the_providers_reason_with_the_key_scrubbed(monkeypatch):
    import io
    import urllib.error

    def boom(url, payload, api_key, timeout):
        body = json.dumps({"error": {"message": "bad request for key abc-secret-key-1234"}})
        raise urllib.error.HTTPError(url, 400, "Bad Request", {}, io.BytesIO(body.encode()))

    monkeypatch.setattr(llm, "_post", boom)
    config = llm.LLMConfig(api_key="abc-secret-key-1234", structured=False)
    with pytest.raises(llm.LLMError) as err:
        llm.call_llm(MESSAGES, HARDEN_SCHEMA, config)
    assert "HTTP 400" in str(err.value) and "bad request" in str(err.value)
    assert "abc-secret-key-1234" not in str(err.value)


# ---- review finding 19: parts of the key in the provider's message -------------------------

KEY = "sk-proj-Q7hT2mVx9LpZ4nRb8cWk3yJd6fGs1aEu5oPi0qXz7wN2VbqZ"


@pytest.mark.parametrize("message", [
    f"Incorrect API key provided: sk-proj-Q7hT{'*' * 40}VbqZ. You can find your API key at "
    "https://platform.openai.com/account/api-keys.",
    "Incorrect API key provided: sk-...VbqZ.",
    "Incorrect API key provided: sk-proj-Q7hT…VbqZ",
    f"Incorrect API key provided: {'•' * 12}VbqZ",
    "Incorrect API key provided: key ending in VbqZ",
    "Incorrect API key provided: sk-proj-Q7hT2mVx9LpZ (truncated)",
    f"Incorrect API key provided: \"{KEY}\"",
    f"Incorrect API key provided: {KEY[:30]}",
    "Incorrect API key provided: keyQ7hT2mVx9LpZ4n",               # glued to another word
    f"Incorrect API key provided: {KEY.upper()}",
    "Incorrect API key provided: key=sk%2Dproj%2DQ7hT2mVx9LpZ",    # percent-encoded
])
def test_provider_messages_lose_every_part_of_the_key(monkeypatch, message):
    import io
    import urllib.error

    def boom(url, payload, api_key, timeout):
        body = json.dumps({"error": {"message": message}})
        raise urllib.error.HTTPError(url, 401, "Unauthorized", {}, io.BytesIO(body.encode()))

    monkeypatch.setattr(llm, "_post", boom)
    with pytest.raises(llm.LLMError) as err:
        llm.call_llm(MESSAGES, HARDEN_SCHEMA, llm.LLMConfig(api_key=KEY, structured=False))
    text = str(err.value).lower()
    assert "http 401" in text and "incorrect api key provided" in text
    for i in range(len(KEY) - 3):              # no run of four of the key's characters, any case
        part = KEY[i:i + 4].lower()
        if part not in ("sk-p", "-pro", "proj", "roj-"):   # the prefix every project key shares
            assert part not in text, part
    assert err.value.public == "Provider returned HTTP 401."


def test_scrub_keeps_ordinary_words():
    text = "Rate limit reached… please wait... then retry; see https://example.com/docs/limits."
    assert llm._scrub(text, KEY) == text


# ---- review finding 6: a redirect must not carry the key to another address ----------------

@pytest.fixture
def two_servers(monkeypatch):
    """Server A answers every POST with a redirect to server B; B records what reaches it."""
    import http.server
    import threading

    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")   # a system proxy must not reroute
    monkeypatch.setenv("no_proxy", "127.0.0.1,localhost")
    reached: list = []

    class Target(http.server.BaseHTTPRequestHandler):
        def _answer(self):
            self.rfile.read(int(self.headers.get("Content-Length", 0)))   # else Windows resets
            reached.append((self.command, self.path, self.headers.get("Authorization")))
            body = json.dumps(REPLY).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        do_GET = do_POST = _answer

        def log_message(self, *_a):
            pass

    target = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Target)
    state = {"code": 302}

    class Redirect(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", 0)))
            self.send_response(state["code"])
            self.send_header("Location", state.get("location")
                             or f"http://127.0.0.1:{target.server_port}{self.path}")
            self.send_header("Content-Length", "0")
            self.end_headers()

        do_GET = do_POST

        def log_message(self, *_a):
            pass

    source = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Redirect)
    for server in (target, source):
        threading.Thread(target=server.serve_forever, daemon=True).start()
    yield source, target, state, reached
    for server in (source, target):
        server.shutdown()
        server.server_close()


@pytest.mark.parametrize("opener", ["direct", "proxied"])   # this machine / a remote endpoint
@pytest.mark.parametrize("location", ["", "http://[", "/elsewhere"])
@pytest.mark.parametrize("code", [301, 302, 303, 307, 308])
def test_a_redirect_is_refused_and_the_key_goes_nowhere_else(two_servers, monkeypatch, code,
                                                              location, opener):
    source, _target, state, reached = two_servers
    state.update(code=code, location=location)
    if opener == "proxied":                  # loopback in the test, so swap the opener in
        monkeypatch.setattr(llm, "_DIRECT", llm._OPENER)
    config = llm.LLMConfig(base_url=f"http://127.0.0.1:{source.server_port}/v1", model="m",
                           api_key="test-key-not-real", retries=0, timeout_s=5)
    with pytest.raises(llm.LLMError) as err:
        llm.call_llm(MESSAGES, HARDEN_SCHEMA, config)
    assert f"HTTP {code}" in str(err.value) and "redirect" in str(err.value)
    assert "127.0.0.1" not in str(err.value)           # the Location is not repeated
    assert reached == []                               # the other server saw nothing


def test_this_machine_is_never_reached_through_a_proxy(two_servers, monkeypatch):
    """A proxy from the environment would get the key in plain http for a localhost URL."""
    import urllib.request

    proxy, target, _state, reached = two_servers        # the redirecting server stands in
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)        # one name on Windows
    monkeypatch.setenv("HTTP_PROXY", f"http://127.0.0.1:{proxy.server_port}")
    # An opener reads the proxy when it is built, so build it as if the proxy had been set
    # before Saikou started.
    proxied = urllib.request.build_opener(llm._NoRedirect())
    assert any(getattr(h, "proxies", {}).get("http") for h in proxied.handlers)
    monkeypatch.setattr(llm, "_OPENER", proxied)
    config = llm.LLMConfig(base_url=f"http://127.0.0.1:{target.server_port}/v1", model="m",
                           api_key="test-key-not-real", retries=0, timeout_s=5)
    llm.call_llm(MESSAGES, HARDEN_SCHEMA, config)
    assert reached == [("POST", "/v1/chat/completions", "Bearer test-key-not-real")]


def test_a_direct_answer_still_works_over_a_real_socket(two_servers):
    _source, target, _state, reached = two_servers
    config = llm.LLMConfig(base_url=f"http://127.0.0.1:{target.server_port}/v1", model="m",
                           api_key="test-key-not-real", retries=0, timeout_s=5)
    assert llm.call_llm(MESSAGES, HARDEN_SCHEMA, config)["hardened_code"].startswith("import shlex")
    assert reached == [("POST", "/v1/chat/completions", "Bearer test-key-not-real")]


# ---- round 3: what the agents found on 29543cf + 02c8dd4 -----------------------------------

def test_local_model_lookup_is_checked_and_never_redirected(two_servers, monkeypatch):
    from saikou import service

    source, _target, state, reached = two_servers
    state["code"] = 302
    base = f"http://127.0.0.1:{source.server_port}/v1"
    with pytest.raises(llm.LLMError, match="No Ollama answering"):
        llm.first_local_model(base)
    assert service._local_models(base) == {"reachable": False, "models": []}
    assert reached == []                                # the other server was never asked


def test_local_model_lookup_asks_only_this_machine(monkeypatch):
    from saikou import service

    asked = []
    monkeypatch.setattr(llm._DIRECT, "open", lambda url, **k: asked.append(url))
    with pytest.raises(llm.LLMError, match="OLLAMA_LOCAL_MODEL"):
        llm.first_local_model("https://models.example.invalid/v1")
    with pytest.raises(llm.LLMError, match="https"):
        llm.first_local_model("http://models.example.invalid/v1")
    assert service._local_models("https://models.example.invalid/v1")["reachable"] is False
    assert asked == []                                  # refused before any request


def test_the_local_preset_never_sends_the_ollama_cloud_key(monkeypatch):
    seen = _capture(monkeypatch)
    monkeypatch.setenv("OLLAMA_API_KEY", "the-users-ollama-cloud-key")
    monkeypatch.setenv("OLLAMA_LOCAL_MODEL", "qwen2.5-coder:3b")
    llm.call_llm(MESSAGES, HARDEN_SCHEMA, llm.LLMConfig.from_env(provider="local"))
    assert seen["api_key"] == "ollama"                  # the placeholder a local Ollama ignores


def test_a_malformed_status_line_is_a_transport_error_without_its_text(monkeypatch):
    import socket
    import threading

    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)

    def answer():
        conn, _ = listener.accept()
        data = b""
        while b"\r\n\r\n" not in data:                  # read the whole request first
            data += conn.recv(65536)
        head, _, body = data.partition(b"\r\n\r\n")
        size = int([line.split(b":")[1] for line in head.split(b"\r\n")
                    if line.lower().startswith(b"content-length")][0])
        while len(body) < size:
            body += conn.recv(65536)
        conn.sendall(f"HTTP/1.1 {KEY} nonsense\r\n\r\n".encode())
        conn.shutdown(socket.SHUT_WR)
        conn.close()

    threading.Thread(target=answer, daemon=True).start()
    config = llm.LLMConfig(base_url=f"http://127.0.0.1:{listener.getsockname()[1]}/v1", model="m",
                           api_key=KEY, retries=0, timeout_s=5)
    try:
        with pytest.raises(llm.LLMError) as err:
            llm.call_llm(MESSAGES, HARDEN_SCHEMA, config)
    finally:
        listener.close()
    assert "transport error" in str(err.value) and "Q7hT" not in str(err.value)


@pytest.mark.parametrize("body, why", [
    ("[" * 100000 + "]" * 100000, "non-JSON"),                         # RecursionError in json
    (json.dumps({"choices": [{"finish_reason": "stop", "message": {"content": ["x"]}}]}),
     "non-text"),
], ids=["deeply-nested", "list-content"])
def test_odd_bodies_are_reported_not_raised(monkeypatch, body, why):
    monkeypatch.setattr(llm, "_post", lambda *a, **k: llm.json.loads(body))
    with pytest.raises(llm.LLMError, match=why):
        llm.call_llm(MESSAGES, HARDEN_SCHEMA, llm.LLMConfig(api_key="test-key-not-real"))


def test_an_error_message_is_scrubbed_with_the_users_key_not_the_placeholder(monkeypatch):
    import io
    import urllib.error

    def boom(url, payload, api_key, timeout):
        body = json.dumps({"error": "model 'llama3' not found in Ollama, try pulling it first"})
        raise urllib.error.HTTPError(url, 404, "Not Found", {}, io.BytesIO(body.encode()))

    monkeypatch.setattr(llm, "_post", boom)
    with pytest.raises(llm.LLMError) as err:
        llm.call_llm(MESSAGES, HARDEN_SCHEMA, llm.LLMConfig(
            base_url="http://localhost:11434/v1", model="llama3", structured=False))
    assert "model 'llama3' not found in Ollama" in str(err.value)


def test_short_glued_fragments_of_the_secret_are_scrubbed():
    text = llm._scrub("bad key xxQ7hTyy and zz9LpZ4 and VbqZ!", KEY)
    for part in ("q7ht", "9lpz", "vbqz"):
        assert part not in text.lower(), text
    assert text.startswith("bad key ")


def test_a_huge_answer_is_refused_unread(two_servers, monkeypatch):
    _source, target, _state, _reached = two_servers
    monkeypatch.setattr(llm, "_MAX_BODY", 100)
    config = llm.LLMConfig(base_url=f"http://127.0.0.1:{target.server_port}/v1", model="m",
                           api_key="test-key-not-real", retries=0, timeout_s=5)
    with pytest.raises(llm.LLMError, match="larger than"):
        llm.call_llm(MESSAGES, HARDEN_SCHEMA, config)


# ---- round 4: the reviewer on 9e30afb..6ef865f ----------------------------------------------

def test_an_error_body_that_breaks_off_is_a_provider_error(monkeypatch):
    import socket
    import threading

    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)

    def answer():
        conn, _ = listener.accept()
        data = b""
        while b"\r\n\r\n" not in data:
            data += conn.recv(65536)
        head, _, body = data.partition(b"\r\n\r\n")
        size = int([line.split(b":")[1] for line in head.split(b"\r\n")
                    if line.lower().startswith(b"content-length")][0])
        while len(body) < size:
            body += conn.recv(65536)
        conn.sendall(f"HTTP/1.1 401 {KEY}\r\nTransfer-Encoding: chunked\r\n\r\n100\r\nabc".encode())
        conn.shutdown(socket.SHUT_WR)
        conn.close()

    threading.Thread(target=answer, daemon=True).start()
    config = llm.LLMConfig(base_url=f"http://127.0.0.1:{listener.getsockname()[1]}/v1", model="m",
                           api_key=KEY, retries=0, timeout_s=5)
    try:
        with pytest.raises(llm.LLMError) as err:
            llm.call_llm(MESSAGES, HARDEN_SCHEMA, config)
    finally:
        listener.close()
    assert str(err.value) == "Provider returned HTTP 401." and err.value.public == str(err.value)


def test_an_explicit_model_skips_the_local_lookup(monkeypatch):
    asked = []
    monkeypatch.setattr(llm._DIRECT, "open", lambda url, **k: asked.append(url))
    config = llm.LLMConfig.from_env(provider="local", base_url="https://gpu-box.example/v1",
                                    model="qwen2.5-coder:3b")
    assert config.model == "qwen2.5-coder:3b" and asked == []
    with pytest.raises(llm.LLMError, match="--model or OLLAMA_LOCAL_MODEL"):
        llm.LLMConfig.from_env(provider="local", base_url="https://gpu-box.example/v1")


def test_the_local_app_says_when_the_local_url_is_not_this_machine():
    from saikou import service
    assert service._local_models("https://gpu-box.example/v1") == {
        "reachable": False, "models": [], "not_local": True}


@pytest.mark.parametrize("placeholder", ["ollama", "EMPTY", "sk-1234", "lm-studio"])
def test_a_placeholder_key_does_not_cost_the_message_its_words(placeholder):
    text = "model 'llama3' not found in Ollama; use lm-studio or try pulling it first"
    assert llm._scrub(text, placeholder) == text.replace(placeholder, "***")


def test_the_hosted_redirect_text_says_nothing_about_a_key(two_servers):
    source, _target, state, _reached = two_servers
    config = llm.LLMConfig(base_url=f"http://127.0.0.1:{source.server_port}/v1", model="m",
                           api_key="test-key-not-real", retries=0, timeout_s=5)
    with pytest.raises(llm.LLMError) as err:
        llm.call_llm(MESSAGES, HARDEN_SCHEMA, config)
    assert err.value.public == "Provider answered HTTP 302, a redirect, which Saikou does not follow."


def test_local_preset_sends_a_repetition_penalty_and_cloud_does_not(monkeypatch):
    seen = _capture(monkeypatch)
    llm.call_llm(MESSAGES, HARDEN_SCHEMA, llm.LLMConfig(base_url="http://localhost:11434/v1",
                                                         model="m", extra={"frequency_penalty": 0.3}))
    assert seen["payload"]["frequency_penalty"] == 0.3
    monkeypatch.setenv("OLLAMA_API_KEY", "test-key-not-real")
    llm.call_llm(MESSAGES, HARDEN_SCHEMA, llm.LLMConfig.from_env(provider="ollama"))
    assert "frequency_penalty" not in seen["payload"]


# ---- a .env from someone else's repository -----------------------------------------------

def test_env_file_never_sets_an_endpoint_proxy_ca_bundle_path_or_git_setting(tmp_path):
    import os
    f = tmp_path / ".env"
    f.write_text("OLLAMA_API_KEY=key-from-file\n"
                 + "".join(f"{name}=https://collector.attacker.example/v1\n" for name in FOREIGN))
    assert llm.load_env_file(str(f)) == ["OLLAMA_API_KEY"]
    assert not [name for name in FOREIGN if name in os.environ]


def test_api_key_env_names_one_more_variable_the_file_may_set(tmp_path):
    import os
    f = tmp_path / ".env"
    f.write_text("MY_KEY=named-on-the-command-line\n")
    assert llm.load_env_file(str(f)) == []
    assert llm.load_env_file(str(f), allow=["MY_KEY"]) == ["MY_KEY"]
    assert os.environ["MY_KEY"] == "named-on-the-command-line"


def test_endpoint_only_in_the_env_file_stops_the_run(tmp_path, monkeypatch):
    f = tmp_path / ".env"
    f.write_text("OLLAMA_API_KEY=key-from-file\nOLLAMA_BASE_URL=https://collector.attacker.example/v1\n")
    llm.load_env_file(str(f))
    with pytest.raises(llm.LLMError, match="OLLAMA_BASE_URL.*--base-url"):
        llm.LLMConfig.from_env(provider="ollama")
    # The flag or the real environment decides instead.
    assert llm.LLMConfig.from_env(provider="ollama",
                                  base_url="https://ollama.com/v1/").base_url == "https://ollama.com/v1"
    monkeypatch.setenv("OLLAMA_BASE_URL", "https://gateway.example/v1")
    assert llm.LLMConfig.from_env(provider="ollama").base_url == "https://gateway.example/v1"
    # Another provider is not affected.
    assert llm.LLMConfig.from_env(provider="openai").base_url == "https://api.openai.com/v1"


def test_cli_harden_never_sends_the_key_to_an_endpoint_from_dotenv(tmp_path, monkeypatch, capsys):
    target = tmp_path / "svc.py"
    target.write_text("x = 1\n")
    (tmp_path / ".env").write_text("LLM_BASE_URL=https://collector.attacker.example/v1\n")
    monkeypatch.setenv("LLM_API_KEY", "the-users-own-key")
    monkeypatch.chdir(tmp_path)
    seen = _capture(monkeypatch)
    assert main(["harden", str(target), "--no-analyser"]) == EXIT_ERROR
    assert "LLM_BASE_URL" in capsys.readouterr().err and not seen
    assert main(["harden", str(target), "--no-analyser",
                 "--base-url", "https://api.openai.com/v1"]) == EXIT_OK
    assert seen["url"] == "https://api.openai.com/v1/chat/completions"


def test_local_app_harden_refuses_an_endpoint_from_dotenv(tmp_path, monkeypatch):
    from saikou.service import ServiceError, harden
    f = tmp_path / ".env"
    f.write_text("OLLAMA_BASE_URL=https://collector.attacker.example/v1\n")
    monkeypatch.setenv("OLLAMA_API_KEY", "the-users-own-key")
    llm.load_env_file(str(f))
    seen = _capture(monkeypatch)
    with pytest.raises(ServiceError) as err:
        harden({"code": "x = 1\n", "provider": "ollama", "language": "python"})
    assert err.value.status == 422 and "OLLAMA_BASE_URL" in str(err.value) and not seen


# ---- which endpoints may receive the key ---------------------------------------------------

@pytest.mark.parametrize("url", [
    "http://localhost.attacker.example/v1",         # the old prefix check let these through
    "http://127.0.0.1.attacker.example/v1",
    "http://localhost:1@attacker.example/v1",
    "https://user:pw@api.example.com/v1",
    "https://localhost%2eattacker.example/v1",      # urllib would unquote the host
    "http://[::1%25eth0]:11434/v1",
    r"http://localhost\@attacker.example/v1",
    "https://api.example.com /v1",
    "https://api.example.com/v1?next=x",
    "http://example.com/v1",
    "http://0.0.0.0:11434/v1",
    "ftp://localhost/v1",
    "https:///v1",
])
def test_key_is_not_sent_to_an_endpoint_that_is_not_https_or_this_machine(monkeypatch, url):
    seen = _capture(monkeypatch)
    with pytest.raises(llm.LLMError):
        llm.call_llm(MESSAGES, HARDEN_SCHEMA, llm.LLMConfig(base_url=url, api_key="the-key"))
    assert not seen


@pytest.mark.parametrize("url, sent", [
    ("http://localhost:11434/v1", "http://localhost:11434/v1/chat/completions"),
    ("http://127.0.0.2:8080/v1", "http://127.0.0.2:8080/v1/chat/completions"),
    ("http://[::1]:11434/v1", "http://[::1]:11434/v1/chat/completions"),
    ("HTTPS://Ollama.com/v1/", "https://ollama.com/v1/chat/completions"),
])
def test_key_goes_to_https_or_a_loopback_address(monkeypatch, url, sent):
    seen = _capture(monkeypatch)
    llm.call_llm(MESSAGES, HARDEN_SCHEMA, llm.LLMConfig(base_url=url, api_key="the-key"))
    assert seen["url"] == sent


# ---- found by the adversarial check of the first version of these fixes -------------------

@pytest.mark.parametrize("name", ["LLM_BASE_URL", "llm_base_url"])
def test_api_key_env_cannot_name_an_endpoint_variable(tmp_path, monkeypatch, capsys, name):
    target = tmp_path / "svc.py"
    target.write_text("x = 1\n")
    (tmp_path / ".env").write_text(f"{name}=https://collector.attacker.example/v1\n")
    monkeypatch.chdir(tmp_path)
    seen = _capture(monkeypatch)
    assert main(["harden", str(target), "--no-analyser", "--api-key-env", name]) == EXIT_ERROR
    assert not seen


def test_env_file_cannot_choose_the_provider(tmp_path, monkeypatch):
    target = tmp_path / "svc.py"
    target.write_text("x = 1\n")
    (tmp_path / ".env").write_text("LLM_PROVIDER=ollama\n")
    monkeypatch.setenv("MY_KEY", "the-users-gateway-key")
    monkeypatch.chdir(tmp_path)
    seen = _capture(monkeypatch)
    assert main(["harden", str(target), "--no-analyser", "--api-key-env", "MY_KEY"]) == EXIT_OK
    assert seen["url"] == "https://api.openai.com/v1/chat/completions"


def test_the_default_endpoint_in_a_copied_env_example_is_not_refused(tmp_path):
    f = tmp_path / ".env"
    f.write_text("LLM_API_KEY=key-from-file\nLLM_BASE_URL=https://api.openai.com/v1\n")
    llm.load_env_file(str(f))
    assert llm.LLMConfig.from_env().base_url == "https://api.openai.com/v1"


def test_harden_names_only_the_checked_endpoint(tmp_path, monkeypatch, capsys):
    target = tmp_path / "svc.py"
    target.write_text("x = 1\n")
    monkeypatch.setenv("LLM_API_KEY", "the-key")
    monkeypatch.chdir(tmp_path)
    seen = _capture(monkeypatch)
    assert main(["harden", str(target), "--no-analyser",
                 "--base-url", "https://alice:fake-pass-456@gw.example/v1"]) == EXIT_ERROR
    assert "fake-pass-456" not in capsys.readouterr().err and not seen


def test_local_provider_on_a_remote_url_does_not_say_nothing_leaves(tmp_path, monkeypatch, capsys):
    target = tmp_path / "svc.py"
    target.write_text("x = 1\n")
    monkeypatch.setenv("OLLAMA_LOCAL_MODEL", "m")
    monkeypatch.chdir(tmp_path)
    _capture(monkeypatch)
    main(["harden", str(target), "--no-analyser", "--provider", "local",
          "--base-url", "https://gateway.example/v1"])
    err = capsys.readouterr().err
    assert "nothing leaves it" not in err and "https://gateway.example/v1" in err
