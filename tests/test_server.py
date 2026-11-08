"""saikou.server (the local app behind `saikou ui`) and the web app it serves."""

import http.client
import json
import re
import shutil
import subprocess
import threading
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import url2pathname

import pytest

from saikou import engine, llm, server, webassets
from saikou.cli import main

WEB = Path(server.__file__).resolve().with_name("web")
FAKE_BEFORE = "import subprocess\n\ndef run(cmd):\n    return subprocess.call(cmd, shell=True)\n"
FAKE_AFTER = FAKE_BEFORE.replace("shell=True)", "shell=True)  # nosec")


@pytest.fixture
def app(tmp_path):
    srv = server.AppServer(0, repo=str(tmp_path), token="test-session-key")
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield srv
    srv.shutdown()
    srv.server_close()


def request(srv, method, path, body=None, *, token=True, host=None, headers=None):
    port = srv.server_address[1]
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    hdrs = {"Host": host or f"127.0.0.1:{port}"}
    if token:
        hdrs["X-Saikou-Token"] = srv.token
    data = None
    if body is not None:
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        hdrs["Content-Type"] = "application/json"
    hdrs.update(headers or {})
    conn.request(method, path, body=data, headers=hdrs)
    resp = conn.getresponse()
    raw = resp.read()
    conn.close()
    try:
        parsed = json.loads(raw)
    except ValueError:
        parsed = raw.decode("utf-8", "replace")
    return resp.status, dict(resp.getheaders()), parsed


def test_serves_the_app_in_local_mode(app):
    status, headers, page = request(app, "GET", "/", token=False)
    assert status == 200 and 'data-mode="local"' in page
    assert "script-src 'self'" in headers["Content-Security-Policy"]
    assert headers["X-Frame-Options"] == "DENY"
    assert request(app, "GET", "/assets/app.js", token=False)[0] == 200
    assert request(app, "GET", "/assets/server.py", token=False)[0] == 404
    assert request(app, "GET", "/assets/../server.py", token=False)[0] == 404


def test_binds_loopback_only(app):
    assert app.server_address[0] == "127.0.0.1"
    assert app.url.startswith("http://127.0.0.1:") and "#t=test-session-key" in app.url


def test_host_header_must_name_this_server(app):
    """DNS rebinding: a page on evil.example resolving to 127.0.0.1 sends its own Host."""
    assert request(app, "GET", "/", host="evil.example")[0] == 421
    assert request(app, "GET", "/api/checks", host="evil.example")[0] == 421
    port = app.server_address[1]
    assert request(app, "GET", "/api/checks", host=f"localhost:{port}")[0] == 200


def test_api_needs_the_session_key(app):
    status, _, body = request(app, "GET", "/api/checks", token=False)
    assert status == 401 and body["error"]["code"] == "unauthorized"
    status, _, body = request(app, "GET", "/api/checks", headers={"X-Saikou-Token": "wrong"})
    assert status == 401
    status, _, body = request(app, "GET", "/api/checks")
    assert status == 200 and len(body["checks"]) > 30


def test_cross_site_origin_is_refused(app):
    status, _, body = request(app, "POST", "/api/verify", {"after": "x"},
                              headers={"Origin": "https://evil.example"})
    assert status == 403 and body["error"]["code"] == "bad_origin"
    port = app.server_address[1]
    status, _, _ = request(app, "POST", "/api/verify", {"after": "x = 1\n"},
                           headers={"Origin": f"http://127.0.0.1:{port}"})
    assert status == 200


def test_post_must_be_json_and_bounded(app, monkeypatch):
    status, _, body = request(app, "POST", "/api/verify", b"after=x",
                              headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert status == 415
    status, _, body = request(app, "POST", "/api/verify", b"{nope")
    assert status == 400 and body["error"]["code"] == "bad_json"
    monkeypatch.setattr(server, "MAX_BODY_BYTES", 100)
    status, _, body = request(app, "POST", "/api/verify", {"after": "x" * 200})
    assert status == 413 and body["error"]["code"] == "body_too_large"


def test_verify_and_errors_share_the_service_shape(app):
    status, _, out = request(app, "POST", "/api/verify", {
        "path": "svc.py", "before": FAKE_BEFORE, "after": FAKE_AFTER, "claimed_threats": ["injection"]})
    assert status == 200 and out["blocked"] is True
    status, _, out = request(app, "POST", "/api/verify", {"before": "x"})
    assert status == 422 and out["error"]["code"] == "missing_field"
    assert request(app, "POST", "/api/nope", {})[0] == 404
    assert request(app, "PUT", "/api/verify", {})[0] == 405


def test_meta_and_file_read(app, tmp_path):
    status, _, meta = request(app, "GET", "/api/meta")
    assert status == 200 and meta["mode"] == "local" and meta["repo"] == str(tmp_path)
    (tmp_path / "a.py").write_bytes(b"x = 1\n")
    status, _, out = request(app, "POST", "/api/file/read", {"path": str(tmp_path / "a.py")})
    assert status == 200 and out["content"] == "x = 1\n"


def test_harden_then_write_exactly_what_was_reviewed(app, tmp_path, monkeypatch):
    monkeypatch.setenv("LLM_API_KEY", "test-key-not-real")
    real = "import shlex\nimport subprocess\n\ndef run(cmd):\n    return subprocess.call(shlex.split(cmd))\n"
    replies = iter([real, "# a different answer\n" + real])

    def fake_post(*_a, **_k):
        payload = {"hardened_code": next(replies), "changes": [], "assumptions": [],
                   "deferred_defects": [{"issue": "x", "why_not_fixed": "y", "operating_limitation": "z"}]}
        return {"choices": [{"finish_reason": "stop", "message": {"content": json.dumps(payload)}}]}

    monkeypatch.setattr(llm, "_post", fake_post)
    target = tmp_path / "svc.py"
    target.write_text(FAKE_BEFORE)
    status, _, out = request(app, "POST", "/api/harden", {
        "code": FAKE_BEFORE, "path": str(target), "provider": "openai", "threats": ["injection"]})
    assert status == 200 and out["status"] == "verified" and out["result_id"]
    assert "+    return subprocess.call(shlex.split(cmd))" in out["diff"]
    assert target.read_text() == FAKE_BEFORE                      # nothing written yet
    status, _, done = request(app, "POST", "/api/harden/write",
                              {"result_id": out["result_id"], "path": str(target)})
    assert status == 200 and done["written"] is True
    assert target.read_text() == real                             # the reviewed output, no new model call
    status, _, again = request(app, "POST", "/api/harden/write",
                               {"result_id": out["result_id"], "path": str(target)})
    assert status == 404 and again["error"]["code"] == "result_not_found"


needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")


@needs_git
def test_gate_defaults_to_the_repo_given_at_start(app, tmp_path):
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
    status, _, out = request(app, "POST", "/api/git/diff", {"base": "HEAD"})
    assert status == 200 and out["blocked"] is True


def test_cli_ui_starts_the_server(monkeypatch):
    seen = {}
    monkeypatch.setattr(server, "serve", lambda **kw: seen.update(kw) or 0)
    assert main(["ui", "--no-browser", "--port", "0", "--env-file", "does-not-exist.env"]) == 0
    assert seen["open_browser"] is False and seen["port"] == 0


# ---- the session key never reaches a command line (review 13) ---------------------------------

def _page_of(uri):
    return Path(url2pathname(urlsplit(uri).path))


def _serve_once(monkeypatch, open_browser):
    """Run server.serve() until it has opened (or not opened) the browser, then stop it."""
    opened = []

    def fake_open(target, *_a, **_k):
        # webbrowser passes this string to the browser (or xdg-open) on its command line
        entry = {"arg": target}
        if target.startswith("file:"):
            page = _page_of(target)
            entry.update(page=page, html=page.read_text(encoding="utf-8"),
                         mode=page.stat().st_mode & 0o777, dir_mode=page.parent.stat().st_mode & 0o777)
        opened.append(entry)
        return True

    def stop(self, *_a, **_k):
        raise KeyboardInterrupt

    monkeypatch.setattr(server.webbrowser, "open", fake_open)
    monkeypatch.setattr(server.AppServer, "serve_forever", stop)
    monkeypatch.setattr(server.secrets, "token_urlsafe", lambda _n: "k3y-only-for-this-test")
    assert server.serve(port=0, open_browser=open_browser) == 0
    return opened


def test_browser_is_opened_without_the_key_on_its_command_line(monkeypatch, capsys):
    opened = _serve_once(monkeypatch, open_browser=True)
    assert len(opened) == 1
    arg = opened[0]["arg"]
    assert "k3y-only-for-this-test" not in arg and "#t=" not in arg
    assert arg.startswith("file:") and arg.endswith(".html")
    page = opened[0]["html"]
    assert re.search(r'http-equiv="refresh" content="0;url=http://127\.0\.0\.1:\d+/#t=k3y-only-for-this-test"',
                     page), page
    if server.os.name == "posix":
        assert opened[0]["mode"] == 0o600 and opened[0]["dir_mode"] == 0o700
    assert not opened[0]["page"].exists() and not opened[0]["page"].parent.exists()  # gone at shutdown
    assert "#t=k3y-only-for-this-test" in capsys.readouterr().out                  # link still printed


def test_no_browser_prints_the_link_and_writes_nothing(monkeypatch, capsys):
    assert _serve_once(monkeypatch, open_browser=False) == []
    assert "#t=k3y-only-for-this-test" in capsys.readouterr().out


def test_redirect_page_is_removed_after_its_lifetime(monkeypatch):
    seen = []
    monkeypatch.setattr(server.webbrowser, "open", lambda target, *a, **k: seen.append(target) or True)
    remove = server._open_in_browser("http://127.0.0.1:1/#t=TTL-KEY", ttl=0.05)
    page = _page_of(seen[0])
    assert "TTL-KEY" not in seen[0]
    for _ in range(200):
        if not page.exists():
            break
        threading.Event().wait(0.02)
    assert not page.parent.exists()
    remove()                                                       # a second removal is harmless


def test_redirect_page_escapes_the_link():
    path = Path(server._write_redirect_page('http://127.0.0.1:1/#t="><script>x</script>'))
    try:
        text = path.read_text(encoding="utf-8")
        assert "<script>" not in text and "&quot;&gt;&lt;script&gt;" in text
    finally:
        shutil.rmtree(path.parent)


def test_unwritable_temp_folder_opens_nothing(monkeypatch, capsys):
    def broken(*_a, **_k):
        raise OSError("no space left")
    seen = []
    monkeypatch.setattr(server.tempfile, "mkdtemp", broken)
    monkeypatch.setattr(server.webbrowser, "open", lambda *a, **k: seen.append(a) or True)
    server._open_in_browser("http://127.0.0.1:1/#t=abc")()
    assert seen == [] and "open the link above" in capsys.readouterr().err


# ---- port 80: browsers leave the default port out of Host and Origin (review 17) ---------------

def test_port_80_accepts_the_portless_host_and_origin():
    hosts, origins = server.allowed_hosts(80)
    assert {"127.0.0.1", "localhost", "127.0.0.1:80", "localhost:80"} == hosts
    assert {"http://127.0.0.1", "http://localhost", "http://127.0.0.1:80", "http://localhost:80"} == origins


def test_other_ports_still_refuse_the_portless_forms():
    hosts, origins = server.allowed_hosts(8765)
    assert hosts == {"127.0.0.1:8765", "localhost:8765"}
    assert origins == {"http://127.0.0.1:8765", "http://localhost:8765"}
    hosts80, origins80 = server.allowed_hosts(80)
    for bad in ("127.0.0.1:8765", "evil.example", "evil.example:80", "127.0.0.2", "[::1]", ""):
        assert bad not in hosts80
    assert "https://127.0.0.1" not in origins80 and "http://evil.example" not in origins80


def test_portless_host_is_refused_on_a_non_default_port(app):
    assert request(app, "GET", "/api/checks", host="127.0.0.1")[0] == 421
    assert request(app, "GET", "/api/checks", host="localhost")[0] == 421


def test_port_80_server_answers_a_browser_request():
    try:
        srv = server.AppServer(80, token="test-session-key")
    except OSError as exc:  # port 80 needs privileges on Linux/macOS, or is taken
        pytest.skip(f"cannot bind 127.0.0.1:80 here: {exc}")
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        assert request(srv, "GET", "/api/checks", host="127.0.0.1")[0] == 200
        status, _, _ = request(srv, "POST", "/api/verify", {"after": "x = 1\n"}, host="localhost",
                               headers={"Origin": "http://127.0.0.1"})
        assert status == 200
        assert request(srv, "GET", "/api/checks", host="127.0.0.1:8080")[0] == 421
        assert request(srv, "POST", "/api/verify", {"after": "x = 1\n"}, host="127.0.0.1",
                       headers={"Origin": "http://127.0.0.1:8080"})[0] == 403
    finally:
        srv.shutdown()
        srv.server_close()


# ---- the web app's own guarantees ------------------------------------------------------------

def _strings(lang):
    src = (WEB / "app.js").read_text(encoding="utf-8")
    block = re.search(rf"\n    {lang}: \{{(.*?)\n    \}}", src, re.S).group(1)
    return set(re.findall(r'"([\w.]+)":', block))


def test_both_languages_have_every_string():
    en, nl = _strings("en"), _strings("nl")
    assert en == nl, (en ^ nl)
    html = (WEB / "index.html").read_text(encoding="utf-8")
    used = set(re.findall(r'data-i18n="([\w.]+)"', html))
    used |= {k for pair in re.findall(r'data-i18n-attr="([^"]+)"', html)
             for k in re.findall(r":([\w.]+)", pair)}
    used |= {k for k in re.findall(r'\bt\("([\w.]+)"', (WEB / "app.js").read_text(encoding="utf-8"))
             if not k.endswith(".")}            # t("applies." + a): covered by `dynamic` below
    dynamic = ({f"threat.{t}" for t in engine.THREAT_CHOICES} | {f"provider.{p}" for p in llm.PROVIDERS}
               | {f"applies.{a}" for a in ("python", "javascript", "config", "all", "harden")}
               | {f"sev.{s}" for s in ("hard", "warn", "depends")} | {f"modes.{m}" for m in ("verify", "gate", "both")}
               | {f"change.{c}" for c in ("added", "modified", "verify")} | {f"theme.{t}" for t in ("system", "light", "dark")}
               | {f"history.{k}" for k in ("verify", "gate", "harden")} | {f"nav.{s}" for s in ("verify", "gate", "harden", "checks", "history")})
    missing = (used | dynamic) - en
    assert not missing, missing


def test_web_app_loads_nothing_from_elsewhere():
    for name in ("index.html", "app.js", "app.css"):
        text = (WEB / name).read_text(encoding="utf-8")
        urls = set(re.findall(r"https?://[^\s\"')]+", text)) - {"http://www.w3.org/2000/svg"}
        assert not urls, (name, urls)
    js = (WEB / "app.js").read_text(encoding="utf-8")
    assert "innerHTML" not in js and "insertAdjacentHTML" not in js and "eval(" not in js
    assert "style=" not in (WEB / "index.html").read_text(encoding="utf-8")   # CSP: no inline styles


def test_dark_theme_tokens_are_defined_once_in_effect():
    css = (WEB / "app.css").read_text(encoding="utf-8")
    media = re.search(r':root:not\(\[data-theme="light"\]\) \{(.*?)color-scheme', css, re.S).group(1)
    forced = re.search(r"/\*dark\*/(.*?)/\*end\*/", css, re.S).group(1)
    norm = lambda s: re.findall(r"--[\w-]+:\s*[^;]+;", s)
    assert norm(media) == norm(forced)


def test_app_code_holds_no_fake_fix_markers():
    """Saikou gates its own saikou/ folder in CI. Example fake fixes live in sample.json
    (data, like tests/fixtures), never in app code, or every PR would block itself."""
    from saikou.verify import verify_pair
    for name in ("app.js", "app.css", "index.html"):
        text = (WEB / name).read_text(encoding="utf-8")
        report = verify_pair("", text, path=f"saikou/web/{name}", expect_change=False, change="added")
        assert not report.blocked, (name, [f.check for f in report.findings])
    sample = json.loads((WEB / "sample.json").read_text(encoding="utf-8"))
    assert "# nosec" in sample["after"] and sample["threats"]


def test_empty_translation_is_not_shown_as_its_key():
    js = (WEB / "app.js").read_text(encoding="utf-8")
    assert '"report.detailLang": ""' in js and "hasOwnProperty" in js


def test_packaged_assets():
    assert {"app.js", "app.css", "logo.svg", "sample.json"} <= set(webassets.ASSETS)
    assert b'data-mode="hosted"' in webassets.page("hosted")
    with pytest.raises(ValueError):
        webassets.page("other")
