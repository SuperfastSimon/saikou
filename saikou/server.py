"""The local Saikou app: `saikou ui`.

A small standard-library web server that serves the Saikou web app and a JSON API backed by
saikou.service. Unlike the hosted API it can open files, gate a git working tree and write a
verified hardening result, so it is locked to this machine and this browser session:

- it binds 127.0.0.1 only (a free port unless --port is given);
- a one-time key travels in the URL fragment (#t=...), which browsers never send to a
  server or put in a Referer; every /api call must echo it in the X-Saikou-Token header;
- the Host header must name this server, which stops DNS rebinding, and a request from any
  other Origin is refused;
- POST bodies must be JSON and are capped in size;
- the browser is opened on a private temporary page that redirects to the link, so the key
  never appears on a command line (`ps` and /proc/*/cmdline are readable by other users).
"""

from __future__ import annotations

import atexit
import html
import json
import os
import secrets
import shutil
import sys
import tempfile
import threading
import traceback
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Set, Tuple
from urllib.parse import urlsplit

from . import service, webassets
from .engine import __version__
from .service import ServiceError

MAX_BODY_BYTES = 2_000_000
# How long the redirect page that carries the key stays on disk. A browser that is still
# starting may read it late, so this is generous; the page goes at shutdown in any case.
REDIRECT_PAGE_TTL_S = 60.0


def allowed_hosts(port: int) -> Tuple[Set[str], Set[str]]:
    """The Host and Origin values that name this server on `port`. A browser leaves out the
    default port, so on port 80 it sends `Host: 127.0.0.1` and `Origin: http://127.0.0.1`;
    on any other port those portless forms name a different server and stay refused."""
    hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
    if port == 80:
        hosts |= {"127.0.0.1", "localhost"}
    return hosts, {f"http://{h}" for h in hosts}


def _meta(server: "AppServer") -> dict:
    return {"version": __version__, "mode": "local", "repo": server.repo or "",
            "cwd": os.getcwd()}


GET_ROUTES: Dict[str, Callable[["AppServer"], dict]] = {
    "/api/meta": _meta,
    "/api/checks": lambda _s: service.checks(),
    "/api/providers": lambda _s: service.providers(),
}
POST_ROUTES: Dict[str, Callable[[Any], dict]] = {
    "/api/verify": service.verify,
    "/api/verify/batch": service.verify_batch,
    "/api/git/diff": service.git_diff,
    "/api/harden": service.harden,
    "/api/harden/write": service.write_result,
    "/api/file/read": service.read_file,
}


class AppServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, port: int = 0, repo: Optional[str] = None,
                 token: Optional[str] = None, verbose: bool = False) -> None:
        super().__init__(("127.0.0.1", port), Handler)
        self.token = token or secrets.token_urlsafe(24)
        self.repo = repo
        self.verbose = verbose
        self.hosts, self.origins = allowed_hosts(self.server_address[1])

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server_address[1]}/#t={self.token}"


class Handler(BaseHTTPRequestHandler):
    server: AppServer
    server_version = "saikou-ui"
    sys_version = ""

    # ---- plumbing ---------------------------------------------------------------------

    def log_message(self, fmt: str, *args: Any) -> None:
        if self.server.verbose:
            sys.stderr.write("saikou ui: " + (fmt % args) + "\n")

    def _send(self, status: int, body: bytes, ctype: str,
              headers: Optional[Dict[str, str]] = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, status: int, data: Any) -> None:
        self._send(status, json.dumps(data).encode("utf-8"), "application/json")

    def _error(self, status: int, code: str, message: str) -> None:
        self._json(status, {"error": {"code": code, "message": message}})

    def _host_ok(self) -> bool:
        return self.headers.get("Host", "") in self.server.hosts

    def _api_allowed(self) -> Optional[Tuple[int, str, str]]:
        origin = self.headers.get("Origin")
        if origin is not None and origin not in self.server.origins:
            return 403, "bad_origin", "Requests from other sites are refused."
        token = self.headers.get("X-Saikou-Token", "")
        if not secrets.compare_digest(token.encode(), self.server.token.encode()):
            return 401, "unauthorized", ("Missing or wrong session key. Open the link that "
                                         "`saikou ui` printed.")
        return None

    def _drain(self) -> None:
        """Read and drop an unread request body, so the client gets our error reply instead
        of a connection reset (Windows resets a socket closed with unread data)."""
        try:
            left = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            left = 0
        if left > 16 * MAX_BODY_BYTES:
            self.close_connection = True
            return
        while left > 0:
            chunk = self.rfile.read(min(left, 65536))
            if not chunk:
                break
            left -= len(chunk)

    def _read_json(self) -> Any:
        ctype = self.headers.get("Content-Type", "").split(";")[0].strip().lower()
        if ctype != "application/json":
            self._drain()
            raise ServiceError(415, "unsupported_media_type", "Send JSON (application/json).")
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            raise ServiceError(411, "length_required", "Content-Length is required.") from None
        if length < 0 or length > MAX_BODY_BYTES:
            self._drain()
            raise ServiceError(413, "body_too_large", f"Request body exceeds {MAX_BODY_BYTES} bytes.")
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise ServiceError(400, "bad_json", "Request body is not valid UTF-8 JSON.") from None

    def _dispatch(self, run: Callable[[], dict]) -> None:
        try:
            self._json(200, run())
        except ServiceError as exc:
            self._json(exc.status, exc.as_dict())
        except Exception as exc:  # report, never crash the server
            traceback.print_exc()
            self._error(500, "internal_error", f"{type(exc).__name__}: {exc}"[:300])

    # ---- verbs ------------------------------------------------------------------------

    def do_GET(self) -> None:
        if not self._host_ok():
            self._error(421, "bad_host", "Unexpected Host header.")
            return
        path = urlsplit(self.path).path
        if path == "/":
            self._send(200, webassets.page("local"), "text/html; charset=utf-8",
                       {"Content-Security-Policy": webassets.CSP})
            return
        if path.startswith("/assets/"):
            found = webassets.asset(path[len("/assets/"):])
            if found is None:
                self._error(404, "not_found", "Not found.")
            else:
                self._send(200, found[0], found[1])
            return
        route = GET_ROUTES.get(path)
        if route is None:
            self._error(404, "not_found", "Not found.")
            return
        refused = self._api_allowed()
        if refused:
            self._error(*refused)
            return
        self._dispatch(lambda: route(self.server))

    def do_HEAD(self) -> None:
        self.do_GET()

    def do_POST(self) -> None:
        route = POST_ROUTES.get(urlsplit(self.path).path)
        if not self._host_ok():
            refused: Optional[Tuple[int, str, str]] = (421, "bad_host", "Unexpected Host header.")
        elif route is None:
            refused = (404, "not_found", "Not found.")
        else:
            refused = self._api_allowed()
        if refused or route is None:
            self._drain()
            self._error(*(refused or (404, "not_found", "Not found.")))
            return
        try:
            body = self._read_json()
        except ServiceError as exc:
            self._json(exc.status, exc.as_dict())
            return
        if route is service.git_diff and isinstance(body, dict) and not body.get("repo") \
                and self.server.repo:
            body["repo"] = self.server.repo
        self._dispatch(lambda: route(body))

    def _refuse(self) -> None:
        self._drain()
        self._error(405, "method_not_allowed", "Method not allowed.")

    do_PUT = do_DELETE = do_PATCH = do_OPTIONS = _refuse


def default_repo(path: Optional[str]) -> Optional[str]:
    """--repo if given, else the current folder when it is a git work tree."""
    candidate = os.path.abspath(path or os.getcwd())
    if path or os.path.exists(os.path.join(candidate, ".git")):
        return candidate
    return None


_REDIRECT_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="referrer" content="no-referrer">
<meta http-equiv="refresh" content="0;url={url}">
<title>Opening Saikou</title>
</head>
<body>
<p>Opening Saikou. If nothing happens, <a href="{url}" rel="noreferrer">open the app</a>.</p>
</body>
</html>
"""


def _write_redirect_page(url: str) -> str:
    """Write a page that sends the browser to `url` into a new private temporary folder
    (mkdtemp: 0700; the page itself 0600) and return its path."""
    folder = tempfile.mkdtemp(prefix="saikou-ui-")
    path = os.path.join(folder, "open.html")
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(_REDIRECT_PAGE.format(url=html.escape(url, quote=True)))
    except BaseException:
        shutil.rmtree(folder, ignore_errors=True)
        raise
    return path


def _open_in_browser(url: str, ttl: float = REDIRECT_PAGE_TTL_S) -> Callable[[], None]:
    """Open `url` in the browser without putting it on a command line.

    webbrowser starts the browser (or xdg-open) with its argument in argv, which other users
    can read; so the browser gets a file:// link to a private page that redirects to `url`,
    the way Jupyter does it. The page is removed after `ttl` seconds, at shutdown (call the
    returned function) or at interpreter exit, whichever comes first. If the page cannot be
    written, nothing is opened: the printed link is the way in."""
    try:
        path = _write_redirect_page(url)
    except OSError as exc:
        print(f"saikou ui: could not prepare the browser page ({exc}); open the link above.",
              file=sys.stderr, flush=True)
        return lambda: None
    folder = os.path.dirname(path)

    def remove() -> None:
        timer.cancel()
        shutil.rmtree(folder, ignore_errors=True)

    timer = threading.Timer(ttl, remove)
    timer.daemon = True
    timer.start()
    atexit.register(remove)
    try:
        webbrowser.open(Path(path).as_uri())
    except Exception as exc:  # a broken browser setup must not stop the server
        print(f"saikou ui: could not open a browser ({exc}); open the link above.",
              file=sys.stderr, flush=True)
    return remove


def serve(port: int = 0, open_browser: bool = True, repo: Optional[str] = None,
          verbose: bool = False) -> int:
    server = AppServer(port, default_repo(repo), verbose=verbose)
    url = server.url
    print(f"Saikou {__version__} is running at:\n\n    {url}\n\n"
          "The link holds a key for this session only; anyone who has it can use the app "
          "on this machine.\nPress Ctrl+C to stop.", flush=True)
    cleanup: Callable[[], None] = lambda: None
    if open_browser:
        cleanup = _open_in_browser(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        cleanup()
        server.server_close()
    return 0
