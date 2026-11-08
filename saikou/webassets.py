"""The Saikou web app's static files (saikou/web/), shared by the local app (saikou.server)
and the hosted playground (saikou.api).

Only the files present in the package directory at import time can be served, looked up by
exact name in a dict, so a request path is never joined onto the file system.
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, Optional, Tuple

WEB = Path(__file__).resolve().with_name("web")
MODES = ("local", "hosted")

_TYPES = {".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8",
          ".js": "text/javascript; charset=utf-8", ".svg": "image/svg+xml",
          ".json": "application/json"}

# Everything the app needs is same-origin; nothing third-party, no inline script or style.
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
       "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")

ASSETS: Dict[str, Path] = {p.name: p for p in WEB.iterdir()
                           if p.is_file() and p.suffix in _TYPES and p.name != "index.html"} \
    if WEB.is_dir() else {}


def asset(name: str) -> Optional[Tuple[bytes, str]]:
    """(content, content type) of a packaged asset, or None for anything else."""
    path = ASSETS.get(name)
    if path is None:
        return None
    return path.read_bytes(), _TYPES[path.suffix]


def page(mode: str) -> bytes:
    """index.html with the app switched to `mode` ('local' = every screen, 'hosted' = Verify
    and Checks only)."""
    if mode not in MODES:
        raise ValueError(mode)
    html = (WEB / "index.html").read_text(encoding="utf-8")
    return html.replace('data-mode="local"', f'data-mode="{mode}"', 1).encode("utf-8")
