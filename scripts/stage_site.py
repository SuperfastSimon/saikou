"""Assemble a deployable copy of the site.

    python scripts/stage_site.py --mode interim --out ../deploy-interim
    python scripts/stage_site.py --mode full    --out ../deploy-full

interim: a small bilingual "being rebuilt" page - removes the old Model10 claims
         immediately, needs nothing else to be live (no PyPI, no GitHub org).
full:    the complete site. Publish it only after the GitHub org / repo is public
         and `pip install saikou` works, because the pages say both are true.

The staged folder is then checked by scripts/check_site.py. Pushing it to the
GitHub Pages repo is a separate step that the maintainer approves.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SITE = ROOT / "site"
SHARED = ["legal.html", "Saikou.tech-logo-flat-hor.svg", "Saikou.tech-favicon.svg", "CNAME"]
INTERIM_ASSETS = ["style.css", "og-en.png"]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=("interim", "full"), required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    out = Path(args.out).resolve()
    if out.exists() and any(out.iterdir()):
        print(f"refusing to write into non-empty {out}", file=sys.stderr)
        return 2
    out.mkdir(parents=True, exist_ok=True)

    if args.mode == "interim":
        (out / "assets").mkdir()
        for name in INTERIM_ASSETS:
            shutil.copy2(SITE / "assets" / name, out / "assets" / name)
        shutil.copy2(SITE / "interim.html", out / "index.html")
        for name in SHARED:
            shutil.copy2(SITE / name, out / name)
        # The interim site has no services or Dutch home page: point legal.html's links at
        # what exists instead of leaving broken ones. Bytes in and out, so the line endings stay as
        # copied (write_text would turn them into CRLF on Windows and the build would differ from live).
        legal = (out / "legal.html").read_bytes().decode("utf-8")
        legal = legal.replace('<a href="services.html">Services &amp; NIS2</a>', "")
        legal = legal.replace('href="nl/index.html"', 'href="#nl"')
        (out / "legal.html").write_bytes(legal.encode("utf-8"))
    else:
        for item in SITE.iterdir():
            if item.name in ("interim.html",) or item.name.startswith("."):
                continue
            if item.is_dir():
                shutil.copytree(item, out / item.name)
            else:
                shutil.copy2(item, out / item.name)

    print(f"staged {args.mode} site in {out}")
    check = [sys.executable, str(ROOT / "scripts" / "check_site.py"), str(out)]
    if args.mode == "full":
        check.append("--require-sitemap")
    return subprocess.call(check)


if __name__ == "__main__":
    raise SystemExit(main())
