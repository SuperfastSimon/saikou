"""Refill the demo blocks on the site with real `saikou verify` output.

    python scripts/render_site_demo.py

Runs the CLI on tests/fixtures/demo and rewrites the text between
<!--demo:NAME-->...<!--/demo--> markers in site/index.html and site/nl/index.html, so the page never
shows output the engine did not produce.
"""

from __future__ import annotations

import html
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEMO = ROOT / "tests" / "fixtures" / "demo"
CASES = {"A_fake": "after_A_fake.py", "B_partial": "after_B_partial.py", "C_real": "after_C_real.py"}
CLAIMS = "injection,crypto,path_traversal"
WRAP = 96


def run(after: str) -> str:
    # The CLI writes UTF-8 (it reconfigures stdout); decode it as such, not with the Windows locale
    # codec, which turned every "·" into "Â·" on the published pages.
    proc = subprocess.run(
        [sys.executable, "-m", "saikou", "verify", "before.py", after, "--claimed-threats", CLAIMS],
        cwd=DEMO, capture_output=True, text=True, encoding="utf-8",
        env={"PYTHONPATH": str(ROOT), "PATH": "", "SYSTEMROOT": "C:\\Windows", "PYTHONIOENCODING": "utf-8"})
    if proc.returncode not in (0, 1):
        raise SystemExit(f"saikou failed on {after}: {proc.stderr}")
    return proc.stdout.rstrip()


def tidy(text: str) -> str:
    """Wrap long finding lines and drop the reading-guide boilerplate line."""
    out = []
    for line in text.splitlines():
        if line.startswith("No score."):
            continue
        if len(line) <= WRAP:
            out.append(line)
            continue
        indent = len(line) - len(line.lstrip())
        cont = " " * (indent + 12)
        words, cur = line.split(" "), ""
        first = True
        for w in words:
            if len(cur) + len(w) + 1 > WRAP:
                out.append(cur if first else cur)
                cur, first = cont + w, False
            else:
                cur = (cur + " " + w) if cur else w
        out.append(cur)
    return "\n".join(out).rstrip()


def main() -> int:
    bodies = {name: html.escape(tidy(run(after))) for name, after in CASES.items()}
    for rel in ("index.html", "nl/index.html"):
        page = ROOT / "site" / rel
        text = page.read_text(encoding="utf-8")
        for name, body in bodies.items():
            text, n = re.subn(rf"(<!--demo:{name}-->).*?(<!--/demo-->)",
                              lambda m: m.group(1) + body + m.group(2), text, flags=re.S)
            if n != 1:
                raise SystemExit(f"{rel}: marker demo:{name} not found exactly once")
        page.write_text(text, encoding="utf-8")
        print(f"site/{rel} demo blocks refreshed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
