"""Measure how Saikou behaves on real code nobody wrote for it.

    python scripts/fp_corpus.py DIR [DIR ...] [--json out.json]

Two numbers per language, never merged:

1. Gating false-block rate. Each real file gets a harmless edit appended (a
   trivial function). The edit introduces nothing unsafe, so ANY hard fail is a
   false positive of the gate. This is the number that decides whether a CI
   check annoys people.

2. New-file block rate. Each real file is treated as newly added. Hard fails
   here are by design (a new eval/shell=True/literal secret is flagged), so this
   is not a false-positive rate - it shows how often real, reviewed code would
   need an explicit decision if it arrived as new code.

The JSON report starts with "produced_by": the engine version, the commit and the
tree of saikou/ it was measured with (and whether saikou/ had uncommitted
changes), the date (UTC) and the Python version. Corpus paths are not recorded,
and example files are given relative to the folder they were found in.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone
from typing import Dict, List, Optional

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, REPO)

from saikou.engine import Severity, __version__, language_for_path, scan_transformation


def _git(*args: str) -> Optional[str]:
    try:
        proc = subprocess.run(["git", *args], cwd=REPO, capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    return proc.stdout.strip() if proc.returncode == 0 else None


def produced_by() -> dict:
    """Which engine produced a report, so a reader can tell whether it still applies."""
    status = _git("status", "--porcelain", "--", "saikou")
    return {
        "engine_version": __version__,
        "commit": _git("rev-parse", "HEAD"),
        "engine_tree": _git("rev-parse", "HEAD:saikou"),
        "engine_modified": None if status is None else bool(status),
        "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "python": platform.python_version(),
    }

PROBE = {
    "python": "\n\ndef _saikou_probe():\n    return 1\n",
    "javascript": "\nfunction saikouProbe() { return 1; }\n",
    "typescript": "\nfunction saikouProbe(): number { return 1; }\n",
}
SKIP_PARTS = ("test", "tests", "testing", "idlelib", "lib2to3", "__pycache__", "site-packages",
              "node_modules/.bin")


def iter_files(root: str, nested_ok: bool):
    for dirpath, dirnames, filenames in os.walk(root):
        rel = os.path.relpath(dirpath, root).replace("\\", "/")
        parts = rel.split("/")
        if any(p in ("test", "tests", "testing", "__pycache__") for p in parts):
            dirnames[:] = []
            continue
        if not nested_ok and ("site-packages" in parts or "idlelib" in parts
                              or "lib2to3" in parts):
            dirnames[:] = []
            continue
        for name in filenames:
            path = os.path.join(dirpath, name)
            lang = language_for_path(name)
            if lang in PROBE and not name.endswith(".min.js"):
                yield path, lang


def hard(findings) -> List[str]:
    return [f.check for f in findings if f.severity is Severity.HARD_FAIL]


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("dirs", nargs="+")
    ap.add_argument("--json")
    ap.add_argument("--nested", action="store_true",
                    help="descend into site-packages-like subfolders")
    args = ap.parse_args(argv)

    stats: Dict[str, Dict] = {}
    for root in args.dirs:
        for path, lang in iter_files(root, args.nested):
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    code = fh.read()
            except (OSError, UnicodeDecodeError):
                continue
            if not code.strip() or len(code) > 1_000_000:
                continue
            s = stats.setdefault(lang, {"files": 0, "gating_blocked": 0, "gating_checks": Counter(),
                                        "gating_examples": [], "newfile_blocked": 0,
                                        "newfile_checks": Counter()})
            s["files"] += 1
            gate = hard(scan_transformation(code, code + PROBE[lang], language=lang,
                                            expect_change=False))
            if gate:
                s["gating_blocked"] += 1
                s["gating_checks"].update(gate)
                if len(s["gating_examples"]) < 10:
                    rel = os.path.relpath(path, root).replace("\\", "/")
                    s["gating_examples"].append({"file": rel, "checks": sorted(set(gate))})
            new = hard(scan_transformation("", code, language=lang, expect_change=False))
            if new:
                s["newfile_blocked"] += 1
                s["newfile_checks"].update(set(new))

    report: Dict[str, Dict] = {"produced_by": produced_by()}
    for lang, s in sorted(stats.items()):
        n = s["files"]
        report[lang] = {
            "files": n,
            "gating_false_block_rate": round(100.0 * s["gating_blocked"] / n, 2) if n else None,
            "gating_blocked_files": s["gating_blocked"],
            "gating_checks": dict(s["gating_checks"].most_common()),
            "gating_examples": s["gating_examples"],
            "newfile_block_rate": round(100.0 * s["newfile_blocked"] / n, 2) if n else None,
            "newfile_checks_by_file": dict(s["newfile_checks"].most_common()),
        }
        print(f"{lang:<11} files={n:<5} gating false-block={report[lang]['gating_false_block_rate']}% "
              f"({s['gating_blocked']})  new-file block={report[lang]['newfile_block_rate']}%")
        for check, count in s["gating_checks"].most_common(5):
            print(f"    gating  {check}: {count}")
        for check, count in s["newfile_checks"].most_common(6):
            print(f"    newfile {check}: {count} file(s)")
    if args.json:
        with open(args.json, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(report, fh, indent=2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
