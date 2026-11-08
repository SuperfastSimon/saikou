"""Refill the data-driven parts of the home pages from the sources they describe.

    python scripts/render_site_data.py           # rewrite site/
    python scripts/render_site_data.py --check   # exit 1 when site/ is out of date

Writes site/assets/site-data.js (the data behind the fake-fix explorer and the two charts) and the
text between <!--data:NAME-->...<!--/data--> markers in site/index.html and site/nl/index.html: the
tables that carry the same numbers without JavaScript, and the single numbers used in the prose. It
also refills the raw command output between <!--demo:NAME-->...<!--/demo--> markers, the same way
scripts/render_site_demo.py does, so `--check` (and the test that runs it) covers that output too.

Sources, all read at build time: `saikou verify --format json` on tests/fixtures/demo, the frozen
oracle answers (through the same summaries the coverage statement is generated from),
docs/measurements/*.json, the engine's marker list and its self-test. Nothing here is typed by hand,
so the page cannot show a number the sources do not. The demo code is read from the fixtures, never
written into this file: the dogfood job checks scripts/ and a fake fix here would be one.
"""

from __future__ import annotations

import argparse
import difflib
import html
import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Dict, List

ROOT = Path(__file__).resolve().parent.parent
DEMO = ROOT / "tests" / "fixtures" / "demo"
SITE = ROOT / "site"
DATA_JS = SITE / "assets" / "site-data.js"
PAGES = {"en": SITE / "index.html", "nl": SITE / "nl" / "index.html"}
CASES = (("fake", "after_A_fake.py"), ("partial", "after_B_partial.py"), ("real", "after_C_real.py"))
# The pages name the verdicts in words ("Blocked", "Passes"); stop if the demo ever stops matching them.
EXPECT_BLOCKED = {"fake": True, "partial": True, "real": False}
CLAIMS = "injection,crypto,path_traversal"
MEASURED = (
    ("stdlib", "stdlib-py311.json", "python",
     {"en": "CPython 3.11 standard library", "nl": "CPython 3.11-standaardbibliotheek"}),
    ("web", "python-web-libraries.json", "python",
     {"en": "flask, fastapi, starlette, aiohttp, requests, pydantic, httpx, jinja2, werkzeug",
      "nl": "flask, fastapi, starlette, aiohttp, requests, pydantic, httpx, jinja2, werkzeug"}),
    ("js", "js-ts-node-modules.json", "javascript",
     {"en": "JavaScript (express and its dependencies)", "nl": "JavaScript (express en zijn afhankelijkheden)"}),
    ("ts", "js-ts-node-modules.json", "typescript",
     {"en": "TypeScript (mostly declaration files)", "nl": "TypeScript (vooral declaratiebestanden)"}),
)
SLOT = re.compile(r"<!--data:([a-z0-9-]+)-->(.*?)<!--/data-->", re.S)
for _p in (str(ROOT), str(ROOT / "scripts")):
    if _p not in sys.path:
        sys.path.insert(0, _p)


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _env() -> Dict[str, str]:
    return {"PYTHONPATH": str(ROOT), "PATH": "", "SYSTEMROOT": "C:\\Windows", "PYTHONIOENCODING": "utf-8"}


def _num(n: int, lang: str) -> str:
    return f"{n:,}".replace(",", "." if lang == "nl" else ",")


def demo_cases(catalog) -> List[dict]:
    before = (DEMO / "before.py").read_text(encoding="utf-8").splitlines()
    cases = []
    for cid, name in CASES:
        proc = subprocess.run([sys.executable, "-m", "saikou", "verify", "before.py", name,
                               "--claimed-threats", CLAIMS, "--format", "json"],
                              cwd=DEMO, capture_output=True, text=True, encoding="utf-8", env=_env())
        if proc.returncode not in (0, 1):
            raise SystemExit(f"saikou failed on {name}: {proc.stderr}")
        report = json.loads(proc.stdout)["files"][0]
        if report["blocked"] != EXPECT_BLOCKED[cid]:
            raise SystemExit(f"{name}: blocked={report['blocked']}, but the pages say otherwise")
        after = (DEMO / name).read_text(encoding="utf-8").splitlines()
        rows = []
        for op, a1, a2, b1, b2 in difflib.SequenceMatcher(None, before, after, autojunk=False).get_opcodes():
            if op == "equal":
                rows += [["=", a1 + i + 1, b1 + i + 1, after[b1 + i]] for i in range(a2 - a1)]
                continue
            rows += [["-", a + 1, None, before[a]] for a in range(a1, a2)]
            rows += [["+", None, b + 1, after[b]] for b in range(b1, b2)]
        findings = []
        for f in sorted(report["findings"], key=lambda f: (f.get("line") or 0, f["check"])):
            line = f.get("line") or None
            if line is not None and not 1 <= line <= len(after):
                raise SystemExit(f"{name}: finding {f['check']} points at line {line}, file has {len(after)}")
            entry = catalog.get(f["check"])
            if entry is None:
                raise SystemExit(f"{name}: {f['check']} is not in saikou/catalog.py")
            findings.append({"check": f["check"], "line": line, "provenance": f["provenance"],
                             "severity": f["severity"], "title": entry["title"], "detail": f["detail"]})
        cases.append({"id": cid, "file": name, "blocked": report["blocked"],
                      "tier": report["verification_tier"], "findings": findings, "diff": rows})
    return cases


def coverage() -> dict:
    oracle = _load("suppression_oracle", ROOT / "scripts" / "suppression_oracle.py")
    golden = json.loads(oracle.GOLDEN.read_text(encoding="utf-8"))
    s, ref = oracle.summarise(golden), golden["reference_tools"]
    k = s["kinds"]
    py = dict(total=s["total"], honoured=s["honoured"], blocks=k["caught"], warns=k["miss-warn-only"],
              missed=k["MISS"], over=sum(k[x] for x in oracle.BLOCKED_ANYWAY),
              tools=[dict(name=oracle.TOOL_NAME[t], honours=sum(s["per_tool"][t].values()),
                          blocks=s["per_tool"][t]["caught"], warns=s["per_tool"][t]["miss-warn-only"],
                          missed=s["per_tool"][t]["MISS"]) for t in oracle.TOOLS],
              executed=[{"bandit": f"bandit {ref['bandit']}", "ruff": ref.get("ruff", "ruff"),
                         "semgrep": f"semgrep {ref.get('semgrep', '')}".strip()}[t]
                        for t in ref.get("executed", ["bandit"])],
              patterns=[f"flake8 {ref['flake8']}"] + [oracle.TOOL_NAME[t] for t in ("sonar", "codeql", "semgrep")
                                                     if t not in ref.get("executed", ["bandit"])])
    gjs = json.loads(oracle.GOLDEN_JS.read_text(encoding="utf-8"))
    j, rjs = oracle.summarise_js(gjs), gjs["reference_tools"]
    js = dict(total=j["total"], honoured=j["honoured"], blocks=j["kinds"]["caught"],
              warns=j["kinds"]["style-warned"], missed=j["kinds"]["MISS"] + j["kinds"]["miss-warn-only"],
              over=j["over"], tools=j["per_tool"],
              executed=[f"ESLint {rjs['eslint']}", f"TypeScript {rjs['tsc']}", f"semgrep {rjs['semgrep']}"],
              patterns=[])
    for part in (py, js):
        if not part["tools"] or not part["executed"]:
            raise SystemExit("coverage: no reference tools in a golden file; the page cannot describe that")
        if part["blocks"] + part["warns"] + part["missed"] != part["honoured"]:
            raise SystemExit("coverage counts do not add up; regenerate the golden files")
    return {"python": py, "js": js}


def measured() -> List[dict]:
    rows = []
    for mid, fname, lang, label in MEASURED:
        part = json.loads((ROOT / "docs" / "measurements" / fname).read_text(encoding="utf-8"))[lang]
        files, rate = part["files"], part["newfile_block_rate"]
        if files <= 0:
            raise SystemExit(f"{fname} {lang}: no files measured")
        as_new = round(files * rate / 100)
        if round(100 * as_new / files, 2) != rate:
            raise SystemExit(f"{fname} {lang}: {rate}% of {files} files is not a whole number of files")
        rows.append({"id": mid, "label": label, "files": files,
                     "false_blocked": part["gating_blocked_files"], "as_new_blocked": as_new})
    return rows


def selftest_checks() -> int:
    proc = subprocess.run([sys.executable, "-m", "saikou", "selftest"], cwd=ROOT, capture_output=True,
                          text=True, encoding="utf-8", env=_env())
    m = re.search(r"(\d+)/(\d+) passed", proc.stdout)
    if proc.returncode != 0 or not m or m.group(1) != m.group(2):
        raise SystemExit("the engine self-test does not pass; fix that first")
    return int(m.group(2))


def build() -> dict:
    from saikou import catalog, engine
    return {"version": engine.__version__, "marker_kinds": len(engine.SUPPRESSION_MARKERS),
            "selftest_checks": selftest_checks(), "demo": demo_cases(catalog),
            "coverage": coverage(), "measured": measured()}


# ---- the parts written into the pages -------------------------------------------------------------

def _coverage_table(part: dict, lang: str) -> str:
    head = {"en": ("Reference tool", "Honours the new marker", "Saikou blocks", "Saikou warns", "Not reported"),
            "nl": ("Referentietool", "Respecteert de nieuwe marker", "Saikou blokkeert", "Saikou waarschuwt",
                   "Niet gemeld")}[lang]
    body = "".join(f"<tr><td>{html.escape(t['name'])}</td>" + "".join(
        f'<td class="num">{_num(t[c], lang)}</td>' for c in ("honours", "blocks", "warns", "missed"))
        + "</tr>" for t in part["tools"])
    return ("<thead><tr>" + "".join(f"<th>{h}</th>" for h in head) + "</tr></thead><tbody>" + body + "</tbody>")


def _measured_table(rows: List[dict], lang: str) -> str:
    head = {"en": ("Corpus", "Files", "Harmless edit blocked", "Same files as new code, blocked"),
            "nl": ("Corpus", "Bestanden", "Onschuldige wijziging geblokkeerd", "Zelfde bestanden als nieuwe code, geblokkeerd")}[lang]
    body = "".join(
        f"<tr><td>{html.escape(r['label'][lang])}</td><td class=\"num\">{_num(r['files'], lang)}</td>"
        f"<td class=\"num\">{_num(r['false_blocked'], lang)}</td><td class=\"num\">{_num(r['as_new_blocked'], lang)}</td></tr>"
        for r in rows)
    return ("<thead><tr>" + "".join(f"<th>{h}</th>" for h in head) + "</tr></thead><tbody>" + body + "</tbody>")


APPLIES = {"python": {"en": "Python", "nl": "Python"}, "all": {"en": "Any file", "nl": "Elk bestand"},
           "javascript": {"en": "JavaScript, TypeScript", "nl": "JavaScript, TypeScript"},
           "config": {"en": "Analyser configuration", "nl": "Analyzer-configuratie"},
           "harden": {"en": "saikou harden results", "nl": "Resultaten van saikou harden"}}
EFFECT = {"hard": {"en": "Blocks", "nl": "Blokkeert"}, "warn": {"en": "Warns", "nl": "Waarschuwt"},
          "depends": {"en": "Depends (see text)", "nl": "Hangt af (zie tekst)"}}
MODES = {"both": "verify, diff", "verify": "verify", "gate": "diff"}
PROV_LABEL = {"tool": "tool", "parser": "parser", "mechanical": "mechanical"}


def _catalogue_table(catalog, lang: str) -> str:
    head = {"en": ("Check", "Established by", "Applies to", "Effect", "Mode"),
            "nl": ("Check", "Vastgesteld door", "Geldt voor", "Effect", "Modus")}[lang]
    rows = []
    for c in catalog.CHECKS:
        rows.append(
            f'<tr data-prov="{c["provenance"]}"><td><strong>{html.escape(c["title"][lang])}</strong> '
            f'<code>{c["id"]}</code><p>{html.escape(c["description"][lang])}</p></td>'
            f'<td><span class="prov">{PROV_LABEL[c["provenance"]]}</span></td>'
            f'<td>{APPLIES[c["applies"]][lang]}</td><td>{EFFECT[c["severity"]][lang]}</td>'
            f'<td><code>{MODES[c["modes"]]}</code></td></tr>')
    return ("<thead><tr>" + "".join(f"<th>{h}</th>" for h in head) + "</tr></thead><tbody>"
            + "".join(rows) + "</tbody>")


def _hero(data: dict) -> Dict[str, str]:
    """The changed line of the fake fix that carries a surviving sink, with what Saikou says about it."""
    fake = next(c for c in data["demo"] if c["id"] == "fake")
    shell = next((f for f in fake["findings"] if f["check"] == "sink_shell_true" and f["line"]), None)
    if shell is None:
        raise SystemExit("the hero shows the fake fix's surviving shell=True; the demo no longer has that finding")
    line = shell["line"]
    i = next((n for n, r in enumerate(fake["diff"]) if r[0] == "+" and r[2] == line), None)
    if i is None:
        raise SystemExit(f"the hero needs line {line} of the fake fix to be a changed line")
    j = i - 1  # the removed line of the same change block, if there is one
    while j >= 0 and fake["diff"][j][0] == "+":
        j -= 1
    removed = [fake["diff"][j]] if j >= 0 and fake["diff"][j][0] == "-" else []
    diff = "\n".join(f'<span class="pl {"del" if r[0] == "-" else "add"}">{r[0]} {html.escape(r[3].strip())}</span>'
                     for r in removed + [fake["diff"][i]])
    found = "".join(f'<li><code>{f["check"]}</code> <span class="prov">{f["provenance"]}</span></li>'
                    for f in fake["findings"] if f["line"] == line)
    sev = "HARD FAIL" if shell["severity"] == "hard_fail" else "WARN"
    anatomy = (f'<span class="a a-sev">{sev}</span> <span class="a a-prov">[{shell["provenance"]}]</span> '
               f'<span class="a a-check">{shell["check"]}</span> <span class="a a-line">L{line}</span>: '
               f'<span class="a a-detail">{html.escape(shell["detail"])}</span>')
    return {"hero-diff": diff, "hero-findings": found, "anatomy": anatomy, "hero-file": fake["file"],
            "anat-sev": sev, "anat-prov": f"[{shell['provenance']}]", "anat-check": shell["check"],
            "anat-line": f"L{line}"}


def _and(items: List[str], lang: str) -> str:
    if not items:
        return "none" if lang == "en" else "geen"
    word = " and " if lang == "en" else " en "
    return items[0] if len(items) == 1 else ", ".join(items[:-1]) + word + items[-1]


def slots(data: dict, lang: str) -> Dict[str, str]:
    py, js = data["coverage"]["python"], data["coverage"]["js"]
    out = {"version": data["version"], "marker-kinds": str(data["marker_kinds"]),
           "selftest-checks": str(data["selftest_checks"]),
           "py-table": _coverage_table(py, lang), "js-table": _coverage_table(js, lang),
           "measured-table": _measured_table(data["measured"], lang),
           "py-executed": html.escape(_and(py["executed"], lang)),
           "py-patterns": html.escape(_and(py["patterns"], lang)),
           "js-executed": html.escape(_and(js["executed"], lang)),
           "measured-files": _num(sum(r["files"] for r in data["measured"]), lang),
           "measured-false": _num(sum(r["false_blocked"] for r in data["measured"]), lang)}
    for key in ("total", "honoured", "blocks", "warns", "missed", "over"):
        out[f"py-{key}"] = _num(py[key], lang)
        out[f"js-{key}"] = _num(js[key], lang)
    from saikou import catalog
    out["check-count"] = str(len(catalog.CHECKS))
    out["catalogue-table"] = _catalogue_table(catalog, lang)
    for key, text in catalog.PROVENANCE_MEANING.items():
        out[f"prov-{key}"] = html.escape(text[lang])
    for key, text in catalog.TIER_MEANING.items():
        out[f"tier-{key.replace('_', '-')}"] = html.escape(text[lang])
    out.update(_hero(data))
    return out


def data_js(data: dict) -> str:
    body = json.dumps(data, ensure_ascii=False, indent=1, sort_keys=True)
    return ("// Generated by scripts/render_site_data.py from the repository's own sources. Do not edit.\n"
            f"window.SAIKOU_DATA = {body};\n")


def _strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from _strings(v)
    elif isinstance(value, list):
        for v in value:
            yield from _strings(v)


def render(data: dict) -> Dict[Path, str]:
    """Every file this script owns, with the content it should have."""
    import check_site
    # every string the page can show, except the demo code itself
    prose = list(_strings({**data, "demo": [{k: v for k, v in c.items() if k != "diff"} for c in data["demo"]]}))
    bad = [e for s in prose for e in check_site.banned_claims("site-data", s)]
    if bad:
        raise SystemExit("banned claim in generated site data:\n" + "\n".join(bad))
    demo = _load("render_site_demo", ROOT / "scripts" / "render_site_demo.py")
    bodies = {name: html.escape(demo.tidy(demo.run(after))) for name, after in demo.CASES.items()}
    out = {DATA_JS: data_js(data)}
    for lang, page in PAGES.items():
        text, values = page.read_text(encoding="utf-8"), slots(data, lang)
        unknown = sorted({m.group(1) for m in SLOT.finditer(text)} - set(values))
        if unknown:
            raise SystemExit(f"{page.relative_to(ROOT)}: unknown data slots {unknown}")
        text = SLOT.sub(lambda m: f"<!--data:{m.group(1)}-->{values[m.group(1)]}<!--/data-->", text)
        for name, body in bodies.items():
            text, n = re.subn(rf"(<!--demo:{name}-->).*?(<!--/demo-->)",
                              lambda m, body=body: m.group(1) + body + m.group(2), text, flags=re.S)
            if n != 1:
                raise SystemExit(f"{page.relative_to(ROOT)}: marker demo:{name} not found exactly once")
        out[page] = text
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Refill the data-driven parts of the home pages.")
    ap.add_argument("--check", action="store_true", help="only report files that are out of date")
    args = ap.parse_args(argv)
    stale = []
    for path, content in render(build()).items():
        current = path.read_text(encoding="utf-8") if path.exists() else None
        if current == content:
            continue
        stale.append(path.relative_to(ROOT).as_posix())
        if not args.check:
            path.write_text(content, encoding="utf-8", newline="\n")
    if args.check:
        for p in stale:
            print("out of date:", p)
        return 1 if stale else 0
    print("rewrote:", ", ".join(stale) if stale else "nothing (already up to date)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
