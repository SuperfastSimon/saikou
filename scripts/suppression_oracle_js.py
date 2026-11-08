#!/usr/bin/env python3
"""Differential oracle for Saikou's suppression counting on JavaScript and TypeScript files.

The same idea as scripts/suppression_oracle.py: before/after pairs in which a suppression marker is
added to code with a finding, the real tools decide whether they honour it, and Saikou's verdict in
change gating is compared with theirs. Reference tools: ESLint (core rules plus eslint-plugin-security,
run with and without --no-inline-config), the TypeScript compiler (a type error with and without the
marker) and semgrep (a rule per sink, with and without --disable-nosem). All three are executed.

    python scripts/suppression_oracle_js.py all --work DIR --eslint-dir NODE_DIR --semgrep EXE
    python scripts/suppression_oracle_js.py engine --work DIR [--label L --repo OTHER_CHECKOUT]
    python scripts/suppression_oracle_js.py report --work DIR
    python scripts/suppression_oracle_js.py freeze --work DIR      # tests/fixtures/..._js_golden.json
    python scripts/suppression_oracle_js.py drift --work DIR

NODE_DIR is a folder with `npm install eslint@9 eslint-plugin-security@3 typescript@5` done in it
and the eslint.config.cjs of this script (written there by the `tools` step).

Engine stays stdlib-only; so does this script.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent


def _load_shared():
    spec = importlib.util.spec_from_file_location("suppression_oracle", HERE / "suppression_oracle.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["suppression_oracle"] = module
    spec.loader.exec_module(module)
    return module


po = _load_shared()

TOOLS = ("eslint", "tsc", "semgrep")
TOOL_LETTER = {"eslint": "e", "tsc": "t", "semgrep": "g"}
TOOL_NAME = {"eslint": "ESLint", "tsc": "TypeScript", "semgrep": "semgrep"}
GOLDEN = REPO / "tests" / "fixtures" / "suppression_oracle_js_golden.json"

# ---------------------------------------------------------------------------
# Sinks and layouts
# ---------------------------------------------------------------------------

SINKS = {
    "eval": dict(ext="js", lang="javascript", pre=[], callee="eval", args=["x"], params="x",
                 rules=("no-eval", "security/detect-eval-with-expression"), semgrep="sink-eval"),
    "exec": dict(ext="js", lang="javascript", pre=['const child_process = require("child_process");'],
                 callee="child_process.exec", args=["cmd"], params="cmd",
                 rules=("security/detect-child-process",), semgrep="sink-exec"),
    "fs": dict(ext="js", lang="javascript", pre=['const fs = require("fs");'], callee="fs.readFile",
               args=["p", "cb"], params="p, cb", rules=("security/detect-non-literal-fs-filename",),
               semgrep="sink-fs"),
    "func": dict(ext="js", lang="javascript", pre=[], callee="new Function", args=["x"], params="x",
                 rules=("no-new-func",), semgrep="sink-func"),
    "ts": dict(ext="ts", lang="typescript", pre=[], callee="", args=[], params="", rules=(),
               semgrep=""),
}
SEMGREP_RULES = """rules:
  - id: sink-eval
    languages: [javascript]
    severity: ERROR
    message: eval
    pattern: eval(...)
  - id: sink-exec
    languages: [javascript]
    severity: ERROR
    message: exec
    pattern: child_process.exec(...)
  - id: sink-fs
    languages: [javascript]
    severity: ERROR
    message: readFile
    pattern: fs.readFile(...)
  - id: sink-func
    languages: [javascript]
    severity: ERROR
    message: new Function
    pattern: new Function(...)
"""
ESLINT_CONFIG = """const security = require("eslint-plugin-security");

module.exports = [
  {
    files: ["**/*.js"],
    languageOptions: { ecmaVersion: 2022, sourceType: "commonjs" },
    plugins: { security },
    rules: {
      "no-eval": "error",
      "no-new-func": "error",
      "no-implied-eval": "error",
      "security/detect-child-process": "error",
      "security/detect-eval-with-expression": "error",
      "security/detect-non-literal-fs-filename": "error",
    },
  },
];
"""


def sink_lines(sink, mode="one"):
    """(header lines, statement text(s)) of a sink. The statement is `return CALL;` for the
    JavaScript sinks and a type error for the TypeScript one."""
    s = SINKS[sink]
    if sink == "ts":
        return [], ["  const n: number = \"text\";"]
    call = f"{s['callee']}({', '.join(s['args'])})"
    return s["pre"], [f"  return {call};"]


def compose(sink, layout, m):
    s = SINKS[sink]
    pre = list(s["pre"])
    sfx = f" {m}" if m else ""
    if sink == "ts":
        head = ["", "function run(): number {"]
        stmt = "  const n: number = \"text\";"
        tail = ["  return n;", "}"]
    else:
        head = ["", f"function run({s['params']}) {{"]
        stmt = f"  return {s['callee']}({', '.join(s['args'])});"
        tail = ["}"]
    if layout == "sink-line":
        return pre + head + [stmt + sfx] + tail
    if layout == "line-above":
        return pre + head + ([f"  {m}"] if m else []) + [stmt] + tail
    if layout == "line-above-col0":
        return pre + head + ([m] if m else []) + [stmt] + tail
    if layout == "line-below":
        return pre + head + [stmt] + ([f"  {m}"] if m else []) + tail
    if layout == "elsewhere":
        return ([m] if m else []) + pre + head + [stmt] + tail
    if layout == "function-line":
        return pre + [head[0], head[1] + sfx] + [stmt] + tail
    if layout == "after-block-comment":
        return pre + head + [stmt + " /* note */" + sfx] + tail
    if layout in ("ml-first", "ml-arg", "ml-close") and sink != "ts":
        call = s["callee"]
        lines = [f"  return {call}("] + [f"    {a}," for a in s["args"]] + ["  );"]
        if layout == "ml-first":
            lines[0] += sfx
        elif layout == "ml-arg":
            lines[1] += sfx
        else:
            lines[-1] += sfx
        return pre + head + lines + tail
    if layout == "ts-type-in-ml" and sink == "ts":
        lines = ["  const n: number =", "    \"text\";" + sfx]
        return pre + head + lines + tail
    raise KeyError(layout)


LAYOUTS_JS = ("sink-line", "line-above", "line-above-col0", "line-below", "elsewhere", "function-line",
              "after-block-comment", "ml-first", "ml-arg", "ml-close")
LAYOUTS_TS = ("sink-line", "line-above", "line-above-col0", "line-below", "elsewhere", "function-line",
              "after-block-comment", "ts-type-in-ml")

# (label, template, family). {R} = the first rule of the sink.
SPELLINGS = [
    # eslint directives
    ("eslint-line", "// eslint-disable-line", "eslint"),
    ("eslint-next", "// eslint-disable-next-line", "eslint"),
    ("eslint-file", "// eslint-disable", "eslint"),
    ("eslint-block-line", "/* eslint-disable-line */", "eslint"),
    ("eslint-block-next", "/* eslint-disable-next-line */", "eslint"),
    ("eslint-block-file", "/* eslint-disable */", "eslint"),
    ("eslint-block-file-tight", "/*eslint-disable*/", "eslint"),
    ("eslint-line-rule", "// eslint-disable-line {R}", "eslint"),
    ("eslint-next-rule", "// eslint-disable-next-line {R}", "eslint"),
    ("eslint-block-rule", "/* eslint-disable {R} */", "eslint"),
    ("eslint-block-line-rule", "/* eslint-disable-line {R} */", "eslint"),
    ("eslint-line-two-rules", "// eslint-disable-line no-console, {R}", "eslint"),
    ("eslint-line-other-rule", "// eslint-disable-line no-console", "eslint"),
    ("eslint-line-reason", "// eslint-disable-line -- reason", "eslint"),
    ("eslint-line-tight", "//eslint-disable-line", "eslint"),
    ("eslint-next-tight", "//eslint-disable-next-line", "eslint"),
    ("eslint-line-spaces", "//   eslint-disable-line", "eslint"),
    ("eslint-line-upper", "// ESLINT-DISABLE-LINE", "eslint"),
    ("eslint-glued", "// eslint-disable-linefoo", "eslint"),
    ("eslint-block-glued", "/* eslint-disable-line-foo */", "eslint"),
    ("eslint-enable", "/* eslint-enable */", "eslint"),
    ("eslint-in-prose", "// we never write eslint-disable here", "eslint"),
    # typescript directives
    ("ts-ignore", "// @ts-ignore", "ts"), ("ts-ignore-block", "/* @ts-ignore */", "ts"),
    ("ts-ignore-tight", "//@ts-ignore", "ts"), ("ts-ignore-reason", "// @ts-ignore: reason", "ts"),
    ("ts-expect", "// @ts-expect-error", "ts"), ("ts-expect-block", "/* @ts-expect-error */", "ts"),
    ("ts-nocheck", "// @ts-nocheck", "ts"), ("ts-nocheck-block", "/* @ts-nocheck */", "ts"),
    ("ts-ignore-upper", "// @TS-IGNORE", "ts"),
    # semgrep
    ("nosemgrep", "{C} nosemgrep", "semgrep"), ("nosemgrep-tight", "{C}nosemgrep", "semgrep"),
    ("nosemgrep-id", "{C} nosemgrep: some.rule-id", "semgrep"), ("nosemgrep-block", "{B} nosemgrep */", "semgrep"),
    ("nosem", "{C} nosem", "semgrep"), ("NOSEMGREP", "{C} NOSEMGREP", "semgrep"),
    # other analysers
    ("NOSONAR", "// NOSONAR", "sonar"), ("NOSONAR-block", "/* NOSONAR */", "sonar"),
    ("lgtm", "// lgtm", "codeql"), ("lgtm-id", "// lgtm[js/code-injection]", "codeql"),
    ("codeql-id", "// codeql[js/code-injection]", "codeql"), ("lgtm-block", "/* lgtm */", "codeql"),
    # controls
    ("plain", "// fine", "control"), ("todo", "// TODO: harden", "control"),
    ("prettier", "// prettier-ignore", "control"),
]
SPELL = {label: (tpl, fam) for label, tpl, fam in SPELLINGS}
CORE_MARKERS = ["eslint-line", "eslint-next", "eslint-block-file", "eslint-line-rule", "ts-ignore",
                "nosemgrep", "NOSONAR", "lgtm", "codeql-id"]
STRING_MARKERS = ["eslint-line", "eslint-block-file", "ts-ignore", "nosemgrep", "NOSONAR"]


def expand(template, sink):
    rules = SINKS[sink]["rules"]
    return template.replace("{R}", rules[0] if rules else "no-console").replace("{C}", "//").replace("{B}", "/*")


def encode(lines, eol="\n", bom=False, tail=True):
    return po.lines_to_bytes(lines, eol=eol, bom=bom, tail=tail)


class Variants:
    def __init__(self):
        self.items = []

    def add(self, category, sink, layout, label, marker, before, after):
        vid = f"j{len(self.items) + 1:04d}"
        self.items.append(dict(id=vid, category=category, sink=sink, layout=layout, label=label,
                               marker=marker, ext=SINKS[sink]["ext"], before=before, after=after))


def generate(work: Path):
    v = Variants()
    for sink in SINKS:
        layouts = LAYOUTS_TS if sink == "ts" else LAYOUTS_JS
        pool = [x for x in SPELLINGS if x[2] in (("ts", "control", "eslint") if sink == "ts" else
                                                  ("eslint", "ts", "semgrep", "sonar", "codeql", "control"))]
        for label, tpl, fam in SPELLINGS:
            if sink == "ts" and fam not in ("ts", "control", "eslint"):
                continue
            m = expand(tpl, sink)
            v.add("spelling", sink, "sink-line", label, m,
                  encode(compose(sink, "sink-line", None)), encode(compose(sink, "sink-line", m)))
        for layout in layouts:
            if layout == "sink-line":
                continue
            for label in CORE_MARKERS if sink != "ts" else ["ts-ignore", "ts-expect", "eslint-line"]:
                m = expand(SPELL[label][0], sink)
                v.add("position", sink, layout, label, m,
                      encode(compose(sink, layout, None)), encode(compose(sink, layout, m)))
    # line endings and encodings
    eols = {"crlf": lambda ls: "\r\n".join(ls) + "\r\n", "cr": lambda ls: "\r".join(ls) + "\r",
            "mixed": lambda ls: "".join(l + ("\r\n" if i % 2 else "\n") for i, l in enumerate(ls)),
            "no-final-newline": lambda ls: "\n".join(ls)}
    for sink in ("exec", "eval", "ts"):
        for layout in ("sink-line", "line-above"):
            for label in (("eslint-line", "eslint-next", "nosemgrep") if sink != "ts" else ("ts-ignore",)):
                m = expand(SPELL[label][0], sink)
                bl, al = compose(sink, layout, None), compose(sink, layout, m)
                for name, fn in eols.items():
                    v.add("newline", sink, layout, f"{label}/{name}", m,
                          fn(bl).encode("utf-8"), fn(al).encode("utf-8"))
                v.add("encoding", sink, layout, f"{label}/bom", m, encode(bl, bom=True), encode(al, bom=True))
                shebang = ["#!/usr/bin/env node"]
                v.add("encoding", sink, layout, f"{label}/shebang", m, encode(shebang + bl), encode(shebang + al))
        # a line separator that JavaScript treats as a newline puts the marker on its own line
        for sep, name in (("\u2028", "ls"), ("\u2029", "ps")):
            m = expand(SPELL["eslint-line" if sink != "ts" else "ts-ignore"][0], sink)
            bl = compose(sink, "sink-line", None)
            stmt = bl[-2 if sink == "ts" else -2]
            after = list(bl)
            after[after.index(stmt)] = stmt + sep + m
            v.add("encoding", sink, "separator-before-marker", f"{name}", m, encode(bl), encode(after))
    # marker as a string / template / regex instead of a comment, and the other way round
    for sink in ("exec", "eval"):
        pre, head = SINKS[sink]["pre"], ["", f"function run({SINKS[sink]['params']}) {{"]
        stmt = compose(sink, "sink-line", None)[-2]
        clean = compose(sink, "sink-line", None)
        for label in STRING_MARKERS:
            m = expand(SPELL[label][0], sink)
            variants = {
                "str-const": pre + [f'const NOTE = "{m}";'] + head + [stmt, "}"],
                "str-single": pre + [f"const NOTE = '{m}';"] + head + [stmt, "}"],
                "str-template": pre + ["const NOTE = `" + m + "`;"] + head + [stmt, "}"],
                "str-on-sink-line": pre + head + [stmt[:-1].rstrip() + f", \"{m}\";", "}"],
                "str-regex": pre + [f"const RE = /{m.replace('/', chr(92) + '/')}/;"] + head + [stmt, "}"],
                "str-in-block-comment-text": pre + ["/* prose: " + m.replace("*/", "") + " */"] + head + [stmt, "}"],
            }
            for name, lines in variants.items():
                v.add("string", sink, name, label, m, encode(clean), encode(lines))
            before_s = pre + [f'const NOTE = "{m}";'] + head + [stmt, "}"]
            v.add("string-to-comment", sink, "sink-line", label, m, encode(before_s),
                  encode(pre + [f'const NOTE = "{m}";'] + head + [stmt + " " + m, "}"]))
            v.add("comment-to-string", sink, "sink-line", label, m, encode(compose(sink, "sink-line", m)),
                  encode(before_s))
    # moved / second marker / legit rewrite
    for sink in ("exec", "eval"):
        s = SINKS[sink]

        def two(m1, m2):
            call = f"{s['callee']}({', '.join(s['args'])})"
            return s["pre"] + ["", f"function a({s['params']}) {{",
                               f"  return {call};" + (f" {m1}" if m1 else ""), "}", "",
                               f"function b({s['params']}) {{", f"  return {call};" + (f" {m2}" if m2 else ""), "}"]
        for label in ("eslint-line", "eslint-block-line", "nosemgrep", "NOSONAR", "lgtm", "ts-ignore"):
            m = expand(SPELL[label][0], sink)
            v.add("moved", sink, "two-sinks", label, m, encode(two(m, None)), encode(two(None, m)))
            v.add("second-marker", sink, "two-sinks", label, m, encode(two(m, None)), encode(two(m, m)))
        m = expand(SPELL["eslint-line"][0], sink)
        fixed = {"eval": "JSON.parse(x)", "exec": "child_process.execFile(cmd, [])"}[sink]
        v.add("legit-rewrite", sink, "fixed-call-keeps-marker", "eslint-line", m,
              encode(compose(sink, "sink-line", m)),
              encode(s["pre"] + ["", f"function run({s['params']}) {{", f"  return {fixed}; {m}", "}"]))
        wrapped = compose(sink, "ml-close", m)
        v.add("reformatted", sink, "marker-follows-statement", "eslint-line", m,
              encode(compose(sink, "sink-line", m)), encode(wrapped))

    work.mkdir(parents=True, exist_ok=True)
    for sub in ("before", "after"):
        (work / sub).mkdir(exist_ok=True)
    manifest = []
    for item in v.items:
        ext = item["ext"]
        (work / "before" / f"{item['id']}.{ext}").write_bytes(item["before"])
        (work / "after" / f"{item['id']}.{ext}").write_bytes(item["after"])
        manifest.append({k: item[k] for k in ("id", "category", "sink", "layout", "label", "marker", "ext")})
    (work / "manifest.json").write_text(json.dumps(manifest, indent=1, ensure_ascii=True), encoding="utf-8")
    print(f"generated {len(manifest)} variants:", dict(Counter(m["category"] for m in manifest)))


def file_of(work, side, item):
    return work / side / f"{item['id']}.{item['ext']}"


def manifest_digest(work: Path) -> str:
    import hashlib
    digest = hashlib.sha256()
    for item in json.loads((work / "manifest.json").read_text(encoding="utf-8")):
        digest.update(json.dumps(item, sort_keys=True).encode("utf-8"))
        digest.update(file_of(work, "before", item).read_bytes())
        digest.update(file_of(work, "after", item).read_bytes())
    return digest.hexdigest()


# ---------------------------------------------------------------------------
# Reference tools
# ---------------------------------------------------------------------------

def _node_env(node_dir: Path):
    return dict(os.environ, NODE_PATH=str(node_dir / "node_modules"))


def eslint_state(node_dir: Path, directory: Path):
    """{stem: {"lines_ign": [(rule, line)], "lines_reg": [...]}} with and without inline config."""
    out = defaultdict(lambda: {"lines_ign": [], "lines_reg": [], "unparsed": False})
    exe = str(node_dir / "node_modules" / ".bin" / ("eslint.cmd" if os.name == "nt" else "eslint"))
    for ignore, key in ((True, "lines_ign"), (False, "lines_reg")):
        cmd = [exe, "--config", str(node_dir / "eslint.config.cjs"), "-f", "json", "--no-warn-ignored"]
        if ignore:
            cmd.append("--no-inline-config")
        cmd.append(str(directory))
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace",
                              cwd=str(directory.parent))
        try:
            data = json.loads(proc.stdout or "[]")
        except json.JSONDecodeError as exc:
            raise SystemExit(f"eslint gave no JSON ({exc}); stderr: {proc.stderr[:500]}")
        for f in data:
            stem = Path(f["filePath"]).stem
            out[stem]  # a file without findings still gets an entry
            for msg in f["messages"]:
                if msg.get("fatal"):
                    out[stem]["unparsed"] = True
                elif msg.get("ruleId"):
                    out[stem][key].append((msg["ruleId"], msg["line"]))
    return out


def tsc_state(node_dir: Path, directory: Path):
    """Type errors per .ts file ('lines_reg'): tsc has no switch that ignores its directives, so
    the comparison is the before file against the after file."""
    out = defaultdict(lambda: {"lines_ign": [], "lines_reg": [], "unparsed": False})
    exe = str(node_dir / "node_modules" / ".bin" / ("tsc.cmd" if os.name == "nt" else "tsc"))
    files = sorted(str(p) for p in directory.glob("*.ts"))
    for name in files:
        proc = subprocess.run([exe, "--noEmit", "--pretty", "false", "--strict", "--target", "es2020", name],
                              capture_output=True, text=True, encoding="utf-8", errors="replace",
                              cwd=str(node_dir))
        stem = Path(name).stem
        out[stem]
        for line in proc.stdout.splitlines():
            if ": error TS" in line:
                code = line.split(": error ")[1].split(":")[0]
                lineno = int(line.split("(")[1].split(",")[0]) if "(" in line else 0
                out[stem]["lines_reg"].append((code, lineno))
    return out


def semgrep_js_state(exe, rules: Path, directory: Path):
    return po.semgrep_state(exe, rules, directory)


def tools_step(work: Path, node_dir: Path, semgrep_exe: str):
    manifest = json.loads((work / "manifest.json").read_text(encoding="utf-8"))
    (node_dir / "eslint.config.cjs").write_text(ESLINT_CONFIG, encoding="utf-8")
    rules = work / "semgrep-rules.yml"
    rules.write_text(SEMGREP_RULES, encoding="utf-8")
    states = {}
    for side in ("before", "after"):
        states[side] = {
            "eslint": eslint_state(node_dir, work / side),
            "tsc": tsc_state(node_dir, work / side),
            "semgrep": semgrep_js_state(semgrep_exe, rules, work / side) if semgrep_exe else {},
        }
    result = {}
    for item in manifest:
        vid, sink = item["id"], item["sink"]
        s = SINKS[sink]
        entry = {"tools": {}, "unparsed": False}
        # ESLint: any of the sink's rules shown only when inline config is ignored
        sup = set()
        for side in ("before", "after"):
            st = states[side]["eslint"].get(vid, {"lines_ign": [], "lines_reg": []})
            for rule in s["rules"]:
                sup_side = po.bandit_suppressed(st, rule)[0]
                if side == "after":
                    sup |= {(rule, i) for i in sup_side}
        before_sup = set()
        for rule in s["rules"]:
            stb = states["before"]["eslint"].get(vid, {"lines_ign": [], "lines_reg": []})
            before_sup |= {(rule, i) for i in po.bandit_suppressed(stb, rule)[0]}
        eslint_honours = bool(sup - before_sup) and sink != "ts"
        entry["tools"]["eslint"] = dict(honoured=eslint_honours, pattern=False, executed=True)
        # tsc: fewer type errors in the after file than in the before file, same statement
        tb = len(states["before"]["tsc"].get(vid, {"lines_reg": []})["lines_reg"])
        ta = len(states["after"]["tsc"].get(vid, {"lines_reg": []})["lines_reg"])
        entry["tools"]["tsc"] = dict(honoured=(sink == "ts" and ta < tb), pattern=False, executed=True)
        # semgrep
        if semgrep_exe and s["semgrep"]:
            sb = states["before"]["semgrep"].get(vid, {"lines_ign": [], "lines_reg": []})
            sa = states["after"]["semgrep"].get(vid, {"lines_ign": [], "lines_reg": []})
            honoured = bool(po.bandit_suppressed(sa, s["semgrep"])[0] - po.bandit_suppressed(sb, s["semgrep"])[0])
        else:
            honoured = False
        entry["tools"]["semgrep"] = dict(honoured=honoured, pattern=False, executed=bool(semgrep_exe))
        result[vid] = entry
    # which marker syntax is spelled at all (a rough pattern check on the added text), per tool family
    for item in manifest:
        marker = item["marker"].lower()
        r = result[item["id"]]["tools"]
        r["eslint"]["pattern"] = "eslint-disable" in marker or "eslint-enable" in marker
        r["tsc"]["pattern"] = "@ts-" in marker
        r["semgrep"]["pattern"] = "nosem" in marker
    (work / "tools.json").write_text(json.dumps(dict(
        eslint=po.tool_version(str(node_dir / "node_modules" / ".bin" / ("eslint.cmd" if os.name == "nt" else "eslint"))),
        tsc=po.tool_version(str(node_dir / "node_modules" / ".bin" / ("tsc.cmd" if os.name == "nt" else "tsc"))).replace("Version ", ""),
        semgrep=po.tool_version(semgrep_exe) if semgrep_exe else "", executed=["eslint", "tsc"] + (["semgrep"] if semgrep_exe else []),
        python=sys.version.split()[0], variants=result), indent=1), encoding="utf-8")
    print("tools done; honoured per tool:", dict(Counter(t for e in result.values() for t, v in e["tools"].items() if v["honoured"])))


# ---------------------------------------------------------------------------
# Saikou, classification, golden file
# ---------------------------------------------------------------------------

def engine_step(work: Path, label: str, repo: Path):
    sys.path.insert(0, str(repo))
    from saikou import engine
    manifest = json.loads((work / "manifest.json").read_text(encoding="utf-8"))
    res = {}
    for item in manifest:
        before = file_of(work, "before", item).read_bytes().decode("utf-8", "replace")
        after = file_of(work, "after", item).read_bytes().decode("utf-8", "replace")
        res[item["id"]] = po.run_engine(engine, before, after, language=SINKS[item["sink"]]["lang"])
    target = work / f"engine_{label}_py{sys.version_info.major}.{sys.version_info.minor}.json"
    target.write_text(json.dumps(dict(python=sys.version.split()[0], label=label, engine=str(repo),
                                      variants=res), indent=1), encoding="utf-8")
    print("engine", label, "done on", sys.version.split()[0], "->", target.name)


STYLE_TOOLS = {"tsc"}                      # a type checker: a warning is the intended verdict
NOT_EXECUTED = {"sonar", "codeql"}        # markers of tools this oracle does not run


def family_of(label):
    return SPELL.get(label.split("/")[0], ("", "control"))[1]


def classify(tool_entry, eng, label=""):
    """caught / MISS / style-warned (only a type checker honours it, Saikou warns) / not-run (a marker
    of a tool that is not executed here, so neither confirmed nor refuted) / fp-placement /
    fp-nopattern / clean."""
    honouring = [t for t, v in tool_entry["tools"].items() if v["honoured"]]
    pattern = [t for t, v in tool_entry["tools"].items() if v.get("pattern")]
    hard = "suppression_introduced" in eng.get("scan_hard", []) or bool(eng.get("intro_hard"))
    warn = bool(eng.get("intro_warn"))
    if "error" in eng:
        return "crash", honouring
    if honouring:
        if hard:
            return "caught", honouring
        if set(honouring) <= STYLE_TOOLS:
            return ("style-warned" if warn else "MISS"), honouring
        return ("miss-warn-only" if warn else "MISS"), honouring
    if family_of(label) in NOT_EXECUTED:
        return ("not-run-blocked" if hard else "not-run-open"), pattern
    if hard:
        return ("fp-placement" if pattern else "fp-nopattern"), pattern
    return "clean", pattern


def tool_entry_from_golden(entry):
    return {"tools": {t: {"honoured": TOOL_LETTER[t] in entry["h"], "pattern": TOOL_LETTER[t] in entry["p"]}
                      for t in TOOLS}}


def report_step(work: Path):
    manifest = {m["id"]: m for m in json.loads((work / "manifest.json").read_text(encoding="utf-8"))}
    tools = json.loads((work / "tools.json").read_text(encoding="utf-8"))
    engines = {}
    for p in sorted(work.glob("engine_*_py*.json")):
        d = json.loads(p.read_text(encoding="utf-8"))
        engines[f"{d['label']} / Python {d['python']}"] = d["variants"]
    lines = [f"ESLint {tools['eslint']}; TypeScript {tools['tsc']}; semgrep {tools['semgrep']}", ""]
    out = {"variants": {}}
    for key, ev in engines.items():
        summary, per_cat = Counter(), defaultdict(Counter)
        for vid, m in manifest.items():
            t = tools["variants"][vid]
            kind, who = classify(t, ev[vid], m["label"])
            summary[kind] += 1
            per_cat[m["category"]][kind] += 1
            out["variants"].setdefault(vid, dict(m, tools=t["tools"], verdict={}))["verdict"][key] = dict(
                kind=kind, who=who, saikou=ev[vid])
        lines += [f"### Saikou: {key}", "", "| verdict | variants |", "|---|---|"]
        lines += [f"| {k} | {n} |" for k, n in sorted(summary.items())]
        kinds = sorted(summary)
        lines += ["", "| category | " + " | ".join(kinds) + " |", "|---|" + "---|" * len(kinds)]
        for c in sorted(per_cat):
            lines.append(f"| {c} | " + " | ".join(str(per_cat[c].get(k, 0)) for k in kinds) + " |")
        lines.append("")
    per_tool = {t: Counter() for t in TOOLS}
    first = next((k for k in engines if k.startswith("work-tree")), next(iter(engines), None))
    for vid, rec in out["variants"].items():
        for t in TOOLS:
            if rec["tools"][t]["honoured"]:
                per_tool[t]["honoured"] += 1
                if first and "suppression_introduced" in rec["verdict"][first]["saikou"].get("scan_hard", []):
                    per_tool[t]["blocked"] += 1
    lines += ["### Per tool", "", "| tool | honours | Saikou blocks |", "|---|---|---|"]
    lines += [f"| {t} | {per_tool[t]['honoured']} | {per_tool[t]['blocked']} |" for t in TOOLS]
    (work / "results.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (work / "results.json").write_text(json.dumps(out, indent=1), encoding="utf-8")
    print("\n".join(lines))


def freeze_step(work: Path, label: str):
    manifest = {m["id"]: m for m in json.loads((work / "manifest.json").read_text(encoding="utf-8"))}
    tools = json.loads((work / "tools.json").read_text(encoding="utf-8"))
    eng = json.loads((work / f"engine_{label}_py{sys.version_info.major}.{sys.version_info.minor}.json")
                     .read_text(encoding="utf-8"))["variants"]
    variants = {}
    for vid, item in manifest.items():
        t = tools["variants"][vid]
        kind, _ = classify(t, eng[vid], item["label"])
        variants[vid] = {"k": kind,
                         "h": "".join(TOOL_LETTER[x] for x in TOOLS if t["tools"][x]["honoured"]),
                         "p": "".join(TOOL_LETTER[x] for x in TOOLS if t["tools"][x].get("pattern")),
                         "c": item["category"], "l": item["label"]}
    reference = {"eslint": tools["eslint"], "tsc": tools["tsc"], "semgrep": tools["semgrep"],
                 "executed": tools["executed"], "letters": TOOL_LETTER, "names": TOOL_NAME,
                 "style_tools": sorted(STYLE_TOOLS), "not_executed": sorted(NOT_EXECUTED)}
    ids = sorted(variants)
    lines = ["{", ' "format": 1,', f' "digest": "{manifest_digest(work)}",',
             " \"reference_tools\": " + json.dumps(reference, sort_keys=True) + ",", ' "variants": {']
    for i, vid in enumerate(ids):
        lines.append(f'  "{vid}": {json.dumps(variants[vid], sort_keys=True)}' + ("," if i < len(ids) - 1 else ""))
    lines += [" }", "}", ""]
    GOLDEN.write_text("\n".join(lines), encoding="utf-8", newline="\n")
    print("froze", len(ids), "variants ->", GOLDEN)


def drift_step(work: Path) -> int:
    golden = json.loads(GOLDEN.read_text(encoding="utf-8"))
    if manifest_digest(work) != golden["digest"]:
        print("the generated pairs differ from the frozen ones: freeze again")
        return 1
    tools = json.loads((work / "tools.json").read_text(encoding="utf-8"))
    ref = golden["reference_tools"]
    print("frozen:", ref["eslint"], "|", ref["tsc"], "| semgrep", ref["semgrep"])
    print("now:   ", tools["eslint"], "|", tools["tsc"], "| semgrep", tools["semgrep"])
    changed = []
    for vid, frozen in sorted(golden["variants"].items()):
        for tool in TOOLS:
            if tool not in tools["executed"] or tool not in ref["executed"]:
                continue
            now, then = bool(tools["variants"][vid]["tools"][tool]["honoured"]), TOOL_LETTER[tool] in frozen["h"]
            if now != then:
                changed.append(f"{vid} {frozen['c']}/{frozen['l']}: {tool} honoured {then} -> {now}")
    print(f"{len(changed)} answers changed")
    for line in changed[:40]:
        print(" ", line)
    return 1 if changed else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("step", choices=["generate", "tools", "engine", "report", "all", "freeze", "drift"])
    ap.add_argument("--work", required=True, type=Path)
    ap.add_argument("--eslint-dir", type=Path, help="folder with eslint, eslint-plugin-security and typescript installed")
    ap.add_argument("--semgrep", default="", help="path to semgrep")
    ap.add_argument("--label", default="work-tree")
    ap.add_argument("--repo", type=Path, default=REPO)
    args = ap.parse_args()
    work = args.work
    work.mkdir(parents=True, exist_ok=True)
    if args.step in ("generate", "all"):
        generate(work)
    if args.step in ("tools", "all"):
        if not args.eslint_dir:
            raise SystemExit("--eslint-dir is required")
        tools_step(work, args.eslint_dir, args.semgrep)
    if args.step in ("engine", "all"):
        engine_step(work, args.label, args.repo)
    if args.step in ("report", "all"):
        report_step(work)
    if args.step == "freeze":
        freeze_step(work, args.label)
    if args.step == "drift":
        raise SystemExit(drift_step(work))


if __name__ == "__main__":
    main()
