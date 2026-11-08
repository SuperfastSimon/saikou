#!/usr/bin/env python3
"""Differential oracle for Saikou's suppression counting on Python files.

Generates before/after pairs (a clean sink; the same code with a suppression
marker in every spelling, position, line ending and encoding we could think of),
asks the real tools whether they would honour the marker, and compares that
with what Saikou says in change-gating mode.

    python scripts/suppression_oracle.py all     --work DIR --bandit BANDIT_EXE
    python scripts/suppression_oracle.py engine  --work DIR            # other interpreter
    python scripts/suppression_oracle.py engine  --work DIR --label head --repo OTHER_CHECKOUT
    python scripts/suppression_oracle.py report  --work DIR
    python scripts/suppression_oracle.py freeze  --work DIR      # golden file for tests/
    python scripts/suppression_oracle.py conformance             # docs/conformance/*.md

Refreshing the frozen reference (new bandit, new variants), in this order: `all --work DIR
--bandit BANDIT_EXE`, read results.md, `freeze --work DIR`, `conformance`, run the tests.
tests/test_suppression_oracle.py only needs the golden file; it does not run bandit.

Steps (each one can be run on its own):
  generate  write before/ and after/ files and manifest.json
  tools     arbiter per variant: bandit (run for real, with and without
            --ignore-nosec), flake8 (NOQA_INLINE_REGEXP read out of the flake8
            wheel, not imported), sonar-python / CodeQL / semgrep (regexes taken
            over from their sources, NOT reproduced locally)
  engine    Saikou on every pair, in the interpreter that runs this script;
            --repo points at another checkout (to compare with an older engine)
  report    results.md + results.json, merged over every engine_*.json

Verdicts per variant:
  caught          a tool honours the new marker and Saikou hard-fails
  MISS            a tool honours it and Saikou says nothing
  miss-warn-only  a tool honours it and Saikou only warns (type/style kinds,
                  usedforsecurity): by design when gating
  clean           no tool honours it and Saikou does not hard-fail
  fp-placement    Saikou hard-fails, no tool honours it here, but a tool's
                  marker syntax is present (other line, other test id): by design,
                  a marker anywhere in changed code is a suppression attempt
  fp-unparsed     Saikou hard-fails on a file the tools cannot parse (text fallback)
  fp-nopattern    Saikou hard-fails and no tool's marker syntax matches at all

Engine stays stdlib-only; so does this script (bandit is a separate process).
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tokenize
import zipfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import List, Optional

REPO = Path(__file__).resolve().parent.parent

# ---------------------------------------------------------------------------
# Sinks and layouts
# ---------------------------------------------------------------------------

SINKS = {
    "shell": dict(imp="import subprocess", callee="subprocess.call", args=["cmd", "shell=True"],
                  param="cmd", test="B602"),
    "eval": dict(imp="import sys", callee="eval", args=["x"], param="x", test="B307"),
    "yaml": dict(imp="import yaml", callee="yaml.load", args=["s"], param="s", test="B506"),
    "md5": dict(imp="import hashlib", callee="hashlib.md5", args=["p"], param="p", test="B324"),
}
TOOLS = ("bandit", "flake8", "ruff", "sonar", "codeql", "semgrep")
LOCAL_TOOLS = ("bandit", "flake8")           # run or read out of the wheel here
OTHER_OTHER = "type: ignore"
# bandit's own names for the tests above (bandit 1.9.4); `generate` asks bandit when it is given
# and uses these otherwise, so the variants are the same with or without bandit
DEFAULT_TEST_NAMES = {"shell": "subprocess_popen_with_shell_equals_true", "eval": "blacklist",
                      "yaml": "yaml_load", "md5": "hashlib"}


def head(s):
    return [s["imp"], "", "", f"def run({s['param']}):"]


def compose(sink, layout, m):
    """Source lines of one variant. `m` is a comment text (e.g. "# nosec") or None."""
    s = SINKS[sink]
    c, a = s["callee"], s["args"]
    call = f"{c}({', '.join(a)})"
    sfx = f"  {m}" if m else ""
    H = head(s)
    if layout == "sink-line":
        return H + [f"    return {call}{sfx}"]
    if layout == "line-above":
        return H + ([f"    {m}"] if m else []) + [f"    return {call}"]
    if layout == "line-above-col0":
        return H + ([m] if m else []) + [f"    return {call}"]
    if layout == "line-below":
        return H + [f"    return {call}"] + ([f"    {m}"] if m else [])
    if layout == "elsewhere":
        return ([m] if m else []) + H + [f"    return {call}"]
    if layout == "def-line":
        return [H[0], "", "", f"def run({s['param']}):{sfx}", f"    return {call}"]
    if layout == "class-line":
        return [H[0], "", "", f"class C:{sfx}", "    @staticmethod", f"    def run({s['param']}):",
                f"        return {call}"]
    if layout == "decorator-line":
        return [H[0], "", "", "class C:", f"    @staticmethod{sfx}", f"    def run({s['param']}):",
                f"        return {call}"]
    if layout == "continuation":
        return H + [f"    return {c}(\\", f"        {', '.join(a)}){sfx}"]
    if layout == "continuation-call-second":
        return H + ["    return \\", f"        {call}{sfx}"]
    if layout == "ml-first":
        return H + [f"    return {c}({sfx}"] + [f"        {x}," for x in a] + ["    )"]
    if layout == "ml-arg":
        body = [f"        {x}," for x in a]
        body[0] = body[0] + sfx
        return H + [f"    return {c}("] + body + ["    )"]
    if layout == "ml-close":
        return H + [f"    return {c}("] + [f"        {x}," for x in a] + [f"    ){sfx}"]
    if layout == "module-level":
        return [s["imp"], "", f"{s['param']} = 'ls'", f"{call}{sfx}"]
    if layout == "after-other-comment":
        return H + [f"    return {call}  # {OTHER_OTHER}{sfx}"]
    if layout == "before-other-comment":
        return H + [f"    return {call}{sfx}  # {OTHER_OTHER}"]
    if layout == "hash-string-then-comment":
        return H + [f"    return {call}, \"a # b\"{sfx}"]
    if layout == "long-line":
        # the marker starts beyond column 130: nothing may depend on a truncated line
        return H + [f"    return {call}" + (" " * 130 + sfx if m else "")]
    if layout == "import-line":
        # a style marker on an unrelated line is ordinary engineering, not a suppression
        return [f"{s['imp']}{sfx}", "", "", H[3], f"    return {call}"]
    raise KeyError(layout)


LAYOUTS = ("sink-line", "line-above", "line-above-col0", "line-below", "elsewhere", "def-line",
           "class-line", "decorator-line", "continuation", "continuation-call-second",
           "ml-first", "ml-arg", "ml-close", "module-level", "after-other-comment",
           "before-other-comment", "hash-string-then-comment", "long-line", "import-line")

# (label, template, family). {T} bandit id, {t} lower-case, {S} flake8-bandit/ruff id,
# {N} bandit test name (filled from bandit itself).
SPELLINGS = [
    # bandit
    ("nosec-tight", "#nosec", "bandit"), ("nosec", "# nosec", "bandit"),
    ("nosec-2sp", "#  nosec", "bandit"), ("nosec-tab", "#\tnosec", "bandit"),
    ("nosec-NoSec", "# NoSec", "bandit"), ("nosec-NOSEC", "# NOSEC", "bandit"),
    ("nosec-colon-id", "# nosec:{T}", "bandit"), ("nosec-glued-id", "# nosec{T}", "bandit"),
    ("nosec-space-id", "# nosec {T}", "bandit"), ("nosec-colon-space-id", "# nosec: {T}", "bandit"),
    ("nosec-tight-colon-id", "#nosec:{T}", "bandit"), ("nosec-two-ids", "# nosec {T},B101", "bandit"),
    ("nosec-two-ids-other-first", "# nosec B101,{T}", "bandit"),
    ("nosec-id-then-reason", "# nosec {T} # reason", "bandit"),
    ("nosec-reason", "# nosec reason text", "bandit"), ("nosec-dash-reason", "# nosec - reason", "bandit"),
    ("nosec-colon-reason", "# nosec: reason", "bandit"), ("nosec-glued-word", "# nosecure", "bandit"),
    ("nosec-glued-word2", "# nosecond", "bandit"), ("nosec-underscore", "# nosec_lines", "bandit"),
    ("nosec-digit", "# nosec1", "bandit"), ("nosec-dash", "# nosec-this", "bandit"),
    ("nosec-dot", "# nosec.", "bandit"), ("nosec-comma", "# nosec,", "bandit"),
    ("nosec-unknown-id", "# nosec B999", "bandit"), ("nosec-other-id", "# nosec B101", "bandit"),
    ("nosec-lower-id", "# nosec {t}", "bandit"), ("nosec-name", "# nosec {N}", "bandit"),
    ("nosec-mid-comment", "# reason first # nosec", "bandit"), ("nosec-double-hash", "## nosec", "bandit"),
    ("nosec-in-prose", "# this is not a nosec marker", "bandit"),
    ("nosec-space-before-hash-ws", "#\x0cnosec", "bandit"), ("nosec-vt", "#\x0bnosec", "bandit"),
    ("nosec-nbsp", "#\u00a0nosec", "bandit"), ("nosec-ls", "#\u2028nosec", "bandit"),
    ("nosec-nel", "#\u0085nosec", "bandit"), ("nosec-after-ls", "# x\u2028# nosec", "bandit"),
    ("nosec-trailing-ls", "# nosec\u2028", "bandit"),
    ("nosec-fullwidth", "# ｎosec", "bandit"),
    # flake8
    ("noqa", "{H} noqa", "flake8"), ("noqa-tight", "{H}noqa", "flake8"), ("noqa-upper", "{H} NOQA", "flake8"),
    ("noqa-2sp", "{H}  noqa", "flake8"), ("noqa-code", "{H} noqa: {S}", "flake8"),
    ("noqa-code-tight", "{H} noqa:{S}", "flake8"), ("noqa-other-code", "{H} noqa: E501", "flake8"),
    ("noqa-bare-colon", "{H} noqa:", "flake8"), ("noqa-reason", "{H} noqa reason", "flake8"),
    ("noqa-glued", "{H} noqafoo", "flake8"), ("noqa-glued-code", "{H} noqa{S}", "flake8"),
    ("noqa-in-prose", "# see noqa docs", "flake8"),
    # sonar-python
    ("NOSONAR", "# NOSONAR", "sonar"), ("NOSONAR-tight", "#NOSONAR", "sonar"),
    ("NOSONAR-colon", "# NOSONAR: reason", "sonar"), ("NOSONAR-rule", "# NOSONAR(S4721)", "sonar"),
    ("NOSONAR-reason", "# NOSONAR reason", "sonar"), ("NOSONAR-lower", "# nosonar", "sonar"),
    ("NOSONAR-mixed", "# NoSonar", "sonar"), ("NOSONAR-tab", "#\tNOSONAR", "sonar"),
    ("NOSONAR-glued", "# NOSONARx", "sonar"), ("NOSONAR-dash", "# NOSONAR-reason", "sonar"),
    ("NOSONAR-after-text", "# reason NOSONAR", "sonar"),
    # CodeQL
    ("lgtm", "# lgtm", "codeql"), ("lgtm-tight", "#lgtm", "codeql"), ("lgtm-upper", "# LGTM", "codeql"),
    ("lgtm-id", "# lgtm[py/command-line-injection]", "codeql"), ("lgtm-space-id", "# lgtm [py/x]", "codeql"),
    ("lgtm-reason", "# lgtm: reason", "codeql"), ("lgtm-after-semi", "# reason; lgtm", "codeql"),
    ("lgtm-after-semi-tight", "# reason;lgtm", "codeql"),
    ("lgtm-after-semi-paren", "# reason; lgtm (approved)", "codeql"),
    ("lgtm-after-semi-eq", "# reason; lgtm = ok", "codeql"),
    ("lgtm-after-semi-dot", "# reason; lgtm. ok", "codeql"), ("lgtm-midtext", "# reason lgtm", "codeql"),
    ("lgtm-in-word", "# lgtmfoo", "codeql"), ("lgtm-id-after-text", "# reason lgtm[py/x]", "codeql"),
    ("lgtm-empty-id", "# lgtm[]", "codeql"), ("codeql-id", "# codeql[py/x]", "codeql"),
    ("codeql-space-id", "# CodeQL [py/x]", "codeql"),
    # semgrep
    ("nosemgrep", "{H} nosemgrep", "semgrep"), ("nosemgrep-tight", "{H}nosemgrep", "semgrep"),
    ("nosemgrep-id", "{H} nosemgrep: rule.id", "semgrep"), ("nosem", "{H} nosem", "semgrep"),
    ("nosem-id", "{H} nosem: rule", "semgrep"), ("NOSEMGREP", "{H} NOSEMGREP", "semgrep"),
    ("nosemgrep-glued-id", "{H} nosemgrep:rule", "semgrep"),
    # controls
    ("type-ignore", "# type: ignore", "control"), ("pylint", "# pylint: disable=all", "control"),
    ("plain", "# fine", "control"), ("todo", "# TODO: harden", "control"),
]
# markers that go through every layout
CORE_MARKERS = ["nosec", "nosec-colon-id", "NOSONAR", "lgtm", "lgtm-id", "codeql-id", "noqa",
                "noqa-code", "nosemgrep"]
SPELL = {label: (tpl, fam) for label, tpl, fam in SPELLINGS}

STRING_MARKERS = ["nosec", "NOSONAR", "lgtm", "noqa-code", "nosemgrep", "nosec-colon-id",
                  "nosec-tight"]


def expand(template, sink, names):
    s = SINKS[sink]
    t = s["test"]
    out = (template.replace("{T}", t).replace("{t}", t.lower()).replace("{S}", "S" + t[1:]).replace("{H}", "#")
           .replace("{N}", names.get(sink, "")))
    return out


def lines_to_bytes(lines, eol="\n", bom=False, tail=True):
    data = eol.join(lines) + (eol if tail else "")
    raw = data.encode("utf-8", "surrogatepass")
    return (b"\xef\xbb\xbf" + raw) if bom else raw


class Variant:
    def __init__(self, vid, category, sink, layout, label, marker, before, after, note="",
                 expect_tools=None):
        self.vid, self.category, self.sink, self.layout = vid, category, sink, layout
        self.label, self.marker, self.before, self.after, self.note = label, marker, before, after, note


def generate(work: Path, bandit_exe: str | None):
    names = dict(DEFAULT_TEST_NAMES)
    if bandit_exe:
        names.update(discover_test_names(bandit_exe, work))
    variants: list[Variant] = []
    n = 0

    def add(category, sink, layout, label, marker, before, after, note=""):
        nonlocal n
        n += 1
        variants.append(Variant(f"v{n:04d}", category, sink, layout, label, marker, before, after, note))

    # 1. spelling x sink on the sink line
    for sink in SINKS:
        for label, tpl, fam in SPELLINGS:
            m = expand(tpl, sink, names)
            if not m or "{N}" in tpl and not names.get(sink):
                continue
            add("spelling", sink, "sink-line", label, m,
                lines_to_bytes(compose(sink, "sink-line", None)),
                lines_to_bytes(compose(sink, "sink-line", m)))
    # 2. position x core spellings x sink
    for sink in SINKS:
        for layout in LAYOUTS:
            if layout == "sink-line":
                continue
            for label in CORE_MARKERS:
                m = expand(SPELL[label][0], sink, names)
                add("position", sink, layout, label, m,
                    lines_to_bytes(compose(sink, layout, None)),
                    lines_to_bytes(compose(sink, layout, m)))
    # 3. line endings and encodings, three layouts, two sinks, five markers
    eols = {"crlf": lambda ls: "\r\n".join(ls) + "\r\n", "cr": lambda ls: "\r".join(ls) + "\r",
            "mixed": lambda ls: "".join(l + ("\r\n" if i % 2 else "\n") for i, l in enumerate(ls)),
            "no-final-newline": lambda ls: "\n".join(ls)}
    for sink in ("shell", "md5"):
        for layout in ("sink-line", "continuation", "ml-arg"):
            for label in ("nosec", "nosec-colon-id", "NOSONAR", "lgtm", "noqa-code"):
                m = expand(SPELL[label][0], sink, names)
                bl, al = compose(sink, layout, None), compose(sink, layout, m)
                for ename, fn in eols.items():
                    add("newline", sink, layout, label + "/" + ename, m,
                        fn(bl).encode(), fn(al).encode())
                for fname, fn in {
                    "form-feed-line": lambda ls: ls[:3] + ["\x0c"] + ls[3:],
                    "bom": None,
                    "coding-utf8": lambda ls: ["# coding: utf-8"] + ls,
                    "coding-latin1": lambda ls: ["# -*- coding: latin-1 -*-", "# caf\xe9"] + ls,
                }.items():
                    if fname == "bom":
                        add("encoding", sink, layout, label + "/bom", m,
                            lines_to_bytes(bl, bom=True), lines_to_bytes(al, bom=True))
                    elif fname == "coding-latin1":
                        add("encoding", sink, layout, label + "/" + fname, m,
                            "\n".join(fn(bl)).encode("latin-1") + b"\n",
                            "\n".join(fn(al)).encode("latin-1") + b"\n")
                    else:
                        add("encoding", sink, layout, label + "/" + fname, m,
                            lines_to_bytes(fn(bl)), lines_to_bytes(fn(al)))
    # 3b. a marker hidden by the source encoding
    for sink in ("shell", "md5"):
        for codec, hidden in (("utf-7", "# x +ACM- nosec"), ("unicode_escape", "# x \\x23 nosec"),
                              ("raw_unicode_escape", "# x \\u0023 nosec"),
                              ("utf-7", "# x +ACM- lgtm"), ("unicode_escape", "# x \\x23 NOSONAR")):
            s = SINKS[sink]
            call = f"{s['callee']}({', '.join(s['args'])})"
            base = [f"# coding: {codec}"] + head(s)
            bl = base + [f"    return {call}"]
            al = base + [f"    return {call}  {hidden}"]
            add("encoding", sink, "sink-line", f"hidden-{codec}", hidden,
                lines_to_bytes(bl), lines_to_bytes(al),
                "marker only exists after decoding with the declared source encoding")
    # 3c. EBCDIC source (ASCII-looking text decoded as cp037 is not valid Python)
    s = SINKS["shell"]
    call = f"{s['callee']}({', '.join(s['args'])})"
    bl = ["# coding: cp037"] + head(s) + [f"    return {call}"]
    al = ["# coding: cp037"] + head(s) + [f"    return {call}  # nosec"]
    add("encoding", "shell", "sink-line", "cp037-ascii-bytes", "# nosec",
        lines_to_bytes(bl), lines_to_bytes(al))
    # 4. marker as a string literal (and the other way round)
    for sink in ("shell", "md5"):
        s = SINKS[sink]
        c, a = s["callee"], s["args"]
        call = f"{c}({', '.join(a)})"
        H = head(s)
        for label in STRING_MARKERS:
            m = expand(SPELL[label][0], sink, names)
            pad = f"x  {m}"
            builders = {
                "str-assign-module": [s["imp"], f'NOTE = "{pad}"', "", "", H[3], f"    return {call}"],
                "str-docstring": H + [f'    """{pad}"""', f"    return {call}"],
                "str-triple-newline": [s["imp"], f'NOTE = """\n{m}\n"""', "", "", H[3], f"    return {call}"],
                "str-in-arg": H + [f"    return {c}({', '.join(a[:1])} + \"{pad}\"{''.join(', ' + x for x in a[1:])})"],
                "str-fstring": [s["imp"], f'NOTE = f"{{1}}  {m}"', "", "", H[3], f"    return {call}"],
                "str-bytes": [s["imp"], f'NOTE = b"{pad}"', "", "", H[3], f"    return {call}"],
                "str-raw": [s["imp"], f'NOTE = r"{pad}"', "", "", H[3], f"    return {call}"],
                "str-implicit-concat": [s["imp"], "NOTE = (", '    "x"', f'    "  {m}"', ")", "", "", H[3],
                                        f"    return {call}"],
                "str-on-sink-line": H + [f'    return {call}, "{pad}"'],
                "str-in-list": [s["imp"], f'NOTES = ["a", "{pad}"]', "", "", H[3], f"    return {call}"],
            }
            clean = compose(sink, "sink-line", None)
            for bname, lines in builders.items():
                add("string", sink, bname, label, m, lines_to_bytes(clean), lines_to_bytes(lines))
            # string in before, real comment in after
            before_s = [s["imp"], f'NOTE = "{pad}"', "", "", H[3], f"    return {call}"]
            after_c = [s["imp"], f'NOTE = "{pad}"', "", "", H[3], f"    return {call}  {m}"]
            add("string-to-comment", sink, "sink-line", label, m, lines_to_bytes(before_s),
                lines_to_bytes(after_c))
            # real comment in before, string in after
            before_c = compose(sink, "sink-line", m)
            after_s = [s["imp"], f'NOTE = "{pad}"', "", "", H[3], f"    return {call}"]
            add("comment-to-string", sink, "sink-line", label, m, lines_to_bytes(before_c),
                lines_to_bytes(after_s))
            # string in both, identical (control)
            add("string-unchanged", sink, "sink-line", label, m, lines_to_bytes(before_s),
                lines_to_bytes(before_s))
    # 4b. semgrep's regex has no comment anchor: a word-initial marker in a string counts
    for sink in ("shell", "md5"):
        s = SINKS[sink]
        c, a = s["callee"], s["args"]
        call = f"{c}({', '.join(a)})"
        H = head(s)
        clean = compose(sink, "sink-line", None)
        for word in ("nosemgrep", "nosem"):
            variants_nohash = {
                "nohash-str-on-sink-line": H + [f'    return {call}, "x {word}"'],
                "nohash-str-in-arg": H + [f"    return {c}({', '.join(a[:1])} + \" {word}\""
                                          f"{''.join(', ' + x for x in a[1:])})"],
                "nohash-str-module": [s["imp"], f'NOTE = "x {word}"', "", "", H[3], f"    return {call}"],
            }
            for bname, lines in variants_nohash.items():
                add("string-nohash", sink, bname, word, f"x {word}", lines_to_bytes(clean),
                    lines_to_bytes(lines))
    # 5. marker moved between sinks, count unchanged
    for sink in SINKS:
        s = SINKS[sink]
        call = f"{s['callee']}({', '.join(s['args'])})"

        def two(m1, m2):
            return [s["imp"], "", "", f"def a({s['param']}):",
                    f"    return {call}" + (f"  {m1}" if m1 else ""), "", "",
                    f"def b({s['param']}):", f"    return {call}" + (f"  {m2}" if m2 else "")]

        def same_scope(m1, m2):
            # two identical statements in one function
            return [s["imp"], "", "", f"def run({s['param']}):",
                    f"    x = {call}" + (f"  {m1}" if m1 else ""),
                    f"    x = {call}" + (f"  {m2}" if m2 else ""), "    return x"]
        for label in ("nosec", "nosec-colon-id", "NOSONAR", "lgtm", "lgtm-id", "noqa", "noqa-code",
                      "nosemgrep"):
            m = expand(SPELL[label][0], sink, names)
            add("moved", sink, "two-sinks", label, m, lines_to_bytes(two(m, None)),
                lines_to_bytes(two(None, m)), "marker moves from sink a to sink b; count stays 1")
            add("moved", sink, "same-scope", label, m, lines_to_bytes(same_scope(m, None)),
                lines_to_bytes(same_scope(None, m)), "marker moves to an identical statement")
            add("second-marker", sink, "two-sinks", label, m, lines_to_bytes(two(m, None)),
                lines_to_bytes(two(m, m)), "a second marker next to an existing one")
        # a marker that stays on its statement while the code around it is reformatted
        m = expand(SPELL["nosec"][0], sink, names)
        add("reformatted", sink, "marker-follows-statement", "nosec", m,
            lines_to_bytes(compose(sink, "sink-line", m)),
            lines_to_bytes(compose(sink, "ml-close", m)), "the same marker, the call wrapped over lines")
        # the textbook fix keeps its old marker: counts as no new suppression, and the
        # fixed call is not a sink any more
        fixed = {"shell": call.replace("shell=True", "shell=False"),
                 "eval": "ast.literal_eval(x)", "yaml": "yaml.safe_load(s)",
                 "md5": "hashlib.sha256(p)"}[sink]
        add("legit-rewrite", sink, "fixed-call-keeps-marker", "nosec", m,
            lines_to_bytes(compose(sink, "sink-line", m)),
            lines_to_bytes(head(s) + [f"    return {fixed}  {m}"]),
            "the sink is fixed and the old marker stays on the line")
    # 6. input that does not tokenize / parse
    for sink in ("shell", "md5"):
        s = SINKS[sink]
        call = f"{s['callee']}({', '.join(s['args'])})"
        H = head(s)

        def body(m, extra):
            return extra[0] + H + [f"    return {call}" + (f"  {m}" if m else "")] + extra[1]
        broken = {
            "py2-print": (['print "x"'], []),
            "stray-operator": (["x = = 1"], []),
            "open-triple-quote": ([], ['NOTE = """open']),
            "open-paren": ([], ["FOO = (1,"]),
            "tab-error": ([], ["def g():", "        a = 1", "\tb = 2"]),
            "fstring-reuse-quotes": (['NOTE = f"{ {"a": 1}["a"] }"'], []),
            "except-no-parens": ([], ["try:", "    pass", "except ValueError, TypeError:", "    pass"]),
        }
        for label in ("nosec", "lgtm", "NOSONAR"):
            m = expand(SPELL[label][0], sink, names)
            for bname, extra in broken.items():
                good = lines_to_bytes(body(None, ([], [])))
                bad_clean = lines_to_bytes(body(None, extra))
                bad_marked = lines_to_bytes(body(m, extra))
                good_marked = lines_to_bytes(body(m, ([], [])))
                add("broken", sink, bname + "/both-broken", label, m, bad_clean, bad_marked)
                add("broken", sink, bname + "/before-broken", label, m, bad_clean, good_marked)
                add("broken", sink, bname + "/after-broken", label, m, good, bad_marked)
    # 7. the usedforsecurity flag
    s = SINKS["md5"]
    H = head(s)
    flags = {
        "flag-plain": ["    return hashlib.md5(p, usedforsecurity=False)"],
        "flag-spaces": ["    return hashlib.md5(p, usedforsecurity = False)"],
        "flag-paren": ["    return hashlib.md5(p, usedforsecurity=(False))"],
        "flag-continuation": ["    return hashlib.md5(p, usedforsecurity=\\", "                       False)"],
        "flag-multiline": ["    return hashlib.md5(", "        p,", "        usedforsecurity=False,", "    )"],
        "flag-zero": ["    return hashlib.md5(p, usedforsecurity=0)"],
        "flag-true": ["    return hashlib.md5(p, usedforsecurity=True)"],
        "flag-in-comment": ["    return hashlib.md5(p)  # usedforsecurity=False"],
        "flag-in-string": ['    return hashlib.md5(p), "usedforsecurity=False"'],
        "flag-kwargs": ['    return hashlib.md5(p, **{"usedforsecurity": False})'],
        "flag-other-hash": ["    return hashlib.sha256(p, usedforsecurity=False)"],
    }
    for fname, body_lines in flags.items():
        add("flag", "md5", fname, fname, "usedforsecurity=False",
            lines_to_bytes(H + ["    return hashlib.md5(p)"]), lines_to_bytes(H + body_lines))
    # on password material the flag is a fake fix, not the documented remedy
    secret_head = [s["imp"], "", "", "def run(password):"]
    for fname, body_line in {
        "flag-secret-plain": "    return hashlib.md5(password, usedforsecurity=False)",
        "flag-secret-paren": "    return hashlib.md5(password, usedforsecurity=(False))",
        "flag-secret-zero": "    return hashlib.md5(password, usedforsecurity=0)",
    }.items():
        add("flag", "md5", fname, fname, "usedforsecurity=False",
            lines_to_bytes(secret_head + ["    return hashlib.md5(password)"]),
            lines_to_bytes(secret_head + [body_line]))

    (work / "before").mkdir(parents=True, exist_ok=True)
    (work / "after").mkdir(parents=True, exist_ok=True)
    manifest = []
    for v in variants:
        (work / "before" / f"{v.vid}.py").write_bytes(v.before)
        (work / "after" / f"{v.vid}.py").write_bytes(v.after)
        manifest.append(dict(id=v.vid, category=v.category, sink=v.sink, layout=v.layout,
                             label=v.label, marker=v.marker, note=v.note))
    (work / "manifest.json").write_text(json.dumps(manifest, indent=1, ensure_ascii=True), encoding="utf-8")
    cats = Counter(v.category for v in variants)
    print(f"generated {len(variants)} variants:", dict(cats))


def discover_test_names(bandit_exe, work):
    probe = work / "probe"
    probe.mkdir(parents=True, exist_ok=True)
    for sink in SINKS:
        (probe / f"{sink}.py").write_bytes(lines_to_bytes(compose(sink, "sink-line", None)))
    data = run_bandit(bandit_exe, probe, ignore=False)
    names = {}
    for r in data.get("results", []):
        stem = Path(r["filename"]).stem
        if stem in SINKS and r["test_id"] == SINKS[stem]["test"]:
            names[stem] = r["test_name"]
    return names


# ---------------------------------------------------------------------------
# Arbiters
# ---------------------------------------------------------------------------

def run_bandit(exe, directory, ignore):
    cmd = [exe, "-q", "-f", "json", "-t", ",".join(sorted({s["test"] for s in SINKS.values()})),
           "-r", str(directory)]
    if ignore:
        cmd.insert(1, "--ignore-nosec")
    proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"bandit gave no JSON ({exc}); stderr: {proc.stderr[:500]}")


def bandit_version(exe):
    proc = subprocess.run([exe, "--version"], capture_output=True, text=True)
    return proc.stdout.strip().replace("\n", " ")


def bandit_state(exe, directory, ignore_dir_files):
    """{file stem: {"lines_ign": [...], "lines_reg": [...], "unparsed": bool}} for a folder."""
    ign = run_bandit(exe, directory, ignore=True)
    reg = run_bandit(exe, directory, ignore=False)
    out = defaultdict(lambda: {"lines_ign": [], "lines_reg": [], "unparsed": False})
    for r in ign.get("results", []):
        out[Path(r["filename"]).stem]["lines_ign"].append((r["test_id"], r["line_number"]))
    for r in reg.get("results", []):
        out[Path(r["filename"]).stem]["lines_reg"].append((r["test_id"], r["line_number"]))
    for e in reg.get("errors", []):
        out[Path(e["filename"]).stem]["unparsed"] = True
    return out


def bandit_suppressed(state, test_id):
    """Ordinals (by line order) of the sink findings that --ignore-nosec shows and the
    normal run hides."""
    ign = sorted(l for t, l in state["lines_ign"] if t == test_id)
    reg = {l for t, l in state["lines_reg"] if t == test_id}
    return {i for i, l in enumerate(ign) if l not in reg}, len(ign)


_VERSION = re.compile(r"(?<![\w.])v?(\d+(?:\.\d+)+(?:[-+.]?(?:a|b|rc|dev|post)\d*)?)(?![\w])")


def plain_version(text: str) -> str:
    """The first version number in what a tool reports about itself: "1.9.4" from bandit's
    whole --version text (which also names the Python version), "7.4.1" from a flake8 wheel
    file name, "0.17.1" from "ruff 0.17.1", "9.39.5" from "v9.39.5". Empty when there is none."""
    m = _VERSION.search(text or "")
    return m.group(1) if m else ""


def tool_version(exe, *args):
    proc = subprocess.run([exe, *(args or ("--version",))], capture_output=True, text=True,
                          encoding="utf-8", errors="replace")
    return (proc.stdout or proc.stderr).strip().splitlines()[0] if (proc.stdout or proc.stderr) else ""


def ruff_state(exe, directory):
    """Same shape as bandit_state, for ruff's S (flake8-bandit) rules and its noqa handling:
    a finding shown with --ignore-noqa and hidden without is one the marker silenced."""
    out = defaultdict(lambda: {"lines_ign": [], "lines_reg": [], "unparsed": False})
    for ignore, key in ((True, "lines_ign"), (False, "lines_reg")):
        cmd = [exe, "check", "--no-cache", "--select", "S", "--output-format", "json", "--exit-zero"]
        if ignore:
            cmd.append("--ignore-noqa")
        proc = subprocess.run(cmd + [str(directory)], capture_output=True, text=True,
                              encoding="utf-8", errors="replace")
        try:
            found = json.loads(proc.stdout or "[]")
        except json.JSONDecodeError as exc:
            raise SystemExit(f"ruff gave no JSON ({exc}); stderr: {proc.stderr[:500]}")
        for r in found:
            stem = Path(r["filename"]).stem
            if r.get("code") is None:
                out[stem]["unparsed"] = True
            else:
                out[stem][key].append((r["code"], r["location"]["row"]))
    return out


SEMGREP_RULES = """rules:
  - id: sink-shell
    languages: [python]
    severity: ERROR
    message: shell=True
    pattern: subprocess.call(..., shell=True, ...)
  - id: sink-eval
    languages: [python]
    severity: ERROR
    message: eval
    pattern: eval(...)
  - id: sink-yaml
    languages: [python]
    severity: ERROR
    message: yaml.load
    pattern: yaml.load(...)
  - id: sink-md5
    languages: [python]
    severity: ERROR
    message: md5
    pattern: hashlib.md5(...)
"""
SEMGREP_RULE_OF = {"shell": "sink-shell", "eval": "sink-eval", "yaml": "sink-yaml", "md5": "sink-md5"}


def semgrep_state(exe, rules: Path, directory):
    """Same shape again, for semgrep's own `nosem` handling (--disable-nosem shows what it hid)."""
    out = defaultdict(lambda: {"lines_ign": [], "lines_reg": [], "unparsed": False})
    env = dict(os.environ, PYTHONUTF8="1")
    for disable, key in ((True, "lines_ign"), (False, "lines_reg")):
        cmd = [exe, "--config", str(rules), "--json", "--metrics=off", "--disable-version-check",
               "--quiet", "--no-git-ignore"]
        if disable:
            cmd.append("--disable-nosem")
        proc = subprocess.run(cmd + [str(directory)], capture_output=True, text=True,
                              encoding="utf-8", errors="replace", env=env)
        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            raise SystemExit(f"semgrep gave no JSON ({exc}); stderr: {proc.stderr[:500]}")
        for r in data.get("results", []):
            out[Path(r["path"]).stem][key].append((r["check_id"].split(".")[-1], r["start"]["line"]))
    return out


def load_flake8_regex(cache: Path):
    wheels = sorted(cache.glob("flake8-*.whl"))
    if not wheels:
        cache.mkdir(parents=True, exist_ok=True)
        subprocess.run([sys.executable, "-m", "pip", "download", "flake8", "--no-deps", "-q",
                        "-d", str(cache)], check=True)
        wheels = sorted(cache.glob("flake8-*.whl"))
    with zipfile.ZipFile(wheels[-1]) as z:
        tree = ast.parse(z.read("flake8/defaults.py").decode("utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(getattr(t, "id", "") == "NOQA_INLINE_REGEXP"
                                                for t in node.targets):
            call = node.value
            pattern = call.args[0].value
            flags = re.IGNORECASE if any("IGNORECASE" in ast.dump(a) for a in call.args[1:]) else 0
            return re.compile(pattern, flags), wheels[-1].name
    raise SystemExit("NOQA_INLINE_REGEXP not found in the flake8 wheel")


# -- sources taken over, not reproduced locally -----------------------------
# sonar-python python-frontend/.../nosonar/NoSonarInfoParser.java (master)
_WS = r"[ \t\n\x0b\f\r]"
_J = r"[^\n\r\u0085\u2028\u2029]"            # Java "." without DOTALL
SONAR_NOSONAR = re.compile(rf"#{_WS}*NOSONAR(?:{_WS}*\(([^)]*)\))?(?:\Z|{_WS}{_J}*)")
SONAR_NOQA = re.compile(rf"#{_WS}*noqa(?::{_WS}*({_J}+))?(?:[ \t\n\x0b\f\r;:]{_J}*)?")
SONAR_NOSEC = re.compile(rf"#{_WS}*nosec\b[:{_WS[1:-1]}]*({_J}*)", re.IGNORECASE)
SONAR_RULE_KEY = re.compile(r"[A-Za-z]\d+")
# github/codeql shared/util/.../AlertSuppression.qll (main); comment text excludes "#"
CODEQL_LGTM_ID = re.compile(r"\blgtm\s*\[[^\]]*\]", re.IGNORECASE)
CODEQL_LGTM_BARE = re.compile(r"(?:\A|(?<=;))\s*lgtm(?!\B|\s*\[)", re.IGNORECASE)
CODEQL_CODEQL_ID = re.compile(r"\bcodeql\s*\[[^\]]*\]", re.IGNORECASE)
# semgrep cli/src/semgrep/constants.py (develop); the matching itself lives in semgrep-core
_RULE_ID = r"(?:[:=][\s]?(?P<ids>([^,\s](?:[,\s]+)?)+))?"
SEMGREP_INLINE = re.compile(r" nosem(?:grep)?" + _RULE_ID, re.IGNORECASE)
SEMGREP_PREVIOUS = re.compile(r"^[^a-zA-Z0-9]* nosem(?:grep)?" + _RULE_ID, re.IGNORECASE)


def dotted(node):
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


def sink_calls(data: bytes, callee: str):
    """[(first line, last line)] of the sink calls, in line order; None when it does not parse."""
    try:
        tree = ast.parse(data)
    except (SyntaxError, ValueError, MemoryError, RecursionError):
        return None
    return sorted((n.lineno, n.end_lineno) for n in ast.walk(tree)
                  if isinstance(n, ast.Call) and dotted(n.func) == callee)


def read_for_tools(data: bytes):
    """(lines, tokens) as a flake8-style reader sees them; None when it cannot."""
    try:
        enc, _ = tokenize.detect_encoding(io.BytesIO(data).readline)
        text = data.decode(enc)
    except (SyntaxError, UnicodeDecodeError, LookupError):
        return None
    lines = io.StringIO(text, newline=None).readlines()
    try:
        toks = list(tokenize.generate_tokens(io.StringIO("".join(lines)).readline))
    except (tokenize.TokenError, IndentationError, SyntaxError, ValueError):
        return None
    return lines, toks


def flake8_mapping(lines, toks):
    ret = {}
    min_line, max_line = len(lines) + 2, -1
    for tp, _, (s_line, _), (e_line, _), _ in toks:
        if tp in (tokenize.ENDMARKER, tokenize.DEDENT):
            continue
        min_line, max_line = min(min_line, s_line), max(max_line, e_line)
        if tp in (tokenize.NL, tokenize.NEWLINE):
            joined = "".join(lines[min_line - 1:max_line])
            for ln in range(min_line, max_line + 1):
                ret[ln] = joined
            min_line, max_line = len(lines) + 2, -1
    return ret


def sonar_kind(comment: str):
    """blanket | security | rule | None for one comment token (sonar-python parser)."""
    content = comment[comment.index("#"):]
    segments = ["#" + s for s in content.split("#") if s.strip()]
    best = None
    for seg in segments:
        m = SONAR_NOSONAR.fullmatch(seg)
        if m:
            rules = [r.strip() for r in (m.group(1) or "").split(",") if r.strip()]
            kind = "rule" if rules else "blanket"
        else:
            m = SONAR_NOQA.fullmatch(seg)
            if m:
                rules = [r.strip() for r in (m.group(1) or "").split(",") if r.strip()]
                kind = "rule" if rules else "blanket"
            else:
                m = SONAR_NOSEC.fullmatch(seg)
                if not m:
                    continue
                toks = [t.strip() for t in re.split(r"[,\s]+", m.group(1).strip()) if t.strip()]
                kind = "rule" if any(SONAR_RULE_KEY.fullmatch(t) for t in toks) else "security"
        if kind == "blanket":
            return "blanket"
        if best is None or (best == "rule" and kind == "security"):
            best = kind
    return best


def flake8_honours(flake8_re, joined_line: str, code: str) -> bool:
    """flake8's own decision (violation.py): a bare marker honours every code, a coded one
    only the codes it lists, matched case-sensitively as prefixes of the reported code."""
    match = flake8_re.search(joined_line)
    if match is None:
        return False
    codes_str = match.groupdict().get("codes")
    if codes_str is None:
        return True
    codes = {c for c in re.split(r"[,\s]+", codes_str.strip()) if c}
    return code in codes or code.startswith(tuple(codes))


def source_tools(data: bytes, callee: str, flake8_re, code: str = ""):
    """{tool: (honoured ordinals, pattern anywhere)} plus 'unparsed'. `code` is the flake8
    (flake8-bandit / ruff) code a finding on the sink would carry."""
    calls = sink_calls(data, callee)
    read = read_for_tools(data)
    out = {t: (set(), False) for t in ("flake8", "sonar", "codeql", "semgrep")}
    if calls is None or read is None:
        # nothing is analysed; the textual patterns still tell whether a marker is spelled
        try:
            text = data.decode("utf-8", "replace")
        except Exception:
            text = ""
        pat = {
            "flake8": bool(flake8_re.search(text)),
            "sonar": any(sonar_kind(c) for c in re.findall(r"#[^\n\r]*", text)),
            "codeql": any(CODEQL_LGTM_ID.search(c) or CODEQL_LGTM_BARE.search(c) or CODEQL_CODEQL_ID.search(c)
                          for c in (x[1:] for x in re.findall(r"#[^\n\r]*", text))),
            "semgrep": bool(SEMGREP_INLINE.search(text)),
        }
        return {t: (set(), pat[t]) for t in pat}, True
    lines, toks = read
    mapping = flake8_mapping(lines, toks)
    comments = [(t.start[0], t.string, t.line, t.start[1]) for t in toks if t.type == tokenize.COMMENT]
    # flake8
    hon = {i for i, (ln, _) in enumerate(calls)
           if flake8_honours(flake8_re, mapping.get(ln, ""), code)}
    out["flake8"] = (hon, any(flake8_re.search(l) for l in lines))
    # sonar
    kinds = [(row, sonar_kind(s)) for row, s, _, _ in comments]
    hon = {i for i, (ln, _) in enumerate(calls)
           if any(r == ln and k in ("blanket", "security") for r, k in kinds)}
    out["sonar"] = (hon, any(k for _, k in kinds))
    # codeql
    hon, pat = set(), False
    for row, s, line, col in comments:
        text = s[1:]
        lg = bool(CODEQL_LGTM_ID.search(text) or CODEQL_LGTM_BARE.search(text))
        cq = bool(CODEQL_CODEQL_ID.search(text))
        pat = pat or lg or cq
        standalone = line[:col].strip() == ""
        for i, (ln, _) in enumerate(calls):
            if (lg and (row == ln or (standalone and row == ln - 1))) or \
               (cq and standalone and row == ln - 1):
                hon.add(i)
    out["codeql"] = (hon, pat)
    # semgrep
    hon = set()
    for i, (ln, end) in enumerate(calls):
        span = lines[ln - 1:end]
        prev = lines[ln - 2] if ln >= 2 else ""
        if any(SEMGREP_INLINE.search(l) for l in span) or SEMGREP_PREVIOUS.search(prev):
            hon.add(i)
    out["semgrep"] = (hon, any(SEMGREP_INLINE.search(l) for l in lines))
    return out, False


def _silenced(state_before, state_after, code, a_data, callee, executed_suppression):
    """Did the tool stop reporting the sink in `after`? For a marker: findings shown only
    when the marker is ignored. For a keyword (usedforsecurity): fewer findings in the normal
    run while the sink call is still there."""
    if executed_suppression == "keyword":
        reg_before = sum(1 for t, _ in state_before["lines_reg"] if t == code)
        reg_after = sum(1 for t, _ in state_after["lines_reg"] if t == code)
        return reg_after < reg_before and bool(sink_calls(a_data, callee))
    return bool(bandit_suppressed(state_after, code)[0] - bandit_suppressed(state_before, code)[0])


def tools_step(work: Path, bandit_exe: str, cache: Path, ruff_exe: str = "", semgrep_exe: str = ""):
    manifest = json.loads((work / "manifest.json").read_text(encoding="utf-8"))
    flake8_re, wheel = load_flake8_regex(cache)
    states = {}
    for side in ("before", "after"):
        states[side] = bandit_state(bandit_exe, work / side, None)
    ruff_states, semgrep_states = {}, {}
    if ruff_exe:
        for side in ("before", "after"):
            ruff_states[side] = ruff_state(ruff_exe, work / side)
    if semgrep_exe:
        rules = work / "semgrep-rules.yml"
        rules.write_text(SEMGREP_RULES, encoding="utf-8")
        for side in ("before", "after"):
            semgrep_states[side] = semgrep_state(semgrep_exe, rules, work / side)
    result = {}
    for item in manifest:
        vid, sink = item["id"], item["sink"]
        s = SINKS[sink]
        entry = {"unparsed": False, "tools": {}}
        b_before, n_before = bandit_suppressed(states["before"][vid], s["test"])
        b_after, n_after = bandit_suppressed(states["after"][vid], s["test"])
        after_state = states["after"][vid]
        bandit_unparsed = after_state["unparsed"] or n_after == 0
        a_data = (work / "after" / f"{vid}.py").read_bytes()
        b_data = (work / "before" / f"{vid}.py").read_bytes()
        honoured_by_bandit = bool(b_after - b_before)
        if item["category"] == "flag":
            # not a nosec: the finding is gone in the normal run while the call is still there
            reg_before = sum(1 for t, _ in states["before"][vid]["lines_reg"] if t == s["test"])
            reg_after = sum(1 for t, _ in after_state["lines_reg"] if t == s["test"])
            honoured_by_bandit = reg_after < reg_before and bool(sink_calls(a_data, s["callee"]))
            bandit_unparsed = after_state["unparsed"]
        entry["tools"]["bandit"] = dict(honoured=honoured_by_bandit, after_findings=n_after,
                                        before_findings=n_before, unparsed=bandit_unparsed)
        scode = "S" + s["test"][1:]
        a_tools, a_unparsed = source_tools(a_data, s["callee"], flake8_re, scode)
        b_tools, _ = source_tools(b_data, s["callee"], flake8_re, scode)
        for t in ("flake8", "sonar", "codeql", "semgrep"):
            hon_a, pat_a = a_tools[t]
            hon_b, _ = b_tools[t]
            entry["tools"][t] = dict(honoured=bool(hon_a - hon_b), pattern=pat_a)
        # bandit's pattern is its own regex over comment tokens
        entry["tools"]["bandit"]["pattern"] = bandit_comment_pattern(a_data)
        entry["unparsed"] = a_unparsed
        kind = "keyword" if item["category"] == "flag" else "marker"
        # ruff: executed when given; its marker handling is flake8's, so the pattern is flake8's
        if ruff_exe:
            entry["tools"]["ruff"] = dict(
                honoured=_silenced(ruff_states["before"][vid], ruff_states["after"][vid], scode,
                                   a_data, s["callee"], kind),
                pattern=entry["tools"]["flake8"]["pattern"], executed=True)
        else:
            entry["tools"]["ruff"] = dict(honoured=False, pattern=False, executed=False)
        # semgrep: executed when given, otherwise the pattern taken over from its source
        if semgrep_exe:
            rule = SEMGREP_RULE_OF[sink]
            entry["tools"]["semgrep"] = dict(
                honoured=_silenced(semgrep_states["before"][vid], semgrep_states["after"][vid], rule,
                                   a_data, s["callee"], kind),
                pattern=entry["tools"]["semgrep"]["pattern"], executed=True)
        else:
            entry["tools"]["semgrep"]["executed"] = False
        entry["tools"]["bandit"]["executed"] = True
        result[vid] = entry
    executed = ["bandit"] + (["ruff"] if ruff_exe else []) + (["semgrep"] if semgrep_exe else [])
    (work / "tools.json").write_text(json.dumps(
        dict(bandit=bandit_version(bandit_exe), flake8_wheel=wheel, python=sys.version.split()[0],
             ruff=tool_version(ruff_exe) if ruff_exe else "",
             semgrep=tool_version(semgrep_exe) if semgrep_exe else "", executed=executed,
             variants=result), indent=1), encoding="utf-8")
    honoured = Counter(t for e in result.values() for t, v in e["tools"].items() if v["honoured"])
    print("tools done; variants where the tool honours a new marker:", dict(honoured))


BANDIT_NOSEC = re.compile(r"#\s*nosec:?\s*(?P<tests>[^#]+)?#?")


def bandit_comment_pattern(data: bytes):
    read = read_for_tools(data)
    if read is None:
        return any(BANDIT_NOSEC.search(c) for c in re.findall(r"#[^\n\r]*", data.decode("utf-8", "replace")))
    return any(BANDIT_NOSEC.search(t.string) for t in read[1] if t.type == tokenize.COMMENT)


# ---------------------------------------------------------------------------
# Saikou
# ---------------------------------------------------------------------------

def run_engine(engine, before: str, after: str, verification: bool = True,
               language: str = "python") -> dict:
    """What Saikou says about one pair in change gating (and, unless switched off, in verification)."""
    try:
        intro = engine.introduced_suppressions(before, after, strict=False, language=language)
        strict = (engine.introduced_suppressions(before, after, strict=True, language=language)
                  if verification else [])
        scan = engine.scan_transformation(before, after, language=language, expect_change=False)
    except Exception as exc:                          # a crash is a result too
        return {"error": f"{type(exc).__name__}: {exc}"}
    hard = engine.Severity.HARD_FAIL
    return {
        "intro_hard": sorted({f.check for f in intro if f.severity is hard}),
        "intro_warn": sorted({f.check for f in intro if f.severity is not hard}),
        "strict_hard": sorted({f.check for f in strict if f.severity is hard}),
        "scan_hard": sorted({f.check for f in scan if f.severity is hard}),
        "kinds": sorted({m.group(1) for f in intro
                         for m in [re.match(r"A (\S+) (?:analyser )?suppression", f.detail)] if m}),
    }


def engine_step(work: Path, label: str, repo: Path):
    sys.path.insert(0, str(repo))
    from saikou import engine
    manifest = json.loads((work / "manifest.json").read_text(encoding="utf-8"))
    res = {}
    for item in manifest:
        vid = item["id"]
        before = (work / "before" / f"{vid}.py").read_bytes().decode("utf-8", "replace")
        after = (work / "after" / f"{vid}.py").read_bytes().decode("utf-8", "replace")
        res[vid] = run_engine(engine, before, after)
    target = work / f"engine_{label}_py{sys.version_info.major}.{sys.version_info.minor}.json"
    target.write_text(json.dumps(dict(python=sys.version.split()[0], label=label, engine=str(repo),
                                      variants=res), indent=1), encoding="utf-8")
    print("engine", label, "done on", sys.version.split()[0], "->", target.name)


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def classify(tool_entry, eng):
    honouring = [t for t, v in tool_entry["tools"].items() if v["honoured"]]
    pattern = [t for t, v in tool_entry["tools"].items() if v.get("pattern")]
    hard = "suppression_introduced" in eng.get("scan_hard", []) or bool(eng.get("intro_hard"))
    warn = bool(eng.get("intro_warn"))
    unparsed = tool_entry.get("unparsed") or tool_entry["tools"]["bandit"].get("unparsed")
    if "error" in eng:
        return "crash", honouring
    if honouring:
        if hard:
            return "caught", honouring
        return ("miss-warn-only" if warn else "MISS"), honouring
    if hard:
        if unparsed:
            return "fp-unparsed", pattern
        return ("fp-placement" if pattern else "fp-nopattern"), pattern
    return "clean", pattern


def report_step(work: Path):
    manifest = {m["id"]: m for m in json.loads((work / "manifest.json").read_text(encoding="utf-8"))}
    tools = json.loads((work / "tools.json").read_text(encoding="utf-8"))
    engines = {}
    for p in sorted(work.glob("engine_*_py*.json")):
        d = json.loads(p.read_text(encoding="utf-8"))
        engines[f"{d['label']} / Python {d['python']}"] = d["variants"]
    out = {"bandit": tools["bandit"], "flake8_wheel": tools["flake8_wheel"],
           "tools_python": tools["python"], "engines": list(engines), "variants": {}}
    summary = {py: Counter() for py in engines}
    per_cat = {py: defaultdict(Counter) for py in engines}
    rows = defaultdict(list)
    for vid, m in manifest.items():
        t = tools["variants"][vid]
        rec = dict(m, tools={k: dict(v) for k, v in t["tools"].items()}, unparsed=t["unparsed"], verdict={})
        for py, ev in engines.items():
            kind, who = classify(t, ev[vid])
            rec["verdict"][py] = dict(kind=kind, who=who, saikou=ev[vid])
            summary[py][kind] += 1
            per_cat[py][m["category"]][kind] += 1
            if kind in ("MISS", "miss-warn-only", "fp-placement", "fp-nopattern", "fp-unparsed", "crash"):
                rows[(py, kind)].append(rec)
        out["variants"][vid] = rec
    (work / "results.json").write_text(json.dumps(out, indent=1), encoding="utf-8")
    cats = Counter(m["category"] for m in manifest.values())
    lines = [f"bandit {tools['bandit']}; flake8 regex from {tools['flake8_wheel']}; tools ran on "
             f"Python {tools['python']}", "", "| category | variants |", "|---|---|"]
    lines += [f"| {c} | {n} |" for c, n in sorted(cats.items())]
    for py in engines:
        lines += ["", f"### Saikou: {py}", "", "| verdict | variants |", "|---|---|"]
        lines += [f"| {k} | {n} |" for k, n in sorted(summary[py].items())]
        lines += ["", "| category | " + " | ".join(sorted(summary[py])) + " |",
                  "|---|" + "---|" * len(summary[py])]
        for c in sorted(per_cat[py]):
            lines.append(f"| {c} | " + " | ".join(str(per_cat[py][c].get(k, 0)) for k in sorted(summary[py])) + " |")
    per_tool = {t: Counter() for t in TOOLS}
    for rec in out["variants"].values():
        for t in TOOLS:
            if rec["tools"][t]["honoured"]:
                per_tool[t]["honoured"] += 1
    first_py = next((k for k in engines if k.startswith("work-tree")), next(iter(engines), None))
    if first_py:
        for rec in out["variants"].values():
            hard = rec["verdict"][first_py]["saikou"]
            counted = "suppression_introduced" in hard.get("scan_hard", [])
            for t in TOOLS:
                if rec["tools"][t]["honoured"] and counted:
                    per_tool[t]["counted_hard"] += 1
    lines += ["", "### Per tool (variants where the tool honours the new marker)", "",
              "| tool | honoured | of those: Saikou hard fail |", "|---|---|---|"]
    lines += [f"| {t} | {per_tool[t]['honoured']} | {per_tool[t]['counted_hard']} |" for t in TOOLS]
    (work / "results.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (work / "deviations.json").write_text(json.dumps(
        {f"{py}|{kind}": [dict(id=r["id"], category=r["category"], sink=r["sink"], layout=r["layout"],
                               label=r["label"], marker=r["marker"], who=r["verdict"][py]["who"],
                               saikou=r["verdict"][py]["saikou"], tools=r["tools"])
                          for r in recs] for (py, kind), recs in rows.items()}, indent=1), encoding="utf-8")
    print("\n".join(lines))


# ---------------------------------------------------------------------------
# Frozen reference (golden file), regression test and the published coverage statement
# ---------------------------------------------------------------------------

TOOL_LETTER = {"bandit": "b", "flake8": "f", "ruff": "r", "sonar": "s", "codeql": "c", "semgrep": "g"}
TOOL_NAME = {"bandit": "bandit", "flake8": "flake8", "ruff": "ruff", "sonar": "sonar-python",
             "codeql": "CodeQL", "semgrep": "semgrep"}
GOLDEN = REPO / "tests" / "fixtures" / "suppression_oracle_golden.json"
GOLDEN_JS = REPO / "tests" / "fixtures" / "suppression_oracle_js_golden.json"
COVERAGE_DOCS = {"en": REPO / "docs" / "conformance" / "suppression-coverage.md",
                 "nl": REPO / "docs" / "conformance" / "suppression-coverage.nl.md"}
BLOCKED_ANYWAY = ("fp-placement", "fp-unparsed", "fp-nopattern")


def manifest_digest(work: Path) -> str:
    """Hash of every generated pair: when the generator changes, the golden file is stale."""
    digest = hashlib.sha256()
    for item in json.loads((work / "manifest.json").read_text(encoding="utf-8")):
        digest.update(json.dumps(item, sort_keys=True).encode("utf-8"))
        digest.update((work / "before" / f"{item['id']}.py").read_bytes())
        digest.update((work / "after" / f"{item['id']}.py").read_bytes())
    return digest.hexdigest()


def tool_entry_from_golden(entry: dict) -> dict:
    tools = {t: {"honoured": TOOL_LETTER[t] in entry["h"], "pattern": TOOL_LETTER[t] in entry["p"]}
             for t in TOOLS}
    tools["bandit"]["unparsed"] = bool(entry["u"])
    return {"tools": tools, "unparsed": bool(entry["u"])}


def freeze_step(work: Path, label: str, out: Path):
    """Write the reference verdicts of the engine `label` (this interpreter) as the golden file."""
    manifest = {m["id"]: m for m in json.loads((work / "manifest.json").read_text(encoding="utf-8"))}
    tools = json.loads((work / "tools.json").read_text(encoding="utf-8"))
    engine_file = work / f"engine_{label}_py{sys.version_info.major}.{sys.version_info.minor}.json"
    verdicts = json.loads(engine_file.read_text(encoding="utf-8"))["variants"]
    variants = {}
    for vid, item in manifest.items():
        t = tools["variants"][vid]
        kind, _ = classify(t, verdicts[vid])
        variants[vid] = {
            "k": kind,
            "h": "".join(TOOL_LETTER[x] for x in TOOLS if t["tools"][x]["honoured"]),
            "p": "".join(TOOL_LETTER[x] for x in TOOLS if t["tools"][x].get("pattern")),
            "u": int(bool(t["unparsed"] or t["tools"]["bandit"].get("unparsed"))),
            "c": item["category"], "l": item["label"]}
    executed = tools.get("executed", ["bandit"])
    reference = {
        "bandit": tools["bandit"].split()[1] if tools["bandit"].startswith("bandit") else tools["bandit"],
        "flake8": tools["flake8_wheel"].replace("flake8-", "", 1).replace("-py2.py3-none-any.whl", ""),
        "sonar-python": "NoSonarInfoParser.java (master), pattern only",
        "codeql": "AlertSuppression.qll (main), pattern only",
        "ruff": tools.get("ruff", "") or "not run",
        "semgrep": (tools.get("semgrep", "") if "semgrep" in executed
                    else "constants.py (develop), pattern only"),
        "executed": executed}
    ids = sorted(variants)
    lines = ["{", ' "format": 1,', f' "digest": "{manifest_digest(work)}",',
             " \"reference_tools\": " + json.dumps(reference, sort_keys=True) + ",", ' "variants": {']
    for i, vid in enumerate(ids):
        lines.append(f'  "{vid}": {json.dumps(variants[vid], sort_keys=True)}'
                     + ("," if i < len(ids) - 1 else ""))
    lines += [" }", "}", ""]
    out.write_text("\n".join(lines), encoding="utf-8", newline="\n")
    print("froze", len(ids), "variants ->", out)


def summarise(golden: dict) -> dict:
    variants = golden["variants"].values()
    per_tool = {t: Counter(v["k"] for v in variants if TOOL_LETTER[t] in v["h"]) for t in TOOLS}
    classes: dict = defaultdict(Counter)
    for v in variants:
        if v["k"] not in ("caught", "clean"):
            classes[v["k"]][(v["c"], v["l"])] += 1
    return dict(total=len(golden["variants"]), kinds=Counter(v["k"] for v in variants),
                categories=Counter(v["c"] for v in variants), per_tool=per_tool,
                honoured=sum(1 for v in variants if v["h"]), classes=classes)


def _class_list(counter: Counter, limit: int = 12, more: str = "and {n} more") -> str:
    items = sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))
    shown = ", ".join(f"{cat}/{label} ({n})" for (cat, label), n in items[:limit])
    return shown + (", " + more.format(n=len(items) - limit) if len(items) > limit else "")


BLOCKED_ANYWAY_TEXT = {
    "fp-placement": ("the marker syntax of a reference tool, but on another line than the finding, "
                     "or naming another rule", "de markersyntaxis van een referentietool, maar op "
                     "een andere regel dan de bevinding of voor een andere regel"),
    "fp-unparsed": ("the reference tools cannot read the file", "de referentietools kunnen het "
                    "bestand niet lezen"),
    "fp-nopattern": ("a look-alike that no reference tool recognises", "een lookalike die geen "
                     "referentietool herkent"),
}


def _render_python_coverage(golden: dict) -> dict:
    """The Python part of the coverage statement, in English and Dutch."""
    s = summarise(golden)
    k, ref = s["kinds"], golden["reference_tools"]
    blocked, warned, missed = k["caught"], k["miss-warn-only"], k["MISS"]
    over = sum(k[x] for x in BLOCKED_ANYWAY)
    cats = ", ".join(f"{c} {n}" for c, n in sorted(s["categories"].items()))
    executed = ref.get("executed", ["bandit"])
    how_en = [f"| bandit {ref['bandit']} | executed on every pair, with and without `--ignore-nosec` |"]
    how_nl = [f"| bandit {ref['bandit']} | uitgevoerd op elk paar, met en zonder `--ignore-nosec` |"]
    if "ruff" in executed:
        how_en.append(f"| {ref['ruff']} | executed with the S rules, with and without `--ignore-noqa` |")
        how_nl.append(f"| {ref['ruff']} | uitgevoerd met de S-regels, met en zonder `--ignore-noqa` |")
    if "semgrep" in executed:
        how_en.append(f"| semgrep {ref['semgrep']} | executed with a rule per sink, with and without "
                      f"`--disable-nosem` |")
        how_nl.append(f"| semgrep {ref['semgrep']} | uitgevoerd met een regel per sink, met en zonder "
                      f"`--disable-nosem` |")
    how_en.append(f"| flake8 {ref['flake8']} | its own marker pattern, read from the release wheel |")
    how_nl.append(f"| flake8 {ref['flake8']} | eigen markerpatroon, uit de release-wheel gelezen |")
    pattern_only = [TOOL_NAME[t] for t in ("sonar", "codeql", "semgrep")
                    if t != "semgrep" or "semgrep" not in executed]
    how_en.append(f"| {', '.join(pattern_only)} | marker patterns from their published sources; not executed |")
    how_nl.append(f"| {', '.join(pattern_only)} | markerpatronen uit hun gepubliceerde bronnen; niet uitgevoerd |")
    how_en, how_nl = "\n".join(how_en), "\n".join(how_nl)
    rows = "\n".join(
        f"| {TOOL_NAME[t]} | {sum(s['per_tool'][t].values())} | {s['per_tool'][t]['caught']} | "
        f"{s['per_tool'][t]['miss-warn-only']} | {s['per_tool'][t]['MISS']} |" for t in TOOLS)
    warn_list = _class_list(s["classes"]["miss-warn-only"]) or "-"
    miss_list = _class_list(s["classes"]["MISS"])
    over_en = "\n".join(
        f"- {BLOCKED_ANYWAY_TEXT[x][0]}: {k[x]} pairs ({_class_list(s['classes'][x], 6)})"
        for x in BLOCKED_ANYWAY if k[x])
    over_nl = "\n".join(
        f"- {BLOCKED_ANYWAY_TEXT[x][1]}: {k[x]} paren "
        f"({_class_list(s['classes'][x], 6, 'en nog {n}')})" for x in BLOCKED_ANYWAY if k[x])
    warn_list_nl = _class_list(s["classes"]["miss-warn-only"], 12, "en nog {n}") or "-"
    miss_list_nl = _class_list(s["classes"]["MISS"], 12, "en nog {n}")
    en = f"""# Suppression coverage

Generated by `python scripts/suppression_oracle.py conformance` from
`tests/fixtures/suppression_oracle_golden.json` (Python) and
`tests/fixtures/suppression_oracle_js_golden.json` (JavaScript and TypeScript).
`tests/test_suppression_oracle.py` and `tests/test_suppression_oracle_js.py` fail when this file or
a golden file is out of date. Do not edit by hand.

## What was checked

Saikou's verdict in change gating on Python files in which a suppression marker is added to code
that carries a security finding: {s['total']} before/after pairs ({cats}). For every pair the
reference tools decide whether they honour the new marker; Saikou's verdict is then compared with
theirs.

| reference tool | how |
|---|---|
{how_en}

## Result

| | pairs |
|---|---|
| a reference tool honours the new marker | {s['honoured']} |
| of those, Saikou blocks | {blocked} |
| of those, Saikou warns | {warned} |
| of those, Saikou does not report | {missed} |
| no reference tool honours the marker, Saikou blocks anyway | {over} |

| reference tool | honours | Saikou blocks | Saikou warns | not reported |
|---|---|---|---|---|
{rows}

## Reported as a warning instead of a block

{warn_list}.

The `usedforsecurity` keyword on data that is not password material is the documented remedy for a
weak-hash finding, so change gating reports it as a warning; on password material, and when a claimed
fix is verified, it blocks. A style marker away from a security call is a warning as well; no
reference tool honours one there.

## Not reported

{miss_list if missed else 'none'}.

{"These are a semgrep marker without a hash sign inside a string; semgrep's Python constants match it, but the matching lives in semgrep-core, which was not executed." if missed else ""}

## Blocked although no reference tool honours the marker

Any marker that looks like a security suppression is treated as one, wherever it sits in the
changed code, and so is code that the tools cannot read.

{over_en}

## Not covered (Python)

Languages other than Python, JavaScript and TypeScript. Versions of the reference tools other than
those above. Marker forms that are not among the pairs. Behaviour of sonar-python and CodeQL beyond
their published marker patterns.
"""
    wb = ", ".join(f"{c} {n}" for c, n in sorted(s["categories"].items()))
    nl = f"""# Dekking van onderdrukkingen

Gegenereerd door `python scripts/suppression_oracle.py conformance` uit
`tests/fixtures/suppression_oracle_golden.json` (Python) en
`tests/fixtures/suppression_oracle_js_golden.json` (JavaScript en TypeScript).
`tests/test_suppression_oracle.py` en `tests/test_suppression_oracle_js.py` falen als dit bestand of
een golden-bestand verouderd is. Niet met de hand aanpassen.

## Wat is gecontroleerd

Het oordeel van Saikou bij wijzigingscontrole op Python-bestanden waarin een onderdrukkingsmarker
wordt toegevoegd aan code met een beveiligingsbevinding: {s['total']} before/after-paren ({wb}).
Per paar bepalen de referentietools of zij de nieuwe marker honoreren; daarna is het oordeel van
Saikou met het hunne vergeleken.

| referentietool | hoe |
|---|---|
{how_nl}

## Resultaat

| | paren |
|---|---|
| een referentietool honoreert de nieuwe marker | {s['honoured']} |
| daarvan blokkeert Saikou | {blocked} |
| daarvan waarschuwt Saikou | {warned} |
| daarvan meldt Saikou niets | {missed} |
| geen referentietool honoreert de marker, Saikou blokkeert toch | {over} |

| referentietool | honoreert | Saikou blokkeert | Saikou waarschuwt | niet gemeld |
|---|---|---|---|---|
{rows}

## Gemeld als waarschuwing in plaats van blokkade

{warn_list_nl}.

Het sleutelwoord `usedforsecurity` op gegevens die geen wachtwoordmateriaal zijn is het
gedocumenteerde middel tegen een zwakke-hashbevinding; wijzigingscontrole meldt het daarom als
waarschuwing. Op wachtwoordmateriaal, en bij verificatie van een beweerde fix, blokkeert het. Een
stijlmarker buiten een beveiligingsaanroep is ook een waarschuwing; geen enkele referentietool
honoreert er daar een.

## Niet gemeld

{miss_list_nl if missed else 'geen'}.

{"Dit zijn semgrep-markers zonder hekje binnen een string; de Python-constanten van semgrep herkennen ze, maar de matching zit in semgrep-core, dat niet is uitgevoerd." if missed else ""}

## Geblokkeerd terwijl geen referentietool de marker honoreert

Elke marker die op een beveiligingsonderdrukking lijkt wordt als zodanig behandeld, waar hij ook
staat in de gewijzigde code, en code die de tools niet kunnen lezen ook.

{over_nl}

## Niet gedekt (Python)

Andere talen dan Python, JavaScript en TypeScript. Andere versies van de referentietools dan
hierboven. Markervormen die niet onder de paren vallen. Gedrag van sonar-python en CodeQL buiten hun
gepubliceerde markerpatronen.
"""
    return {"en": en, "nl": nl}


def summarise_js(g: dict) -> dict:
    """The counts behind the JavaScript/TypeScript coverage statement (also used for the site)."""
    ref = g["reference_tools"]
    letters, names = ref["letters"], ref["names"]
    variants = list(g["variants"].values())
    kinds = Counter(v["k"] for v in variants)
    classes: dict = defaultdict(Counter)
    for v in variants:
        if v["k"] not in ("caught", "clean"):
            classes[v["k"]][(v["c"], v["l"])] += 1
    per_tool = []
    for tool in ref["executed"]:
        mine = Counter(v["k"] for v in variants if letters[tool] in v["h"])
        per_tool.append(dict(name=names[tool], honours=sum(mine.values()), blocks=mine["caught"],
                             warns=mine["style-warned"], missed=mine["miss-warn-only"] + mine["MISS"]))
    return dict(total=len(variants), kinds=kinds, classes=classes, per_tool=per_tool,
                categories=Counter(v["c"] for v in variants),
                honoured=sum(1 for v in variants if v["h"]),
                over=sum(kinds[x] for x in ("fp-placement", "fp-nopattern")))


def _render_js_coverage(g: dict) -> dict:
    """The JavaScript/TypeScript part of the coverage statement, from its golden file."""
    ref = g["reference_tools"]
    s = summarise_js(g)
    variants, kinds, classes, honoured = list(g["variants"].values()), s["kinds"], s["classes"], s["honoured"]
    cats = ", ".join(f"{c} {n}" for c, n in sorted(s["categories"].items()))
    rows = "\n".join(f"| {t['name']} | {t['honours']} | {t['blocks']} | {t['warns']} | {t['missed']} |"
                     for t in s["per_tool"])
    over = s["over"]
    over_en = "\n".join(
        f"- {BLOCKED_ANYWAY_TEXT[x][0]}: {kinds[x]} pairs ({_class_list(classes[x], 6)})"
        for x in ("fp-placement", "fp-nopattern") if kinds[x])
    over_nl = "\n".join(
        f"- {BLOCKED_ANYWAY_TEXT[x][1]}: {kinds[x]} paren ({_class_list(classes[x], 6, 'en nog {n}')})"
        for x in ("fp-placement", "fp-nopattern") if kinds[x])
    missed = kinds["MISS"] + kinds["miss-warn-only"]
    miss_en = _class_list(classes["MISS"] + classes["miss-warn-only"]) if missed else "none"
    miss_nl = _class_list(classes["MISS"] + classes["miss-warn-only"], 12, "en nog {n}") if missed else "geen"
    en = f"""
## JavaScript and TypeScript

Saikou's verdict in change gating on `.js` and `.ts` files in which a suppression marker is added to
code that a reference tool reports: {len(variants)} before/after pairs ({cats}). Reference tools, all
executed: ESLint {ref['eslint']} (core rules and eslint-plugin-security, with and without inline
config), the TypeScript compiler {ref['tsc']} (a type error with and without the directive) and
semgrep {ref['semgrep']} (a rule per sink, with and without `--disable-nosem`).

| | pairs |
|---|---|
| a reference tool honours the new marker | {honoured} |
| of those, Saikou blocks | {kinds['caught']} |
| of those, Saikou warns (a type-checker directive) | {kinds['style-warned']} |
| of those, Saikou does not report | {missed} |
| no reference tool honours the marker, Saikou blocks anyway | {over} |
| marker of a tool that is not executed here (SonarJS, CodeQL): Saikou blocks | {kinds['not-run-blocked']} |
| marker of a tool that is not executed here: Saikou does not block (inside a string) | {kinds['not-run-open']} |

| reference tool | honours | Saikou blocks | Saikou warns | not reported |
|---|---|---|---|---|
{rows}

Not reported: {miss_en}.

An ESLint directive without a rule list silences every rule, so it counts as a security suppression
where it covers a line that holds a risky call (`eval`, `new Function`, child_process, `fs`, `vm`,
`innerHTML`, a non-literal `require`, ...); on another line, or naming another rule, it is a warning.
TypeScript directives are type-checker markers and are reported as warnings.

## JavaScript and TypeScript: blocked although no executed tool honours the marker

{over_en}

## JavaScript and TypeScript: not covered

SonarJS and CodeQL (their markers are blocked, but their behaviour was not run). ESLint rules beyond
the six configured. Calls outside the risky-call list. A marker moved across the lines of one
multi-line call. Markers inside JavaScript strings are counted as markers (conservative).
"""
    nl = f"""
## JavaScript en TypeScript

Het oordeel van Saikou bij wijzigingscontrole op `.js`- en `.ts`-bestanden waarin een
onderdrukkingsmarker wordt toegevoegd aan code die een referentietool meldt: {len(variants)}
before/after-paren ({cats}). Referentietools, allemaal uitgevoerd: ESLint {ref['eslint']} (kernregels
en eslint-plugin-security, met en zonder inline-configuratie), de TypeScript-compiler {ref['tsc']}
(een typefout met en zonder de directive) en semgrep {ref['semgrep']} (een regel per sink, met en
zonder `--disable-nosem`).

| | paren |
|---|---|
| een referentietool honoreert de nieuwe marker | {honoured} |
| daarvan blokkeert Saikou | {kinds['caught']} |
| daarvan waarschuwt Saikou (een type-checker-directive) | {kinds['style-warned']} |
| daarvan meldt Saikou niets | {missed} |
| geen referentietool honoreert de marker, Saikou blokkeert toch | {over} |
| marker van een tool die hier niet is uitgevoerd (SonarJS, CodeQL): Saikou blokkeert | {kinds['not-run-blocked']} |
| marker van een tool die hier niet is uitgevoerd: Saikou blokkeert niet (binnen een string) | {kinds['not-run-open']} |

| referentietool | honoreert | Saikou blokkeert | Saikou waarschuwt | niet gemeld |
|---|---|---|---|---|
{rows}

Niet gemeld: {miss_nl}.

Een ESLint-directive zonder regellijst zet alle regels uit en telt daarom als
beveiligingsonderdrukking waar hij een regel met een risicovolle aanroep dekt (`eval`,
`new Function`, child_process, `fs`, `vm`, `innerHTML`, een niet-letterlijke `require`, ...); op een
andere regel, of voor een andere regel, is het een waarschuwing. TypeScript-directives zijn
type-checkermarkers en worden als waarschuwing gemeld.

## JavaScript en TypeScript: geblokkeerd terwijl geen uitgevoerde tool de marker honoreert

{over_nl}

## JavaScript en TypeScript: niet gedekt

SonarJS en CodeQL (hun markers worden geblokkeerd, maar hun gedrag is niet uitgevoerd).
ESLint-regels buiten de zes ingestelde. Aanroepen buiten de lijst met risicovolle aanroepen. Een
marker die binnen één meerregelige aanroep van regel wisselt. Markers binnen JavaScript-strings
tellen als marker (conservatief).
"""
    return {"en": en, "nl": nl}


def render_coverage(golden: dict, golden_js: Optional[dict] = None) -> dict:
    """The coverage statement, in English and Dutch, from the golden files alone."""
    parts = _render_python_coverage(golden)
    if golden_js is None and GOLDEN_JS.exists():
        golden_js = json.loads(GOLDEN_JS.read_text(encoding="utf-8"))
    if golden_js is None:
        return parts
    extra = _render_js_coverage(golden_js)
    return {lang: parts[lang].rstrip("\n") + "\n" + extra[lang] for lang in parts}


def shown_version(raw: str) -> str:
    """A tool version for the drift report: the plain number, else the stored text (for a tool
    that was only read as a pattern, or not run)."""
    return plain_version(raw) or (" ".join((raw or "").split())[:60] or "not run")


def drift_versions(ref: dict, tools: dict) -> List[str]:
    """The frozen and the current tool versions, one line each, as plain version numbers."""
    def line(label, values):
        return label + " | ".join(f"{name} {shown_version(value)}" for name, value in values)
    return [line("frozen: ", [("bandit", ref.get("bandit", "")), ("flake8", ref.get("flake8", "")),
                              ("ruff", ref.get("ruff", "")), ("semgrep", ref.get("semgrep", ""))]),
            line("now:    ", [("bandit", tools.get("bandit", "")), ("flake8", tools.get("flake8_wheel", "")),
                              ("ruff", tools.get("ruff", "")), ("semgrep", tools.get("semgrep", ""))])]


def drift_step(work: Path) -> int:
    """Compare what the executed reference tools say now with the frozen answers. A changed
    answer means a new bandit or flake8 reads a marker differently: look at it, then refresh
    the reference (see the top of this file)."""
    golden = json.loads(GOLDEN.read_text(encoding="utf-8"))
    if manifest_digest(work) != golden["digest"]:
        print("the generated pairs differ from the frozen ones: freeze again")
        return 1
    tools = json.loads((work / "tools.json").read_text(encoding="utf-8"))
    ref = golden["reference_tools"]
    for line in drift_versions(ref, tools):
        print(line)
    frozen_run = set(ref.get("executed", ["bandit"])) | {"flake8"}
    run_now = set(tools.get("executed", ["bandit"])) | {"flake8"}
    compared = [t for t in ("bandit", "flake8", "ruff", "semgrep") if t in frozen_run and t in run_now]
    for tool in sorted(frozen_run - run_now):
        print(f"note: {tool} was executed for the frozen answers and was not now; not compared")
    changed = []
    for vid, frozen in sorted(golden["variants"].items()):
        entry = tools["variants"][vid]["tools"]
        for tool in compared:
            now = bool(entry[tool]["honoured"])
            then = TOOL_LETTER[tool] in frozen["h"]
            if now != then:
                changed.append(f"{vid} {frozen['c']}/{frozen['l']}: {tool} honoured {then} -> {now}")
    print(f"{len(changed)} answers changed")
    for line in changed[:40]:
        print(" ", line)
    return 1 if changed else 0


def conformance_step(golden_path: Path = GOLDEN):
    golden = json.loads(golden_path.read_text(encoding="utf-8"))
    for lang, text in render_coverage(golden).items():
        COVERAGE_DOCS[lang].parent.mkdir(parents=True, exist_ok=True)
        COVERAGE_DOCS[lang].write_text(text, encoding="utf-8", newline="\n")
        print("wrote", COVERAGE_DOCS[lang])


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("step", choices=["generate", "tools", "engine", "report", "all", "freeze",
                                     "conformance", "drift"])
    ap.add_argument("--work", type=Path, help="scratch folder (every step except conformance)")
    ap.add_argument("--bandit", help="path to bandit.exe (generate/tools/all)")
    ap.add_argument("--ruff", default="", help="path to ruff.exe: run it as a reference tool (tools/all)")
    ap.add_argument("--semgrep", default="", help="path to semgrep.exe: run it as a reference tool (tools/all)")
    ap.add_argument("--cache", type=Path, help="folder for the flake8 wheel (default WORK/sources)")
    ap.add_argument("--label", default="work-tree", help="name of the engine under test (engine step)")
    ap.add_argument("--repo", type=Path, default=REPO,
                    help="checkout whose saikou package is tested (engine step; default this one)")
    args = ap.parse_args()
    if args.step == "conformance":
        conformance_step()
        return
    if args.work is None:
        raise SystemExit("--work is required")
    work = args.work
    work.mkdir(parents=True, exist_ok=True)
    cache = args.cache or work / "sources"
    if args.step in ("generate", "all"):
        generate(work, args.bandit)
    if args.step in ("tools", "all"):
        if not args.bandit:
            raise SystemExit("--bandit is required")
        tools_step(work, args.bandit, cache, args.ruff, args.semgrep)
    if args.step in ("engine", "all"):
        engine_step(work, args.label, args.repo)
    if args.step in ("report", "all"):
        report_step(work)
    if args.step == "freeze":
        freeze_step(work, args.label, GOLDEN)
    if args.step == "drift":
        raise SystemExit(drift_step(work))


if __name__ == "__main__":
    main()
