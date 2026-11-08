import sys

import pytest

from saikou import engine
from saikou.engine import Severity, scan_transformation


def test_selftest_passes(capsys):
    assert engine._selftest() == 0
    assert "passed" in capsys.readouterr().out


def test_engine_imports_without_third_party_modules():
    import subprocess
    import sys

    code = ("import sys, saikou; "
            "bad = [m for m in sys.modules if m.split('.')[0] in "
            "('fastapi','pydantic','httpx','bandit','requests')]; "
            "print(bad); sys.exit(1 if bad else 0)")
    proc = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_preexisting_shell_true_is_warning_in_gating_mode():
    before = "import subprocess\nsubprocess.run(cmd, shell=True)\n"
    after = before + "print('unrelated change')\n"
    findings = scan_transformation(before, after, language="python", expect_change=False)
    assert [f.severity for f in findings if f.check == "sink_shell_true"] == [Severity.WARN]


def test_new_shell_true_is_hard_fail_in_gating_mode():
    before = "import subprocess\n"
    after = before + "subprocess.run(cmd, shell=True)\n"
    findings = scan_transformation(before, after, language="python", expect_change=False)
    assert any(f.check == "sink_shell_true" and f.severity is Severity.HARD_FAIL
               for f in findings)


# --- suppression markers inside Python string literals -------------------------------------

def _suppressions(before, after, *, strict=False, language="python"):
    return [(f.check, f.severity, f.line) for f in engine.introduced_suppressions(
        before, after, strict=strict, language=language)]


# Marker words kept apart, so that the test lines below are not themselves suppressions
# when `saikou diff` reads this file (flake8 and semgrep markers are matched on raw lines).
_SEM = "nosem"
_NOQA = "no" + "qa"


# False positives found on 2026-10-12: by `saikou diff` on this repo (fake-fix samples as test
# data) and by measuring 17,372 real Python files as new code (bandit's own help and report
# texts, docstrings). bandit reads its nosec marker from comment tokens only; eslint never
# reads .py files. None of these silence anything.
STRING_MARKER_LINES = [
    'FAKE = CODE.replace("shell=True)", "shell=True)  # nosec")\n',               # test_api.py
    'assert "# nosec" in sample["after"] and sample["threats"]\n',               # test_server.py
    'FAKE_AFTER = ("import subprocess\\n\\ndef run(cmd):\\n"\n'                  # test_service.py
    '              "    return subprocess.call(cmd, shell=True)  # nosec\\n")\n',
    'assert "+    return subprocess.call(cmd, shell=True)  # nosec" in out["diff"]\n',
    'AFTER = ("def run(cmd):\\n"\n'                                              # test_cli.py
    '         "    return subprocess.call(cmd, shell=True)  # nosec - reviewed\\n")\n',
    '_c("x", "subprocess.call(cmd, shell=True)  # nosec B602", "subprocess.run(a)")\n',  # catalog.py
    'def f():\n    """Example: subprocess.call(c, shell=True)  # nosec"""\n',
    'p.add_argument("--ignore-nosec", help="do not skip lines with # nosec comments")\n',
    'def scan(ignore_nosec):\n    """:param ignore_nosec: Whether to ignore #nosec or not"""\n',
    'TEMPLATE = """\n<p>Total lines skipped (#nosec): <span id="nosec">{nosec}</span></p>\n"""\n',
    'print("\\tTotal lines skipped (#nosec): %i" % n)\n',
    'SAMPLE = "// eslint-disable-next-line security/detect-object-injection\\na();\\n"\n',
]


@pytest.mark.parametrize("added", STRING_MARKER_LINES)
@pytest.mark.parametrize("strict", [False, True])
def test_marker_inside_a_python_string_is_not_a_suppression(added, strict):
    before = "import os\n"
    assert _suppressions(before, before + added, strict=strict) == []


def test_real_nosec_comment_is_still_a_hard_fail():
    before = "import subprocess\nsubprocess.call(c, shell=True)\n"
    after = "import subprocess\nsubprocess.call(c, shell=True)  # nosec\n"
    assert _suppressions(before, after) == [
        ("suppression_introduced", Severity.HARD_FAIL, 2)]


def test_real_nosec_comment_next_to_a_string_marker_is_counted():
    # Two string markers before, one string marker plus one real comment after: the
    # text count is unchanged (2 -> 2), the comment count grew (0 -> 1).
    before = 'A = "# nosec"\nB = "# nosec"\nsubprocess.call(c, shell=True)\n'
    after = 'A = "# nosec"\nsubprocess.call(c, shell=True)  # nosec\n'
    assert _suppressions(before, after) == [
        ("suppression_introduced", Severity.HARD_FAIL, 2)]


def test_string_marker_moved_into_a_comment_is_counted():
    before = 'x = f("# nosec")\n'
    after = 'x = f("")  # nosec\n'
    assert _suppressions(before, after) == [
        ("suppression_introduced", Severity.HARD_FAIL, 1)]


def test_noqa_inside_a_string_still_counts():
    # flake8 matches its marker on the raw physical line, string or not. The rule code is
    # filled in at run time so this source line is not itself a security suppression.
    rule = "S602"
    before = "import subprocess\nsubprocess.call(c, shell=True)\n"
    after = f'import subprocess\nsubprocess.call(c, shell=True, env={{"x": "# noqa: {rule}"}})\n'
    assert _suppressions(before, after) == [
        ("suppression_introduced", Severity.HARD_FAIL, 2)]


def test_untokenizable_python_falls_back_to_the_text_count():
    before = "x = 1\n"
    after = 'x = 1\ny = "# nosec"\nz = """never closed\n'
    assert engine._python_comments(after) is None
    assert _suppressions(before, after) == [
        ("suppression_introduced", Severity.HARD_FAIL, 2)]


def test_one_untokenizable_side_counts_both_sides_as_text():
    # The string marker is in both versions, so the text count does not grow.
    before = 'x = "# nosec"\ny = """never closed\n'
    after = 'x = "# nosec"\n'
    assert _suppressions(before, after) == []


def test_javascript_string_markers_are_unchanged():
    before = "a();\n"
    after = 'a();\nconst s = "// eslint-disable-next-line security/detect-object-injection";\n'
    assert _suppressions(before, after, language="javascript") == [
        ("suppression_introduced", Severity.HARD_FAIL, 2)]


def test_gating_a_python_test_file_with_fake_fix_data_passes():
    before = "import os\n"
    after = before + ('CODE = "subprocess.call(cmd, shell=True)\\n"\n'
                      'FAKE = CODE.replace("shell=True)", "shell=True)  # nosec")\n')
    findings = scan_transformation(before, after, language="python", expect_change=False)
    assert [f.check for f in findings if f.severity is Severity.HARD_FAIL] == []


# --- security suppression markers the old patterns missed ----------------------------------

@pytest.mark.parametrize("language, before, after", [
    # bandit's regex has no word boundary: `nosecB602` skips B602.
    ("python", "x = 1\n", "x = 1  # nosecB602\n"),
    ("python", "x = 1\n", "x = 1  # nosecb602,B603\n"),
    ("python", "x = 1\n", "x = 1  # nosec:B602\n"),
    ("python", "x = 1\n", "x = 1  # nosec - validated upstream\n"),
    # sonar-python honours nosec in any case for its security rules.
    ("python", "x = 1\n", "x = 1  # NOSEC\n"),
    ("python", "x = 1\n", "x = 1  # NOSONAR\n"),
    ("python", "x = 1\n", "x = 1  # NOSONAR(S2076)\n"),
    ("python", "x = 1\n", "x = 1  # lgtm[py/command-line-injection]\n"),
    ("python", "x = 1\n", "x = 1  # lgtm\n"),
    ("python", "x = 1\n", "x = 1  # reviewed by the team; lgtm\n"),
    ("python", "x = 1\n", "x = 1  # codeql[py/path-injection]\n"),
    ("python", "x = 1\n", "x = 1  # CodeQL[py/path-injection]\n"),
    # Found by scripts/suppression_oracle.py, checked against bandit 1.9.4: a word glued to
    # the marker names no known test, which bandit reads as a bare marker (skips everything).
    ("python", "x = 1\n", "x = 1  # nosecure transport is handled upstream\n"),
    ("python", "x = 1\n", "x = {}  # nosec_lines is a dict of line number -> set of tests\n"),
    ("python", "x = 1\n", "x = 1  # nosecond\n"),
    # CodeQL's bare annotation after a semicolon, whatever follows the word.
    ("python", "x = 1\n", "x = 1  # reason; lgtm (approved)\n"),
    ("python", "x = 1\n", "x = 1  # reason; lgtm = ok\n"),
    ("python", "x = 1\n", "x = 1  # reason; lgtm. fine\n"),
    # semgrep ignores the case and takes the short form (spelled apart so this file is
    # not itself a suppression).
    ("python", "x = 1\n", f"x = 1  # {_SEM.upper()}GREP\n"),
    ("python", "x = 1\n", f"x = 1  # {_SEM}\n"),
    ("python", "x = 1\n", f"x = 1  # {_SEM}: some.rule-id\n"),
    ("javascript", "a();\n", "a(); // LGTM\n"),
    ("javascript", "a();\n", "a(); /* lgtm[js/xss] */\n"),
])
def test_security_suppression_markers_block_when_gating(language, before, after):
    assert _suppressions(before, after, language=language) == [
        ("suppression_introduced", Severity.HARD_FAIL, 1)]


@pytest.mark.parametrize("after", [
    'x = "# NOSONAR"\n',                    # in a string: Sonar reads comments only
    'x = "# lgtm[py/xss]"\n',
    "x = 1  # nosonar\n",                   # sonar-python's NOSONAR is case-sensitive
    "x = 1  # looks good to me\n",
    "x = lgtm_count + 1\n",
    "x = 1  # this is not a nosec marker\n",
    "x = 1; lgtm = 2\n",                    # code, not a comment
])
def test_not_a_python_suppression(after):
    assert _suppressions("x = 1\n", after) == []


@pytest.mark.parametrize("after", [
    f"x = 1  # {_NOQA.upper()}\n",          # flake8 ignores the case
    f"x = 1  # {_NOQA}foo\n",               # and has no word boundary
    f"x = 1  # {_NOQA}S602\n",
])
def test_flake8_marker_spellings_warn(after):
    assert _suppressions("x = 1\n", after) == [("suppression_added", Severity.WARN, 1)]


@pytest.mark.parametrize("keyword", [
    "usedforsecurity=False", "usedforsecurity = False", "usedforsecurity=(False)",
    "usedforsecurity=0", "usedforsecurity=None", "usedforsecurity=flag",
    "usedforsecurity=\\\n    False", "usedforsecurity=\n    False",
])
def test_usedforsecurity_values_other_than_true_warn(keyword):
    # bandit's weak-hash check only fires when the keyword is the constant True.
    before = "import hashlib\nh = hashlib.md5(p)\n"
    after = f"import hashlib\nh = hashlib.md5(p, {keyword})\n"
    assert _suppressions(before, after) == [("suppression_added", Severity.WARN, 2)]


@pytest.mark.parametrize("keyword", ["usedforsecurity=True", "usedforsecurity = True",
                                     "usedforsecurity=(True)"])
def test_usedforsecurity_true_is_not_a_suppression(keyword):
    before = "import hashlib\nh = hashlib.md5(p)\n"
    after = f"import hashlib\nh = hashlib.md5(p, {keyword})\n"
    assert _suppressions(before, after) == []


def test_marker_hidden_by_the_declared_source_encoding_is_counted():
    # Under a utf-7 declaration the characters +ACM- are a hash sign, so bandit reads a
    # marker comment that this text does not show.
    hash_sign = "+ACM-"
    before = "# coding: utf-7\nx = f(1)\n"
    after = f"# coding: utf-7\nx = f(1)  # note {hash_sign} nosec\n"
    assert _suppressions(before, after) == [("suppression_introduced", Severity.HARD_FAIL, 2)]


def test_a_plain_8_bit_declaration_changes_nothing():
    before = "# -*- coding: latin-1 -*-\nx = f(1)\n"
    after = "# -*- coding: latin-1 -*-\nx = f(1)  # a note\n"
    assert _suppressions(before, after) == []
    assert engine._declared_text(after) is None


# --- a marker moved onto existing code (found by scripts/suppression_oracle.py) -----------------

_SHELL_CALL = "subprocess.call(cmd, shell=True)"
_TWO_SINKS = "import subprocess\n\n\ndef a(cmd):\n    return {a}\n\n\ndef b(cmd):\n    return {b}\n"
_SAME_SCOPE = "import subprocess\n\n\ndef run(cmd):\n    x = {a}\n    x = {b}\n    return x\n"


def test_a_marker_moved_to_another_sink_is_a_new_suppression():
    # The per-kind count is 1 before and after, but sink b was not suppressed before.
    before = _TWO_SINKS.format(a=f"{_SHELL_CALL}  # nosec", b=_SHELL_CALL)
    after = _TWO_SINKS.format(a=_SHELL_CALL, b=f"{_SHELL_CALL}  # nosec")
    assert _suppressions(before, after) == [("suppression_introduced", Severity.HARD_FAIL, 9)]


def test_a_marker_moved_to_an_identical_statement_is_a_new_suppression():
    before = _SAME_SCOPE.format(a=f"{_SHELL_CALL}  # nosec", b=_SHELL_CALL)
    after = _SAME_SCOPE.format(a=_SHELL_CALL, b=f"{_SHELL_CALL}  # nosec")
    assert _suppressions(before, after) == [("suppression_introduced", Severity.HARD_FAIL, 6)]


def test_a_second_marker_is_reported_by_the_count_and_not_a_second_time_as_moved():
    before = _TWO_SINKS.format(a=f"{_SHELL_CALL}  # nosec", b=_SHELL_CALL)
    after = _TWO_SINKS.format(a=f"{_SHELL_CALL}  # nosec", b=f"{_SHELL_CALL}  # nosec")
    found = _suppressions(before, after)
    assert sorted(line for _, _, line in found) == [5, 9]


def test_a_marker_follows_its_statement_through_a_rewrap():
    one = _TWO_SINKS.format(a=f"{_SHELL_CALL}  # nosec", b="0")
    wrapped = _TWO_SINKS.format(a="subprocess.call(\n        cmd,\n        shell=True,\n    )  # nosec",
                                b="0")
    assert _suppressions(one, wrapped) == []


def test_fixing_the_sink_and_keeping_its_marker_is_not_new():
    before = "import ast\n\n\ndef run(x):\n    return eval(x)  # nosec\n"
    after = "import ast\n\n\ndef run(x):\n    return ast.literal_eval(x)  # nosec\n"
    assert _suppressions(before, after) == []


def test_reordering_functions_keeps_each_marker_with_its_code():
    before = _TWO_SINKS.format(a=f"{_SHELL_CALL}  # nosec", b=_SHELL_CALL)
    swapped = ("import subprocess\n\n\ndef b(cmd):\n    return " + _SHELL_CALL
               + "\n\n\ndef a(cmd):\n    return " + _SHELL_CALL + "  # nosec\n")
    assert _suppressions(before, swapped) == []


# --- a marker that silences everything, on a security call ---------------------------------

def _bare(code):
    return f"{code}  # {_NOQA}"


@pytest.mark.parametrize("imports, call", [
    ("import subprocess", "subprocess.call(cmd, shell=True)"),
    ("import subprocess as sp", "sp.run(cmd, check=True)"),
    ("from os import system", "system(cmd)"),
    ("import yaml", "yaml.load(s)"),
    ("import hashlib", "hashlib.md5(p)"),
    ("import pickle", "pickle.loads(blob)"),
    ("from xml.etree import ElementTree as ET", "ET.fromstring(text)"),
    ("import requests", "requests.get(url, verify=False)"),
    ("import random", "random.choice(items)"),
])
def test_bare_noqa_on_a_security_call_blocks_when_gating(imports, call):
    before = f"{imports}\n\n\ndef run(cmd, s, p, blob, text, url, items):\n    return {call}\n"
    after = before.replace(call, _bare(call))
    assert _suppressions(before, after) == [("suppression_introduced", Severity.HARD_FAIL, 5)]


def test_bare_noqa_behind_a_wrapped_security_call_blocks():
    before = "import subprocess\n\n\ndef run(cmd):\n    return subprocess.call(\n        cmd,\n    )\n"
    after = before.replace("    )\n", f"    )  # {_NOQA}\n")
    assert _suppressions(before, after) == [("suppression_introduced", Severity.HARD_FAIL, 7)]


@pytest.mark.parametrize("before, after", [
    ("import os\n", f"import os  # {_NOQA}\n"),                                  # F401 and friends
    ("import json\nx = json.loads(s)\n", f"import json\nx = json.loads(s)  # {_NOQA}\n"),
    ("import subprocess\nsubprocess.call(c)\n",                                 # style code only
     f"import subprocess\nsubprocess.call(c)  # {_NOQA}: E501\n"),
])
def test_style_markers_away_from_security_calls_stay_warnings(before, after):
    assert [(c, s) for c, s, _ in _suppressions(before, after)] == [
        ("suppression_added", Severity.WARN)]


def test_a_security_code_behind_a_long_line_still_blocks():
    # The excerpt of a hit is cut at 120 characters; classifying on it hid this marker.
    rule = "S602"
    before = "import subprocess\nsubprocess.call(c, shell=True)\n"
    after = f"import subprocess\nsubprocess.call(c, shell=True){' ' * 130}# {_NOQA}: {rule}\n"
    assert _suppressions(before, after) == [("suppression_introduced", Severity.HARD_FAIL, 2)]


def test_usedforsecurity_on_password_material_blocks_when_gating():
    before = "import hashlib\n\n\ndef run(password):\n    return hashlib.md5(password)\n"
    after = before.replace("hashlib.md5(password)", "hashlib.md5(password, usedforsecurity=False)")
    assert _suppressions(before, after) == [("suppression_introduced", Severity.HARD_FAIL, 5)]


@pytest.mark.parametrize("tail", [', "x nosemgrep"', ', "x nosem"', f"  # see {_SEM}grep"])
def test_a_semgrep_mention_without_a_hash_sign_counts_on_a_security_call(tail):
    # semgrep 1.181, executed, ignores a finding whose line holds a space and `nosem[grep]`
    # anywhere, a string included.
    before = "import subprocess\n\n\ndef run(cmd):\n    return subprocess.call(cmd, shell=True)\n"
    after = before.replace("shell=True)\n", "shell=True)" + tail + "\n")
    assert _suppressions(before, after) == [("suppression_introduced", Severity.HARD_FAIL, 5)]


def test_a_semgrep_word_in_prose_away_from_a_security_call_is_not_a_suppression():
    before = "x = 1\n"
    after = f'x = 1\ny = "we do not use {_SEM}grep here"\n'
    assert _suppressions(before, after) == []


# --- JavaScript and TypeScript (scripts/suppression_oracle_js.py) --------------------------------

_JS_CALL = 'const child_process = require("child_process");\n\nfunction run(cmd) {\n  return child_process.exec(cmd);\n}\n'


def _js(before, after, language="javascript", strict=False):
    return _suppressions(before, after, language=language, strict=strict)


@pytest.mark.parametrize("marker", [
    "/* eslint-disable-line */", "/* eslint-disable-line security/detect-child-process */",
    "// eslint-disable-line", "// eslint-disable-line -- reason", "//eslint-disable-line",
])
def test_an_eslint_directive_without_a_rule_list_blocks_on_a_risky_line(marker):
    after = _JS_CALL.replace("exec(cmd);", "exec(cmd); " + marker)
    assert _js(_JS_CALL, after) == [("suppression_introduced", Severity.HARD_FAIL, 4)]


@pytest.mark.parametrize("marker", ["// eslint-disable-next-line", "/* eslint-disable-next-line */"])
def test_an_eslint_next_line_directive_blocks_when_the_next_line_is_risky(marker):
    after = _JS_CALL.replace("  return child_process", f"  {marker}\n  return child_process")
    assert _js(_JS_CALL, after) == [("suppression_introduced", Severity.HARD_FAIL, 4)]


@pytest.mark.parametrize("marker", ["/* eslint-disable */", "/*eslint-disable*/"])
def test_a_block_eslint_disable_blocks_when_a_risky_call_follows(marker):
    after = _JS_CALL.replace("function run", f"{marker}\nfunction run")
    assert _js(_JS_CALL, after) == [("suppression_introduced", Severity.HARD_FAIL, 3)]


@pytest.mark.parametrize("before, after", [
    ("const a = 1;\n", "const a = 1; // eslint-disable-line\n"),                 # nothing risky
    (_JS_CALL, _JS_CALL.replace("exec(cmd);", "exec(cmd); // eslint-disable-line no-console")),
    (_JS_CALL, _JS_CALL.replace("function run", "// eslint-disable-next-line\nfunction run")),
])
def test_an_eslint_directive_away_from_a_risky_call_or_for_another_rule_is_a_warning(before, after):
    assert [(c, s) for c, s, _ in _js(before, after)] == [("suppression_added", Severity.WARN)]


@pytest.mark.parametrize("marker, language", [
    ("// @ts-ignore", "typescript"), ("/* @ts-ignore */", "typescript"),
    ("// @ts-expect-error", "typescript"), ("/* @ts-nocheck */", "typescript"),
])
def test_typescript_directives_are_a_warning_not_a_block(marker, language):
    before = "function run(): number {\n  const n: number = 'text';\n  return n;\n}\n"
    after = before.replace("  const n", f"  {marker}\n  const n")
    assert [(c, s) for c, s, _ in _js(before, after, language)] == [("suppression_added", Severity.WARN)]


@pytest.mark.parametrize("marker", ["/* NOSONAR */", "/* lgtm */", f"/* {_SEM}grep */", f"// {_SEM}"])
def test_other_analyser_markers_in_js_block_comments_block(marker):
    after = _JS_CALL.replace("exec(cmd);", "exec(cmd); " + marker)
    assert _js(_JS_CALL, after) == [("suppression_introduced", Severity.HARD_FAIL, 4)]


_JS_TWO = ('const child_process = require("child_process");\n\nfunction a(cmd) {\n  return child_process.exec(cmd);%s\n}\n\n'
           'function b(cmd) {\n  return child_process.exec(cmd);%s\n}\n')


def test_a_js_marker_moved_to_another_sink_is_a_new_suppression():
    before = _JS_TWO % (" // eslint-disable-line", "")
    after = _JS_TWO % ("", " // eslint-disable-line")
    assert _js(before, after) == [("suppression_introduced", Severity.HARD_FAIL, 8)]


def test_a_js_marker_stays_with_its_line_through_a_rewrap_and_a_fix():
    marked = _JS_TWO % (" // eslint-disable-line", "")
    swapped = ('const child_process = require("child_process");\n\nfunction b(cmd) {\n  return child_process.exec(cmd);\n}\n\n'
               'function a(cmd) {\n  return child_process.exec(cmd); // eslint-disable-line\n}\n')
    assert _js(marked, swapped) == []
    fixed = marked.replace("child_process.exec(cmd); // eslint-disable-line", "child_process.execFile(cmd, []); // eslint-disable-line")
    assert _js(marked, fixed) == []


# --- elision markers must not vanish behind string blanking --------------------------------

PAD = 'pad = "' + "a" * 60 + '"\n'


@pytest.mark.parametrize("separator", ["\u2028", "\u2029", "\x0c", "\x85", "\x1c"])
def test_python_line_separator_in_a_comment_does_not_hide_an_elision(separator):
    # splitlines() breaks on these, tokenize does not: rows used to shift by one, so the
    # string on the next line blanked the marker line.
    after = f"x = 1  # note{separator}more\n# ... existing code ...\n" + PAD
    findings = engine.elisions(after, "x = 1\n", strict=False, language="python")
    assert [(f.check, f.severity) for f in findings] == [("elided_output", Severity.HARD_FAIL)]


@pytest.mark.parametrize("code", [
    'def f():\n    """Keeping the rest unchanged."""\n',
    'x = f"{a} rest of the file unchanged {b!r}"\n',
    "x = f\"{f'{a} rest unchanged'}\"\n",
    'x = rb"rest of the code unchanged"\n',
])
def test_python_elision_phrases_in_strings_are_prose(code):
    assert engine.elisions(code, "", strict=False, language="python") == []


@pytest.mark.parametrize("code", [
    "// Don't change this\n// ... existing code ...\nconst x = 'a';\n",
    "const A = () => <p>Don't</p>;\n// ... existing code ...\nconst b = 'x';\n",
    "const r = /don't/g;\n// ... existing code ...\nconst s = 'x';\n",
    "const r = /[`]/;\n// ... existing code ...\nconst t = `x`;\n",
    "const m = `a ${b /* c */} d`;\n// ... existing code ...\n",
    "const u = 'http://x'; // ... existing code ...\n",
])
def test_javascript_elision_marker_after_quote_like_text_is_found(code):
    findings = engine.elisions(code, "", strict=False, language="javascript")
    assert [(f.check, f.line) for f in findings] == [("elided_output", 2 if "\n//" in code else 1)]


@pytest.mark.parametrize("code", [
    "const m = 'rest of the file unchanged';\n",
    'const m = "keep the existing code";\n',
    "const m = `a ${b} rest of the file unchanged ${c}`;\n",
])
def test_javascript_elision_phrases_in_strings_are_prose(code):
    assert engine.elisions(code, "", strict=False, language="javascript") == []


def test_javascript_unclosed_template_after_substitution_is_not_trusted():
    code = "const a = `x ${b} y;\n// ... existing code ...\n"
    assert engine._js_spans(code) is None
    assert engine._blank_strings(code, "javascript") == code
    assert [f.check for f in engine.elisions(code, "", strict=False, language="javascript")] == [
        "elided_output"]


def test_marker_scan_stays_linear_on_a_huge_line():
    # A bundled 4.6 MB base64 line (postject) took 90 s with a comment-opener-then-anything
    # branch in the codeql pattern. Kept small here; quadratic would still take minutes.
    import time
    line = "const wasm = 'data:" + "ab//c" * 60_000 + "';\n"
    start = time.perf_counter()
    engine.introduced_suppressions("", line, strict=False, language="javascript")
    engine.elisions(line, "", strict=False, language="javascript")
    assert time.perf_counter() - start < 5


def test_js_strip_keeps_code_after_a_url_string():
    src = engine._js_strip('const safe = sanitize("http://x"); use(safe);\n')
    assert "use(safe);" in src and "http" not in src


@pytest.mark.parametrize("code", [
    'const safe = sanitize("http://x");\nuse(safe);\n',           # `//` in a string
    "const safe = escapeHtml(s);\nel.textContent = `${safe}`;\n",  # used in a template
    "const safe = escapeHtml(s);\nconst q = '/*';\nrender(safe);\nconst z = '*/';\n",
])
def test_js_guard_that_is_used_is_not_flagged(code):
    assert engine.js_unwired_guards(code) == []


def test_js_guard_that_is_only_mentioned_in_comments_and_strings_is_flagged():
    code = "const safe = sanitize(x); // safe\nconst note = 'safe';\nrender(x);\n"
    assert [f.check for f in engine.js_unwired_guards(code)] == ["js_guard_computed_but_unused"]


# --- found by the adversarial review, 2026-10-13 -------------------------------------------

def _strong_elisions(after, before="", language="python"):
    return [f.check for f in engine.elisions(after, before, strict=False, language=language)
            if f.severity is Severity.HARD_FAIL]


@pytest.mark.skipif(sys.version_info < (3, 12), reason="comments in f-string fields: PEP 701")
def test_comment_inside_an_fstring_replacement_field_is_not_blanked():
    after = 'x = f"""{\n    a  # ... existing code ...\n}"""\n'
    compile(after, "<t>", "exec")
    assert _strong_elisions(after) == ["elided_output"]


def test_lone_cr_line_endings_do_not_hide_an_elision_marker():
    # 3.12+ tokenize reads "\r#" as an operator and the quotes in later comments as strings.
    after = "x = 1\r# don't\ry = 2\r# ... existing code ...\rz = 'a'\r"
    assert _strong_elisions(after) == ["elided_output"]


def test_lone_cr_line_endings_do_not_hide_a_suppression():
    after = "import subprocess\r# it's fine\rsubprocess.call(c, shell=True)  # nosec\rz = 'q'\r"
    assert _suppressions("import subprocess\r", after) == [
        ("suppression_introduced", Severity.HARD_FAIL, 3)]


def test_unscannable_before_does_not_offset_a_new_marker_in_after():
    # Blanking only `after` let the docstring prose in an unblanked `before` count as the
    # existing marker, so a new real one did not grow the count.
    before = '"""Keeps the rest of the file unchanged."""\nx = (\n'
    after = '"""Keeps the rest of the file unchanged."""\nx = 1\n# rest of the file unchanged\n'
    assert engine._python_string_spans(before) is None
    findings = engine.elisions(after, before, strict=False, language="python")
    assert 3 in [f.line for f in findings if f.check == "elided_output"]


def test_python_that_does_not_parse_is_not_blanked():
    assert engine._python_string_spans('def f(:\n    "x"\n') is None
    assert engine._python_comments('def f(:\n    pass  # nosec\n') is None


@pytest.mark.parametrize("code", [
    "const safe = sanitize(name);\nconst el = <label>Name: <em>x</em> {safe}</label>;\n",
    "const safe = clean(f);\nconst p = <code>{dir}/{safe}</code>;\n",
    "const safe = escapeHtml(s);\nconst r = total! / count + safe / 2;\n",
    "const safe = escapeHtml(s);\nconst r = i++ / count + safe / 2;\n",
    "const safeArgs = sanitize(args);\ncall(...safeArgs);\n",
])
def test_js_guard_used_after_slash_lookalikes_or_spread_is_not_flagged(code):
    assert engine.js_unwired_guards(code) == []


def test_js_regex_after_an_arrow_is_still_a_regex():
    code = "const f = s => /x'y/.test(s);\n// ... existing code ...\nconst z = 'q';\n"
    assert _strong_elisions(code, language="javascript") == ["elided_output"]


def test_jsx_text_quotes_do_not_hide_an_elision_comment():
    code = "const A = () => <p>Don`t</p>;\n{/* ... existing code ... */}\nconst b = `x`;\n"
    assert _strong_elisions(code, language="javascript") == ["elided_output"]


def test_async_method_does_not_make_a_bare_call_of_the_same_name_async():
    code = "class A { async filter(x) { return x; } }\nif (filter(body)) { go(); }\n"
    assert engine.js_promise_in_boolean(code) == []


def test_async_method_called_on_this_in_a_boolean_is_flagged():
    code = ("class A {\n  async canEdit(u) { return db.check(u); }\n"
            "  run(u) { if (!this.canEdit(u)) { deny(); } }\n}\n")
    assert [f.check for f in engine.js_promise_in_boolean(code)] == ["js_async_guard_in_boolean"]


def test_js_scan_stays_linear_on_unclosed_regex_candidates():
    import time
    code = "x = [" + "(/[" * 40_000 + "\n"
    start = time.perf_counter()
    engine._js_spans(code)
    assert time.perf_counter() - start < 5


@pytest.mark.parametrize("code", [
    # measured on @hono/node-server and ai: a floated cancel is not an authorisation guard
    "function w(reader) {\n  const cancel = (e) => {\n    reader.cancel(e).catch(() => {});\n  };\n}\n",
    "stream.cancel().catch(() => {});\n",
    "canvas.render(ctx).catch(report);\n",
])
def test_cancel_with_catch_is_not_a_floated_guard(code):
    assert engine.js_floating_guard(code) == []


def test_camel_case_guard_names_still_count():
    assert [f.check for f in engine.js_floating_guard("canWrite(user).catch(log);\n")] == [
        "js_floating_guard_promise"]
    assert [f.check for f in engine.js_unwired_guards("const ok = isValid(x);\nrender(x);\n")] == [
        "js_guard_computed_but_unused"]


@pytest.mark.parametrize("name", ["hash", "cancel", "isolate", "issue", "island", "safely"])
def test_lowercase_word_that_merely_starts_like_a_guard_is_not_one(name):
    code = f"const v = {name}(x);\nrender(x);\n"
    assert engine.js_unwired_guards(code) == []


@pytest.mark.parametrize("language, text", [
    # @types-style JSDoc in tar/dist/*/options.d.ts, measured 2026-10-13
    ("typescript", "/**\n * When extracting, keep the existing file on disk if it's newer than the\n"
                   " * file in the archive.\n */\nnewer?: boolean;\n"),
    ("javascript", "// keep the existing code style when you edit this\nconst a = 1;\n"),
    ("javascript", "// keep the existing function signature, add an options bag\n"),
    ("python", "# keep the existing code path for old clients, with a warning\nx = 1\n"),
    ("python", '"""Keep the existing class hierarchy as it is documented."""\nx = 1\n'),
])
def test_keep_existing_in_prose_is_not_an_elision(language, text):
    assert _strong_elisions(text, language=language) == []


@pytest.mark.parametrize("line", [
    "// keep the existing code",
    "# keep existing implementation here",
    "// ... keep the rest of the code unchanged ...",
    "/* keep the remaining logic */",
    "// keep the existing code below",
    "# (keep the existing code)",
    "// keep existing code as is",
    "// keep the existing body...",
    "<!-- keep the existing file -->",
    "// KEEP THE EXISTING CODE",
])
def test_keep_existing_placeholders_still_block(line):
    findings = engine.elisions(f"x = 1\n{line}\ny = 2\n", "", strict=False, language="javascript")
    hard = [f for f in findings if f.severity is Severity.HARD_FAIL]
    assert hard and all(f.check == "elided_output" and f.line == 2 for f in hard)


def test_gating_a_new_empty_file_is_not_blocked():
    findings = scan_transformation("", "", language="python", expect_change=False)
    assert [f.check for f in findings if f.severity is Severity.HARD_FAIL] == []
    strict = scan_transformation("x = 1\n", "", language="python", expect_change=True)
    assert "empty_output" in [f.check for f in strict]


# ---- sinks written differently from the literal form (finding 20) ------------------------

SHELL_TRUE = "import subprocess\n\ndef run(cmd):\n    return subprocess.call(cmd, shell=True)\n"
VERIFY_OFF = "import requests\n\ndef get(url):\n    return requests.get(url, verify=False)\n"
EVAL = "def calc(e):\n    return eval(e)\n"
SQL_F = "def find(cur, uid):\n    cur.execute(f\"SELECT * FROM u WHERE id = {uid}\")\n"
DEBUG_TRUE = "from app import app\n\napp.run(debug=True)\n"
_DEF_RUN = "import subprocess\n\n"
_SQL = "    sql = f\"SELECT * FROM u WHERE id = {uid}\"\n"

REWRITES = [
    # (label, the sink as it was, the same sink rewritten, the check that must still fire)
    ("shell=1", SHELL_TRUE, SHELL_TRUE.replace("shell=True", "shell=1"), "sink_shell_true"),
    ("shell=bool(1)", SHELL_TRUE, SHELL_TRUE.replace("shell=True", "shell=bool(1)"),
     "sink_shell_true"),
    ("shell=not False", SHELL_TRUE, SHELL_TRUE.replace("shell=True", "shell=not False"),
     "sink_shell_true"),
    ("module constant", SHELL_TRUE,
     _DEF_RUN + "USE_SHELL = True\n\ndef run(cmd):\n    return subprocess.call(cmd, shell=USE_SHELL)\n",
     "sink_shell_true"),
    ("**{'shell': True}", SHELL_TRUE, SHELL_TRUE.replace("shell=True", "**{'shell': True}"),
     "sink_shell_true"),
    ("**dict(shell=True)", SHELL_TRUE, SHELL_TRUE.replace("shell=True", "**dict(shell=True)"),
     "sink_shell_true"),
    ("**OPTS", SHELL_TRUE,
     _DEF_RUN + "OPTS = {'shell': True}\n\ndef run(cmd):\n    return subprocess.call(cmd, **OPTS)\n",
     "sink_shell_true"),
    ("shell=False or 1", SHELL_TRUE, SHELL_TRUE.replace("shell=True", "shell=False or 1"),
     "sink_shell_true"),
    ("**{**base, 'shell': True}", SHELL_TRUE,
     SHELL_TRUE.replace("shell=True", "**{**base, 'shell': True}").replace("(cmd)", "(cmd, base)"),
     "sink_shell_true"),
    ("verify=bool(0)", VERIFY_OFF, VERIFY_OFF.replace("verify=False", "verify=bool(0)"),
     "sink_tls_verify_off"),
    ("session.verify = False", VERIFY_OFF,
     "import requests\n\ndef get(url):\n    s = requests.Session()\n    s.verify = False\n"
     "    return s.get(url)\n", "sink_tls_verify_off"),
    ("_e = eval", EVAL, "_e = eval\n\ndef calc(e):\n    return _e(e)\n", "sink_dynamic_exec"),
    ("alias of an alias", EVAL, "_e = eval\n_f = _e\n\ndef calc(e):\n    return _f(e)\n",
     "sink_dynamic_exec"),
    ("execute(sql, ())", SQL_F, "def find(cur, uid):\n" + _SQL + "    cur.execute(sql, ())\n",
     "sink_sql_nonparameterised"),
    ("execute(sql, None)", SQL_F, "def find(cur, uid):\n" + _SQL + "    cur.execute(sql, None)\n",
     "sink_sql_nonparameterised"),
    ("run = cur.execute", SQL_F,
     "def find(cur, uid):\n    run = cur.execute\n    run(f\"SELECT * FROM u WHERE id = {uid}\")\n",
     "sink_sql_interpolated"),
    ("debug=DEBUG", DEBUG_TRUE, "from app import app\n\nDEBUG = True\napp.run(debug=DEBUG)\n",
     "sink_debug_true"),
    ("**dict(debug=True)", DEBUG_TRUE, DEBUG_TRUE.replace("debug=True", "**dict(debug=True)"),
     "sink_debug_true"),
]
_THREAT = {"sink_shell_true": "injection", "sink_tls_verify_off": "ssrf",
           "sink_debug_true": "untrusted_input",
           "sink_dynamic_exec": "injection", "sink_sql_nonparameterised": "injection",
           "sink_sql_interpolated": "injection"}


def _hard_checks(findings):
    return [f.check for f in findings if f.severity is Severity.HARD_FAIL]


@pytest.mark.parametrize("label, before, after, check", REWRITES, ids=[r[0] for r in REWRITES])
def test_a_rewritten_sink_still_counts(label, before, after, check):
    # Each of these came back `ok` from a claimed fix: the check only knew the literal form.
    claimed = scan_transformation(before, after, language="python",
                                  claimed_threats=[_THREAT[check]])
    assert check in _hard_checks(claimed)
    # And written into a file that did not have it, the change gate blocks it as new.
    gated = scan_transformation("x = 1\n", after, language="python", expect_change=False)
    assert check in _hard_checks(gated)


@pytest.mark.parametrize("code", [
    _DEF_RUN + "def run(cmd, use_shell):\n    return subprocess.call(cmd, shell=use_shell)\n",
    _DEF_RUN + "SHELL = True\nSHELL = False\n\ndef run(cmd):\n    return subprocess.call(cmd, shell=SHELL)\n",
    _DEF_RUN + "def run(cmd):\n    return subprocess.call(cmd, shell=bool(0))\n",
    _DEF_RUN + "def run(cmd):\n    return subprocess.call(cmd, shell=not True)\n",
    _DEF_RUN + "def run(cmd):\n    return subprocess.call(cmd, shell=0)\n",
    _DEF_RUN + "def run(cmd, **opts):\n    return subprocess.call(cmd, **opts)\n",
    _DEF_RUN + "def run(cmd):\n    return subprocess.call(cmd, **{'shell': False})\n",
    _DEF_RUN + "def bool(x):\n    return False\n\ndef run(c):\n    return subprocess.call(c, shell=bool(1))\n",
    "import requests\n\ndef get(url, ca):\n    return requests.get(url, verify=ca)\n",
    "import requests\n\ndef get(url):\n    return requests.get(url, verify='/etc/ca.pem')\n",
    "import requests\n\ndef get(url, ca):\n    s = requests.Session()\n    s.verify = ca\n"
    "    s.verify = True\n    return s.get(url)\n",
    "_e = str\n\ndef calc(e):\n    return _e(e)\n",
    "_e = eval\n_e = str\n\ndef calc(e):\n    return _e(e)\n",
    "def find(cur, uid):\n    cur.execute(\"SELECT * FROM u WHERE id = ?\", (uid,))\n",
    "def find(cur, sql, params):\n    cur.execute(sql, params)\n",
    "QUERY = \"SELECT * FROM u\"\n\ndef every(cur):\n    cur.execute(QUERY)\n",
    "QUERY = \"SELECT * FROM u\"\n\ndef every(cur):\n    cur.execute(QUERY, ())\n",
    "class C:\n    def go(self, m):\n        run = self.execute\n        return run(f\"{m}\")\n",
    # A list, dict or set can change after it is bound: not followed unless only `**`-read.
    "def search(cur, name=None):\n    clauses = []\n    params = []\n    if name:\n"
    "        clauses.append('name = ?')\n        params.append(name)\n"
    "    sql = 'SELECT * FROM t'\n    if clauses:\n"
    "        sql += ' WHERE ' + ' AND '.join(clauses)\n    cur.execute(sql, params)\n",
    _DEF_RUN + "import sys\nKW = {'shell': True}\nif sys.platform != 'win32':\n"
    "    KW['shell'] = False\n\ndef run(cmd):\n    return subprocess.call(cmd, **KW)\n",
    _DEF_RUN + "KW = {'shell': True}\nKW.update(shell=False)\n\n"
    "def run(cmd):\n    return subprocess.call(cmd, **KW)\n",
    _DEF_RUN + "def run(cmd, extra):\n    return subprocess.call(cmd, **{'shell': True, **extra})\n",
    # (`dict(debug=True)` is not itself a `run` call, so only the outer call could count)
    "from app import app\n\ndef dict(**k):\n    return {}\n\napp.run(**dict(debug=True))\n",
    _DEF_RUN + "def run(cmd, flag):\n    return subprocess.call(cmd, shell=flag or False)\n",
    _DEF_RUN + "def run(cmd, flag):\n    return subprocess.call(cmd, shell=flag and True)\n",
])
def test_values_and_names_that_are_not_fixed_stay_unflagged(code):
    assert _hard_checks(scan_transformation("x = 1\n", code, language="python",
                                            expect_change=False)) == []


def test_a_wrapper_hiding_an_aliased_or_empty_parameter_execute_is_a_shared_sink():
    for body in ("    run = cur.execute\n    run(sql)\n", "    cur.execute(sql, ())\n"):
        code = (f"def q(cur, sql):\n{body}\n\ndef find(cur, uid):\n"
                "    q(cur, f\"SELECT * FROM u WHERE id = {uid}\")\n")
        assert "shared_sink_injection_path" in _hard_checks(
            scan_transformation("x = 1\n", code, language="python", expect_change=False))


def test_where_a_bare_flake8_marker_hides_a_report_is_still_the_literal_form():
    # Which lines an analyser reports is decided against the real tools
    # (scripts/suppression_oracle.py); the sink checks reading `shell=1` as true does not
    # change it. A bare marker on a call that is not on the subprocess list stays a style
    # marker unless the call says shell=True literally.
    marker = "  # " + "noqa"
    for value, blocks in (("True", True), ("1", False), ("not False", False)):
        before = f"from tools import invoke\ninvoke(c, shell={value})\n"
        after = before.replace(")\n", ")" + marker + "\n")
        hard = _hard_checks(scan_transformation(before, after, language="python",
                                                expect_change=False))
        assert ("suppression_introduced" in hard) is blocks, value


# ---- language of a script without an extension, from its #! line ------------------------

@pytest.mark.parametrize("first_line, language", [
    ("#!/usr/bin/env python", "python"),
    ("#!/usr/bin/env python3", "python"),
    ("#!/usr/local/bin/python3.12 -u", "python"),
    ("#!/usr/bin/env -S python3 -X utf8", "python"),
    ("#!/usr/bin/env -u PYTHONPATH LANG=C python3", "python"),
    ("#!/usr/bin/pypy3", "python"),
    ("#! /usr/bin/env node", "javascript"),
    ("#!/usr/bin/env nodejs", "javascript"),
    ("#!/usr/bin/env -S deno run --allow-net", "javascript"),
    ("#!/usr/bin/env ts-node", "typescript"),
    ("#!/bin/bash", "shell"),
    ("#!/bin/sh -e", "shell"),
    ("#!/usr/bin/env zsh", "shell"),
    ("#!/usr/bin/env ruby", "ruby"),
    ("#!/usr/bin/php8.2", "php"),
    ("#!/usr/bin/perl", "unknown"),
    ("#!/usr/bin/env", "unknown"),
    ("#!", "unknown"),
    ("# not a shebang", "unknown"),
    ("\ufeff#!/usr/bin/env python", "unknown"),   # the kernel needs #! as the first bytes
    (" #!/usr/bin/env python", "unknown"),
])
def test_language_from_shebang(first_line, language):
    assert engine.language_from_shebang(first_line + "\nrest\n") == language
    assert engine.language_from_shebang((first_line + "\r\nrest\n").encode()) == language


def test_language_for_file_prefers_the_extension_then_the_new_shebang():
    py, sh = "#!/usr/bin/env python3\n", "#!/bin/sh\n"
    assert engine.language_for_file("tool.sh", py) == "shell"
    assert engine.language_for_file("bin/deploy", py, sh) == "python"
    assert engine.language_for_file("bin/deploy", "x\n", sh) == "shell"
    assert engine.language_for_file("bin/deploy", "x\n", "") == "unknown"
    assert engine.language_for_file("deploy.cgi", py) == "python"
    assert engine.language_for_file("deploy", None, 42, b"#!/bin/sh\x00") == "shell"


# ---- code that nests too deeply to parse or analyse (finding 8) --------------------------

# 40,004 characters: under the hosted API's 60,000, and too deep for ast.parse on 3.11-3.13.
DEEP = "x = " + "+".join(["1"] * 20_000) + "\n"
# Parses everywhere, but ast.dump (the comment-only check) recurses out at the default limit.
MID = "x = " + "+".join(["1"] * 1_500) + "\n"
SHELL = "import subprocess\nsubprocess.run(cmd, shell=True)\n"


def _only_too_deep(findings):
    return ([(f.check, f.severity) for f in findings] == [("parse_failure", Severity.HARD_FAIL)]
            and "nests too deeply" in findings[0].detail)


@pytest.mark.parametrize("exc", [RecursionError, MemoryError])
@pytest.mark.parametrize("expect_change", [True, False])
def test_parser_giving_up_is_a_parse_failure_not_an_exception(engine_ast_raises, exc,
                                                              expect_change):
    engine_ast_raises("parse", exc)
    for before, after in (("x = 1\n", SHELL), (SHELL, "x = 1\n"), ("", SHELL)):
        assert _only_too_deep(scan_transformation(before, after, language="python",
                                                  expect_change=expect_change,
                                                  claimed_threats=["injection"]))


def test_a_check_giving_up_after_parsing_is_a_parse_failure(engine_ast_raises):
    # Between about 1,000 and 3,000 terms (3.11, default limit) the code parses, but
    # ast.dump in the comment-only check recursed out and the exception escaped.
    engine_ast_raises("dump", RecursionError)
    assert _only_too_deep(scan_transformation(SHELL, SHELL + "y = 2\n", language="python"))


def test_too_deep_api_diff_and_ledger(engine_ast_raises):
    engine_ast_raises("parse", RecursionError)
    diff = engine.diff_python_surface("def f():\n    pass\n", "def f(a):\n    pass\n")
    assert not diff.parsed and diff.too_deep and "nests too deeply" in diff.parse_error
    assert engine.python_surface("def f():\n    pass\n") is None
    ledger = engine.assemble_ledger("x = 1\n", SHELL, "python", engine.Tier.AST_VERIFIED,
                                    engine.Contract(), [], [], run_tools=False)
    hard = [f for f in ledger.findings if f.severity is Severity.HARD_FAIL]
    assert [f.check for f in hard] == ["parse_failure"] and "nests too deeply" in hard[0].detail


def _raises(fn, *args):
    try:
        fn(*args)
    except RecursionError:
        return True
    return False


def test_real_deep_expression_does_not_escape_as_an_exception():
    import ast

    too_deep_here = _raises(ast.parse, DEEP)
    for before, after, change in (("x = 1\n", DEEP, True), ("", DEEP, False),
                                  (DEEP, DEEP + "y = 2\n", False)):
        findings = scan_transformation(before, after, language="python", expect_change=change)
        if too_deep_here:
            assert _only_too_deep(findings)
    ledger = engine.assemble_ledger("x = 1\n", DEEP, "python", engine.Tier.AST_VERIFIED,
                                    engine.Contract(), [], [], run_tools=False)
    if too_deep_here:
        assert [f.check for f in ledger.findings if f.severity is Severity.HARD_FAIL] == [
            "parse_failure"]


def test_real_expression_that_parses_but_is_too_deep_to_compare():
    import ast

    if not _raises(lambda: ast.dump(ast.parse(MID))):
        pytest.skip("ast.dump handles this depth here")
    assert _only_too_deep(scan_transformation("x = 1\n", MID, language="python"))
    # Change gating does not compare syntax trees, so the same file passes there.
    assert [f.check for f in scan_transformation("x = 1\n", MID, language="python",
                                                 expect_change=False)
            if f.severity is Severity.HARD_FAIL] == []
