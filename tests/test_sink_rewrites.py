"""Sink checks against rewritten fake fixes: the attack round on 1.2.1.

Every fake fix below came back ok in 1.2.1 with a claimed fix. A fix that is claimed for a
threat class must now be verifiable: a value at a sink that Saikou cannot establish blocks
then (fail closed). Without a claim, change gating blocks what it can fold and warns about
what it cannot. The false positives 1.2.1 introduced stay unflagged.
"""
import pytest

from saikou import service

H = "import subprocess\n\n"
SHELL = H + "def run(cmd):\n    return subprocess.call(cmd, shell=True)\n"
VER = "import requests\n\ndef get(url):\n    return requests.get(url, verify=False)\n"
EVAL = "def calc(e):\n    return eval(e)\n"
SQL = "def find(cur, uid):\n    cur.execute(f\"SELECT * FROM u WHERE id = {uid}\")\n"
RQ = "import requests\n\ndef get(url):\n    s = requests.Session()\n"
FM = "def find(cur, uid):\n    sql = 'SELECT * FROM u WHERE id = {}'.format(uid)\n"


def sh(expr, pre="", inner=""):
    return H + pre + "def run(cmd):\n" + inner + "    return subprocess.call(cmd, " + expr + ")\n"


def hard(out):
    return [f["check"] for f in out["files"][0]["findings"] if f["severity"] == "hard_fail"]


def _findings(out):
    return out["files"][0]["findings"]


def assert_fake_fix_blocked(before, after, threat):
    compile(after, "after.py", "exec")      # the fake fix is valid Python
    claimed = service.verify({"path": "m.py", "before": before, "after": after,
                              "claimed_threats": [threat]})
    gated = service.verify({"mode": "gate", "path": "m.py", "before": "x = 1\n", "after": after})
    assert claimed["blocked"], f"claimed fix came back ok: hard={hard(claimed)}"
    # Without a claim, a value Saikou can fold blocks; one it cannot establish is a warning.
    sinks = [f for f in _findings(gated) if f["check"].startswith("sink_")]
    assert gated["blocked"] or sinks, f"new sink passed the change gate silently: {_findings(gated)}"


def cases(d):
    return pytest.mark.parametrize("after", list(d.values()), ids=list(d.keys()))


# ---- 1. fold depth: the documented forms (not / bool / names bound once), 14 levels ---------
DEPTH = {
    "not x14": sh("shell=" + "not " * 14 + "True"),
    "bool x14": sh("shell=" + "bool(" * 14 + "1" + ")" * 14),
    "or nested x14": sh("shell=" + "(0 or " * 14 + "True" + ")" * 14),
    "alias chain x14": sh("shell=S14", "S0 = True\n" + "".join(f"S{i+1} = S{i}\n" for i in range(14))),
}


@cases(DEPTH)
def test_documented_forms_nested_14_deep_still_count(after):
    assert_fake_fix_blocked(SHELL, after, "injection")


def test_eval_alias_chain_14_long_still_counts():
    after = "e0 = eval\n" + "".join(f"e{i+1} = e{i}\n" for i in range(14)) + "\ndef calc(e):\n    return e14(e)\n"
    assert_fake_fix_blocked(EVAL, after, "injection")


def test_verify_not_x14_still_counts():
    assert_fake_fix_blocked(VER, VER.replace("verify=False", "verify=" + "not " * 13 + "True"), "ssrf")


# ---- 2. values the file fixes, written as another constant expression ----------------------
CONST_EXPR = {
    "1 == 1": sh("shell=1 == 1"),
    "True if cmd else True": sh("shell=True if cmd else True"),
    "int(1)": sh("shell=int(1)"),
    "-1": sh("shell=-1"),
    "[True][0]": sh("shell=[True][0]"),
    "walrus": sh("shell=(s := True)"),
    "True | False": sh("shell=True | False"),
    "len('a')": sh("shell=len('a')"),
    "f-string": sh("shell=f'x'"),
}


@cases(CONST_EXPR)
def test_constant_expression_for_shell_still_counts(after):
    assert_fake_fix_blocked(SHELL, after, "injection")


# ---- 3. a name the file fixes, but not by exactly one `name = value` -----------------------
NAMES = {
    "bound twice, both true": sh("shell=S", "S = True\nS = 1\n"),
    "S = T = True": sh("shell=S", "S = T = True\n"),
    "S, T = True, 1": sh("shell=S", "S, T = True, 1\n"),
    "default argument": H + "def run(cmd, s=True):\n    return subprocess.call(cmd, shell=s)\n",
    "class attribute": H + "class C:\n    S = True\n\ndef run(cmd):\n    return subprocess.call(cmd, shell=C.S)\n",
    "for S in (True,)": sh("shell=S", "for S in (True,):\n    pass\n"),
    "if/else both true": sh("shell=S", "import sys\nif sys.argv:\n    S = True\nelse:\n    S = 1\n"),
    "shadowed bool()": sh("shell=bool(0)", "def bool(x):\n    return True\n"),
}


@cases(NAMES)
def test_name_fixed_by_the_file_still_counts(after):
    assert_fake_fix_blocked(SHELL, after, "injection")


# ---- 4. shell=True through a mapping -------------------------------------------------------
KWARGS = {
    "**dict({'shell': True})": sh("**dict({'shell': True})"),
    "**{**{'shell': True}}": sh("**{**{'shell': True}}"),
    "**{'shell': True, **{}}": sh("**{'shell': True, **{}}"),
    "kw = {}; kw['shell'] = True": sh("**kw", inner="    kw = {}\n    kw['shell'] = True\n"),
    "B = A": sh("**B", "A = {'shell': True}\nB = A\n"),
    "{'sh' + 'ell': True}": sh("**{'sh' + 'ell': True}"),
    "{K: True}": sh("**{K: True}", "K = 'shell'\n"),
    "dict([('shell', True)])": sh("**dict([('shell', True)])"),
}


@cases(KWARGS)
def test_shell_true_through_a_mapping_still_counts(after):
    assert_fake_fix_blocked(SHELL, after, "injection")


# ---- 5. TLS verification switched off on the session, not by `s.verify = False` ------------
VERIFY = {
    "setattr": RQ + "    setattr(s, 'verify', False)\n    return s.get(url)\n",
    "s.verify &= False": RQ + "    s.verify &= False\n    return s.get(url)\n",
    "s.verify, x = False, 1": RQ + "    s.verify, x = False, 1\n    return s.get(url)\n",
    "vars(s)['verify']": RQ + "    vars(s)['verify'] = False\n    return s.get(url)\n",
    "Session subclass": "import requests\n\nclass S(requests.Session):\n    verify = False\n\ndef get(url):\n    return S().get(url)\n",
    "verify=1 == 2": VER.replace("verify=False", "verify=1 == 2"),
    "verify=(v := False)": VER.replace("verify=False", "verify=(v := False)"),
    "V bound twice": "import requests\nV = False\nV = 0\n\ndef get(url):\n    return requests.get(url, verify=V)\n",
    "default argument": "import requests\n\ndef get(url, v=False):\n    return requests.get(url, verify=v)\n",
}


@cases(VERIFY)
def test_tls_verification_off_rewritten_still_counts(after):
    assert_fake_fix_blocked(VER, after, "ssrf")


# ---- 6. eval under another name ------------------------------------------------------------
EVALS = {
    "from builtins import eval as ev": "from builtins import eval as ev\n\ndef calc(e):\n    return ev(e)\n",
    "__builtins__['eval']": "def calc(e):\n    return __builtins__['eval'](e)\n",
    "getattr(builtins, 'eval')": "import builtins\n\ndef calc(e):\n    return getattr(builtins, 'eval')(e)\n",
    "_e = eval twice": "_e = eval\n_e = eval\n\ndef calc(e):\n    return _e(e)\n",
    "default argument": "def calc(e, _f=eval):\n    return _f(e)\n",
    "walrus": "def calc(e):\n    return (f := eval)(e)\n",
    "(eval,)[0]": "_t = (eval,)\n\ndef calc(e):\n    return _t[0](e)\n",
    "map(eval, [e])": "def calc(e):\n    return list(map(eval, [e]))[0]\n",
    "(eval if e else eval)": "def calc(e):\n    return (eval if e else eval)(e)\n",
}


@cases(EVALS)
def test_eval_under_another_name_still_counts(after):
    assert_fake_fix_blocked(EVAL, after, "injection")


# ---- 7. SQL: an empty parameter argument that is not literally () [] {} None ---------------
SQLS = {
    "tuple()": FM + "    cur.execute(sql, tuple())\n",
    "dict()": FM + "    cur.execute(sql, dict())\n",
    "list()": FM + "    cur.execute(sql, list())\n",
    "*()": FM + "    cur.execute(sql, *())\n",
    "(*(),)": FM + "    cur.execute(sql, (*(),))\n",
    "p = []": FM + "    p = []\n    cur.execute(sql, p)\n",
    "p = () twice": FM + "    p = ()\n    p = ()\n    cur.execute(sql, p)\n",
    "() if uid else ()": FM + "    cur.execute(sql, () if uid else ())\n",
    "unused named parameter": FM + "    cur.execute(sql, {'_': 0})\n",
    "getattr(cur, 'execute')": "def find(cur, uid):\n    getattr(cur, 'execute')(f'SELECT * FROM u WHERE id = {uid}')\n",
    "(cur.execute,)[0]": "def find(cur, uid):\n    t = (cur.execute,)\n    t[0](f'SELECT * FROM u WHERE id = {uid}')\n",
    "run = cur.execute twice": "def find(cur, uid):\n    run = cur.execute\n    run = cur.execute\n    run(f'SELECT * FROM u WHERE id = {uid}')\n",
    "c = cur": "def find(cur, uid):\n    c = cur\n    c.execute(f'SELECT * FROM u WHERE id = {uid}')\n",
}


@cases(SQLS)
def test_sql_without_real_parameters_still_counts(after):
    assert_fake_fix_blocked(SQL, after, "injection")


# ---- 8. regression against 1.2.0: a "constant" query name that is rebound ------------------
def test_query_name_rebound_through_globals_is_not_a_constant():
    # 1.2.0 blocked this (execute() of a name, no parameters). 1.2.1 reads SQLQ as a constant.
    after = ("SQLQ = 'SELECT 1'\n\ndef find(cur, uid):\n"
             "    globals().update(SQLQ=f'SELECT * FROM u WHERE id = {uid}')\n    cur.execute(SQLQ)\n")
    assert_fake_fix_blocked(SQL, after, "injection")


# ---- 9. false positives new in 1.2.1 -------------------------------------------------------
BASE = "import logging\n\nlog = logging.getLogger(__name__)\n"
LEGIT_VERIFY = {
    "self.verify = None in __init__": "class Client:\n    def __init__(self, token):\n        self.token = token\n        self.verify = None\n",
    "e-mail not verified yet": "class Signup:\n    def __init__(self, email):\n        self.email = email\n        self.verify = False\n",
    "user.verify = False": "def reset(user):\n    user.verify = False\n    user.save()\n",
    "args.verify = 0": "def defaults(args):\n    args.verify = 0\n    return args\n",
}
LEGIT_SQL = {
    "class constant, ()": "class Repo:\n    SQL = 'SELECT * FROM u'\n\n    def every(self, cur):\n        cur.execute(self.SQL, ())\n",
    "module constant, ()": "import queries\n\ndef every(cur):\n    cur.execute(queries.ALL_USERS, ())\n",
    "sqlalchemy text(), {}": "from sqlalchemy import text\n\ndef every(conn):\n    conn.execute(text('SELECT 1'), {})\n",
    "sqlalchemy statement, {}": "def every(session, stmt):\n    return session.execute(stmt, {})\n",
    "constant concatenation, []": "T = 'users'\nQ = 'SELECT * FROM ' + T\n\ndef every(cur):\n    cur.execute(Q, [])\n",
}
LEGIT_CONST = {
    "sql in two functions": "def a(cur):\n    sql = 'SELECT 1'\n    cur.execute(sql)\n\ndef b(cur):\n    sql = 'SELECT 2'\n    cur.execute(sql)\n",
    "sql in if/else": "def every(cur, asc):\n    if asc:\n        sql = 'SELECT a FROM u ORDER BY a'\n    else:\n        sql = 'SELECT a FROM u ORDER BY a DESC'\n    cur.execute(sql)\n",
}
LEGIT_ALIAS = {
    "ev = model.eval": "def calc(model, batch):\n    ev = model.eval\n    return ev(batch)\n",
    "exec_ = runner.exec": "def start(runner, cmd):\n    exec_ = runner.exec\n    return exec_(cmd)\n",
}


def assert_legit_passes(code):
    out = service.verify({"mode": "gate", "path": "m.py", "before": BASE, "after": BASE + code})
    assert not out["blocked"], f"legitimate change blocked: hard={hard(out)}"


@cases(LEGIT_VERIFY)
def test_an_attribute_named_verify_is_not_tls(after):
    assert_legit_passes(after)          # passed in 1.2.0


@cases(LEGIT_SQL)
def test_a_fixed_query_with_empty_parameters_is_not_injection(after):
    assert_legit_passes(after)          # passed in 1.2.0


@cases(LEGIT_CONST)
def test_local_constant_sql_is_not_reported(after):
    # CHANGELOG 1.2.1: "A local constant SQL string passed to execute() is no longer reported."
    assert_legit_passes(after)


@cases(LEGIT_ALIAS)
def test_alias_of_a_method_named_eval_or_exec(after):
    assert_legit_passes(after)          # passed in 1.2.0


