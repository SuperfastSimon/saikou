"""Regression tests for the 1.2.2 audit fixes (4 high + 4 medium)."""

from saikou import catalog, sarif, service
from saikou.engine import (
    Finding,
    Severity,
    Tier,
    danger_sinks,
    introduced_suppressions,
    shared_sink_paths,
    unwired_guards,
)
from saikou.verify import FileReport, config_weakening, provenance_of

# assembled, not literal: flake8 and Saikou read the marker on the raw line, even inside a string
_NOQA = "no" + "qa"


def test_gating_style_suppression_does_not_escalate_preexisting_security_suppression():
    before = (
        "import subprocess\n"
        "subprocess.run(cmd, shell=True)  # " + _NOQA + ": S602\n"
        "x = 1\n"
    )
    after = (
        "import subprocess\n"
        "subprocess.run(cmd, shell=True)  # " + _NOQA + ": S602\n"
        "x = 1  # " + _NOQA + ": E501\n"
    )
    findings = introduced_suppressions(before, after, strict=False, language="python")
    assert all(f.severity is not Severity.HARD_FAIL for f in findings), findings
    assert [f.check for f in findings] == ["suppression_added"]
    assert findings[0].line == 3


def test_gating_new_security_suppression_still_blocks_when_style_preexists():
    before = (
        "import subprocess\n"
        "x = 1  # " + _NOQA + ": E501\n"
        "subprocess.run(cmd, shell=True)\n"
    )
    after = (
        "import subprocess\n"
        "x = 1  # " + _NOQA + ": E501\n"
        "subprocess.run(cmd, shell=True)  # " + _NOQA + ": S602\n"
    )
    findings = introduced_suppressions(before, after, strict=False, language="python")
    assert any(f.check == "suppression_introduced" and f.severity is Severity.HARD_FAIL
               and f.line == 3 for f in findings), findings


def test_eslint_numeric_option_with_zero_is_not_treated_as_off():
    before = "module.exports = { rules: {} };\n"
    after = (
        'module.exports = { rules: { '
        '"security/detect-object-injection": ["error", { max: 10 }] '
        "} };\n"
    )
    report = config_weakening("eslint.config.js", before, after, "modified")
    assert not report.blocked, report.findings


def test_eslint_security_rule_disabled_with_zero_or_off_still_blocks():
    before = "{ \"rules\": {} }\n"
    for value in ('"off"', "0", '["off"]', "[0]"):
        after = f'{{ "rules": {{ "security/detect-object-injection": {value} }} }}\n'
        report = config_weakening(".eslintrc.json", before, after, "modified")
        assert report.blocked, f"Expected block for {value}"


def test_annassign_hardcoded_secret_detected():
    code = 'API_SECRET_KEY: str = "sk-live-supersecretvalue123456"\n'
    findings = danger_sinks(code)
    assert any(f.check == "hardcoded_secret_material" for f in findings), findings


def test_annassign_unwired_guard_detected():
    code = (
        "def read_file(p: str):\n"
        "    safe: str = sanitize(p)\n"
        "    return open(p)\n"
    )
    findings = unwired_guards(code)
    assert any(f.check == "guard_computed_but_unused" for f in findings), findings


def test_annassign_without_value_is_ignored():
    code = "API_SECRET_KEY: str\n"
    assert danger_sinks(code) == []


def test_shared_sink_paths_detects_keyword_arguments():
    code = (
        "def run_query(sql):\n"
        "    cur.execute(sql)\n\n"
        "def lookup(name):\n"
        '    run_query(sql=f"SELECT * FROM users WHERE name = \'{name}\'")\n'
    )
    findings = shared_sink_paths(code)
    assert any(f.check == "shared_sink_injection_path" for f in findings), findings


def test_shared_sink_paths_detects_method_wrappers():
    code = (
        "class Repo:\n"
        "    def run(self, sql):\n"
        "        self.cur.execute(sql)\n"
        "    def lookup(self, name):\n"
        '        self.run(f"SELECT * FROM users WHERE name = \'{name}\'")\n'
    )
    findings = shared_sink_paths(code)
    assert any(f.check == "shared_sink_injection_path" for f in findings), findings


def test_shared_sink_paths_detects_annassign_hop():
    code = (
        "def run_query(sql):\n"
        "    cur.execute(sql)\n\n"
        "def lookup(name):\n"
        '    q: str = f"SELECT * FROM users WHERE name = \'{name}\'"\n'
        "    run_query(q)\n"
    )
    findings = shared_sink_paths(code)
    assert any(f.check == "shared_sink_injection_path" for f in findings), findings


def test_config_weakening_honours_warn_only():
    before = "[tool.bandit]\n"
    after = '[tool.bandit]\nskips = ["B602"]\n'
    report = config_weakening("pyproject.toml", before, after, "modified",
                              warn_only=["analyser_config_weakened"])
    assert not report.blocked
    assert report.warnings and report.warnings[0].check == "analyser_config_weakened"

    out = service.verify({
        "mode": "gate",
        "path": "pyproject.toml",
        "before": before,
        "after": after,
        "warn_only": ["analyser_config_weakened"],
    })
    assert out["blocked"] is False


def test_new_findings_provenance_is_tool():
    assert provenance_of("new_findings") == "tool"
    assert catalog.BY_ID["new_findings"]["provenance"] == "tool"


def test_sarif_descriptions_cover_all_catalog_checks():
    for entry in catalog.CHECKS:
        cid = entry["id"]
        rep = FileReport("a.py", "python", Tier.AST_VERIFIED, "verify",
                         [Finding(cid, Severity.HARD_FAIL, "detail", 1)])
        doc = sarif.to_sarif([rep])
        desc = doc["runs"][0]["tool"]["driver"]["rules"][0]["shortDescription"]["text"]
        assert desc != cid.replace("_", " "), f"SARIF fell back to raw id for {cid}"



def test_windows_path_entries_lose_their_quotes():
    from saikou.engine import _path_folders

    assert _path_folders('"C:\\Program Files\\Git\\cmd";C:\\bin', windows=True) == [
        "C:\\Program Files\\Git\\cmd", "C:\\bin"]
    assert _path_folders('/usr/bin:"/odd"', windows=False) == ["/usr/bin", '"/odd"']
