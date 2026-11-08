from saikou.engine import Severity
from saikou.verify import config_weakening, is_analyser_config


def _sev(path, before, after):
    report = config_weakening(path, before, after, "modified")
    return sorted({f.severity.value for f in report.findings})


def test_recognises_config_files():
    assert is_analyser_config("pyproject.toml")
    assert is_analyser_config("sub/dir/.eslintrc.json")
    assert is_analyser_config(".semgrepignore")
    assert not is_analyser_config("src/app.py")


def test_bandit_skip_added_blocks():
    before = "[tool.bandit]\nexclude_dirs = []\n"
    after = before + 'skips = ["B602"]\n'
    assert _sev("pyproject.toml", before, after) == ["hard_fail"]


def test_ruff_security_ignore_blocks_but_style_ignore_warns():
    base = "[tool.ruff.lint]\nselect = [\"E\", \"F\", \"S\"]\n"
    assert _sev("pyproject.toml", base, base + 'ignore = ["S602"]\n') == ["hard_fail"]
    assert _sev("pyproject.toml", base, base + 'ignore = ["E501"]\n') == ["warn"]


def test_assert_rule_in_tests_only_warns():
    base = "[tool.ruff.lint.per-file-ignores]\n"
    assert _sev("pyproject.toml", base, base + '"tests/*" = ["S101"]\n') == ["warn"]


def test_semgrepignore_entry_blocks():
    assert _sev(".semgrepignore", "", "src/payments/\n") == ["hard_fail"]


def test_unrelated_pyproject_change_is_quiet():
    before = "[project]\nname = \"x\"\nversion = \"1.0\"\n"
    after = before.replace("1.0", "1.1")
    assert _sev("pyproject.toml", before, after) == []


def test_eslint_security_rule_off_blocks():
    before = '{ "rules": {} }\n'
    after = '{ "rules": {\n  "security/detect-object-injection": "off"\n} }\n'
    assert _sev(".eslintrc.json", before, after) == ["hard_fail"]


def test_comments_are_ignored():
    before = "[tool.bandit]\n"
    assert _sev("pyproject.toml", before, before + "# we might skip B101 later\n") == []
    assert Severity.HARD_FAIL.value == "hard_fail"
