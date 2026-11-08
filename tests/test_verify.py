import pytest

from saikou.engine import Severity
from saikou.verify import is_test_path, verify_pair

SECRET = 'TOKEN = "t0ken-for-tests"\n'      # tests/test_api.py, 2026-10-12


@pytest.mark.parametrize("path", [
    "tests/test_api.py", "tests/helpers.py", "pkg/tests/data/keys.py", "test/x.py",
    "testing/fixtures.py", "Tests\\test_x.py", "src/test_util.py", "src/util_test.py",
    "conftest.py", "app/tests.py",
])
def test_test_paths(path):
    assert is_test_path(path)


@pytest.mark.parametrize("path", [
    "saikou/api.py", "src/latest.py", "src/contest.py", "attestation/keys.py", "tests",
    "src/testing_tools.py", "protests/x.py", "",
    # absolute or climbing paths: the "test" folder is outside the repository
    "/home/runner/work/test/test/app/settings.py", "C:\\test\\app\\settings.py",
    "tests/../app/settings.py", "../tests/x.py", "..test_x.py/app.py",
])
def test_not_test_paths(path):
    assert not is_test_path(path)


def _secret_findings(path, *, expect_change):
    report = verify_pair("import os\n", "import os\n" + SECRET, path=path,
                         expect_change=expect_change)
    return [(f.severity, f.detail) for f in report.findings
            if f.check == "hardcoded_secret_material"]


def test_literal_secret_in_a_test_file_warns_when_gating():
    [(severity, detail)] = _secret_findings("tests/test_api.py", expect_change=False)
    assert severity is Severity.WARN
    assert detail.startswith("In a test file") and "rotate" in detail


def test_literal_secret_outside_tests_still_blocks_when_gating():
    [(severity, _)] = _secret_findings("saikou/api.py", expect_change=False)
    assert severity is Severity.HARD_FAIL


def test_literal_secret_in_a_test_file_still_blocks_a_claimed_fix():
    [(severity, _)] = _secret_findings("tests/test_api.py", expect_change=True)
    assert severity is Severity.HARD_FAIL


@pytest.mark.parametrize("value", [
    "AKIA" + "Q3EXAMPLE7ABCDEF",
    "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8",
    "sk_live_" + "9f3a2b7c1d8e4f60aa",
    "xoxb-" + "1234567890-abcdefghij",
    "-----BEGIN RSA " + "PRIVATE KEY-----\\nMIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu",
])
def test_recognisable_provider_keys_still_block_in_test_files(value):
    report = verify_pair("import os\n", f'import os\nAPI_KEY = "{value}"\n',
                         path="tests/test_api.py", expect_change=False)
    assert "hardcoded_secret_material" in {f.check for f in report.hard_fails}


def test_only_the_secret_check_is_demoted_in_test_files():
    report = verify_pair("import subprocess\n",
                         "import subprocess\nsubprocess.run(c, shell=True)\n" + SECRET,
                         path="tests/test_x.py", expect_change=False)
    hard = {f.check for f in report.hard_fails}
    assert "sink_shell_true" in hard and "hardcoded_secret_material" not in hard
