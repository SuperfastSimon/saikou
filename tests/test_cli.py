import json
import shutil
import subprocess
from pathlib import Path

import pytest

from saikou.cli import EXIT_BLOCKED, EXIT_ERROR, EXIT_OK, main

DEMO = Path(__file__).parent / "fixtures" / "demo"
CLAIMS = "injection,crypto,path_traversal"


def _verify(after: str, *extra: str) -> int:
    return main(["verify", str(DEMO / "before.py"), str(DEMO / after),
                 "--claimed-threats", CLAIMS, *extra])


def test_fake_fix_blocked(capsys):
    assert _verify("after_A_fake.py") == EXIT_BLOCKED
    out = capsys.readouterr().out
    assert "suppression_introduced" in out and "sink_shell_true" in out


def test_partial_fix_blocked(capsys):
    assert _verify("after_B_partial.py") == EXIT_BLOCKED
    out = capsys.readouterr().out
    assert "guard_computed_but_unused" in out and "shared_sink_injection_path" in out


def test_real_fix_passes():
    assert _verify("after_C_real.py") == EXIT_OK


def test_json_output_shape(capsys):
    _verify("after_A_fake.py", "--format", "json")
    data = json.loads(capsys.readouterr().out)
    assert data["blocked"] is True
    (file_report,) = data["files"]
    assert file_report["verification_tier"] == "ast_verified"
    assert {f["provenance"] for f in file_report["findings"]} <= {"tool", "parser", "mechanical"}
    assert "score" not in json.dumps(data).lower().replace("no score", "")


def test_sarif_output_shape(capsys, tmp_path):
    sarif_path = tmp_path / "out.sarif"
    _verify("after_B_partial.py", "--format", "sarif", "--sarif-file", str(sarif_path))
    data = json.loads(capsys.readouterr().out)
    assert data["version"] == "2.1.0"
    results = data["runs"][0]["results"]
    assert results and all(r["level"] in ("error", "warning") for r in results)
    assert all(r["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1
               for r in results)
    assert json.loads(sarif_path.read_text(encoding="utf-8")) == data


def test_markdown_summary(tmp_path):
    summary = tmp_path / "summary.md"
    _verify("after_A_fake.py", "--summary", str(summary))
    text = summary.read_text(encoding="utf-8")
    assert text.startswith("### Saikou: 1 file(s) blocked") and "| **hard fail** |" in text


def test_unknown_threat_is_usage_error():
    assert _verify("after_C_real.py", "--claimed-threats", "zzz") == EXIT_ERROR


def test_warn_only_demotes(capsys):
    code = _verify("after_B_partial.py", "--warn-only",
                   "sink_sql_nonparameterised,shared_sink_injection_path,guard_computed_but_unused")
    assert code == EXIT_OK
    assert "demoted by --warn-only" in capsys.readouterr().out


def test_unparseable_python_output_blocked(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n")
    (tmp_path / "b.py").write_text("def f(:\n")
    assert main(["verify", str(tmp_path / "a.py"), str(tmp_path / "b.py")]) == EXIT_BLOCKED


# ---------------------------------------------------------------------------
# git diff mode
# ---------------------------------------------------------------------------

needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)


@pytest.fixture
def repo(tmp_path, monkeypatch):
    _git(tmp_path, "init", "-q", "-b", "main")
    _git(tmp_path, "config", "user.email", "test@example.invalid")
    _git(tmp_path, "config", "user.name", "test")
    _git(tmp_path, "config", "commit.gpgsign", "false")
    (tmp_path / "app.py").write_text(
        "import subprocess\n\ndef run(cmd):\n    return subprocess.call(cmd, shell=True)\n")
    (tmp_path / "README.md").write_text("Details omitted for brevity.\n")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-q", "-m", "base")
    monkeypatch.chdir(tmp_path)
    return tmp_path


@needs_git
def test_diff_blocks_suppression_laundering(repo, capsys):
    (repo / "app.py").write_text(
        "import subprocess\n\ndef run(cmd):\n"
        "    return subprocess.call(cmd, shell=True)  # nosec - reviewed\n")
    assert main(["diff", "--base", "HEAD"]) == EXIT_BLOCKED
    assert "suppression_introduced" in capsys.readouterr().out


@needs_git
def test_diff_allows_unrelated_change_and_skips_docs(repo, capsys):
    (repo / "app.py").write_text(
        "import subprocess\n\ndef run(cmd):\n    return subprocess.call(cmd, shell=True)\n\n"
        "def version():\n    return '1.0'\n")
    (repo / "README.md").write_text("Details omitted for brevity. Now with more docs.\n")
    assert main(["diff", "--base", "HEAD"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "Pre-existing" in out          # the old shell=True is reported, not blocking
    assert "README.md: language not recognised" in out


@needs_git
def test_diff_staged_mode(repo):
    (repo / "new.py").write_text("SECRET_KEY = 'Zm9vYmFyMTIzNDU2Nzg5'\n")
    _git(repo, "add", "new.py")
    assert main(["diff", "--base", "HEAD", "--staged"]) == EXIT_BLOCKED


@needs_git
def test_diff_bad_ref_is_usage_error(repo):
    assert main(["diff", "--base", "does-not-exist"]) == EXIT_ERROR


# ---- code that nests too deeply to parse or analyse (finding 8) ------------------------------

DEEP = "x = " + "+".join(["1"] * 20_000) + "\n"


@needs_git
def test_diff_blocks_code_too_deep_to_analyse_and_says_why(repo, capsys, engine_ast_raises):
    # It used to escape as a RecursionError: fail closed, but with a traceback instead of a report.
    (repo / "app.py").write_text("x = 1\n")
    engine_ast_raises("parse", RecursionError)
    assert main(["diff", "--base", "HEAD"]) == EXIT_BLOCKED
    out = capsys.readouterr().out
    assert "parse_failure" in out and "nests too deeply" in out


@needs_git
def test_diff_blocks_a_real_deep_expression(repo, capsys):
    import ast

    try:
        ast.parse(DEEP)
        pytest.skip("this interpreter parses the expression")
    except RecursionError:
        pass
    (repo / "deep.py").write_text(DEEP)
    _git(repo, "add", "deep.py")
    assert main(["diff", "--base", "HEAD"]) == EXIT_BLOCKED
    out = capsys.readouterr().out
    assert "parse_failure" in out and "nests too deeply" in out
    assert main(["verify", str(repo / "app.py"), str(repo / "deep.py")]) == EXIT_BLOCKED
    assert "nests too deeply" in capsys.readouterr().out


# ---- a file the gate cannot read must not pass it --------------------------------------------

EVASION_JS = ("// eslint-disable-next-line security/detect-eval-with-expression\n"
              "module.exports = (s) => eval(s);\n")


@needs_git
def test_diff_blocks_a_checked_file_with_a_nul_byte(repo, capsys):
    # One NUL byte in a comment used to make the gate skip the file as binary and pass.
    (repo / "app.js").write_bytes(b"/* build \x00 marker */\n" + EVASION_JS.encode())
    _git(repo, "add", "app.js")
    assert main(["diff", "--base", "HEAD"]) == EXIT_BLOCKED
    out = capsys.readouterr().out
    assert "content_not_checked" in out and "app.js" in out


@needs_git
def test_diff_blocks_a_checked_file_over_the_size_limit(repo, capsys):
    (repo / "app.py").write_text(
        "import subprocess\n\ndef run(cmd):\n    return subprocess.call(cmd, shell=True)  # nosec\n"
        + "# padding\n" * 120_000)
    assert main(["diff", "--base", "HEAD"]) == EXIT_BLOCKED
    assert "content_not_checked" in capsys.readouterr().out


@needs_git
def test_unreadable_old_version_means_the_new_one_is_checked_as_new(repo, capsys):
    (repo / "lib.py").write_bytes(b"# \x00\nx = 1\n")
    _git(repo, "add", "lib.py")
    _git(repo, "commit", "-q", "-m", "binary-looking")
    (repo / "lib.py").write_text("x = 1\n")
    assert main(["diff", "--base", "HEAD"]) == EXIT_OK
    assert "checked as if the file were new" in capsys.readouterr().out
    (repo / "lib.py").write_text("x = 1  # nosec\n")
    assert main(["diff", "--base", "HEAD"]) == EXIT_BLOCKED
    assert "suppression_introduced" in capsys.readouterr().out


def _blob(repo: Path, data: bytes) -> str:
    return subprocess.run(["git", "hash-object", "-w", "--stdin"], cwd=repo, input=data,
                          check=True, capture_output=True).stdout.decode().strip()


@needs_git
def test_diff_checks_a_symlink_replaced_by_a_file(repo, capsys):
    # Status T (type change) was left out by --diff-filter=AM, so the new file passed unseen.
    _git(repo, "update-index", "--add", "--cacheinfo", f"120000,{_blob(repo, b'app.py')},evil.py")
    _git(repo, "commit", "-q", "-m", "symlink")
    _git(repo, "rm", "-q", "--cached", "evil.py")
    (repo / "evil.py").write_text("import subprocess\nsubprocess.call(c, shell=True)  # nosec\n")
    _git(repo, "add", "evil.py")
    _git(repo, "commit", "-q", "-m", "now a file")
    assert main(["diff", "--base", "HEAD~1", "--head", "HEAD"]) == EXIT_BLOCKED
    assert "suppression_introduced" in capsys.readouterr().out


@needs_git
def test_diff_blocks_a_checked_path_that_becomes_a_symlink(repo, capsys):
    _git(repo, "update-index", "--add", "--cacheinfo", f"120000,{_blob(repo, b'README.md')},run.py")
    assert main(["diff", "--base", "HEAD", "--staged"]) == EXIT_BLOCKED
    assert "now a symbolic link" in capsys.readouterr().out


@needs_git
def test_utf16_with_a_bom_is_checked_as_text(repo, capsys):
    (repo / "u16.py").write_bytes("x = 1\n".encode("utf-16"))
    _git(repo, "add", "u16.py")
    assert main(["diff", "--base", "HEAD"]) == EXIT_OK
    (repo / "u16.py").write_bytes("import subprocess\nsubprocess.call(c, shell=True)  # nosec\n"
                                  .encode("utf-16"))
    _git(repo, "add", "u16.py")
    assert main(["diff", "--base", "HEAD"]) == EXIT_BLOCKED
    out = capsys.readouterr().out
    assert "suppression_introduced" in out and "content_not_checked" not in out


@needs_git
def test_include_unknown_also_blocks_an_unreadable_unknown_file(repo, capsys):
    (repo / "deploy").write_bytes(b"#!/usr/bin/env python\n# \x00\nimport os\n")
    _git(repo, "add", "deploy")
    assert main(["diff", "--base", "HEAD"]) == EXIT_OK
    assert main(["diff", "--base", "HEAD", "--include-unknown"]) == EXIT_BLOCKED


@needs_git
def test_unread_file_claims_no_parse(repo, capsys):
    (repo / "app.js").write_bytes(b"/* \x00 */\n" + EVASION_JS.encode())
    _git(repo, "add", "app.js")
    main(["diff", "--base", "HEAD", "--format", "json"])
    report = json.loads(capsys.readouterr().out)["files"][0]
    assert report["verification_tier"] == "asserted" and report["checks_run"] == ["content-readable"]


@needs_git
def test_a_pathspec_leaves_a_vendored_file_out(repo):
    (repo / "vendor.js").write_bytes(b"\x00" + b"x" * 10)
    _git(repo, "add", "vendor.js")
    assert main(["diff", "--base", "HEAD"]) == EXIT_BLOCKED
    assert main(["diff", "--base", "HEAD", "--", ".", ":(exclude)vendor.js"]) == EXIT_OK


@needs_git
def test_diff_blocks_an_analyser_config_with_a_nul_byte(repo):
    (repo / ".bandit").write_bytes(b"\x00\n[bandit]\nskips = B602\n")
    _git(repo, "add", ".bandit")
    assert main(["diff", "--base", "HEAD"]) == EXIT_BLOCKED


@needs_git
def test_unreadable_file_can_be_demoted_with_warn_only(repo, capsys):
    (repo / "vendor.js").write_bytes(b"\x00" + b"x" * 10)
    _git(repo, "add", "vendor.js")
    assert main(["diff", "--base", "HEAD", "--warn-only", "content_not_checked"]) == EXIT_OK
    assert "[demoted by --warn-only]" in capsys.readouterr().out


@needs_git
def test_binary_file_in_an_unchecked_language_is_still_skipped(repo, capsys):
    (repo / "logo.png").write_bytes(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR")
    _git(repo, "add", "logo.png")
    assert main(["diff", "--base", "HEAD"]) == EXIT_OK
    assert "logo.png: binary or larger than" in capsys.readouterr().out
