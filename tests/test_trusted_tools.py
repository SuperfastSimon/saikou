"""git and bandit come from the system, never from the repository under check.

Found by the attack round on 1.2.1: on Windows a bare program name runs from the current
folder before PATH, so a pull request that added git.exe to the repository root replaced
git, reported no changed files, and its fake fix passed the gate.
"""

import io
import os
import stat
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from saikou import engine, service

FAKE_BEFORE = "import subprocess\n\ndef run(cmd):\n    return subprocess.call(cmd, shell=True)\n"
FAKE_AFTER = "import subprocess\n\ndef run(cmd):\n    return subprocess.call(cmd, shell=True)  # nosec\n"


def _plant(folder: Path, name: str) -> Path:
    """A program called `name` in `folder` that the system would find by its bare name."""
    if os.name == "nt":
        path = folder / f"{name}.exe"
        path.write_bytes(b"MZ not a real program")
    else:
        path = folder / name
        path.write_text("#!/bin/sh\nexit 0\n")
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


def test_the_current_folder_and_the_repository_are_never_searched(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    (repo / "bin").mkdir(parents=True)
    _plant(repo, "git")
    _plant(repo / "bin", "git")
    monkeypatch.chdir(repo)
    monkeypatch.setenv("PATH", os.pathsep.join([".", "bin", str(repo / "bin"), str(repo),
                                                os.environ.get("PATH", "")]))
    found = engine.trusted_executable("git", str(repo))
    assert found is None or not os.path.realpath(found).startswith(os.path.realpath(str(repo)))


def test_an_untrusted_folder_elsewhere_is_not_searched_either(tmp_path, monkeypatch):
    other = tmp_path / "checkout"
    other.mkdir()
    planted = _plant(other, "saikou-test-tool")
    monkeypatch.setenv("PATH", str(other) + os.pathsep + os.environ.get("PATH", ""))
    found = engine.trusted_executable("saikou-test-tool")                        # trusted
    assert found and os.path.normcase(found) == os.path.normcase(str(planted))
    assert engine.trusted_executable("saikou-test-tool", str(other)) is None    # not when untrusted


def _make_exe(path: Path, main_src: str) -> None:
    """A real Windows .exe that runs `main_src` (pip's launcher stub + a zipped __main__)."""
    import pip
    stub = (Path(pip.__file__).parent / "_vendor" / "distlib" / "t64.exe").read_bytes()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("__main__.py", main_src)
    path.write_bytes(stub + b"#!" + sys.executable.encode() + b"\r\n" + buf.getvalue())


@pytest.mark.skipif(os.name != "nt", reason="Windows looks in the current folder first")
def test_a_git_exe_in_the_repository_does_not_replace_git(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()

    def git(*args):
        return subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, text=True)
    git("init", "-q")
    git("config", "user.email", "t@example.invalid")
    git("config", "user.name", "t")
    git("config", "core.autocrlf", "false")
    (repo / "svc.py").write_text(FAKE_BEFORE)
    git("add", ".")
    git("commit", "-qm", "base")
    (repo / "svc.py").write_text(FAKE_AFTER)
    marker = tmp_path / "PLANTED-GIT-RAN"
    _make_exe(repo / "git.exe", f"open({str(marker)!r}, 'a').write('ran')\n")
    for key in [k for k in os.environ if k.upper() == "NODEFAULTCURRENTDIRECTORYINEXEPATH"]:
        monkeypatch.delenv(key)
    monkeypatch.chdir(repo)
    out = service.git_diff({"repo": str(repo)})
    assert not marker.exists(), "the repository's git.exe ran"
    assert out["blocked"] is True
