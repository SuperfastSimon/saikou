"""action.yml, the composite GitHub Action: what its shell steps run.

The steps run with the checked-out repository as the working directory, and a pull request
decides what is in it. A saikou/ (or pip/, or sitecustomize.py) folder there must never run in
place of the installed engine: `python -m saikou` would import it from the current folder, and a
console script honours PYTHONPATH. action.yml is read as text; PyYAML is not a dependency.
"""

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
ACTION = ROOT / "action.yml"

PY = re.compile(r"(?<![\w./$-])python3?(?![\w.-])")
PY_CALL = re.compile(r"(?<![\w./$-])python3?((?:\s+-[A-Za-z]+)*)\s+-m\s+([\w.]+)")
BARE_SAIKOU = re.compile(r"(?:^|&&|\|\||;|\bthen\b|\bdo\b)\s*saikou(?=\s|$)")

FAKE_BEFORE = "import subprocess\n\ndef run(cmd):\n    return subprocess.call(cmd, shell=True)\n"
FAKE_AFTER = FAKE_BEFORE.replace("shell=True)", "shell=True)  # nosec")
PLANTED = "open({marker!r}, 'w').write('ran')\n"


def run_steps():
    """[(step id or None, bash body)] for every `run: |` step of action.yml."""
    lines = ACTION.read_text(encoding="utf-8").splitlines()
    steps, step_id, i = [], None, 0
    while i < len(lines):
        line = lines[i]
        if re.match(r"\s*- ", line):
            step_id = None
        found_id = re.match(r"\s*(?:- )?id: (\S+)", line)
        if found_id:
            step_id = found_id.group(1)
        block = re.match(r"(\s*)run: \|\s*$", line)
        i += 1
        if not block:
            continue
        indent, body = len(block.group(1)), []
        while i < len(lines) and (not lines[i].strip()
                                  or len(lines[i]) - len(lines[i].lstrip()) > indent):
            body.append(lines[i])
            i += 1
        cut = min(len(b) - len(b.lstrip()) for b in body if b.strip())
        steps.append((step_id, "\n".join(b[cut:] for b in body)))
    return steps


def python_calls():
    """[(interpreter flags, module)] for every `python ... -m MODULE` in a run step."""
    calls = []
    for _sid, body in run_steps():
        for m in PY_CALL.finditer(body):
            calls.append((m.group(1).split(), m.group(2)))
    return calls


def test_the_action_has_the_steps_these_tests_read():
    ids = [sid for sid, _ in run_steps()]
    assert "gate" in ids and "run" in ids and len(ids) >= 4
    assert {"pip", "saikou"} <= {module for _flags, module in python_calls()}


def test_every_python_call_is_isolated_from_the_workspace():
    for sid, body in run_steps():
        for line in body.splitlines():
            for m in PY.finditer(line):
                call = PY_CALL.match(line, m.start())
                assert call and "-I" in call.group(1).split(), (sid, line)


def test_saikou_is_never_run_as_a_bare_command():
    """The console script honours PYTHONPATH (a workflow may set it to the workspace)."""
    for sid, body in run_steps():
        for line in body.splitlines():
            assert not BARE_SAIKOU.search(line), (sid, line)
    run = dict(run_steps())["run"]
    assert 'python -I -m saikou "${args[@]}"' in run


def test_pythonpath_is_unset_before_anything_runs():
    """-I covers the interpreter it is given to; bandit, started by saikou, is not covered."""
    for sid, body in run_steps():
        if PY.search(body):
            first = body.strip().splitlines()[0]
            assert first == "unset PYTHONPATH", (sid, first)


def _plant(folder: Path) -> Path:
    """A workspace that holds its own saikou, pip and bandit packages and a sitecustomize."""
    marker = folder / "PLANTED-CODE-RAN"
    for pkg in ("saikou", "pip", "bandit"):
        (folder / pkg).mkdir(parents=True, exist_ok=True)
        for name in ("__init__.py", "__main__.py"):
            (folder / pkg / name).write_text(PLANTED.format(marker=str(marker)), encoding="utf-8")
    (folder / "sitecustomize.py").write_text(PLANTED.format(marker=str(marker)), encoding="utf-8")
    return marker


def test_no_python_call_of_the_action_runs_a_planted_package(tmp_path):
    marker = _plant(tmp_path)
    env = dict(os.environ, PYTHONPATH=str(tmp_path))
    for flags, module in python_calls():
        subprocess.run([sys.executable, *flags, "-m", module, "--version"], cwd=tmp_path, env=env,
                       capture_output=True, timeout=120)
        assert not marker.exists(), f"python {' '.join(flags)} -m {module} ran the workspace copy"


def _bash():
    found = shutil.which("bash")
    if not found or shutil.which("git") is None:
        return None
    if os.name == "nt" and "system32" in found.lower():   # WSL's bash, not Git Bash
        return None
    return found


def _installed_saikou(cwd: Path) -> bool:
    probe = subprocess.run([sys.executable, "-I", "-c", "import saikou"], cwd=cwd,
                           capture_output=True, timeout=60)
    return probe.returncode == 0


def test_the_run_step_gates_with_the_installed_engine(tmp_path):
    """Run the action's `run` step itself in a repository that carries a planted saikou/ and
    sets PYTHONPATH to the workspace: the installed engine must do the gating."""
    bash = _bash()
    if bash is None:
        pytest.skip("needs bash (Git Bash on Windows) and git")
    repo = tmp_path / "repo"
    repo.mkdir()
    if not _installed_saikou(tmp_path):
        pytest.skip("saikou is not installed in this interpreter (pip install -e .)")

    def git(*args):
        return subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True,
                              text=True).stdout.strip()
    git("init", "-q", "-b", "main")
    git("config", "user.email", "t@example.invalid")
    git("config", "user.name", "t")
    git("config", "commit.gpgsign", "false")
    (repo / "svc.py").write_text(FAKE_BEFORE, encoding="utf-8")
    git("add", ".")
    git("commit", "-q", "-m", "base")
    base = git("rev-parse", "HEAD")
    (repo / "svc.py").write_text(FAKE_AFTER, encoding="utf-8")
    git("commit", "-q", "-am", "claims a fix, adds a suppression")
    marker = _plant(repo)                       # untracked, but in the working directory

    python = Path(sys.executable).as_posix()
    script = PY.sub(lambda _m: '"$PYTHON_UNDER_TEST"', dict(run_steps())["run"])
    (tmp_path / "step.sh").write_text(script + "\n", encoding="utf-8", newline="\n")
    out, summary = tmp_path / "output.txt", tmp_path / "summary.md"
    env = dict(os.environ, PYTHON_UNDER_TEST=python, PYTHONPATH=repo.as_posix(),
               INPUT_BASE=base, PR_BASE="", PUSH_BEFORE="", CLAIMS="", STRICT_API="false",
               PATHS="", WARN_ONLY="", ANALYSER="false",
               GITHUB_OUTPUT=out.as_posix(), GITHUB_STEP_SUMMARY=summary.as_posix())
    # a console script `saikou` next to the interpreter would be found first (the old step used it)
    env["PATH"] = os.path.dirname(sys.executable) + os.pathsep + env.get("PATH", "")
    proc = subprocess.run([bash, "--noprofile", "--norc", "-eo", "pipefail",
                           (tmp_path / "step.sh").as_posix()], cwd=repo, env=env,
                          capture_output=True, text=True, encoding="utf-8", errors="replace",
                          timeout=300)
    assert not marker.exists(), "the run step imported the workspace's saikou/"
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "blocked=true" in out.read_text(encoding="utf-8")
    assert "suppression" in summary.read_text(encoding="utf-8").lower()
    assert (repo / "saikou.sarif").exists()
