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


def test_sarif_upload_requirements_are_stated_in_full():
    """GitHub: a private repository needs GitHub Code Security or GitHub Advanced Security, and
    `actions: read` ("only required for workflows in private repositories")."""
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    example = re.search(r"```yaml\nname: saikou\n(.*?)```", readme, re.S).group(1)
    permissions = re.search(r"^permissions:\n((?:  .*\n)+)", example, re.M).group(1)
    assert re.search(r"^  actions: read\b", permissions, re.M)
    assert re.search(r"^  security-events: write\b", permissions, re.M)
    action = ACTION.read_text(encoding="utf-8")
    for text in (readme, action):
        assert "GitHub Code Security or GitHub Advanced Security" in " ".join(text.split())
    assert "actions: read" in action
    dogfood = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8").split("dogfood:")[1]
    assert re.search(r"^      actions: read\b", dogfood, re.M)


USES = re.compile(r"^\s*(?:- )?uses:\s*(\S+)(.*)$", re.M)
# Majors that run on the deprecated Node 20 (checkout, setup-*) or expire in December 2026
# (codeql-action v3): the pinned version must be newer.
DEPRECATED_MAJOR = {"actions/checkout": 4, "actions/setup-python": 5, "actions/setup-node": 4,
                    "github/codeql-action": 3}


def test_every_external_action_is_pinned_to_a_commit():
    """Review G6: a tag or branch can be moved; a full commit SHA cannot. The comment names the
    release the SHA was taken from."""
    files = [ACTION, *sorted((ROOT / ".github" / "workflows").glob("*.yml"))]
    seen = 0
    for f in files:
        for m in USES.finditer(f.read_text(encoding="utf-8")):
            ref, rest = m.group(1), m.group(2)
            if ref.startswith("./"):
                continue
            seen += 1
            assert re.fullmatch(r"[\w.-]+/[\w.-]+(?:/[\w./-]+)?@[0-9a-f]{40}", ref), (f.name, ref)
            version = re.fullmatch(r"\s+# v(\d+)\.\d+\.\d+", rest)
            assert version, (f.name, ref, rest)
            repo = "/".join(ref.split("@")[0].split("/")[:2])
            assert int(version.group(1)) > DEPRECATED_MAJOR.get(repo, 0), (f.name, ref, rest)
    assert seen >= 10


# A command line `python -m saikou <something>`; the sentence that warns against it names the bare
# `python -m saikou` and is not matched.
PY_M_SAIKOU_COMMAND = re.compile(r"python3?\s+-m\s+saikou\s+[\w-]")


def test_user_docs_do_not_tell_anyone_to_run_python_m_saikou():
    """Run in a project that holds a saikou/ folder, `python -m saikou` runs that folder instead of
    the installed engine; what users and the agents read names the `saikou` console script."""
    docs = [ROOT / "README.md", *sorted((ROOT / "docs").rglob("*.md")),
            *sorted((ROOT / "plugins").rglob("*.md")), *sorted((ROOT / ".claude" / "agents").glob("*.md")),
            *sorted((ROOT / "site").rglob("*.html")), ROOT / "saikou" / "web" / "index.html"]
    assert (ROOT / "plugins" / "saikou-harden" / "agents" / "code-hardener.md") in docs
    for f in docs:
        for n, line in enumerate(f.read_text(encoding="utf-8").splitlines(), 1):
            assert not PY_M_SAIKOU_COMMAND.search(line), (f.relative_to(ROOT).as_posix(), n, line)


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
    (tmp_path / "step.sh").write_bytes((script + "\n").encode("utf-8"))   # LF, also on Windows
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
