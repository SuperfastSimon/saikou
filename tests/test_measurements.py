"""docs/measurements/*.json and scripts/fp_corpus.py, which writes them (review S2).

A measurement is only worth something together with the engine it was taken with: every report
names its engine version, commit and date, so a reader can tell whether it still applies.
"""

import importlib.util
import json
import re
import sys
from pathlib import Path

import pytest

from saikou import engine

ROOT = Path(__file__).resolve().parent.parent
MEASUREMENTS = sorted((ROOT / "docs" / "measurements").glob("*.json"))
FIELDS = {"engine_version", "commit", "engine_tree", "engine_modified", "date", "python"}


@pytest.fixture(scope="module")
def fp_corpus():
    spec = importlib.util.spec_from_file_location("fp_corpus", ROOT / "scripts" / "fp_corpus.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["fp_corpus"] = module
    spec.loader.exec_module(module)
    return module


def _corpus(folder: Path) -> Path:
    folder.mkdir()
    (folder / "plain.py").write_text("def f():\n    return 1\n", encoding="utf-8")
    (folder / "dynamic.py").write_text("def f(s):\n    return eval(s)\n", encoding="utf-8")
    return folder


def _run(fp_corpus, monkeypatch, corpus: Path, out: Path) -> None:
    monkeypatch.setattr(sys, "argv", ["fp_corpus.py", str(corpus), "--json", str(out)])
    assert fp_corpus.main() == 0


def test_a_report_names_the_engine_that_produced_it(fp_corpus, tmp_path, monkeypatch):
    corpus = _corpus(tmp_path / "corpus")
    out = tmp_path / "report.json"
    _run(fp_corpus, monkeypatch, corpus, out)
    assert b"\r\n" not in out.read_bytes()             # the same bytes on every platform
    report = json.loads(out.read_text(encoding="utf-8"))
    meta = report["produced_by"]
    assert set(meta) == FIELDS
    assert meta["engine_version"] == engine.__version__
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", meta["date"])
    assert re.fullmatch(r"\d+\.\d+\.\d+\S*", meta["python"])
    if meta["commit"] is not None:                      # None outside a git checkout
        assert re.fullmatch(r"[0-9a-f]{40}", meta["commit"])
        assert re.fullmatch(r"[0-9a-f]{40}", meta["engine_tree"])
        assert isinstance(meta["engine_modified"], bool)
    # the measured numbers themselves are where they always were
    assert report["python"]["files"] == 2
    assert report["python"]["gating_blocked_files"] == 0
    assert report["python"]["newfile_checks_by_file"] == {"sink_dynamic_exec": 1}


def test_a_report_carries_no_local_paths(fp_corpus, tmp_path, monkeypatch):
    corpus = _corpus(tmp_path / "corpus")
    out = tmp_path / "report.json"
    monkeypatch.setattr(fp_corpus, "hard", lambda findings: ["sink_dynamic_exec"])  # every file blocks
    _run(fp_corpus, monkeypatch, corpus, out)
    text = out.read_text(encoding="utf-8")
    examples = json.loads(text)["python"]["gating_examples"]
    assert sorted(e["file"] for e in examples) == ["dynamic.py", "plain.py"]
    assert str(tmp_path) not in text and tmp_path.as_posix() not in text


@pytest.mark.parametrize("path", MEASUREMENTS, ids=lambda p: p.name)
def test_every_published_measurement_says_which_engine_produced_it(path):
    text = path.read_text(encoding="utf-8")
    meta = json.loads(text)["produced_by"]
    if meta.get("engine_version") is None:
        # measured before the engine was recorded: say so, and say what is known
        assert meta.get("note") and set(meta) >= {"engine_version", "commit", "date"}
    else:
        assert set(meta) == FIELDS and re.fullmatch(r"\d{4}-\d{2}-\d{2}", meta["date"])
    assert not re.search(r"[A-Za-z]:[\\/]|/home/|/Users/|\\\\", text), "local path in a public file"
