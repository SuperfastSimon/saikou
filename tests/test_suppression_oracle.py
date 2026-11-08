"""The suppression oracle as a regression test (scripts/suppression_oracle.py).

bandit, flake8 and the other reference tools were asked once whether they honour each of the
generated before/after pairs; their answers are frozen in
tests/fixtures/suppression_oracle_golden.json. This test regenerates the pairs, runs Saikou on all
of them, and requires the frozen verdict for every one: a pair that used to be reported and is not
any more fails, and so does a pair that is reported now and was not (review it, then freeze again:
python scripts/suppression_oracle.py freeze). The published coverage statement is generated from
the same file and must not be out of date.

Refreshing the reference itself (new bandit, new variants) needs bandit and the flake8 wheel; see
the docstring of the script.
"""
import importlib.util
import json
import sys
from pathlib import Path

import pytest

from saikou import engine

ROOT = Path(__file__).resolve().parent.parent

# Pairs in which a reference tool honours the marker and Saikou says nothing. Anything else
# fails the test: widen this only together with the coverage statement.
ALLOWED_UNREPORTED = set()


@pytest.fixture(scope="module")
def oracle():
    spec = importlib.util.spec_from_file_location(
        "suppression_oracle", ROOT / "scripts" / "suppression_oracle.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["suppression_oracle"] = module     # dataclasses and pickle look it up by name
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def golden():
    return json.loads((ROOT / "tests" / "fixtures" / "suppression_oracle_golden.json")
                      .read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def pairs(oracle, tmp_path_factory):
    work = tmp_path_factory.mktemp("oracle")
    oracle.generate(work, None)
    return work


@pytest.fixture(scope="module")
def verdicts(oracle, golden, pairs):
    """{pair id: (verdict now, engine answer)} for every pair."""
    out = {}
    for vid, frozen in golden["variants"].items():
        before = (pairs / "before" / f"{vid}.py").read_bytes().decode("utf-8", "replace")
        after = (pairs / "after" / f"{vid}.py").read_bytes().decode("utf-8", "replace")
        answer = oracle.run_engine(engine, before, after, verification=False)
        kind, _ = oracle.classify(oracle.tool_entry_from_golden(frozen), answer)
        out[vid] = (kind, answer)
    return out


def test_the_generated_pairs_are_the_frozen_ones(oracle, golden, pairs):
    manifest = json.loads((pairs / "manifest.json").read_text(encoding="utf-8"))
    assert {m["id"] for m in manifest} == set(golden["variants"])
    assert oracle.manifest_digest(pairs) == golden["digest"], (
        "the pair generator changed: re-run the tools step and freeze the golden file")


def test_no_pair_makes_the_engine_crash(verdicts):
    assert [vid for vid, (kind, _) in verdicts.items() if kind == "crash"] == []


def test_every_pair_gets_its_frozen_verdict(golden, verdicts):
    changed = [(vid, golden["variants"][vid]["k"], kind, golden["variants"][vid]["c"],
                golden["variants"][vid]["l"])
               for vid, (kind, _) in verdicts.items() if kind != golden["variants"][vid]["k"]]
    assert changed == [], f"{len(changed)} pairs changed verdict (id, frozen, now, group): {changed[:10]}"


def test_only_the_documented_class_goes_unreported(golden, verdicts):
    unreported = {golden["variants"][vid]["c"] for vid, (kind, _) in verdicts.items() if kind == "MISS"}
    assert unreported <= ALLOWED_UNREPORTED, unreported


def test_a_marker_a_reference_tool_honours_is_never_silently_dropped(golden, verdicts):
    # blocked, or a warning for the documented style-only classes, or the documented class
    silent = [vid for vid, (kind, _) in verdicts.items()
              if golden["variants"][vid]["h"] and kind not in ("caught", "miss-warn-only", "MISS")]
    assert silent == []


@pytest.mark.parametrize("lang", ["en", "nl"])
def test_the_coverage_statement_is_generated_from_the_golden_file(oracle, golden, lang):
    committed = oracle.COVERAGE_DOCS[lang].read_text(encoding="utf-8").replace("\r\n", "\n")
    assert committed == oracle.render_coverage(golden)[lang], (
        "run: python scripts/suppression_oracle.py conformance")
