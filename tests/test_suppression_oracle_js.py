"""The JavaScript/TypeScript suppression oracle as a regression test (scripts/suppression_oracle_js.py).

ESLint (with eslint-plugin-security), the TypeScript compiler and semgrep were asked once whether they
honour each generated before/after pair; their answers are frozen in
tests/fixtures/suppression_oracle_js_golden.json. This test regenerates the pairs, runs Saikou on all
of them and requires the frozen verdict for every one. After an intended change: read what moved,
then `python scripts/suppression_oracle_js.py freeze` and `python scripts/suppression_oracle.py
conformance` (the coverage statement is generated from the same file). Refreshing the frozen answers
themselves needs node, eslint, typescript and semgrep; see the docstring of the script.
"""
import importlib.util
import json
import sys
from pathlib import Path

import pytest

from saikou import engine

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def oracle():
    spec = importlib.util.spec_from_file_location(
        "suppression_oracle_js", ROOT / "scripts" / "suppression_oracle_js.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["suppression_oracle_js"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def golden():
    return json.loads((ROOT / "tests" / "fixtures" / "suppression_oracle_js_golden.json")
                      .read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def pairs(oracle, tmp_path_factory):
    work = tmp_path_factory.mktemp("oracle_js")
    oracle.generate(work)
    return work


@pytest.fixture(scope="module")
def verdicts(oracle, golden, pairs):
    manifest = {m["id"]: m for m in json.loads((pairs / "manifest.json").read_text(encoding="utf-8"))}
    out = {}
    for vid, frozen in golden["variants"].items():
        item = manifest[vid]
        before = oracle.file_of(pairs, "before", item).read_bytes().decode("utf-8", "replace")
        after = oracle.file_of(pairs, "after", item).read_bytes().decode("utf-8", "replace")
        answer = oracle.po.run_engine(engine, before, after, verification=False,
                                      language=oracle.SINKS[item["sink"]]["lang"])
        kind, _ = oracle.classify(oracle.tool_entry_from_golden(frozen), answer, frozen["l"])
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


def test_a_marker_an_executed_tool_honours_is_never_dropped(golden, verdicts):
    # blocked, or a warning for a type-checker directive; never silence
    silent = [(vid, golden["variants"][vid]["c"], golden["variants"][vid]["l"])
              for vid, (kind, _) in verdicts.items()
              if golden["variants"][vid]["h"] and kind not in ("caught", "style-warned")]
    assert silent == [], silent[:10]
