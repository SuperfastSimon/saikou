"""The check catalogue must describe exactly what the engine can report."""

import re
from pathlib import Path

from saikou import catalog
from saikou.verify import provenance_of

SRC = Path(__file__).resolve().parent.parent / "saikou"


def _emitted_ids() -> set:
    ids = set()
    for name in ("engine.py", "verify.py"):
        text = (SRC / name).read_text(encoding="utf-8")
        ids |= set(re.findall(r'Finding\(\s*"([a-z_]+)"', text))
        ids |= set(re.findall(r'flag\(node,\s*"([a-z_]+)"', text))
    return ids


def test_every_emitted_check_is_described():
    missing = sorted(_emitted_ids() - set(catalog.BY_ID))
    assert not missing, f"engine emits checks the catalogue does not describe: {missing}"


def test_catalogue_has_no_invented_checks():
    invented = sorted(set(catalog.BY_ID) - _emitted_ids())
    assert not invented, f"catalogue describes checks the engine never emits: {invented}"


def test_provenance_matches_reports():
    wrong = {c["id"]: (c["provenance"], provenance_of(c["id"])) for c in catalog.CHECKS
             if c["provenance"] != provenance_of(c["id"])}
    assert not wrong, f"catalogue provenance disagrees with reports: {wrong}"


def test_every_entry_is_bilingual_and_well_formed():
    for c in catalog.CHECKS:
        assert c["severity"] in ("hard", "warn", "depends"), c["id"]
        assert c["modes"] in ("verify", "gate", "both"), c["id"]
        for field in ("title", "description"):
            assert c[field]["en"].strip() and c[field]["nl"].strip(), (c["id"], field)
    for group in (catalog.PROVENANCE_MEANING, catalog.TIER_MEANING):
        for value in group.values():
            assert value["en"] and value["nl"]


def test_not_checked_lists_python_checks_for_javascript():
    ids = {c["id"] for c in catalog.not_checked("javascript", "verify")}
    assert "cosmetic_only_change" in ids and "sink_shell_true" in ids
    assert "suppression_introduced" not in ids
