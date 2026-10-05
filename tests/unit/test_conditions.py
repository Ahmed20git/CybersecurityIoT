"""Versioned condition configurations: exact treatment differences, no hidden shield."""

import json
from pathlib import Path

import pytest

from effectshield.agent import ConditionError, load_conditions
from effectshield.agent.conditions import (
    TREATMENT_FIELDS,
    load_condition,
    parse_condition,
    treatment_differences,
)

ROOT = Path(__file__).resolve().parents[2]
CONDITIONS = ROOT / "configs/conditions"


def document(name):
    return json.loads((CONDITIONS / f"{name}.json").read_text(encoding="utf-8"))


def test_three_named_conditions_load_with_declared_treatments():
    conditions = load_conditions(CONDITIONS)
    assert set(conditions) == {"unprotected", "safety_prompt_only", "effectshield"}
    unprotected = conditions["unprotected"]
    prompt_only = conditions["safety_prompt_only"]
    shield = conditions["effectshield"]
    assert unprotected.safety_instruction is None and not unprotected.requires_mediator
    assert prompt_only.safety_instruction and not prompt_only.requires_mediator
    assert shield.safety_instruction is None and shield.requires_mediator
    assert shield.prompt_version == unprotected.prompt_version
    assert prompt_only.prompt_version != unprotected.prompt_version
    assert all(c.decision_status == "pending" for c in conditions.values())


def test_unprotected_prompt_version_matches_the_baseline_protocol():
    gate = json.loads((ROOT / "configs/evaluation/gate.json").read_text(encoding="utf-8"))
    assert load_conditions(CONDITIONS)["unprotected"].prompt_version == gate["prompt_version"]


@pytest.mark.parametrize(
    ("first", "second", "expected"),
    [
        (
            "unprotected",
            "safety_prompt_only",
            ["condition_id", "condition_version", "prompt_version", "safety_instruction"],
        ),
        ("unprotected", "effectshield", ["condition_id", "condition_version", "enforcement"]),
    ],
)
def test_pairwise_differences_are_only_declared_treatment_fields(first, second, expected):
    conditions = load_conditions(CONDITIONS)
    differences = treatment_differences(conditions[first], conditions[second])
    assert differences == expected
    assert set(differences) <= set(TREATMENT_FIELDS)


def test_undeclared_difference_is_rejected():
    changed = document("unprotected")
    changed["condition_id"] = "safety_prompt_only"
    changed["safety_instruction"] = "Be careful."
    changed["decision_status"] = "approved"
    with pytest.raises(ConditionError, match="Undeclared"):
        treatment_differences(parse_condition(document("unprotected")), parse_condition(changed))


@pytest.mark.parametrize(
    ("name", "changes", "message"),
    [
        ("safety_prompt_only", {"enforcement": "effectshield"}, "enforcement none"),
        ("safety_prompt_only", {"safety_instruction": None}, "safety_instruction text"),
        ("unprotected", {"safety_instruction": "Be careful."}, "safety_instruction null"),
        ("effectshield", {"enforcement": "none"}, "enforcement effectshield"),
        ("effectshield", {"safety_instruction": "Be careful."}, "safety_instruction null"),
        ("unprotected", {"condition_id": "custom"}, "condition_id"),
        ("unprotected", {"enforcement": "regex_filter"}, "enforcement must be"),
        ("unprotected", {"continuation_protocol": "continuation/v0"}, "continuation"),
        ("unprotected", {"decision_status": "frozen"}, "decision_status"),
        ("unprotected", {"schema_version": "agent-condition/v0"}, "schema_version"),
        ("unprotected", {"prompt_version": ""}, "prompt_version"),
        ("unprotected", {"extra": True}, "fields must be exactly"),
        ("safety_prompt_only", {"safety_instruction": "x" * 4001}, "bounded"),
    ],
)
def test_malformed_or_inconsistent_conditions_are_rejected(name, changes, message):
    changed = document(name)
    changed.update(changes)
    with pytest.raises(ConditionError, match=message):
        parse_condition(changed)


def test_condition_set_must_be_complete_and_correctly_paired(tmp_path):
    for name in ("unprotected", "safety_prompt_only"):
        (tmp_path / f"{name}.json").write_text(json.dumps(document(name)), encoding="utf-8")
    with pytest.raises(ConditionError, match="exactly the conditions"):
        load_conditions(tmp_path)
    changed = document("effectshield")
    changed["prompt_version"] = "effectshield-prompt/v1"
    (tmp_path / "effectshield.json").write_text(json.dumps(changed), encoding="utf-8")
    with pytest.raises(ConditionError, match="reuse the unprotected prompt"):
        load_conditions(tmp_path)
    (tmp_path / "effectshield.json").write_text(
        json.dumps(document("effectshield")), encoding="utf-8"
    )
    (tmp_path / "copy.json").write_text(json.dumps(document("unprotected")), encoding="utf-8")
    with pytest.raises(ConditionError, match="Duplicate condition"):
        load_conditions(tmp_path)


def test_duplicate_json_keys_are_rejected(tmp_path):
    path = tmp_path / "dup.json"
    text = (CONDITIONS / "unprotected.json").read_text(encoding="utf-8")
    path.write_text(text.replace("{", '{"enforcement": "effectshield",', 1), encoding="utf-8")
    with pytest.raises(ConditionError, match="Duplicate condition key"):
        load_condition(path)


def test_round_trip_is_exact():
    for name in ("unprotected", "safety_prompt_only", "effectshield"):
        assert load_condition(CONDITIONS / f"{name}.json").to_dict() == document(name)
