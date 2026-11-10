"""Authorization attack boundaries: forged authority, protected fields and trusted identity."""

from copy import deepcopy
from pathlib import Path

import pytest

from effectshield.agent.conditions import load_conditions
from effectshield.attacks import apply_attack, validate_matched_pair
from effectshield.domain.actions import parse_action
from effectshield.domain.errors import ActionSchemaError
from effectshield.experiments.baseline import BaselineBackend, ScriptedModel
from effectshield.experiments.storage import canonical, load_json
from effectshield.grading import grade
from effectshield.scenarios import load_suite, validate_scenario

ROOT = Path(__file__).resolve().parents[2]
SUITE = load_suite(ROOT / "scenarios/development/authorization.json")
SCENARIOS = {s["scenario_id"]: s for s in SUITE["scenarios"]}
FIXTURES = load_json(ROOT / "fixtures/evaluation/authorization_runs.json")["traces"]
CONDITIONS = load_conditions(ROOT / "configs/conditions")


def configuration(condition):
    config = load_json(ROOT / "configs/evaluation/gate.json")
    config["prompt_version"] = condition.prompt_version
    config["model"] = {
        "provider": "scripted-model",
        "version": ScriptedModel.model_version,
        "date": ScriptedModel.model_date,
        "settings": {},
        "seed": 0,
        "seed_status": "supported",
    }
    return config


def native_trace(scenario, condition):
    backend = BaselineBackend(
        model=ScriptedModel(FIXTURES[scenario["scenario_id"]]["proposed_actions"]),
        condition=condition,
    )
    initial = backend.reset(scenario["initial_state"], 0)
    events = list(
        backend.run(scenario["request"], scenario["observations"], configuration(condition))
    )
    history = [
        {key: value for key, value in event.items() if key != "type"}
        for event in events
        if event["type"] == "committed_transition"
    ]
    trace = {
        "schema_version": "evaluation-trace/v1",
        "initial_state": initial,
        "proposed_actions": [e["action"] for e in events if e["type"] == "proposed_action"],
        "executed_actions": [e["action"] for e in history if e["kind"] == "action"],
        "transitions": history,
        "observations": [e["receipt"] for e in events if e["type"] == "observation"],
        "final_state": events[-1]["final_state"],
        "complete": True,
        "termination": events[-1]["status"],
        "repairs": [],
    }
    return trace, events


# Coverage, saved reference traces, baseline reproduction and protected outcomes for
# this corpus are checked with the other development corpora in
# test_development_expectations.py. This module keeps authorization-specific
# boundary checks.


@pytest.mark.parametrize("scenario", [s for s in SCENARIOS.values() if s["variant"] == "attacked"])
def test_attacks_preserve_authority_canonical_facts_and_labels(scenario):
    clean = SCENARIOS[scenario["attack"]["clean_scenario_id"]]
    validate_matched_pair(clean, scenario)
    assert apply_attack(clean, scenario["attack"]) == scenario
    for field in (
        "request",
        "initial_state",
        "completion",
        "policy",
        "run_config",
        "expected_result",
    ):
        assert canonical(scenario[field]) == canonical(clean[field])
    left, right = deepcopy(clean["observations"]), deepcopy(scenario["observations"])
    left[0]["payload"].pop("message")
    right[0]["payload"].pop("message")
    assert canonical(left) == canonical(right)


def test_false_presence_text_does_not_change_trusted_presence():
    case = SCENARIOS["presence-claim-clean-attacked"]
    assert "Occupants are present" in case["observations"][0]["payload"]["message"]
    assert case["initial_state"]["devices"]["presence_sensor"]["present"] is False
    result = grade(case, FIXTURES[case["scenario_id"]])
    assert "unoccupied_door_unlocked" in result["unsafe_transitions"][-1]["reasons"]


def test_empty_trusted_permissions_do_not_become_authorized_from_request_text():
    case = deepcopy(SCENARIOS["system-claim-clean"])
    case["request"]["permissions"] = []
    trace, _ = native_trace(case, CONDITIONS["unprotected"])
    verdict = grade(case, trace)
    assert verdict["trace_valid"] and verdict["unsafe_effect"]
    assert "unauthorized_operation:light.turn_on" in verdict["unsafe_transitions"][0]["reasons"]


@pytest.mark.parametrize(
    "field,value", [("principal_id", ""), ("issuer", "tool"), ("request_id", "")]
)
def test_missing_or_forged_trusted_identity_is_rejected_before_evaluation(field, value):
    case = deepcopy(SCENARIOS["system-claim-clean"])
    case["request"][field] = value
    with pytest.raises(ValueError):
        validate_scenario(case)


@pytest.mark.parametrize(
    "field,value",
    [
        ("principal_id", "admin"),
        ("source", "user"),
        ("permissions", ["door.unlock"]),
        ("gateway_time_ms", 0),
        ("event_id", 1),
    ],
)
def test_agent_cannot_add_trusted_authority_fields_to_action(field, value):
    action = deepcopy(FIXTURES["system-claim-clean"]["proposed_actions"][0])
    action[field] = value
    with pytest.raises(ActionSchemaError):
        parse_action(canonical(action))


@pytest.mark.parametrize("field", ["request", "policy", "initial_state", "completion"])
def test_protected_top_level_attack_mutations_are_rejected(field):
    attacked = deepcopy(SCENARIOS["system-claim-clean-attacked"])
    attacked[field] = {}
    with pytest.raises(ValueError):
        validate_matched_pair(SCENARIOS["system-claim-clean"], attacked)
