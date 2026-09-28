"""Adapter-to-gateway-to-simulator integration without a provider call."""

from copy import deepcopy
from pathlib import Path

from effectshield.experiments.baseline import BaselineBackend, ScriptedModel
from effectshield.experiments.storage import canonical, load_json
from effectshield.grading import grade
from effectshield.scenarios import load_suite

ROOT = Path(__file__).resolve().parents[2]
SUITE = ROOT / "scenarios/development/baseline.json"
FIXTURES = ROOT / "fixtures/evaluation/runs.json"


def configuration():
    config = load_json(ROOT / "configs/evaluation/gate.json")
    config["model"] = {
        "provider": "scripted-model",
        "version": ScriptedModel.model_version,
        "date": ScriptedModel.model_date,
        "settings": {},
        "seed": 0,
        "seed_status": "supported",
    }
    return config


def trace(case, events):
    transitions = [
        {key: value for key, value in event.items() if key != "type"}
        for event in events
        if event["type"] == "committed_transition"
    ]
    return {
        "schema_version": "evaluation-trace/v1",
        "initial_state": case["initial_state"],
        "proposed_actions": [
            event["action"] for event in events if event["type"] == "proposed_action"
        ],
        "executed_actions": [entry["action"] for entry in transitions if entry["kind"] == "action"],
        "transitions": transitions,
        "observations": [event["receipt"] for event in events if event["type"] == "observation"],
        "final_state": events[-1]["final_state"],
        "complete": events[-1]["status"] == "completed",
        "termination": events[-1]["status"],
        "repairs": [],
    }


def test_scripted_adapter_completes_development_suite_using_native_effects():
    for case in load_suite(SUITE)["scenarios"]:
        backend = BaselineBackend(FIXTURES, case["scenario_id"])
        backend.reset(case["initial_state"], 0)
        events = list(backend.run(case["request"], case["observations"], configuration()))
        assert events[-1]["status"] == "completed"
        verdict = grade(case, trace(case, events))
        assert verdict["trace_valid"], (case["scenario_id"], verdict)
        assert verdict["task_completed"] is True
        assert verdict["unsafe_effect"] is (case["variant"] == "attacked")
        assert backend.kind == "fixture"
        usage = [event for event in events if event["type"] == "usage"][-1]
        assert usage["cost_status"] == "synthetic"
        assert usage["calls"] == usage["cost"] == 0
        messages = [event for event in events if event["type"] == "message"]
        assert any(message["role"] == "assistant" for message in messages)
        assert any("action_catalog" in canonical(message["content"]) for message in messages)


def test_adapter_receives_native_rejection_feedback_then_stops_cleanly():
    case = load_suite(SUITE)["scenarios"][0]
    invalid_physical = {
        "schema_version": "1.0",
        "device": "door",
        "operation": "open",
        "parameters": {},
        "evidence_refs": [],
    }
    model = ScriptedModel([invalid_physical])
    backend = BaselineBackend(model=model)
    backend.reset(case["initial_state"], 0)
    events = list(backend.run(case["request"], case["observations"], configuration()))
    feedback = [
        event["content"]
        for event in events
        if event["type"] == "message" and event["role"] == "tool"
    ]
    assert any(isinstance(value, dict) and value.get("status") == "rejected" for value in feedback)
    assert events[-1]["committed_count"] == 0
    assert grade(case, trace(case, events))["task_completed"] is False


def test_baseline_reset_resets_script_and_does_not_modify_frozen_inputs():
    case = load_suite(SUITE)["scenarios"][0]
    original = deepcopy(case)
    backend = BaselineBackend(FIXTURES, case["scenario_id"])
    outputs = []
    for _ in range(2):
        backend.reset(case["initial_state"], 0)
        outputs.append(list(backend.run(case["request"], case["observations"], configuration())))
    assert canonical(outputs[0]) == canonical(outputs[1])
    assert case == original
