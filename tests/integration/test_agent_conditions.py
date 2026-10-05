"""Conditions and continuation through the real adapter, gateway and simulator, offline."""

from pathlib import Path

import pytest

from effectshield.agent import load_conditions
from effectshield.experiments.baseline import BaselineBackend, ScriptedModel
from effectshield.experiments.storage import canonical, load_json
from effectshield.scenarios import load_suite

ROOT = Path(__file__).resolve().parents[2]
CONDITIONS = load_conditions(ROOT / "configs/conditions")


def configuration(condition):
    config = load_json(ROOT / "configs/evaluation/gate.json")
    config["model"] = {
        "provider": "scripted-model",
        "version": ScriptedModel.model_version,
        "date": ScriptedModel.model_date,
        "settings": {},
        "seed": 0,
        "seed_status": "supported",
    }
    config["prompt_version"] = condition.prompt_version
    return {key: config[key] for key in ("model", "limits", "prompt_version")}


def case(scenario_id):
    suite = load_suite(ROOT / "scenarios/development/baseline.json")
    return next(item for item in suite["scenarios"] if item["scenario_id"] == scenario_id)


def run(condition, scenario_id, proposals):
    scenario = case(scenario_id)
    backend = BaselineBackend(model=ScriptedModel(proposals), condition=condition)
    backend.reset(scenario["initial_state"], 0)
    return list(
        backend.run(scenario["request"], scenario["observations"], configuration(condition))
    )


def action(device, operation):
    return {
        "schema_version": "1.0",
        "device": device,
        "operation": operation,
        "parameters": {},
        "evidence_refs": [],
    }


@pytest.mark.parametrize("name", ["unprotected", "safety_prompt_only"])
def test_runnable_conditions_complete_a_benign_task(name):
    events = run(CONDITIONS[name], "light-on-clean", [action("light", "turn_on")])
    finish = events[-1]
    assert finish["status"] == "completed"
    assert finish["final_state"]["devices"]["light"]["power"] == "on"
    system = next(e for e in events if e["type"] == "message" and e["role"] == "system")
    assert system["content"]["prompt_version"] == CONDITIONS[name].prompt_version
    assert ("safety_instruction" in system["content"]) is (name == "safety_prompt_only")


def test_effectshield_condition_is_refused_rather_than_run_unprotected():
    with pytest.raises(ValueError, match="requires a mediator"):
        BaselineBackend(model=ScriptedModel([]), condition=CONDITIONS["effectshield"])


def test_repeated_simulator_rejections_terminate_with_no_effect():
    locked_open = action("door", "open")
    events = run(CONDITIONS["unprotected"], "light-on-clean", [locked_open] * 5)
    finish = events[-1]
    assert finish["status"] == "budget_exceeded"
    assert finish["error"] == "Consecutive refusal limit reached"
    proposals = [e for e in events if e["type"] == "proposed_action"]
    assert len(proposals) == 2
    assert finish["final_state"]["devices"]["door"] == {"position": "closed", "lock": "locked"}
    feedback = [
        e["content"]
        for e in events
        if e["type"] == "message" and e["role"] == "tool" and "status" in e["content"]
    ]
    assert [f["status"] for f in feedback] == ["rejected", "rejected"]
    assert all("entries" not in f and "detail" not in f for f in feedback)
    assert canonical(finish["final_state"]["devices"]) == canonical(
        case("light-on-clean")["initial_state"]["devices"]
    )
