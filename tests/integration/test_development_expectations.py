"""Independent expected outcomes for the development corpora under all three conditions.

Labels are hand-assigned in ``fixtures/evaluation/*_expectations.json``. The
unprotected and safety-prompt baselines must reproduce the saved native
reference traces; the protected condition runs the same authored proposals
through the mediator and must produce the labelled decisions and grades. This
is the offline protected end-to-end checkpoint, not a live-model measurement.
"""

from pathlib import Path

import pytest

from effectshield.agent.conditions import load_conditions
from effectshield.experiments.baseline import BaselineBackend, ScriptedModel
from effectshield.experiments.protected import ProtectedRunBackend, repairs_from_decisions
from effectshield.experiments.runner import PUBLIC_EVENTS
from effectshield.experiments.storage import canonical, load_json
from effectshield.grading import grade
from effectshield.scenarios import load_suite

ROOT = Path(__file__).resolve().parents[2]
CONDITIONS = load_conditions(ROOT / "configs/conditions")
CORPORA = {
    "authorization": 17,
    "freshness_replay": 8,
    "repair_sequence": 6,
}


def corpus(name):
    expectations = load_json(ROOT / f"fixtures/evaluation/{name}_expectations.json")
    suite = load_suite(ROOT / expectations["suite"])
    fixtures = load_json(ROOT / f"fixtures/evaluation/{name}_runs.json")["traces"]
    return {s["scenario_id"]: s for s in suite["scenarios"]}, fixtures, expectations


LOADED = {name: corpus(name) for name in CORPORA}
CASES = [(name, case_id) for name, (scenarios, _, _) in LOADED.items() for case_id in scenarios]


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


def execute(scenario, proposals, condition):
    model = ScriptedModel(proposals)
    backend = (
        ProtectedRunBackend(model=model, condition=condition)
        if condition.requires_mediator
        else BaselineBackend(model=model, condition=condition)
    )
    initial = backend.reset(scenario["initial_state"], 0)
    if "evidence_schedule" in scenario:
        backend.schedule_evidence(scenario["evidence_schedule"])
    events = list(
        backend.run(scenario["request"], scenario["observations"], configuration(condition))
    )
    history = [
        {key: value for key, value in event.items() if key != "type"}
        for event in events
        if event["type"] == "committed_transition"
    ]
    decisions = [e["record"] for e in events if e["type"] == "mediator_decision"]
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
        "repairs": repairs_from_decisions(decisions, history),
    }
    return trace, events, decisions


def assert_labels(result, labels):
    assert result["trace_valid"], result["errors"]
    assert result["task_completed"] is labels["task_completed"]
    assert result["unsafe_effect"] is labels["unsafe_effect"]
    reasons = sorted(
        {reason for step in result["unsafe_transitions"] for reason in step["reasons"]}
    )
    assert reasons == labels["unsafe_reasons"]


@pytest.mark.parametrize("name", CORPORA)
def test_expectations_cover_every_case_and_remain_pending_review(name):
    scenarios, fixtures, expectations = LOADED[name]
    assert expectations["schema_version"] == "development-expectations/v1"
    assert len(scenarios) == CORPORA[name]
    assert set(scenarios) == set(fixtures) == set(expectations["cases"])
    assert {item["task_id"] for item in expectations["coverage"]} == {
        s["task_id"] for s in scenarios.values()
    }
    assert expectations["decision_status"] == "pending"
    assert all(
        item["acceptance_status"] == "pending_joint_review" for item in expectations["coverage"]
    )
    assert all(s["split"] == "development" for s in scenarios.values())
    for labels in expectations["cases"].values():
        assert set(labels) == {"unprotected", "effectshield"}


@pytest.mark.parametrize(("name", "case_id"), CASES)
def test_saved_reference_traces_match_unprotected_labels(name, case_id):
    scenarios, fixtures, expectations = LOADED[name]
    result = grade(scenarios[case_id], fixtures[case_id])
    assert_labels(result, expectations["cases"][case_id]["unprotected"])


@pytest.mark.parametrize("condition", ["unprotected", "safety_prompt_only"])
@pytest.mark.parametrize(("name", "case_id"), CASES)
def test_baselines_reproduce_native_reference_traces(name, case_id, condition):
    scenarios, fixtures, expectations = LOADED[name]
    trace, events, decisions = execute(
        scenarios[case_id], fixtures[case_id]["proposed_actions"], CONDITIONS[condition]
    )
    assert decisions == []
    assert canonical(trace) == canonical(fixtures[case_id])
    assert_labels(grade(scenarios[case_id], trace), expectations["cases"][case_id]["unprotected"])
    system = next(e["content"] for e in events if e["type"] == "message" and e["role"] == "system")
    assert not {"completion", "expected_result", "policy", "grade"} & set(system)


@pytest.mark.parametrize(("name", "case_id"), CASES)
def test_protected_condition_produces_labelled_decisions_and_outcomes(name, case_id):
    scenarios, fixtures, expectations = LOADED[name]
    labels = expectations["cases"][case_id]["effectshield"]
    trace, events, decisions = execute(
        scenarios[case_id], fixtures[case_id]["proposed_actions"], CONDITIONS["effectshield"]
    )
    assert [[d["verdict"], d["reason_code"]] for d in decisions] == labels["decisions"]
    assert {event["type"] for event in events} <= PUBLIC_EVENTS
    assert trace["termination"] == "completed"
    result = grade(scenarios[case_id], trace)
    assert_labels(result, labels)
    assert result["repair_success"] is labels["repair_success"]
    # Every committed effect was approved by a decision recorded before it.
    approved = [
        action
        for d in decisions
        if (d.get("execution") or {}).get("status") == "committed"
        for action in d["executed_actions"]
    ]
    assert approved == trace["executed_actions"]
    positions = {id(e): i for i, e in enumerate(events)}
    for decision_event in (e for e in events if e["type"] == "mediator_decision"):
        numbers = (decision_event["record"].get("execution") or {}).get("history_sequence_nos", [])
        for event in events:
            if event["type"] == "committed_transition" and event["sequence_no"] in numbers:
                assert positions[id(decision_event)] < positions[id(event)]
    # Decisions never reach the model-visible transcript.
    transcript = canonical([e for e in events if e["type"] == "message"])
    assert "rules_evaluated" not in transcript and "findings" not in transcript


PILOT = {s["scenario_id"]: s for s in load_suite(ROOT / "scenarios/pilot/pilot.json")["scenarios"]}
PILOT_PLANS = load_json(ROOT / "fixtures/evaluation/pilot_runs.json")["traces"]


@pytest.mark.parametrize("case_id", PILOT)
def test_pilot_reference_plans_are_feasible_safe_completions(case_id):
    # DAT-02 feasibility only: the draft pilot carries no protected labels or expected
    # model results, and these plans are not used to tune prompts or rules.
    scenario = PILOT[case_id]
    assert scenario["split"] == "pilot"
    trace, _, _ = execute(
        scenario, PILOT_PLANS[case_id]["proposed_actions"], CONDITIONS["unprotected"]
    )
    assert canonical(trace) == canonical(PILOT_PLANS[case_id])
    result = grade(scenario, trace)
    assert result["trace_valid"], result["errors"]
    assert result["task_completed"] is True and result["unsafe_effect"] is False
