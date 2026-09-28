"""Simon-owned evaluation replay over Ahmed's real deterministic runtime."""

import json
from copy import deepcopy
from pathlib import Path

import pytest

from effectshield.domain import DeviceId
from effectshield.domain.events import SetPresence
from effectshield.experiments.replay import SimulatorReplayBackend
from effectshield.experiments.storage import canonical, load_json
from effectshield.grading import grade
from effectshield.scenarios import load_suite

ROOT = Path(__file__).resolve().parents[2]
SUITE = ROOT / "scenarios/development/baseline.json"
FIXTURES = ROOT / "fixtures/evaluation/runs.json"


def configuration():
    config = load_json(ROOT / "configs/evaluation/gate.json")
    config["model"] = {
        "provider": "simulator-replay",
        "version": "recorded-proposals-v1",
        "date": "2026-09-28",
        "settings": {},
        "seed": 0,
        "seed_status": "supported",
    }
    return config


def replay(case, fixtures=FIXTURES):
    backend = SimulatorReplayBackend(fixtures, case["scenario_id"])
    assert backend.reset(case["initial_state"], 0) == case["initial_state"]
    events = list(backend.run(case["request"], case["observations"], configuration()))
    return backend, events


def trace_from_events(case, events):
    transitions = [
        {key: value for key, value in event.items() if key != "type"}
        for event in events
        if event["type"] == "committed_transition"
    ]
    finish = events[-1]
    assert finish["type"] == "finish"
    return {
        "schema_version": "evaluation-trace/v1",
        "initial_state": deepcopy(case["initial_state"]),
        "proposed_actions": [
            event["action"] for event in events if event["type"] == "proposed_action"
        ],
        "executed_actions": [entry["action"] for entry in transitions if entry["kind"] == "action"],
        "transitions": transitions,
        "observations": [event["receipt"] for event in events if event["type"] == "observation"],
        "final_state": finish["final_state"],
        "complete": finish["status"] in {"completed", "abstained"},
        "termination": finish["status"],
        "repairs": [],
    }


def test_real_runtime_completes_all_clean_tasks_and_retains_scripted_unsafe_effect():
    for case in load_suite(SUITE)["scenarios"]:
        backend, events = replay(case)
        trace = trace_from_events(case, events)
        assert backend.kind == "fixture"
        assert trace["transitions"] == [
            entry.to_dict() for entry in backend.environment.simulator.history
        ]
        assert events[-1]["committed_count"] == len(trace["transitions"])
        verdict = grade(case, trace)
        assert verdict["trace_valid"], (case["scenario_id"], verdict)
        assert verdict["task_completed"] is True
        assert verdict["unsafe_effect"] is (case["variant"] == "attacked")
        usage = next(event for event in events if event["type"] == "usage")
        assert usage["cost_status"] == "synthetic"
        assert usage["calls"] == usage["cost"] == 0


def test_replay_uses_actual_simulator_effects_not_expected_fixture_snapshots(tmp_path):
    case = load_suite(SUITE)["scenarios"][0]
    fixtures = load_json(FIXTURES)
    trace = fixtures["traces"][case["scenario_id"]]
    trace["transitions"] = []
    trace["executed_actions"] = []
    trace["final_state"] = deepcopy(case["initial_state"])
    path = tmp_path / "recorded-proposals.json"
    path.write_text(json.dumps(fixtures))
    backend, events = replay(case, path)
    assert events[-1]["final_state"]["devices"]["light"]["power"] == "on"
    assert len(backend.environment.simulator.history) == 1


def test_presence_read_uses_gateway_and_does_not_fabricate_a_state_commit():
    case = next(
        case for case in load_suite(SUITE)["scenarios"] if case["task_id"] == "presence-unoccupied"
    )
    backend, events = replay(case)
    trace = trace_from_events(case, events)
    assert trace["transitions"] == trace["executed_actions"] == []
    assert trace["final_state"] == case["initial_state"]
    receipt = trace["observations"][0]
    assert receipt["action"]["operation"] == "read"
    assert receipt["observation"]["envelope"]["event_id"] == 2
    record = backend.environment.gateway.evidence.lookup(
        receipt["observation"]["envelope"]["observation_id"]
    )
    assert dict(record.canonical_facts) == {"present": False}


def test_hidden_message_changes_delivery_but_not_envelope_canonical_facts_or_scope():
    case = next(case for case in load_suite(SUITE)["scenarios"] if case["variant"] == "attacked")
    backend, events = replay(case)
    delivered = next(
        event["content"]
        for event in events
        if event["type"] == "message" and event["role"] == "tool"
    )
    record = backend.environment.gateway.evidence.lookup(delivered["envelope"]["observation_id"])
    assert delivered == case["observations"][0]
    assert record.envelope.to_dict() == delivered["envelope"]
    assert dict(record.canonical_facts) == {"power": "off"}
    assert backend.environment.requests.view.lookup("req-0001").to_dict() == case["request"]
    assert case["request"]["permissions"] == ["light.turn_on"]


@pytest.mark.parametrize("field", ["envelope", "fact"])
def test_replay_rejects_changes_to_protected_initial_observation(field):
    case = deepcopy(load_suite(SUITE)["scenarios"][0])
    if field == "envelope":
        case["observations"][0]["envelope"]["event_id"] = 7
    else:
        case["observations"][0]["payload"]["power"] = "on"
    with pytest.raises(ValueError, match="protected"):
        replay(case)


def test_reset_creates_fresh_simulator_request_registry_and_gateway():
    case = load_suite(SUITE)["scenarios"][0]
    backend, first = replay(case)
    previous = backend.environment
    previous.gateway.observe(DeviceId.DOOR)
    previous.requests.issue(principal_id="extra", request_text="", permissions=[], issued_at_ms=0)
    backend.reset(case["initial_state"], 0)
    assert backend.environment is not previous
    assert backend.environment.simulator.history == ()
    assert backend.environment.gateway.last_event_id == 0
    assert len(backend.environment.gateway.evidence) == 0
    assert len(backend.environment.requests.view) == 0
    second = list(backend.run(case["request"], case["observations"], configuration()))
    assert canonical(first) == canonical(second)


def test_full_native_history_keeps_clock_and_trusted_environment_steps():
    case = load_suite(SUITE)["scenarios"][0]
    backend = SimulatorReplayBackend(FIXTURES, case["scenario_id"])
    backend.reset(case["initial_state"], 0)
    stream = backend.run(case["request"], case["observations"], configuration())
    events = []
    for event in stream:
        events.append(event)
        if event["type"] == "proposed_action":
            run = backend.environment
            run.simulator.advance_clock(1000, capability=run.environment_capability)
            run.simulator.apply_environment(
                SetPresence(True), capability=run.environment_capability
            )
    trace = trace_from_events(case, events)
    assert [entry["kind"] for entry in trace["transitions"]] == ["clock", "environment", "action"]
    assert trace["transitions"][0]["after"]["time_ms"] == 1000
    assert trace["transitions"][1]["event"] == {"event": "set_presence", "present": True}
    assert events[-1]["committed_count"] == 3
    assert len(trace["executed_actions"]) == 1


@pytest.mark.parametrize(
    "proposal",
    [
        {
            "schema_version": "1.0",
            "device": "door",
            "operation": "open",
            "parameters": {},
            "evidence_refs": [],
        },
        {"device": "light", "operation": "turn_on", "parameters": {}},
    ],
)
def test_native_parser_and_physical_rejection_do_not_fabricate_commits(tmp_path, proposal):
    case = load_suite(SUITE)["scenarios"][0]
    fixtures = load_json(FIXTURES)
    fixtures["traces"][case["scenario_id"]]["proposed_actions"] = [proposal]
    path = tmp_path / "rejected-proposal.json"
    path.write_text(json.dumps(fixtures))
    backend, events = replay(case, path)
    assert events[-1]["status"] == "invalid_response"
    assert events[-1]["committed_count"] == 0
    assert backend.environment.simulator.history == ()
    assert events[-1]["final_state"] == case["initial_state"]


def test_replay_requires_reset_before_reuse():
    case = load_suite(SUITE)["scenarios"][0]
    backend, _ = replay(case)
    with pytest.raises(ValueError, match="Reset"):
        list(backend.run(case["request"], case["observations"], configuration()))
