"""SIM-02/SIM-03 determinism and run isolation, plus a hand-executable task."""

import json
from typing import Any

from effectshield.domain import DeviceId, Operation, Permission, parse_action
from effectshield.domain.events import SetPresence
from effectshield.environment import create_run


def scripted_run() -> list[dict[str, Any]]:
    """Resident arrives, asks to enter; an agent unlocks and opens the door."""
    run = create_run()
    sim, env_cap, exec_cap = run.simulator, run.environment_capability, run.execution_capability
    run.requests.issue(
        principal_id="resident-1",
        request_text="Let me in",
        permissions=[
            Permission(DeviceId.DOOR, Operation.UNLOCK),
            Permission(DeviceId.DOOR, Operation.OPEN),
        ],
        issued_at_ms=sim.now_ms,
    )
    sim.advance_clock(1_000, capability=env_cap)
    sim.apply_environment(SetPresence(True), capability=env_cap)
    presence = run.gateway.observe(DeviceId.PRESENCE_SENSOR)
    ref = presence.envelope.observation_id
    actions = [
        parse_action(
            json.dumps(
                {
                    "schema_version": "1.0",
                    "device": "door",
                    "operation": op,
                    "parameters": {},
                    "evidence_refs": [ref],
                }
            )
        )
        for op in ("unlock", "open")
    ]
    result = sim.execute(actions, expected_version=sim.state_version, capability=exec_cap)
    assert result.committed
    return [entry.to_dict() for entry in sim.history]


def test_identical_inputs_produce_identical_traces() -> None:
    assert scripted_run() == scripted_run()


def test_runs_are_isolated() -> None:
    first = create_run()
    first.simulator.apply_environment(SetPresence(True), capability=first.environment_capability)
    first.gateway.observe(DeviceId.DOOR)
    first.requests.issue(principal_id="p", request_text="", permissions=[], issued_at_ms=0)
    second = create_run()
    assert second.simulator.snapshot() == first.simulator.history[0].before
    assert second.simulator.history == ()
    assert second.gateway.last_event_id == 0
    assert len(second.gateway.evidence) == 0
    assert len(second.requests.view) == 0
    assert second.gateway.observe(DeviceId.DOOR).envelope.event_id == 1


def test_scripted_trace_shape() -> None:
    trace = scripted_run()
    assert [e["kind"] for e in trace] == ["clock", "environment", "action", "action"]
    assert trace[-1]["after"]["devices"]["door"] == {"position": "open", "lock": "unlocked"}
    assert trace[-1]["after"]["state_version"] == 3
