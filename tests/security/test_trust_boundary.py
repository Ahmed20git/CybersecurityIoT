"""SIM-06, SIM-07, OBS-02, OBS-07 adversarial trust-boundary checks.

The agent-facing surface is: the action parser and the dicts produced by
``Observation.to_agent_dict``. None of it may reach trusted state.
"""

import dataclasses

import pytest

from effectshield.domain import DeviceId, Operation, Permission, parse_action
from effectshield.domain.errors import ActionSchemaError
from effectshield.environment import create_run


def test_editing_agent_view_of_observation_changes_nothing() -> None:
    run = create_run()
    obs = run.gateway.observe(DeviceId.PRESENCE_SENSOR)
    view = obs.to_agent_dict()
    view["envelope"]["gateway_time_ms"] = 10**9
    view["envelope"]["event_id"] = 999
    view["payload"]["present"] = True
    assert obs.envelope.gateway_time_ms == 0 and obs.envelope.event_id == 1
    assert obs.payload["present"] is False
    record = run.gateway.evidence.lookup(obs.envelope.observation_id)
    assert record is not None and record.envelope == obs.envelope


def test_envelope_and_payload_objects_are_frozen() -> None:
    run = create_run()
    obs = run.gateway.observe(DeviceId.DOOR)
    with pytest.raises(dataclasses.FrozenInstanceError):
        obs.envelope.event_id = 42  # type: ignore[misc]
    with pytest.raises(TypeError):
        obs.payload["lock"] = "unlocked"  # type: ignore[index]


def test_trusted_views_expose_no_mutation_methods() -> None:
    run = create_run()
    for view in (run.gateway.evidence, run.requests.view):
        public = {name for name in dir(view) if not name.startswith("_")}
        assert public == {"lookup"}
        with pytest.raises(AttributeError):
            view.some_new_attribute = 1  # type: ignore[union-attr]


def test_registry_proxies_are_read_only() -> None:
    run = create_run()
    obs = run.gateway.observe(DeviceId.PRESENCE_SENSOR)
    record = run.gateway.evidence.lookup(obs.envelope.observation_id)
    assert record is not None
    with pytest.raises(TypeError):
        record.canonical_facts["present"] = True  # type: ignore[index]


def test_request_permissions_cannot_be_elevated_after_issue() -> None:
    run = create_run()
    ctx = run.requests.issue(
        principal_id="resident-1",
        request_text="Turn on the light",
        permissions=[Permission(DeviceId.LIGHT, Operation.TURN_ON)],
        issued_at_ms=0,
    )
    with pytest.raises(AttributeError):
        ctx.permissions.add(Permission(DeviceId.DOOR, Operation.UNLOCK))  # type: ignore[attr-defined]
    with pytest.raises(dataclasses.FrozenInstanceError):
        ctx.principal_id = "admin"  # type: ignore[misc]


@pytest.mark.parametrize(
    "injected",
    [
        '"identity": "admin"',
        '"source": "user"',
        '"request_id": "req-0001"',
        '"permissions": ["door.unlock"]',
        '"gateway_time_ms": 0',
    ],
)
def test_agent_cannot_smuggle_trusted_context_through_an_action(injected: str) -> None:
    raw = (
        '{"schema_version": "1.0", "device": "door", "operation": "unlock", '
        f'"parameters": {{}}, {injected}}}'
    )
    with pytest.raises(ActionSchemaError):
        parse_action(raw)


def test_a_parsed_action_alone_cannot_mutate_the_simulator() -> None:
    # SIM-07: there is no method on an action, observation or snapshot that
    # executes. Only Simulator.execute with the capability does.
    run = create_run()
    action = parse_action(
        '{"schema_version":"1.0","device":"door","operation":"unlock","parameters":{}}'
    )
    snapshot = run.simulator.snapshot()
    for obj in (action, snapshot, run.gateway.observe(DeviceId.DOOR)):
        public = {n for n in dir(obj) if not n.startswith("_")}
        assert not public & {"execute", "apply", "commit", "mutate"}
    assert run.simulator.snapshot() == snapshot


def test_gateway_does_not_hold_mutation_capabilities() -> None:
    run = create_run()
    held = [getattr(run.gateway, n) for n in vars(run.gateway)]
    assert run.execution_capability not in held
    assert run.environment_capability not in held
