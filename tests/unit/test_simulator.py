"""SIM-02, SIM-07, SIM-08, SIM-09 simulator ownership and transactions."""

import dataclasses

import pytest

from effectshield.domain import ActionProposal, DeviceId, HomeState, LockState, Operation, Power
from effectshield.domain.errors import (
    CapabilityError,
    ExecutionRejectionCode,
    TransitionErrorCode,
)
from effectshield.domain.events import SetPresence
from effectshield.environment import create_run
from effectshield.simulator import MAX_TRANSACTION_ACTIONS, Simulator, TraceKind

LIGHT_ON = ActionProposal(DeviceId.LIGHT, Operation.TURN_ON)
UNLOCK = ActionProposal(DeviceId.DOOR, Operation.UNLOCK)
OPEN = ActionProposal(DeviceId.DOOR, Operation.OPEN)


def test_snapshot_is_immutable_and_detached() -> None:
    run = create_run()
    snap = run.simulator.snapshot()
    with pytest.raises(dataclasses.FrozenInstanceError):
        snap.home.light.power = Power.ON  # type: ignore[misc]
    exported = snap.to_dict()
    exported["devices"]["light"]["power"] = "on"
    assert run.simulator.snapshot().home.light.power is Power.OFF


def test_committed_transaction_advances_version_and_records_trace() -> None:
    run = create_run()
    result = run.simulator.execute(
        [UNLOCK, OPEN], expected_version=0, capability=run.execution_capability
    )
    assert result.committed
    assert (result.version_before, result.version_after) == (0, 2)
    assert [e.action for e in result.entries] == [UNLOCK, OPEN]
    assert result.entries[0].after == result.entries[1].before
    assert run.simulator.history == result.entries


def test_no_op_does_not_bump_version() -> None:
    run = create_run()
    close = ActionProposal(DeviceId.DOOR, Operation.CLOSE)
    result = run.simulator.execute([close], expected_version=0, capability=run.execution_capability)
    assert result.committed and result.version_after == 0
    assert not result.entries[0].changed


def test_invalid_step_rejects_whole_transaction_without_effect() -> None:
    run = create_run()
    before = run.simulator.snapshot()
    # Light would turn on, but opening a locked door is invalid: all-or-nothing.
    result = run.simulator.execute(
        [LIGHT_ON, OPEN], expected_version=0, capability=run.execution_capability
    )
    assert not result.committed
    assert result.reason_code == TransitionErrorCode.DOOR_LOCKED_CANNOT_OPEN
    assert result.failed_index == 1
    assert run.simulator.snapshot() == before
    assert run.simulator.history == ()


def test_stale_version_is_rejected() -> None:
    run = create_run()
    checked_version = run.simulator.state_version
    run.simulator.apply_environment(SetPresence(True), capability=run.environment_capability)
    result = run.simulator.execute(
        [UNLOCK], expected_version=checked_version, capability=run.execution_capability
    )
    assert result.reason_code == ExecutionRejectionCode.STALE_STATE_VERSION
    assert run.simulator.snapshot().home.door.lock is LockState.LOCKED


def test_empty_and_overlong_transactions_are_rejected() -> None:
    run = create_run()
    cap = run.execution_capability
    assert run.simulator.execute([], expected_version=0, capability=cap).reason_code == (
        ExecutionRejectionCode.EMPTY_TRANSACTION
    )
    too_long = [LIGHT_ON] * (MAX_TRANSACTION_ACTIONS + 1)
    assert run.simulator.execute(too_long, expected_version=0, capability=cap).reason_code == (
        ExecutionRejectionCode.TRANSACTION_TOO_LONG
    )


def test_policy_unsafe_actions_still_execute_in_the_simulator() -> None:
    # SIM-08: the simulator is not the mediator. Nobody is present, and 35 C
    # is outside policy, but both are physically valid and measurable.
    run = create_run()
    setpoint = ActionProposal(DeviceId.THERMOSTAT, Operation.SET_SETPOINT, {"setpoint_c": 35})
    result = run.simulator.execute(
        [UNLOCK, OPEN, setpoint], expected_version=0, capability=run.execution_capability
    )
    assert result.committed
    home = run.simulator.snapshot().home
    assert home.thermostat.setpoint_c == 35.0
    assert home.presence_sensor.present is False


def test_capabilities_are_required_and_not_interchangeable() -> None:
    run = create_run()
    sim = run.simulator
    with pytest.raises(CapabilityError):
        sim.execute([LIGHT_ON], expected_version=0, capability=run.environment_capability)  # type: ignore[arg-type]
    with pytest.raises(CapabilityError):
        sim.execute([LIGHT_ON], expected_version=0, capability=None)  # type: ignore[arg-type]
    with pytest.raises(CapabilityError):
        sim.advance_clock(10, capability=run.execution_capability)  # type: ignore[arg-type]
    other = create_run()
    with pytest.raises(CapabilityError):
        sim.execute([LIGHT_ON], expected_version=0, capability=other.execution_capability)
    with pytest.raises(CapabilityError):
        sim.issue_capabilities()


def test_clock_only_moves_forward_and_is_traced() -> None:
    run = create_run(start_time_ms=1_000)
    entry = run.simulator.advance_clock(500, capability=run.environment_capability)
    assert entry.kind is TraceKind.CLOCK
    assert (entry.before.time_ms, entry.after.time_ms) == (1_000, 1_500)
    for bad in (0, -1, 1.5):
        with pytest.raises(ValueError):
            run.simulator.advance_clock(bad, capability=run.environment_capability)  # type: ignore[arg-type]


def test_preview_does_not_mutate() -> None:
    run = create_run()
    states = run.simulator.preview([UNLOCK, OPEN])
    assert len(states) == 2
    assert run.simulator.snapshot().home == HomeState()


def test_simulator_rejects_bad_construction() -> None:
    with pytest.raises(TypeError):
        Simulator({})  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        Simulator(HomeState(), start_time_ms=-1)
