"""SIM-01 transition table: every supported effect transition has a fixture."""

from dataclasses import dataclass

import pytest

from effectshield.domain import (
    ActionProposal,
    DeviceId,
    DoorPosition,
    DoorState,
    FanState,
    HomeState,
    LightState,
    LockState,
    Operation,
    Power,
    ThermostatState,
)
from effectshield.domain.catalog import effect_operations
from effectshield.domain.errors import InvalidTransitionError, TransitionErrorCode
from effectshield.domain.events import SetAmbientTemperature, SetPresence
from effectshield.simulator.transitions import (
    apply_action,
    apply_environment_event,
    apply_sequence,
    handled_effects,
)

CLOSED_LOCKED = DoorState(DoorPosition.CLOSED, LockState.LOCKED)
CLOSED_UNLOCKED = DoorState(DoorPosition.CLOSED, LockState.UNLOCKED)
OPEN_UNLOCKED = DoorState(DoorPosition.OPEN, LockState.UNLOCKED)


@dataclass(frozen=True)
class Case:
    name: str
    before: HomeState
    action: ActionProposal
    after: HomeState | None = None
    error: TransitionErrorCode | None = None


def act(device: DeviceId, operation: Operation, **params: float) -> ActionProposal:
    return ActionProposal(device, operation, params)


H = HomeState()
L, F, T, D = DeviceId.LIGHT, DeviceId.FAN, DeviceId.THERMOSTAT, DeviceId.DOOR
Op = Operation

CASES = [
    Case("light on", H, act(L, Op.TURN_ON), H.with_device(L, LightState(Power.ON))),
    Case(
        "light on no-op",
        H.with_device(L, LightState(Power.ON)),
        act(L, Op.TURN_ON),
        H.with_device(L, LightState(Power.ON)),
    ),
    Case("light off", H.with_device(L, LightState(Power.ON)), act(L, Op.TURN_OFF), H),
    Case("fan on", H, act(F, Op.TURN_ON), H.with_device(F, FanState(Power.ON))),
    Case("fan off", H.with_device(F, FanState(Power.ON)), act(F, Op.TURN_OFF), H),
    Case("thermostat on", H, act(T, Op.TURN_ON), H.with_device(T, ThermostatState(power=Power.ON))),
    Case(
        "thermostat off", H.with_device(T, ThermostatState(power=Power.ON)), act(T, Op.TURN_OFF), H
    ),
    Case(
        "setpoint in policy range",
        H,
        act(T, Op.SET_SETPOINT, setpoint_c=24.5),
        H.with_device(T, ThermostatState(setpoint_c=24.5)),
    ),
    Case(
        "setpoint 35 C is a valid device value (no clamping)",
        H,
        act(T, Op.SET_SETPOINT, setpoint_c=35),
        H.with_device(T, ThermostatState(setpoint_c=35.0)),
    ),
    Case(
        "setpoint device max inclusive",
        H,
        act(T, Op.SET_SETPOINT, setpoint_c=50),
        H.with_device(T, ThermostatState(setpoint_c=50.0)),
    ),
    Case(
        "setpoint above device range",
        H,
        act(T, Op.SET_SETPOINT, setpoint_c=50.01),
        error=TransitionErrorCode.SETPOINT_OUTSIDE_DEVICE_RANGE,
    ),
    Case(
        "setpoint below device range",
        H,
        act(T, Op.SET_SETPOINT, setpoint_c=-0.5),
        error=TransitionErrorCode.SETPOINT_OUTSIDE_DEVICE_RANGE,
    ),
    Case(
        "unlock",
        H.with_device(D, CLOSED_LOCKED),
        act(D, Op.UNLOCK),
        H.with_device(D, CLOSED_UNLOCKED),
    ),
    Case(
        "unlock no-op",
        H.with_device(D, OPEN_UNLOCKED),
        act(D, Op.UNLOCK),
        H.with_device(D, OPEN_UNLOCKED),
    ),
    Case(
        "open", H.with_device(D, CLOSED_UNLOCKED), act(D, Op.OPEN), H.with_device(D, OPEN_UNLOCKED)
    ),
    Case(
        "open while locked",
        H.with_device(D, CLOSED_LOCKED),
        act(D, Op.OPEN),
        error=TransitionErrorCode.DOOR_LOCKED_CANNOT_OPEN,
    ),
    Case(
        "close",
        H.with_device(D, OPEN_UNLOCKED),
        act(D, Op.CLOSE),
        H.with_device(D, CLOSED_UNLOCKED),
    ),
    Case(
        "close no-op",
        H.with_device(D, CLOSED_LOCKED),
        act(D, Op.CLOSE),
        H.with_device(D, CLOSED_LOCKED),
    ),
    Case(
        "lock", H.with_device(D, CLOSED_UNLOCKED), act(D, Op.LOCK), H.with_device(D, CLOSED_LOCKED)
    ),
    Case(
        "lock while open",
        H.with_device(D, OPEN_UNLOCKED),
        act(D, Op.LOCK),
        error=TransitionErrorCode.DOOR_OPEN_CANNOT_LOCK,
    ),
    Case(
        "read is not an effect",
        H,
        act(DeviceId.PRESENCE_SENSOR, Op.READ),
        error=TransitionErrorCode.NOT_AN_EFFECT,
    ),
    Case("unsupported pair", H, act(L, Op.LOCK), error=TransitionErrorCode.UNSUPPORTED_OPERATION),
]


@pytest.mark.parametrize("case", CASES, ids=lambda c: c.name)
def test_transition(case: Case) -> None:
    if case.error is None:
        assert apply_action(case.before, case.action) == case.after
    else:
        with pytest.raises(InvalidTransitionError) as info:
            apply_action(case.before, case.action)
        assert info.value.code is case.error


def test_every_effect_operation_has_a_handler_and_a_fixture() -> None:
    catalog = {(s.device, s.operation) for s in effect_operations()}
    assert handled_effects() == catalog
    covered = {(c.action.device, c.action.operation) for c in CASES if c.error is None}
    assert catalog <= covered


def test_sequence_reports_index_of_first_invalid_step() -> None:
    home = H.with_device(D, CLOSED_LOCKED)
    with pytest.raises(InvalidTransitionError) as info:
        apply_sequence(home, [act(L, Op.TURN_ON), act(D, Op.OPEN)])
    assert info.value.index == 1


def test_sequence_returns_every_intermediate_state() -> None:
    home = H.with_device(D, CLOSED_LOCKED)
    states = apply_sequence(home, [act(D, Op.UNLOCK), act(D, Op.OPEN)])
    assert [s.door for s in states] == [CLOSED_UNLOCKED, OPEN_UNLOCKED]


def test_environment_events() -> None:
    assert apply_environment_event(H, SetPresence(True)).presence_sensor.present is True
    assert apply_environment_event(H, SetAmbientTemperature(27)).thermostat.ambient_c == 27.0
