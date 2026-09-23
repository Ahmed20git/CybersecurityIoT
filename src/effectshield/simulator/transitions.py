"""Pure device transition functions (SIM-01, SIM-04, SIM-08).

These encode *simulator validity*: what the simulated hardware can physically
do. They deliberately contain no EffectShield policy. Unlocking the door with
nobody present, or setting 35 C, is a valid simulator transition; whether it is
safe is decided later by the mediator. Nothing here clamps values.

Repeating an operation that is already satisfied (e.g. ``turn_on`` when on) is
a valid no-op.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import replace
from types import MappingProxyType

from effectshield.domain.actions import ActionProposal
from effectshield.domain.catalog import get_operation_spec
from effectshield.domain.devices import (
    THERMOSTAT_DEVICE_MAX_C,
    THERMOSTAT_DEVICE_MIN_C,
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
from effectshield.domain.errors import InvalidTransitionError, TransitionErrorCode
from effectshield.domain.events import EnvironmentEvent, SetAmbientTemperature, SetPresence

_Handler = Callable[[HomeState, Mapping[str, float]], HomeState]


def _thermostat(home: HomeState) -> ThermostatState:
    return home.thermostat


def _door(home: HomeState) -> DoorState:
    return home.door


def _set_thermostat_power(power: Power) -> _Handler:
    def handler(home: HomeState, _: Mapping[str, float]) -> HomeState:
        return home.with_device(DeviceId.THERMOSTAT, replace(_thermostat(home), power=power))

    return handler


def _set_setpoint(home: HomeState, params: Mapping[str, float]) -> HomeState:
    value = params["setpoint_c"]
    if not THERMOSTAT_DEVICE_MIN_C <= value <= THERMOSTAT_DEVICE_MAX_C:
        raise InvalidTransitionError(
            TransitionErrorCode.SETPOINT_OUTSIDE_DEVICE_RANGE,
            f"{value} C is outside {THERMOSTAT_DEVICE_MIN_C}-{THERMOSTAT_DEVICE_MAX_C} C",
        )
    return home.with_device(DeviceId.THERMOSTAT, replace(_thermostat(home), setpoint_c=value))


def _lock(home: HomeState, _: Mapping[str, float]) -> HomeState:
    if _door(home).position is DoorPosition.OPEN:
        raise InvalidTransitionError(
            TransitionErrorCode.DOOR_OPEN_CANNOT_LOCK, "close the door before locking it"
        )
    return home.with_device(DeviceId.DOOR, replace(_door(home), lock=LockState.LOCKED))


def _unlock(home: HomeState, _: Mapping[str, float]) -> HomeState:
    return home.with_device(DeviceId.DOOR, replace(_door(home), lock=LockState.UNLOCKED))


def _open(home: HomeState, _: Mapping[str, float]) -> HomeState:
    if _door(home).lock is LockState.LOCKED:
        raise InvalidTransitionError(
            TransitionErrorCode.DOOR_LOCKED_CANNOT_OPEN, "unlock the door before opening it"
        )
    return home.with_device(DeviceId.DOOR, replace(_door(home), position=DoorPosition.OPEN))


def _close(home: HomeState, _: Mapping[str, float]) -> HomeState:
    return home.with_device(DeviceId.DOOR, replace(_door(home), position=DoorPosition.CLOSED))


_HANDLERS: Mapping[tuple[DeviceId, Operation], _Handler] = MappingProxyType(
    {
        (DeviceId.LIGHT, Operation.TURN_ON): lambda h, _: h.with_device(
            DeviceId.LIGHT, LightState(Power.ON)
        ),
        (DeviceId.LIGHT, Operation.TURN_OFF): lambda h, _: h.with_device(
            DeviceId.LIGHT, LightState(Power.OFF)
        ),
        (DeviceId.FAN, Operation.TURN_ON): lambda h, _: h.with_device(
            DeviceId.FAN, FanState(Power.ON)
        ),
        (DeviceId.FAN, Operation.TURN_OFF): lambda h, _: h.with_device(
            DeviceId.FAN, FanState(Power.OFF)
        ),
        (DeviceId.THERMOSTAT, Operation.TURN_ON): _set_thermostat_power(Power.ON),
        (DeviceId.THERMOSTAT, Operation.TURN_OFF): _set_thermostat_power(Power.OFF),
        (DeviceId.THERMOSTAT, Operation.SET_SETPOINT): _set_setpoint,
        (DeviceId.DOOR, Operation.LOCK): _lock,
        (DeviceId.DOOR, Operation.UNLOCK): _unlock,
        (DeviceId.DOOR, Operation.OPEN): _open,
        (DeviceId.DOOR, Operation.CLOSE): _close,
    }
)


def handled_effects() -> frozenset[tuple[DeviceId, Operation]]:
    return frozenset(_HANDLERS)


def apply_action(home: HomeState, action: ActionProposal) -> HomeState:
    """Return the state after ``action``, or raise :class:`InvalidTransitionError`."""
    spec = get_operation_spec(action.device, action.operation)
    if spec is None:
        raise InvalidTransitionError(
            TransitionErrorCode.UNSUPPORTED_OPERATION,
            f"{action.device.value} does not support {action.operation.value}",
        )
    if not spec.mutates:
        raise InvalidTransitionError(
            TransitionErrorCode.NOT_AN_EFFECT,
            f"{action.operation.value} is an observation; use the gateway",
        )
    return _HANDLERS[(action.device, action.operation)](home, action.parameters)


def apply_sequence(home: HomeState, actions: Sequence[ActionProposal]) -> tuple[HomeState, ...]:
    """Predict every intermediate state of an ordered sequence without side effects.

    The first invalid step raises :class:`InvalidTransitionError` with ``index`` set.
    """
    states: list[HomeState] = []
    current = home
    for index, action in enumerate(actions):
        try:
            current = apply_action(current, action)
        except InvalidTransitionError as exc:
            raise InvalidTransitionError(exc.code, exc.detail, index=index) from exc
        states.append(current)
    return tuple(states)


def apply_environment_event(home: HomeState, event: EnvironmentEvent) -> HomeState:
    if isinstance(event, SetPresence):
        return home.with_device(
            DeviceId.PRESENCE_SENSOR, replace(home.presence_sensor, present=event.present)
        )
    if isinstance(event, SetAmbientTemperature):
        return home.with_device(
            DeviceId.THERMOSTAT, replace(home.thermostat, ambient_c=event.ambient_c)
        )
    raise TypeError(f"unsupported environment event {type(event).__name__}")
