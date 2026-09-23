"""Device identifiers, operations and immutable device state (SIM-01, SIM-04).

All state objects are frozen. The simulator replaces them on each transition,
so a snapshot handed to any other component cannot alter core state (SIM-02).

The semantics below are the *proposed* D04 baseline; see ``docs/interfaces.md``.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, replace
from enum import StrEnum
from typing import Any

# Physical limits of the simulated thermostat hardware. Deliberately wider than
# the contract's 16-30 C policy range so that a value such as 35 C is a valid
# simulator operation that reaches the mediator's policy check (SIM-05, SIM-08).
THERMOSTAT_DEVICE_MIN_C = 0.0
THERMOSTAT_DEVICE_MAX_C = 50.0


class DeviceId(StrEnum):
    LIGHT = "light"
    FAN = "fan"
    THERMOSTAT = "thermostat"
    DOOR = "door"
    PRESENCE_SENSOR = "presence_sensor"


class Operation(StrEnum):
    READ = "read"
    TURN_ON = "turn_on"
    TURN_OFF = "turn_off"
    SET_SETPOINT = "set_setpoint"
    LOCK = "lock"
    UNLOCK = "unlock"
    OPEN = "open"
    CLOSE = "close"


class Power(StrEnum):
    ON = "on"
    OFF = "off"


class DoorPosition(StrEnum):
    OPEN = "open"
    CLOSED = "closed"


class LockState(StrEnum):
    LOCKED = "locked"
    UNLOCKED = "unlocked"


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def is_json_number(value: object) -> bool:
    """True for int/float but not bool, which Python treats as an int."""
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _finite_celsius(value: object, name: str) -> float:
    _require(is_json_number(value), f"{name} must be a number")
    as_float = float(value)  # type: ignore[arg-type]
    _require(math.isfinite(as_float), f"{name} must be finite")
    return as_float


@dataclass(frozen=True, slots=True)
class LightState:
    power: Power = Power.OFF

    def __post_init__(self) -> None:
        _require(isinstance(self.power, Power), "light power must be a Power")

    def to_dict(self) -> dict[str, Any]:
        return {"power": self.power.value}


@dataclass(frozen=True, slots=True)
class FanState:
    """On/off only: the contract assumes no speed feature."""

    power: Power = Power.OFF

    def __post_init__(self) -> None:
        _require(isinstance(self.power, Power), "fan power must be a Power")

    def to_dict(self) -> dict[str, Any]:
        return {"power": self.power.value}


@dataclass(frozen=True, slots=True)
class ThermostatState:
    """Power, target setpoint and the simulated ambient reading, all in Celsius."""

    power: Power = Power.OFF
    setpoint_c: float = 21.0
    ambient_c: float = 21.0

    def __post_init__(self) -> None:
        _require(isinstance(self.power, Power), "thermostat power must be a Power")
        setpoint = _finite_celsius(self.setpoint_c, "setpoint_c")
        _require(
            THERMOSTAT_DEVICE_MIN_C <= setpoint <= THERMOSTAT_DEVICE_MAX_C,
            "setpoint_c is outside the device range",
        )
        object.__setattr__(self, "setpoint_c", setpoint)
        object.__setattr__(self, "ambient_c", _finite_celsius(self.ambient_c, "ambient_c"))

    def to_dict(self) -> dict[str, Any]:
        return {
            "power": self.power.value,
            "setpoint_c": self.setpoint_c,
            "ambient_c": self.ambient_c,
        }


@dataclass(frozen=True, slots=True)
class DoorState:
    """An open door cannot be locked; that combination is not a valid state."""

    position: DoorPosition = DoorPosition.CLOSED
    lock: LockState = LockState.LOCKED

    def __post_init__(self) -> None:
        _require(isinstance(self.position, DoorPosition), "position must be a DoorPosition")
        _require(isinstance(self.lock, LockState), "lock must be a LockState")
        _require(
            not (self.position is DoorPosition.OPEN and self.lock is LockState.LOCKED),
            "an open door cannot be locked",
        )

    def to_dict(self) -> dict[str, Any]:
        return {"position": self.position.value, "lock": self.lock.value}


@dataclass(frozen=True, slots=True)
class PresenceState:
    """Read-only for the agent; changed only by trusted environment events."""

    present: bool = False

    def __post_init__(self) -> None:
        _require(isinstance(self.present, bool), "present must be a bool")

    def to_dict(self) -> dict[str, Any]:
        return {"present": self.present}


DeviceState = LightState | FanState | ThermostatState | DoorState | PresenceState

_STATE_TYPES: dict[DeviceId, type] = {
    DeviceId.LIGHT: LightState,
    DeviceId.FAN: FanState,
    DeviceId.THERMOSTAT: ThermostatState,
    DeviceId.DOOR: DoorState,
    DeviceId.PRESENCE_SENSOR: PresenceState,
}


@dataclass(frozen=True, slots=True)
class HomeState:
    """The complete state of exactly the five full-scope devices."""

    light: LightState = LightState()
    fan: FanState = FanState()
    thermostat: ThermostatState = ThermostatState()
    door: DoorState = DoorState()
    presence_sensor: PresenceState = PresenceState()

    def __post_init__(self) -> None:
        for device, state_type in _STATE_TYPES.items():
            _require(
                isinstance(getattr(self, device.value), state_type),
                f"{device.value} must be a {state_type.__name__}",
            )

    def device(self, device: DeviceId) -> DeviceState:
        state: DeviceState = getattr(self, DeviceId(device).value)
        return state

    def with_device(self, device: DeviceId, state: DeviceState) -> HomeState:
        # __post_init__ re-checks that the state type matches the device.
        changes: dict[str, Any] = {DeviceId(device).value: state}
        return replace(self, **changes)

    def to_dict(self) -> dict[str, dict[str, Any]]:
        return {device.value: self.device(device).to_dict() for device in DeviceId}


@dataclass(frozen=True, slots=True)
class HomeSnapshot:
    """An immutable view of simulator state at one version and simulated time."""

    state_version: int
    time_ms: int
    home: HomeState

    def to_dict(self) -> dict[str, Any]:
        return {
            "state_version": self.state_version,
            "time_ms": self.time_ms,
            "devices": self.home.to_dict(),
        }
