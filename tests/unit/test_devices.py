"""SIM-01/SIM-04 device state invariants."""

import math

import pytest

from effectshield.domain import (
    DeviceId,
    DoorPosition,
    DoorState,
    HomeState,
    LockState,
    PresenceState,
    ThermostatState,
    supported_operations,
)
from effectshield.domain.devices import Operation


def test_home_has_exactly_the_five_contract_devices() -> None:
    assert set(HomeState().to_dict()) == {
        "light",
        "fan",
        "thermostat",
        "door",
        "presence_sensor",
    }
    assert len(DeviceId) == 5


def test_presence_sensor_is_read_only_for_the_agent() -> None:
    assert supported_operations(DeviceId.PRESENCE_SENSOR) == (Operation.READ,)


def test_open_and_locked_is_not_a_valid_door_state() -> None:
    with pytest.raises(ValueError):
        DoorState(DoorPosition.OPEN, LockState.LOCKED)


@pytest.mark.parametrize("value", [math.nan, math.inf, "21", True, None, -1.0, 50.5])
def test_invalid_thermostat_setpoints_cannot_be_constructed(value: object) -> None:
    with pytest.raises(ValueError):
        ThermostatState(setpoint_c=value)  # type: ignore[arg-type]


def test_presence_must_be_boolean() -> None:
    with pytest.raises(ValueError):
        PresenceState(present=1)  # type: ignore[arg-type]


def test_home_state_rejects_wrong_device_type() -> None:
    with pytest.raises(ValueError):
        HomeState(door=PresenceState())  # type: ignore[arg-type]


def test_to_dict_returns_fresh_copies() -> None:
    home = HomeState()
    exported = home.to_dict()
    exported["door"]["lock"] = "unlocked"
    assert home.door.lock is LockState.LOCKED
