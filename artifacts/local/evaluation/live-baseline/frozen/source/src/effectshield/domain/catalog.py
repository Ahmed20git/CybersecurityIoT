"""The supported device/operation/parameter catalog (SIM-04, SIM-05, rule 1).

This is the single source of truth for which typed actions exist. The action
parser, the simulator and permission records all read it.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType

from effectshield.domain.devices import DeviceId, Operation


class ParameterKind(StrEnum):
    NUMBER = "number"


@dataclass(frozen=True, slots=True)
class ParameterSpec:
    name: str
    kind: ParameterKind
    unit: str | None = None


@dataclass(frozen=True, slots=True)
class OperationSpec:
    device: DeviceId
    operation: Operation
    parameters: tuple[ParameterSpec, ...] = ()
    mutates: bool = True
    """False for reads, which produce a gateway observation and no state change."""

    @property
    def parameter_names(self) -> frozenset[str]:
        return frozenset(p.name for p in self.parameters)


_SETPOINT = ParameterSpec("setpoint_c", ParameterKind.NUMBER, unit="C")

_SPECS: tuple[OperationSpec, ...] = (
    OperationSpec(DeviceId.LIGHT, Operation.READ, mutates=False),
    OperationSpec(DeviceId.LIGHT, Operation.TURN_ON),
    OperationSpec(DeviceId.LIGHT, Operation.TURN_OFF),
    OperationSpec(DeviceId.FAN, Operation.READ, mutates=False),
    OperationSpec(DeviceId.FAN, Operation.TURN_ON),
    OperationSpec(DeviceId.FAN, Operation.TURN_OFF),
    OperationSpec(DeviceId.THERMOSTAT, Operation.READ, mutates=False),
    OperationSpec(DeviceId.THERMOSTAT, Operation.TURN_ON),
    OperationSpec(DeviceId.THERMOSTAT, Operation.TURN_OFF),
    OperationSpec(DeviceId.THERMOSTAT, Operation.SET_SETPOINT, (_SETPOINT,)),
    OperationSpec(DeviceId.DOOR, Operation.READ, mutates=False),
    OperationSpec(DeviceId.DOOR, Operation.LOCK),
    OperationSpec(DeviceId.DOOR, Operation.UNLOCK),
    OperationSpec(DeviceId.DOOR, Operation.OPEN),
    OperationSpec(DeviceId.DOOR, Operation.CLOSE),
    OperationSpec(DeviceId.PRESENCE_SENSOR, Operation.READ, mutates=False),
)

OPERATION_CATALOG: Mapping[tuple[DeviceId, Operation], OperationSpec] = MappingProxyType(
    {(spec.device, spec.operation): spec for spec in _SPECS}
)


def get_operation_spec(device: DeviceId, operation: Operation) -> OperationSpec | None:
    return OPERATION_CATALOG.get((device, operation))


def supported_operations(device: DeviceId) -> tuple[Operation, ...]:
    return tuple(spec.operation for spec in _SPECS if spec.device is device)


def effect_operations() -> tuple[OperationSpec, ...]:
    return tuple(spec for spec in _SPECS if spec.mutates)
