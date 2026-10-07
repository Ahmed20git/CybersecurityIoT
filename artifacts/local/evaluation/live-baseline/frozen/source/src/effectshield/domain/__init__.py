"""Shared typed records and errors. No simulator, model or experiment dependencies."""

from effectshield.domain.actions import (
    MAX_ACTION_BYTES,
    SCHEMA_VERSION,
    ActionProposal,
    action_from_object,
    parse_action,
)
from effectshield.domain.catalog import (
    OPERATION_CATALOG,
    OperationSpec,
    ParameterSpec,
    get_operation_spec,
    supported_operations,
)
from effectshield.domain.context import (
    Envelope,
    Observation,
    Permission,
    RequestContext,
)
from effectshield.domain.devices import (
    DeviceId,
    DoorPosition,
    DoorState,
    FanState,
    HomeSnapshot,
    HomeState,
    LightState,
    LockState,
    Operation,
    Power,
    PresenceState,
    ThermostatState,
)
from effectshield.domain.events import EnvironmentEvent, SetAmbientTemperature, SetPresence

__all__ = [
    "MAX_ACTION_BYTES",
    "OPERATION_CATALOG",
    "SCHEMA_VERSION",
    "ActionProposal",
    "DeviceId",
    "DoorPosition",
    "DoorState",
    "EnvironmentEvent",
    "Envelope",
    "FanState",
    "HomeSnapshot",
    "HomeState",
    "LightState",
    "LockState",
    "Observation",
    "Operation",
    "OperationSpec",
    "ParameterSpec",
    "Permission",
    "Power",
    "PresenceState",
    "RequestContext",
    "SetAmbientTemperature",
    "SetPresence",
    "ThermostatState",
    "action_from_object",
    "get_operation_spec",
    "parse_action",
    "supported_operations",
]
