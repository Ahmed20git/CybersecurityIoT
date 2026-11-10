"""Trusted context records: request identity, envelopes and observations.

Trust model from the contract (OBS-01, OBS-02, SIM-06):

- :class:`RequestContext` is issued by the scenario harness. It carries the
  authenticated request, the principal and device-scoped permissions.
- :class:`Envelope` is issued by the gateway. Source identity, gateway time and
  the monotonic event ID are trusted transport metadata.
- :class:`Observation` pairs a trusted envelope with an untrusted payload. The
  attacker may edit designated payload fields or replay an observation with
  its original envelope, but cannot forge or alter the envelope.

Authenticity of the envelope does not make the payload true (OBS-04): trusted
code compares payloads with the canonical facts held by the gateway's evidence
registry.
"""

from __future__ import annotations

import math
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from effectshield.domain.catalog import get_operation_spec
from effectshield.domain.devices import DeviceId, Operation

HARNESS_ISSUER = "scenario_harness"
GATEWAY_ISSUER = "gateway"

JsonScalar = str | int | float | bool


def source_id_for(device: DeviceId) -> str:
    """The gateway-issued source identity for a device's observations."""
    return f"{GATEWAY_ISSUER}/{DeviceId(device).value}"


def observation_id_for(event_id: int) -> str:
    """Observation references are derived from the gateway event ID."""
    return f"obs-{event_id:06d}"


@dataclass(frozen=True, slots=True)
class Permission:
    """Permission for one principal to perform one effect operation on one device."""

    device: DeviceId
    operation: Operation

    def __post_init__(self) -> None:
        spec = get_operation_spec(self.device, self.operation)
        if spec is None or not spec.mutates:
            raise ValueError(f"{self.device}.{self.operation} is not a supported effect operation")


@dataclass(frozen=True, slots=True)
class RequestContext:
    """A harness-issued authenticated user request (OBS-01, rule 2, rule 3).

    Only trusted code constructs these; the agent never supplies them.
    """

    request_id: str
    principal_id: str
    request_text: str
    permissions: frozenset[Permission]
    issued_at_ms: int
    issuer: str = HARNESS_ISSUER

    def __post_init__(self) -> None:
        object.__setattr__(self, "permissions", frozenset(self.permissions))
        for permission in self.permissions:
            if not isinstance(permission, Permission):
                raise ValueError("permissions must contain Permission records")

    def allows(self, device: DeviceId, operation: Operation) -> bool:
        return Permission(device, operation) in self.permissions

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "principal_id": self.principal_id,
            "request_text": self.request_text,
            "permissions": sorted(
                f"{p.device.value}.{p.operation.value}" for p in self.permissions
            ),
            "issued_at_ms": self.issued_at_ms,
            "issuer": self.issuer,
        }


@dataclass(frozen=True, slots=True)
class Envelope:
    """Gateway-issued transport metadata. Immutable once issued."""

    observation_id: str
    device: DeviceId
    source_id: str
    event_id: int
    gateway_time_ms: int
    issuer: str = GATEWAY_ISSUER

    def to_dict(self) -> dict[str, Any]:
        return {
            "observation_id": self.observation_id,
            "device": self.device.value,
            "source_id": self.source_id,
            "event_id": self.event_id,
            "gateway_time_ms": self.gateway_time_ms,
            "issuer": self.issuer,
        }


def validate_payload_value(name: str, value: object) -> JsonScalar:
    if isinstance(value, bool | str):
        return value
    if isinstance(value, int | float):
        if not math.isfinite(value):
            raise ValueError(f"payload field {name} must be finite")
        return value
    raise ValueError(f"payload field {name} must be a JSON scalar")


@dataclass(frozen=True, slots=True)
class Observation:
    """A delivered observation: trusted envelope plus untrusted payload."""

    envelope: Envelope
    payload: Mapping[str, JsonScalar]

    def __post_init__(self) -> None:
        frozen = {k: validate_payload_value(k, v) for k, v in dict(self.payload).items()}
        object.__setattr__(self, "payload", MappingProxyType(frozen))

    def to_agent_dict(self) -> dict[str, Any]:
        """A fresh, JSON-ready copy for the agent. Editing it changes nothing."""
        return {"envelope": self.envelope.to_dict(), "payload": dict(self.payload)}
