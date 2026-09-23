"""The versioned typed JSON action boundary (SIM-05, SIM-06, rule 1).

The agent's only way to propose an effect is a JSON object of the form::

    {
      "schema_version": "1.0",
      "device": "thermostat",
      "operation": "set_setpoint",
      "parameters": {"setpoint_c": 22},
      "evidence_refs": ["obs-000003"]
    }

``evidence_refs`` is optional. Everything else in the object is rejected,
including agent-asserted ``identity``, ``source``, timestamps or event IDs:
trusted context is never taken from agent-controlled fields (SIM-06).

This module checks *structure* only. A finite 35 C setpoint parses
successfully so that policy bounds and repair can be tested later.
"""

from __future__ import annotations

import json
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, TypeVar

from effectshield.domain.catalog import ParameterKind, get_operation_spec
from effectshield.domain.devices import DeviceId, Operation, is_json_number
from effectshield.domain.errors import ActionSchemaError, SchemaErrorCode

SCHEMA_VERSION = "1.0"
MAX_ACTION_BYTES = 4096
MAX_EVIDENCE_REFS = 8
EVIDENCE_REF_PATTERN = re.compile(r"obs-[0-9]{6,12}")

_REQUIRED_FIELDS = frozenset({"schema_version", "device", "operation", "parameters"})
_OPTIONAL_FIELDS = frozenset({"evidence_refs"})
_ALLOWED_FIELDS = _REQUIRED_FIELDS | _OPTIONAL_FIELDS

_E = TypeVar("_E", DeviceId, Operation)


def _empty_parameters() -> Mapping[str, float]:
    return MappingProxyType({})


@dataclass(frozen=True, slots=True)
class ActionProposal:
    """A structurally valid, immutable action proposed by the untrusted agent."""

    device: DeviceId
    operation: Operation
    parameters: Mapping[str, float] = field(default_factory=_empty_parameters)
    evidence_refs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        # Freeze a caller-supplied dict so later edits to it cannot alter us.
        object.__setattr__(self, "parameters", MappingProxyType(dict(self.parameters)))
        object.__setattr__(self, "evidence_refs", tuple(self.evidence_refs))

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "device": self.device.value,
            "operation": self.operation.value,
            "parameters": dict(self.parameters),
            "evidence_refs": list(self.evidence_refs),
        }


class _DuplicateKey(Exception):
    pass


class _NonFinite(Exception):
    pass


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKey(key)
        result[key] = value
    return result


def _reject_constant(name: str) -> Any:
    raise _NonFinite(name)


def _finite_float(text: str) -> float:
    value = float(text)
    if not math.isfinite(value):
        raise _NonFinite(text)
    return value


def parse_action(raw: str | bytes) -> ActionProposal:
    """Parse and validate raw agent output into an :class:`ActionProposal`.

    Raises :class:`ActionSchemaError` with a stable code on any failure.
    """
    if isinstance(raw, bytes):
        encoded = raw
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ActionSchemaError(SchemaErrorCode.INVALID_ENCODING, "not UTF-8") from exc
    elif isinstance(raw, str):
        text = raw
        try:
            encoded = raw.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise ActionSchemaError(SchemaErrorCode.INVALID_ENCODING, "not UTF-8") from exc
    else:
        raise ActionSchemaError(SchemaErrorCode.WRONG_TYPE, "raw action must be str or bytes")

    if len(encoded) > MAX_ACTION_BYTES:
        raise ActionSchemaError(
            SchemaErrorCode.ACTION_TOO_LARGE, f"{len(encoded)} bytes > {MAX_ACTION_BYTES}"
        )

    try:
        decoded = json.loads(
            text,
            object_pairs_hook=_reject_duplicates,
            parse_constant=_reject_constant,
            parse_float=_finite_float,
        )
    except _DuplicateKey as exc:
        raise ActionSchemaError(SchemaErrorCode.DUPLICATE_KEY, f"duplicate key {exc}") from exc
    except _NonFinite as exc:
        raise ActionSchemaError(SchemaErrorCode.NON_FINITE_NUMBER, str(exc)) from exc
    except (ValueError, RecursionError) as exc:
        raise ActionSchemaError(SchemaErrorCode.INVALID_JSON, "malformed JSON") from exc

    return action_from_object(decoded)


def action_from_object(obj: object) -> ActionProposal:
    """Validate an already-decoded JSON value.

    Prefer :func:`parse_action` for raw model output: duplicate keys and
    non-finite literals can only be detected before decoding.
    """
    if not isinstance(obj, dict):
        raise ActionSchemaError(SchemaErrorCode.NOT_AN_OBJECT, "action must be a JSON object")

    unknown = set(obj) - _ALLOWED_FIELDS
    if unknown:
        raise ActionSchemaError(SchemaErrorCode.UNKNOWN_FIELD, ", ".join(sorted(unknown)))
    missing = _REQUIRED_FIELDS - set(obj)
    if missing:
        raise ActionSchemaError(SchemaErrorCode.MISSING_FIELD, ", ".join(sorted(missing)))

    version = obj["schema_version"]
    if not isinstance(version, str):
        raise ActionSchemaError(SchemaErrorCode.WRONG_TYPE, "schema_version must be a string")
    if version != SCHEMA_VERSION:
        raise ActionSchemaError(SchemaErrorCode.UNSUPPORTED_SCHEMA_VERSION, version)

    device = _parse_enum(obj["device"], DeviceId, "device", SchemaErrorCode.UNKNOWN_DEVICE)
    operation = _parse_enum(
        obj["operation"], Operation, "operation", SchemaErrorCode.UNKNOWN_OPERATION
    )
    spec = get_operation_spec(device, operation)
    if spec is None:
        raise ActionSchemaError(
            SchemaErrorCode.UNSUPPORTED_OPERATION,
            f"{device.value} does not support {operation.value}",
        )

    raw_params = obj["parameters"]
    if not isinstance(raw_params, dict):
        raise ActionSchemaError(SchemaErrorCode.WRONG_TYPE, "parameters must be an object")
    unknown_params = set(raw_params) - spec.parameter_names
    if unknown_params:
        raise ActionSchemaError(
            SchemaErrorCode.UNKNOWN_PARAMETER, ", ".join(sorted(unknown_params))
        )
    parameters: dict[str, float] = {}
    for param in spec.parameters:
        if param.name not in raw_params:
            raise ActionSchemaError(SchemaErrorCode.MISSING_PARAMETER, param.name)
        value = raw_params[param.name]
        if param.kind is ParameterKind.NUMBER:
            if not is_json_number(value):
                raise ActionSchemaError(
                    SchemaErrorCode.WRONG_TYPE, f"{param.name} must be a number"
                )
            if not math.isfinite(float(value)):
                raise ActionSchemaError(SchemaErrorCode.NON_FINITE_NUMBER, param.name)
            parameters[param.name] = float(value)

    evidence_refs = _parse_evidence_refs(obj.get("evidence_refs", []))
    return ActionProposal(device, operation, parameters, evidence_refs)


def _parse_enum(value: object, enum_type: type[_E], name: str, unknown_code: SchemaErrorCode) -> _E:
    if not isinstance(value, str):
        raise ActionSchemaError(SchemaErrorCode.WRONG_TYPE, f"{name} must be a string")
    try:
        return enum_type(value)
    except ValueError as exc:
        raise ActionSchemaError(unknown_code, value) from exc


def _parse_evidence_refs(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ActionSchemaError(SchemaErrorCode.WRONG_TYPE, "evidence_refs must be a list")
    if len(value) > MAX_EVIDENCE_REFS:
        raise ActionSchemaError(
            SchemaErrorCode.TOO_MANY_EVIDENCE_REFS, f"{len(value)} > {MAX_EVIDENCE_REFS}"
        )
    for ref in value:
        if not isinstance(ref, str) or not EVIDENCE_REF_PATTERN.fullmatch(ref):
            raise ActionSchemaError(SchemaErrorCode.INVALID_EVIDENCE_REF, repr(ref)[:64])
    if len(set(value)) != len(value):
        raise ActionSchemaError(SchemaErrorCode.DUPLICATE_EVIDENCE_REF, "refs must be unique")
    return tuple(value)
