"""Stable error types and reason codes shared across modules."""

from __future__ import annotations

from enum import StrEnum


class SchemaErrorCode(StrEnum):
    """Why a proposed action failed the typed JSON boundary (SIM-05)."""

    INVALID_ENCODING = "invalid_encoding"
    ACTION_TOO_LARGE = "action_too_large"
    INVALID_JSON = "invalid_json"
    DUPLICATE_KEY = "duplicate_key"
    NON_FINITE_NUMBER = "non_finite_number"
    NOT_AN_OBJECT = "not_an_object"
    UNKNOWN_FIELD = "unknown_field"
    MISSING_FIELD = "missing_field"
    WRONG_TYPE = "wrong_type"
    UNSUPPORTED_SCHEMA_VERSION = "unsupported_schema_version"
    UNKNOWN_DEVICE = "unknown_device"
    UNKNOWN_OPERATION = "unknown_operation"
    UNSUPPORTED_OPERATION = "unsupported_operation"
    UNKNOWN_PARAMETER = "unknown_parameter"
    MISSING_PARAMETER = "missing_parameter"
    INVALID_EVIDENCE_REF = "invalid_evidence_ref"
    TOO_MANY_EVIDENCE_REFS = "too_many_evidence_refs"
    DUPLICATE_EVIDENCE_REF = "duplicate_evidence_ref"


class TransitionErrorCode(StrEnum):
    """Why the simulator rejected an operation as physically invalid (SIM-08).

    These are simulator validity failures, not EffectShield policy decisions.
    """

    UNSUPPORTED_OPERATION = "unsupported_operation"
    NOT_AN_EFFECT = "not_an_effect"
    SETPOINT_OUTSIDE_DEVICE_RANGE = "setpoint_outside_device_range"
    DOOR_LOCKED_CANNOT_OPEN = "door_locked_cannot_open"
    DOOR_OPEN_CANNOT_LOCK = "door_open_cannot_lock"


class ExecutionRejectionCode(StrEnum):
    """Why a transaction was rejected before any state change (SIM-09)."""

    EMPTY_TRANSACTION = "empty_transaction"
    TRANSACTION_TOO_LONG = "transaction_too_long"
    STALE_STATE_VERSION = "stale_state_version"


class EffectShieldError(Exception):
    """Base class for all EffectShield errors."""


class ActionSchemaError(EffectShieldError):
    """A proposed action is structurally invalid."""

    def __init__(self, code: SchemaErrorCode, detail: str) -> None:
        super().__init__(f"{code.value}: {detail}")
        self.code = code
        self.detail = detail


class InvalidTransitionError(EffectShieldError):
    """The simulator cannot perform an operation from the given state."""

    def __init__(self, code: TransitionErrorCode, detail: str, *, index: int | None = None) -> None:
        super().__init__(f"{code.value}: {detail}")
        self.code = code
        self.detail = detail
        self.index = index


class CapabilityError(EffectShieldError, PermissionError):
    """A privileged simulator path was called without its capability."""


class ForbiddenMutationError(EffectShieldError):
    """An observation edit touched a protected or non-designated field (OBS-02)."""


class UnknownObservationError(EffectShieldError):
    """An observation's envelope was not issued by this gateway."""
