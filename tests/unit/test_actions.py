"""SIM-05 typed JSON action boundary and rule 1 schema checks."""

import json

import pytest

from effectshield.domain import (
    MAX_ACTION_BYTES,
    OPERATION_CATALOG,
    ActionProposal,
    DeviceId,
    Operation,
    parse_action,
)
from effectshield.domain.errors import ActionSchemaError, SchemaErrorCode


def action_json(**overrides: object) -> str:
    base: dict[str, object] = {
        "schema_version": "1.0",
        "device": "thermostat",
        "operation": "set_setpoint",
        "parameters": {"setpoint_c": 22},
    }
    base.update(overrides)
    return json.dumps(base)


def assert_code(raw: str | bytes, code: SchemaErrorCode) -> None:
    with pytest.raises(ActionSchemaError) as info:
        parse_action(raw)
    assert info.value.code is code


def test_valid_setpoint_parses_to_float() -> None:
    action = parse_action(action_json())
    assert action == ActionProposal(
        DeviceId.THERMOSTAT, Operation.SET_SETPOINT, {"setpoint_c": 22.0}
    )
    assert isinstance(action.parameters["setpoint_c"], float)


@pytest.mark.parametrize("spec", list(OPERATION_CATALOG.values()), ids=str)
def test_every_catalog_operation_has_a_valid_example(spec: object) -> None:
    device, operation = spec.device, spec.operation  # type: ignore[attr-defined]
    params = {"setpoint_c": 21} if operation is Operation.SET_SETPOINT else {}
    raw = action_json(device=device.value, operation=operation.value, parameters=params)
    action = parse_action(raw)
    assert (action.device, action.operation) == (device, operation)


def test_policy_unsafe_but_finite_value_reaches_policy_check() -> None:
    # 35 C is outside the 16-30 C policy but structurally valid.
    assert parse_action(action_json(parameters={"setpoint_c": 35})).parameters["setpoint_c"] == 35.0


def test_evidence_refs_are_optional_and_preserved() -> None:
    action = parse_action(action_json(evidence_refs=["obs-000001", "obs-000002"]))
    assert action.evidence_refs == ("obs-000001", "obs-000002")


def test_round_trip_through_to_dict() -> None:
    action = parse_action(action_json(evidence_refs=["obs-000009"]))
    assert parse_action(json.dumps(action.to_dict())) == action


@pytest.mark.parametrize(
    ("raw", "code"),
    [
        ("not json", SchemaErrorCode.INVALID_JSON),
        ("[]", SchemaErrorCode.NOT_AN_OBJECT),
        ("null", SchemaErrorCode.NOT_AN_OBJECT),
        (
            '{"schema_version":"1.0","device":"light","device":"door",'
            '"operation":"turn_on","parameters":{}}',
            SchemaErrorCode.DUPLICATE_KEY,
        ),
        (
            '{"schema_version":"1.0","device":"thermostat","operation":"set_setpoint",'
            '"parameters":{"setpoint_c":NaN}}',
            SchemaErrorCode.NON_FINITE_NUMBER,
        ),
        (
            '{"schema_version":"1.0","device":"thermostat","operation":"set_setpoint",'
            '"parameters":{"setpoint_c":Infinity}}',
            SchemaErrorCode.NON_FINITE_NUMBER,
        ),
        (
            '{"schema_version":"1.0","device":"thermostat","operation":"set_setpoint",'
            '"parameters":{"setpoint_c":1e400}}',
            SchemaErrorCode.NON_FINITE_NUMBER,
        ),
        ("[" * 2000 + "]" * 2000, SchemaErrorCode.INVALID_JSON),
    ],
    ids=["text", "array", "null", "dup-key", "nan", "infinity", "overflow", "deep-nesting"],
)
def test_malformed_input_is_rejected(raw: str, code: SchemaErrorCode) -> None:
    assert_code(raw, code)


def test_oversized_input_is_rejected() -> None:
    padding = "x" * MAX_ACTION_BYTES
    assert_code(action_json(evidence_refs=[padding]), SchemaErrorCode.ACTION_TOO_LARGE)


def test_invalid_utf8_bytes_are_rejected() -> None:
    assert_code(b"\xff\xfe{}", SchemaErrorCode.INVALID_ENCODING)


@pytest.mark.parametrize(
    ("overrides", "code"),
    [
        ({"schema_version": "2.0"}, SchemaErrorCode.UNSUPPORTED_SCHEMA_VERSION),
        ({"schema_version": 1.0}, SchemaErrorCode.WRONG_TYPE),
        ({"device": "oven"}, SchemaErrorCode.UNKNOWN_DEVICE),
        ({"device": None}, SchemaErrorCode.WRONG_TYPE),
        ({"operation": "explode"}, SchemaErrorCode.UNKNOWN_OPERATION),
        (
            {"device": "presence_sensor", "operation": "turn_on", "parameters": {}},
            SchemaErrorCode.UNSUPPORTED_OPERATION,
        ),
        ({"device": "light", "operation": "set_setpoint"}, SchemaErrorCode.UNSUPPORTED_OPERATION),
        ({"parameters": None}, SchemaErrorCode.WRONG_TYPE),
        ({"parameters": {}}, SchemaErrorCode.MISSING_PARAMETER),
        ({"parameters": {"setpoint_c": "22"}}, SchemaErrorCode.WRONG_TYPE),
        ({"parameters": {"setpoint_c": True}}, SchemaErrorCode.WRONG_TYPE),
        ({"parameters": {"setpoint_c": None}}, SchemaErrorCode.WRONG_TYPE),
        ({"parameters": {"setpoint_c": 22, "unit": "F"}}, SchemaErrorCode.UNKNOWN_PARAMETER),
        ({"evidence_refs": "obs-000001"}, SchemaErrorCode.WRONG_TYPE),
        ({"evidence_refs": ["obs-1"]}, SchemaErrorCode.INVALID_EVIDENCE_REF),
        ({"evidence_refs": [7]}, SchemaErrorCode.INVALID_EVIDENCE_REF),
        ({"evidence_refs": ["obs-000001", "obs-000001"]}, SchemaErrorCode.DUPLICATE_EVIDENCE_REF),
        (
            {"evidence_refs": [f"obs-{i:06d}" for i in range(9)]},
            SchemaErrorCode.TOO_MANY_EVIDENCE_REFS,
        ),
    ],
)
def test_structural_violations(overrides: dict[str, object], code: SchemaErrorCode) -> None:
    assert_code(action_json(**overrides), code)


@pytest.mark.parametrize("field", ["schema_version", "device", "operation", "parameters"])
def test_missing_required_field(field: str) -> None:
    obj = json.loads(action_json())
    del obj[field]
    assert_code(json.dumps(obj), SchemaErrorCode.MISSING_FIELD)


@pytest.mark.parametrize(
    "field", ["identity", "source", "timestamp", "event_id", "request_id", "approved"]
)
def test_agent_asserted_trust_fields_are_rejected(field: str) -> None:
    # SIM-06: provenance, time or identifiers asserted by the agent never enter.
    assert_code(action_json(**{field: "user"}), SchemaErrorCode.UNKNOWN_FIELD)


def test_proposal_parameters_are_immutable() -> None:
    params = {"setpoint_c": 20.0}
    action = ActionProposal(DeviceId.THERMOSTAT, Operation.SET_SETPOINT, params)
    params["setpoint_c"] = 99.0
    assert action.parameters["setpoint_c"] == 20.0
    with pytest.raises(TypeError):
        action.parameters["setpoint_c"] = 1.0  # type: ignore[index]
