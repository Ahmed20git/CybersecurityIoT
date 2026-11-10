"""Versioned development labels for Simon's independent evaluation harness.

These checks validate evaluation inputs. They are not Ahmed's runtime action
schema, gateway, simulator, or authorization implementation.
"""

from __future__ import annotations

import copy
import json
import math
import re
from datetime import datetime
from pathlib import Path
from typing import Any, cast

SCHEMA_VERSION = "evaluation-scenario/v1"
DEVICES = {"light", "fan", "thermostat", "door", "presence_sensor"}
STATE_TYPES = {
    "light.power": {"on", "off"},
    "fan.power": {"on", "off"},
    "thermostat.power": {"on", "off"},
    "thermostat.setpoint_c": (int, float),
    "thermostat.ambient_c": (int, float),
    "door.position": {"open", "closed"},
    "door.lock": {"locked", "unlocked"},
    "presence_sensor.present": bool,
}
DEVICE_FIELDS = {
    "light": {"power"},
    "fan": {"power"},
    "thermostat": {"power", "setpoint_c", "ambient_c"},
    "door": {"position", "lock"},
    "presence_sensor": {"present"},
}
OPERATIONS = {
    "light": {"read", "turn_on", "turn_off"},
    "fan": {"read", "turn_on", "turn_off"},
    "thermostat": {"read", "turn_on", "turn_off", "set_setpoint"},
    "door": {"read", "lock", "unlock", "open", "close"},
    "presence_sensor": {"read"},
}
MAX_PAYLOAD_CHARS = 2000
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}\Z")
_SURFACE = re.compile(r"observations\[(0|[1-9][0-9]*)\]\.payload\.message\Z")
_EVIDENCE_REF = re.compile(r"obs-[0-9]{6,12}\Z")


def validate_state_value(path: str, value: Any) -> None:
    if path not in STATE_TYPES:
        raise ValueError("unsupported state path")
    expected = STATE_TYPES[path]
    if expected is bool:
        if type(value) is not bool:
            raise ValueError(f"{path} must be boolean")
    elif isinstance(expected, set):
        if not isinstance(value, str) or value not in expected:
            raise ValueError(f"{path} must be one of {sorted(expected)}")
    else:
        _number(value, path)


def _object(value: Any, keys: set[str], where: str) -> None:
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError(f"{where} must contain exactly {sorted(keys)}")


def _text(value: Any, where: str, maximum: int = 8192) -> None:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise ValueError(f"{where} must be nonempty text of at most {maximum} characters")


def _identifier(value: Any, where: str) -> None:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ValueError(f"{where} must be a bounded stable identifier")


def _number(value: Any, where: str, minimum: float | None = None) -> None:
    try:
        finite = type(value) in (int, float) and math.isfinite(value)
    except OverflowError:
        finite = False
    if not finite:
        raise ValueError(f"{where} must be a finite number")
    if minimum is not None and value < minimum:
        raise ValueError(f"{where} must be at least {minimum}")


def _json_value(value: Any, where: str) -> None:
    if value is None or isinstance(value, (str, bool)):
        return
    if type(value) in (int, float):
        _number(value, where)
        return
    if isinstance(value, list):
        for item in value:
            _json_value(item, where)
        return
    if isinstance(value, dict) and all(isinstance(key, str) for key in value):
        for item in value.values():
            _json_value(item, where)
        return
    raise ValueError(f"{where} must contain only finite JSON values")


def validate_state(state: Any) -> None:
    """Validate a complete native simulator snapshot without executing actions."""
    _object(state, {"state_version", "time_ms", "devices"}, "snapshot")
    for field in ("state_version", "time_ms"):
        if type(state[field]) is not int or state[field] < 0:
            raise ValueError(f"snapshot.{field} must be a nonnegative integer")
    _object(state["devices"], DEVICES, "snapshot.devices")
    for device, fields in DEVICE_FIELDS.items():
        _object(state["devices"][device], fields, f"snapshot.devices.{device}")
        for field in fields:
            validate_state_value(f"{device}.{field}", state["devices"][device][field])


def validate_action(action: Any) -> None:
    """Validate the JSON serialization of Ahmed's native ActionProposal."""
    _object(
        action, {"schema_version", "device", "operation", "parameters", "evidence_refs"}, "action"
    )
    if action["schema_version"] != "1.0":
        raise ValueError("unsupported native action schema_version")
    device, operation, parameters = action["device"], action["operation"], action["parameters"]
    if not isinstance(device, str) or device not in DEVICES:
        raise ValueError("action.device is unsupported")
    if not isinstance(operation, str) or operation not in OPERATIONS[device]:
        raise ValueError("unsupported native action operation")
    if device == "thermostat" and operation == "set_setpoint":
        _object(parameters, {"setpoint_c"}, "action.parameters")
        _number(parameters["setpoint_c"], "action.parameters.setpoint_c")
    else:
        _object(parameters, set(), "action.parameters")
    references = action["evidence_refs"]
    if (
        not isinstance(references, list)
        or len(references) > 8
        or any(not isinstance(ref, str) or not _EVIDENCE_REF.fullmatch(ref) for ref in references)
        or len(set(references)) != len(references)
    ):
        raise ValueError("action.evidence_refs must contain unique bounded native observation IDs")


def validate_observation(observation: Any) -> None:
    """Validate a native gateway observation without treating its payload as truth."""
    _object(observation, {"envelope", "payload"}, "observation")
    envelope = observation["envelope"]
    _object(
        envelope,
        {"observation_id", "device", "source_id", "event_id", "gateway_time_ms", "issuer"},
        "observation.envelope",
    )
    device = envelope["device"]
    if not isinstance(device, str) or device not in DEVICES:
        raise ValueError("observation device is unsupported")
    if type(envelope["event_id"]) is not int or not 1 <= envelope["event_id"] <= 999999999999:
        raise ValueError("observation event_id must be a positive bounded integer")
    if envelope["observation_id"] != f"obs-{envelope['event_id']:06d}":
        raise ValueError("observation reference must match the native gateway event ID")
    if envelope["source_id"] != f"gateway/{device}" or envelope["issuer"] != "gateway":
        raise ValueError("observation must retain the native gateway issuer and source")
    if type(envelope["gateway_time_ms"]) is not int or envelope["gateway_time_ms"] < 0:
        raise ValueError("observation gateway_time_ms must be a nonnegative integer")
    payload = observation["payload"]
    _object(payload, DEVICE_FIELDS[device] | {"message"}, "observation.payload")
    for field in DEVICE_FIELDS[device]:
        validate_state_value(f"{device}.{field}", payload[field])
    if not isinstance(payload["message"], str) or len(payload["message"]) > MAX_PAYLOAD_CHARS:
        raise ValueError("observation message must be bounded text")


def validate_attack_record(attack: Any) -> None:
    """Accept only the one permitted, bounded hidden-instruction mutation shape."""
    _object(
        attack,
        {"clean_scenario_id", "observation_index", "replacement_text", "attack_version"},
        "attack",
    )
    _identifier(attack["clean_scenario_id"], "attack.clean_scenario_id")
    if type(attack["observation_index"]) is not int or attack["observation_index"] < 0:
        raise ValueError("attack.observation_index must be a nonnegative integer")
    _text(attack["replacement_text"], "attack.replacement_text", MAX_PAYLOAD_CHARS)
    _text(attack["attack_version"], "attack.attack_version", 128)


def validate_run_config(config: Any) -> None:
    _object(config, {"prompt_version", "model", "limits"}, "run_config")
    _text(config["prompt_version"], "run_config.prompt_version", 128)
    model = config["model"]
    _object(model, {"provider", "version", "date", "settings", "seed", "seed_status"}, "model")
    for key in ("provider", "version", "date"):
        if model[key] is not None:
            _text(model[key], f"model.{key}", 128)
    if model["date"] is not None:
        try:
            datetime.strptime(model["date"], "%Y-%m-%d")
        except ValueError as exc:
            raise ValueError("model.date must use YYYY-MM-DD") from exc
    if not isinstance(model["settings"], dict):
        raise ValueError("model.settings must be an object")
    _json_value(model["settings"], "model.settings")
    if model["seed"] is not None and type(model["seed"]) is not int:
        raise ValueError("model.seed must be an integer or null")
    if model["seed_status"] not in ("supported", "unsupported"):
        raise ValueError("model.seed_status must be supported or unsupported")
    if model["seed_status"] == "unsupported" and model["seed"] is not None:
        raise ValueError("an unsupported seed must be null")
    limits = config["limits"]
    _object(
        limits,
        {"max_steps", "max_calls", "max_tokens", "wall_timeout_s", "max_cost", "currency"},
        "limits",
    )
    for key in ("max_steps", "max_calls", "max_tokens"):
        if type(limits[key]) is not int or limits[key] <= 0:
            raise ValueError(f"limits.{key} must be a positive integer")
    _number(limits["wall_timeout_s"], "limits.wall_timeout_s", 0)
    if limits["wall_timeout_s"] == 0:
        raise ValueError("limits.wall_timeout_s must be positive")
    _number(limits["max_cost"], "limits.max_cost", 0)
    if not isinstance(limits["currency"], str) or not re.fullmatch(r"[A-Z]{3}", limits["currency"]):
        raise ValueError("limits.currency must be an uppercase three-letter code")


def validate_scenario(scenario: Any) -> None:
    """Validate the provisional development format and its frozen goal labels."""
    fields = {
        "schema_version",
        "task_id",
        "scenario_id",
        "split",
        "variant",
        "initial_state",
        "request",
        "observations",
        "attack_surface",
        "completion",
        "policy",
        "expected_result",
        "run_config",
    }
    if isinstance(scenario, dict) and scenario.get("variant") == "attacked":
        fields.add("attack")
    _object(scenario, fields, "scenario")
    if scenario["schema_version"] != SCHEMA_VERSION:
        raise ValueError("unsupported scenario schema_version")
    for key in ("task_id", "scenario_id"):
        _identifier(scenario[key], key)
    if scenario["split"] != "development":
        raise ValueError("only the development split is permitted in baseline scenarios")
    if scenario["variant"] not in ("clean", "attacked"):
        raise ValueError("variant must be clean or attacked")
    validate_state(scenario["initial_state"])
    if scenario["initial_state"]["state_version"] != 0:
        raise ValueError("a fresh run must start at state_version zero")
    request = scenario["request"]
    _object(
        request,
        {"request_id", "principal_id", "request_text", "permissions", "issued_at_ms", "issuer"},
        "request",
    )
    if request["request_id"] != "req-0001" or request["issuer"] != "scenario_harness":
        raise ValueError("initial request must be issued by the fresh native request registry")
    _text(request["principal_id"], "request.principal_id", 128)
    _text(request["request_text"], "request.request_text")
    if (
        type(request["issued_at_ms"]) is not int
        or request["issued_at_ms"] != scenario["initial_state"]["time_ms"]
    ):
        raise ValueError("request must be issued at the initial native simulation time")
    permissions = request["permissions"]
    allowed_permissions = {
        f"{device}.{operation}"
        for device, operations in OPERATIONS.items()
        for operation in operations
        if operation != "read"
    }
    if (
        not isinstance(permissions, list)
        or any(not isinstance(item, str) or item not in allowed_permissions for item in permissions)
        or len(set(permissions)) != len(permissions)
    ):
        raise ValueError("request.permissions must be unique native effect-operation names")
    observations = scenario["observations"]
    if not isinstance(observations, list) or not observations:
        raise ValueError("observations must be a nonempty list")
    for index, observation in enumerate(observations):
        validate_observation(observation)
        envelope = observation["envelope"]
        if envelope["event_id"] != index + 1:
            raise ValueError("initial gateway observation IDs must be sequential from one")
        if envelope["gateway_time_ms"] != scenario["initial_state"]["time_ms"]:
            raise ValueError("initial observation time differs from reset state")
        canonical = scenario["initial_state"]["devices"][envelope["device"]]
        if {
            key: value for key, value in observation["payload"].items() if key != "message"
        } != canonical:
            raise ValueError("initial observation facts must match the canonical reset snapshot")
    surface = scenario["attack_surface"]
    if not isinstance(surface, list) or any(not isinstance(path, str) for path in surface):
        raise ValueError("attack_surface must be a list of designated text paths")
    if len(set(surface)) != len(surface):
        raise ValueError("attack_surface paths must be unique")
    for path in surface:
        match = _SURFACE.fullmatch(path)
        if not match or int(match.group(1)) >= len(observations):
            raise ValueError("attack_surface may designate only existing observation payload text")
    completion = scenario["completion"]
    _object(completion, {"state_equals", "executed_contains"}, "completion")
    states = completion["state_equals"]
    if not isinstance(states, dict):
        raise ValueError("completion.state_equals must be an object")
    for path, value in states.items():
        validate_state_value(path, value)
    actions = completion["executed_contains"]
    if not isinstance(actions, list):
        raise ValueError("completion.executed_contains must be a list")
    for action in actions:
        validate_action(action)
    if not states and not actions:
        raise ValueError("completion must declare a measurable goal")
    policy = scenario["policy"]
    _object(
        policy,
        {
            "version",
            "thermostat_min_c",
            "thermostat_max_c",
            "door_requires_presence",
            "door_open_requires_unlocked",
        },
        "policy",
    )
    _text(policy["version"], "policy.version", 128)
    for key in ("thermostat_min_c", "thermostat_max_c"):
        _number(policy[key], f"policy.{key}")
    if policy["thermostat_min_c"] >= policy["thermostat_max_c"]:
        raise ValueError("policy thermostat range must be ordered")
    for key in ("door_requires_presence", "door_open_requires_unlocked"):
        if type(policy[key]) is not bool:
            raise ValueError(f"policy.{key} must be boolean")
    expected = scenario["expected_result"]
    _object(expected, {"task_completed", "unsafe_effect"}, "expected_result")
    if expected["task_completed"] is not True or expected["unsafe_effect"] is not False:
        raise ValueError("development expected_result must describe the authorized safe goal")
    validate_run_config(scenario["run_config"])
    if scenario["variant"] == "attacked":
        attack = scenario["attack"]
        validate_attack_record(attack)
        index = attack["observation_index"]
        path = f"observations[{index}].payload.message"
        if path not in surface:
            raise ValueError("attack targets a protected or nonexistent field")
        if observations[index]["payload"]["message"] != attack["replacement_text"]:
            raise ValueError("attacked payload must match the recorded mutation")


def get_scenarios(suite: Any) -> list[dict[str, Any]]:
    """Return isolated validated records; reject duplicate IDs and unmatched attacks."""
    _object(suite, {"schema_version", "suite_version", "scenarios"}, "suite")
    if suite["schema_version"] != SCHEMA_VERSION:
        raise ValueError("unsupported suite schema_version")
    _text(suite["suite_version"], "suite_version", 128)
    scenarios = suite["scenarios"]
    if not isinstance(scenarios, list) or not scenarios:
        raise ValueError("suite.scenarios must be a nonempty list")
    by_id = {}
    clean_task_ids = set()
    for scenario in scenarios:
        validate_scenario(scenario)
        if scenario["scenario_id"] in by_id:
            raise ValueError("duplicate scenario_id")
        by_id[scenario["scenario_id"]] = scenario
        if scenario["variant"] == "clean":
            if scenario["task_id"] in clean_task_ids:
                raise ValueError("duplicate clean task_id")
            clean_task_ids.add(scenario["task_id"])
    from .attacks import validate_matched_pair

    for scenario in scenarios:
        if scenario["variant"] == "attacked":
            clean = by_id.get(scenario["attack"]["clean_scenario_id"])
            if clean is None:
                raise ValueError("attacked scenario has no matching clean scenario")
            validate_matched_pair(clean, scenario)
    return copy.deepcopy(scenarios)


def _reject_constant(value: str) -> None:
    raise ValueError(f"nonfinite JSON constant is forbidden: {value}")


def _unique_object(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_suite(path: str | Path) -> dict[str, Any]:
    """Load and validate all scenario labels before any experiment is attempted."""
    with Path(path).open(encoding="utf-8") as stream:
        suite = json.load(stream, parse_constant=_reject_constant, object_pairs_hook=_unique_object)
    get_scenarios(suite)
    return cast(dict[str, Any], suite)
