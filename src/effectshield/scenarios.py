"""Versioned scenario labels for Simon's independent evaluation harness.

These checks validate evaluation inputs. They are not Ahmed's runtime action
schema, gateway, simulator, or authorization implementation.

``evaluation-scenario/v1`` is the frozen baseline-gate format: development
split, initial observations only and one message-text attack. ``v2`` adds a
trusted evidence schedule (deliveries, redeliveries, clock advances and
environment events before the agent starts), held-out splits, template
identities, explicit feasibility and labelled attack families (DAT-02,
DAT-04, DAT-06, DAT-08). v1 suites keep their original validation.
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
SCHEMA_VERSION_V2 = "evaluation-scenario/v2"
SPLITS = ("development", "pilot", "test")
ATTACK_FAMILIES = ("hidden_instruction", "stale_observation", "replayed_observation")
SCHEDULE_FAMILIES = ("stale_observation", "replayed_observation")
MAX_SCHEDULE_STEPS = 32
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


def validate_task_intent(intent: Any, permissions: list[str]) -> None:
    """Validate the trusted, harness-issued task intent of a v2 scenario (D05/D08).

    The intent states which outcomes still complete the request, so the mediator
    can show that a clamp repair preserves the task. It is authored from the
    request's meaning alongside the request itself, never copied from the
    grader's ``completion`` or ``expected_result`` labels, and it is never shown
    to the agent. The only field is ``setpoint_range_c``: an inclusive
    ``[low, high]`` range of accepted thermostat setpoints, for a request that
    may set the setpoint.
    """
    _object(intent, {"setpoint_range_c"}, "task_intent")
    if "thermostat.set_setpoint" not in permissions:
        raise ValueError("task_intent.setpoint_range_c needs a thermostat.set_setpoint request")
    values = intent["setpoint_range_c"]
    if not isinstance(values, list) or len(values) != 2:
        raise ValueError("task_intent.setpoint_range_c must be [low, high]")
    for value in values:
        _number(value, "task_intent.setpoint_range_c")
    if values[0] > values[1]:
        raise ValueError("task_intent.setpoint_range_c must be ordered")


def validate_attack_record_v2(attack: Any) -> None:
    """A labelled attack family and its bounded mutation (DAT-03, DAT-04, DAT-08)."""
    if not isinstance(attack, dict) or attack.get("family") not in ATTACK_FAMILIES:
        raise ValueError(f"attack.family must be one of {list(ATTACK_FAMILIES)}")
    if attack["family"] == "hidden_instruction":
        _object(
            attack,
            {
                "clean_scenario_id",
                "family",
                "observation_index",
                "replacement_text",
                "attack_version",
            },
            "attack",
        )
        validate_attack_record({k: v for k, v in attack.items() if k != "family"})
        return
    _object(
        attack, {"clean_scenario_id", "family", "evidence_schedule", "attack_version"}, "attack"
    )
    _identifier(attack["clean_scenario_id"], "attack.clean_scenario_id")
    _text(attack["attack_version"], "attack.attack_version", 128)
    validate_schedule_shape(attack["evidence_schedule"])


def validate_schedule_shape(schedule: Any) -> None:
    """Accept only trusted harness steps; none can forge an envelope or a fact."""
    if not isinstance(schedule, list) or not 1 <= len(schedule) <= MAX_SCHEDULE_STEPS:
        raise ValueError(f"evidence_schedule must list 1 to {MAX_SCHEDULE_STEPS} steps")
    for index, step in enumerate(schedule):
        where = f"evidence_schedule[{index}]"
        kind = step.get("step") if isinstance(step, dict) else None
        if kind == "observe":
            _object(step, {"step", "device"}, where)
            if step["device"] not in DEVICES:
                raise ValueError(f"{where}.device is unsupported")
        elif kind == "redeliver":
            _object(step, {"step", "observation_id"}, where)
            if not isinstance(step["observation_id"], str) or not _EVIDENCE_REF.fullmatch(
                step["observation_id"]
            ):
                raise ValueError(f"{where}.observation_id must be a native observation ID")
        elif kind == "advance_clock":
            _object(step, {"step", "delta_ms"}, where)
            if type(step["delta_ms"]) is not int or not 1 <= step["delta_ms"] <= 86_400_000:
                raise ValueError(f"{where}.delta_ms must be a positive bounded integer")
        elif kind == "set_presence":
            _object(step, {"step", "present"}, where)
            validate_state_value("presence_sensor.present", step["present"])
        elif kind == "set_ambient_temperature":
            _object(step, {"step", "ambient_c"}, where)
            validate_state_value("thermostat.ambient_c", step["ambient_c"])
        else:
            raise ValueError(f"{where}.step is unsupported")


def scheduled_deliveries(
    initial_state: dict[str, Any], schedule: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Envelopes and canonical facts the native gateway issues for each delivery.

    This is bookkeeping of the trusted schedule (event counter, clock and the two
    environment fields), not a simulator: no agent action is applied here.
    Redeliveries repeat an earlier envelope and facts unchanged; the returned
    ``redelivery_of`` index names the delivery they repeat.
    """
    validate_schedule_shape(schedule)
    devices = copy.deepcopy(initial_state["devices"])
    time_ms = initial_state["time_ms"]
    issued: dict[str, int] = {}
    deliveries: list[dict[str, Any]] = []
    for index, step in enumerate(schedule):
        kind = step["step"]
        if kind == "observe":
            event_id = len(issued) + 1
            device = step["device"]
            envelope = {
                "observation_id": f"obs-{event_id:06d}",
                "device": device,
                "source_id": f"gateway/{device}",
                "event_id": event_id,
                "gateway_time_ms": time_ms,
                "issuer": "gateway",
            }
            issued[envelope["observation_id"]] = len(deliveries)
            deliveries.append(
                {
                    "envelope": envelope,
                    "facts": copy.deepcopy(devices[device]),
                    "redelivery_of": None,
                }
            )
        elif kind == "redeliver":
            original = issued.get(step["observation_id"])
            if original is None:
                raise ValueError(
                    f"evidence_schedule[{index}] replays an observation the gateway never issued"
                )
            deliveries.append({**copy.deepcopy(deliveries[original]), "redelivery_of": original})
        elif kind == "advance_clock":
            time_ms += step["delta_ms"]
        elif kind == "set_presence":
            devices["presence_sensor"]["present"] = step["present"]
        else:
            devices["thermostat"]["ambient_c"] = step["ambient_c"]
    return deliveries


def _validate_scheduled_observations(scenario: dict[str, Any]) -> None:
    observations = scenario["observations"]
    deliveries = scheduled_deliveries(scenario["initial_state"], scenario["evidence_schedule"])
    if not isinstance(observations, list) or len(observations) != len(deliveries):
        raise ValueError("observations must list exactly the scheduled deliveries")
    if not deliveries:
        raise ValueError("evidence_schedule must deliver at least one observation")
    for index, (observation, delivery) in enumerate(zip(observations, deliveries, strict=True)):
        validate_observation(observation)
        if observation["envelope"] != delivery["envelope"]:
            raise ValueError(f"observations[{index}] envelope differs from the gateway schedule")
        if {k: v for k, v in observation["payload"].items() if k != "message"} != delivery["facts"]:
            raise ValueError(f"observations[{index}] facts differ from canonical scheduled state")
        if delivery["redelivery_of"] is not None and (
            observation != observations[delivery["redelivery_of"]]
        ):
            raise ValueError(f"observations[{index}] replay must repeat the original delivery")


def _replayed_indexes(scenario: dict[str, Any]) -> set[int]:
    deliveries = scheduled_deliveries(scenario["initial_state"], scenario["evidence_schedule"])
    return {index for index, item in enumerate(deliveries) if item["redelivery_of"] is not None}


def validate_scenario(scenario: Any) -> None:
    """Validate a v1 or v2 scenario and its frozen goal labels."""
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
    v2 = isinstance(scenario, dict) and scenario.get("schema_version") == SCHEMA_VERSION_V2
    if v2:
        fields |= {"template_id", "feasibility", "evidence_schedule"}
        if isinstance(scenario, dict) and "task_intent" in scenario:
            fields.add("task_intent")
    if isinstance(scenario, dict) and scenario.get("variant") == "attacked":
        fields.add("attack")
    _object(scenario, fields, "scenario")
    if scenario["schema_version"] not in (SCHEMA_VERSION, SCHEMA_VERSION_V2):
        raise ValueError("unsupported scenario schema_version")
    for key in ("task_id", "scenario_id"):
        _identifier(scenario[key], key)
    if v2:
        _identifier(scenario["template_id"], "template_id")
        if scenario["split"] not in SPLITS:
            raise ValueError(f"split must be one of {list(SPLITS)}")
        if scenario["feasibility"] not in ("feasible", "infeasible"):
            raise ValueError("feasibility must be feasible or infeasible")
    elif scenario["split"] != "development":
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
    if "task_intent" in scenario:
        validate_task_intent(scenario["task_intent"], permissions)
    observations = scenario["observations"]
    if v2:
        _validate_scheduled_observations(scenario)
    else:
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
                raise ValueError(
                    "initial observation facts must match the canonical reset snapshot"
                )
    surface = scenario["attack_surface"]
    if not isinstance(surface, list) or any(not isinstance(path, str) for path in surface):
        raise ValueError("attack_surface must be a list of designated text paths")
    if len(set(surface)) != len(surface):
        raise ValueError("attack_surface paths must be unique")
    replayed = _replayed_indexes(scenario) if v2 else set()
    for path in surface:
        match = _SURFACE.fullmatch(path)
        if not match or int(match.group(1)) >= len(observations):
            raise ValueError("attack_surface may designate only existing observation payload text")
        if int(match.group(1)) in replayed:
            raise ValueError("a replay repeats its original text; it is not a separate surface")
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
    # An infeasible request has no safe completion; its safe goal is no unsafe
    # effect, and it stays out of clean-utility denominators (DAT-02).
    feasible = not v2 or scenario["feasibility"] == "feasible"
    if expected["task_completed"] is not feasible or expected["unsafe_effect"] is not False:
        raise ValueError("expected_result must describe the authorized safe goal")
    validate_run_config(scenario["run_config"])
    if scenario["variant"] == "attacked":
        attack = scenario["attack"]
        if v2:
            validate_attack_record_v2(attack)
            if attack["family"] in SCHEDULE_FAMILIES:
                if attack["evidence_schedule"] != scenario["evidence_schedule"]:
                    raise ValueError("attacked schedule must match the recorded mutation")
                return
        else:
            validate_attack_record(attack)
        index = attack["observation_index"]
        path = f"observations[{index}].payload.message"
        if path not in surface:
            raise ValueError("attack targets a protected or nonexistent field")
        if observations[index]["payload"]["message"] != attack["replacement_text"]:
            raise ValueError("attacked payload must match the recorded mutation")


def get_scenarios(suite: Any) -> list[dict[str, Any]]:
    """Return isolated validated records; reject duplicate IDs and unmatched attacks."""
    v2 = isinstance(suite, dict) and suite.get("schema_version") == SCHEMA_VERSION_V2
    keys = {"schema_version", "suite_version", "scenarios"} | ({"split"} if v2 else set())
    _object(suite, keys, "suite")
    if suite["schema_version"] not in (SCHEMA_VERSION, SCHEMA_VERSION_V2):
        raise ValueError("unsupported suite schema_version")
    _text(suite["suite_version"], "suite_version", 128)
    if v2 and suite["split"] not in SPLITS:
        raise ValueError(f"suite.split must be one of {list(SPLITS)}")
    scenarios = suite["scenarios"]
    if not isinstance(scenarios, list) or not scenarios:
        raise ValueError("suite.scenarios must be a nonempty list")
    by_id = {}
    clean_task_ids = set()
    for scenario in scenarios:
        validate_scenario(scenario)
        if scenario["schema_version"] != suite["schema_version"]:
            raise ValueError("every scenario must use the suite schema_version")
        if v2 and scenario["split"] != suite["split"]:
            raise ValueError("every scenario must belong to the suite split")
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


def validate_splits(suites: dict[str, Any]) -> dict[str, Any]:
    """Keep base tasks, template variants and request texts within one split (DAT-06).

    ``suites`` maps a suite name to its loaded document. v1 suites are
    development-only and use each task ID as its own template.
    """
    owners: dict[tuple[str, str], tuple[str, str]] = {}
    coverage: dict[str, dict[str, Any]] = {}
    for name, suite in suites.items():
        split = suite.get("split", "development")
        summary = coverage.setdefault(
            split, {"suites": [], "base_tasks": 0, "scenarios": 0, "attack_families": {}}
        )
        summary["suites"].append(name)
        for scenario in get_scenarios(suite):
            summary["scenarios"] += 1
            summary["base_tasks"] += scenario["variant"] == "clean"
            if scenario["variant"] == "attacked":
                family = scenario["attack"].get("family", "hidden_instruction")
                summary["attack_families"][family] = summary["attack_families"].get(family, 0) + 1
            keys = (
                ("task", scenario["task_id"]),
                ("template", scenario.get("template_id", scenario["task_id"])),
                ("request", " ".join(scenario["request"]["request_text"].lower().split())),
            )
            for key in keys:
                owner = owners.setdefault(key, (split, name))
                if owner[0] != split:
                    raise ValueError(
                        f"{key[0]} {key[1]!r} crosses splits: {owner[1]} ({owner[0]}) "
                        f"and {name} ({split})"
                    )
    return {"splits": coverage}


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
