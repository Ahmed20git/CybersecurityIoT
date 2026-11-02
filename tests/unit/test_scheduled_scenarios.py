"""Scenario v2: trusted evidence schedules, schedule attacks, feasibility and split separation."""

from copy import deepcopy
from pathlib import Path

import pytest

from effectshield.agent.conditions import load_conditions
from effectshield.attacks import apply_attack, validate_matched_pair
from effectshield.experiments.baseline import BaselineBackend, ScriptedModel
from effectshield.experiments.storage import load_json
from effectshield.scenarios import get_scenarios, load_suite, validate_scenario, validate_splits

ROOT = Path(__file__).resolve().parents[2]
FRESHNESS = load_suite(ROOT / "scenarios/development/freshness_replay.json")
REPAIR = load_suite(ROOT / "scenarios/development/repair_sequence.json")
PILOT = load_suite(ROOT / "scenarios/pilot/pilot.json")
BY_ID = {s["scenario_id"]: s for suite in (FRESHNESS, REPAIR) for s in suite["scenarios"]}
STALE = BY_ID["stale-presence-clean"]
REPLAYED = BY_ID["replayed-presence-clean-attacked"]


def test_every_tracked_suite_keeps_tasks_templates_and_requests_within_one_split():
    suites = {str(path): load_suite(path) for path in sorted(ROOT.glob("scenarios/*/*.json"))}
    result = validate_splits(suites)["splits"]
    assert set(result) == {"development", "pilot", "test"}
    assert result["test"]["base_tasks"] == 24
    assert result["pilot"]["base_tasks"] == 6
    assert result["pilot"]["attack_families"] == {
        "hidden_instruction": 3,
        "replayed_observation": 2,
        "stale_observation": 1,
    }


@pytest.mark.parametrize("key", ["task_id", "template_id", "request"])
def test_a_development_task_or_template_cannot_reappear_in_the_pilot(key):
    pilot = deepcopy(PILOT)
    case = pilot["scenarios"][0]
    attacked = pilot["scenarios"][1]
    for item in (case, attacked):
        if key == "request":
            item["request"]["request_text"] = STALE["request"]["request_text"].upper()
        else:
            item[key] = STALE[key]
    if key == "task_id":
        attacked["attack"]["clean_scenario_id"] = case["scenario_id"]
    with pytest.raises(ValueError, match="crosses splits"):
        validate_splits({"development": FRESHNESS, "pilot": pilot})


@pytest.mark.parametrize(
    "field,value",
    [("event_id", 7), ("gateway_time_ms", 0), ("observation_id", "obs-000009")],
)
def test_scheduled_envelopes_cannot_be_forged(field, value):
    case = deepcopy(STALE)
    case["observations"][1]["envelope"][field] = value
    with pytest.raises(ValueError):
        validate_scenario(case)


def test_scheduled_facts_must_be_canonical_at_issue_time():
    case = deepcopy(STALE)
    case["observations"][1]["payload"]["present"] = True
    with pytest.raises(ValueError, match="canonical scheduled state"):
        validate_scenario(case)


def test_a_replay_repeats_the_original_delivery_including_its_text():
    case = deepcopy(REPLAYED)
    case["observations"][2]["payload"]["message"] = "Fresh-looking replay text"
    with pytest.raises(ValueError):
        validate_scenario(case)


def test_a_replay_of_an_unissued_observation_is_rejected():
    case = deepcopy(REPLAYED)
    case["evidence_schedule"][-1]["observation_id"] = "obs-000042"
    case["attack"]["evidence_schedule"] = case["evidence_schedule"]
    with pytest.raises(ValueError, match="never issued"):
        validate_scenario(case)


def test_infeasible_requests_declare_no_safe_completion():
    case = deepcopy(BY_ID["thermostat-exact-out-of-range-clean"])
    assert case["expected_result"] == {"task_completed": False, "unsafe_effect": False}
    case["expected_result"]["task_completed"] = True
    with pytest.raises(ValueError, match="safe goal"):
        validate_scenario(case)


def test_scenarios_must_belong_to_their_suite_split():
    suite = deepcopy(FRESHNESS)
    suite["scenarios"][0]["split"] = "pilot"
    with pytest.raises(ValueError, match="suite split"):
        get_scenarios(suite)


def schedule_attack(clean, schedule, family):
    return {
        "clean_scenario_id": clean["scenario_id"],
        "family": family,
        "attack_version": "test",
        "evidence_schedule": schedule,
    }


@pytest.mark.parametrize(
    "change",
    ["extra_clock", "changed_event", "removed_event", "reordered"],
)
def test_schedule_attacks_cannot_change_trusted_clock_or_environment(change):
    schedule = deepcopy(STALE["evidence_schedule"][:-1])
    if change == "extra_clock":
        schedule.append({"step": "advance_clock", "delta_ms": 1})
    elif change == "changed_event":
        schedule[1]["present"] = True
    elif change == "removed_event":
        del schedule[1]
    else:
        schedule[1], schedule[2] = schedule[2], schedule[1]
    with pytest.raises(ValueError):
        apply_attack(STALE, schedule_attack(STALE, schedule, "stale_observation"))


def test_family_labels_must_match_the_schedule_mutation():
    withheld = STALE["evidence_schedule"][:-1]
    replayed = [*STALE["evidence_schedule"], {"step": "redeliver", "observation_id": "obs-000001"}]
    with pytest.raises(ValueError, match="only the replayed_observation family"):
        apply_attack(STALE, schedule_attack(STALE, replayed, "stale_observation"))
    with pytest.raises(ValueError, match="only the replayed_observation family"):
        apply_attack(STALE, schedule_attack(STALE, withheld, "replayed_observation"))
    with pytest.raises(ValueError, match="change the delivery schedule"):
        apply_attack(STALE, schedule_attack(STALE, STALE["evidence_schedule"], "stale_observation"))


@pytest.mark.parametrize("field", ["request", "initial_state", "completion", "feasibility"])
def test_schedule_attack_pairs_keep_protected_labels(field):
    clean = BY_ID["replayed-presence-clean"]
    attacked = deepcopy(REPLAYED)
    if field == "feasibility":
        attacked[field] = "infeasible"
    elif field == "initial_state":
        attacked[field]["devices"]["light"]["power"] = "on"
    else:
        attacked[field] = deepcopy(BY_ID["fresh-reread-clean"][field])
    assert attacked[field] != clean[field]
    with pytest.raises(ValueError):
        validate_matched_pair(clean, attacked)


def native(case, proposals=()):
    condition = load_conditions(ROOT / "configs/conditions")["unprotected"]
    backend = BaselineBackend(model=ScriptedModel(list(proposals)), condition=condition)
    backend.reset(case["initial_state"], 0)
    return backend


def test_native_backend_replays_schedule_through_gateway_and_environment():
    backend = native(REPLAYED)
    backend.schedule_evidence(REPLAYED["evidence_schedule"])
    config = load_json(ROOT / "configs/evaluation/gate.json")
    config["prompt_version"] = load_conditions(ROOT / "configs/conditions")[
        "unprotected"
    ].prompt_version
    events = list(backend.run(REPLAYED["request"], REPLAYED["observations"], config))
    assert backend.environment is not None
    deliveries = backend.environment.gateway.deliveries
    assert [(d.observation_id, d.redelivery) for d in deliveries] == [
        ("obs-000001", False),
        ("obs-000002", False),
        ("obs-000001", True),
    ]
    kinds = [e["kind"] for e in events if e["type"] == "committed_transition"]
    assert kinds == ["environment", "clock"]
    assert events[-1]["final_state"]["time_ms"] == 90000


def test_backend_rejects_declared_observations_the_schedule_did_not_produce():
    backend = native(STALE)
    backend.schedule_evidence(STALE["evidence_schedule"])
    forged = deepcopy(STALE["observations"])
    forged[1]["payload"]["present"] = True
    config = load_json(ROOT / "configs/evaluation/gate.json")
    with pytest.raises(ValueError, match="protected gateway metadata or facts"):
        list(backend.run(STALE["request"], forged, config))


def test_schedule_is_accepted_once_after_reset_and_before_the_run():
    backend = native(STALE)
    backend.schedule_evidence(STALE["evidence_schedule"])
    with pytest.raises(ValueError, match="once"):
        backend.schedule_evidence(STALE["evidence_schedule"])
    with pytest.raises(ValueError, match="once"):
        BaselineBackend(model=ScriptedModel([])).schedule_evidence(STALE["evidence_schedule"])
