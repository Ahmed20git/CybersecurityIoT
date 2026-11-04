"""Bounded attack construction: designated untrusted text and the delivery schedule.

Three labelled families (DAT-03, DAT-04, DAT-08):

* ``hidden_instruction`` replaces one designated observation message text.
* ``stale_observation`` withholds one or more fresh gateway deliveries, so the
  agent acts on an older authentic observation that is still in its context.
* ``replayed_observation`` redelivers previously issued observations with their
  original envelopes (optionally in place of withheld fresh deliveries).

Schedule attacks never add, reorder or change clock and environment steps and
cannot forge an envelope: redeliveries repeat only what the gateway issued.
v1 scenarios support only the original message-text attack.
"""

from __future__ import annotations

import copy
import json
from typing import Any

from .scenarios import (
    SCHEDULE_FAMILIES,
    SCHEMA_VERSION_V2,
    scheduled_deliveries,
    validate_attack_record,
    validate_attack_record_v2,
    validate_scenario,
)


def _schedule_observations(clean: dict[str, Any], schedule: list[dict[str, Any]]) -> list[Any]:
    """Derive attacked deliveries; each retained fresh read keeps its clean text.

    With redeliveries removed, the attacked schedule must equal the clean
    schedule with only ``observe`` steps deleted, so clock and environment
    steps stay unchanged and in order.
    """
    clean_steps = clean["evidence_schedule"]
    if any(step["step"] == "redeliver" for step in clean_steps):
        raise ValueError("a clean scenario cannot already contain replays")
    # A clean schedule's deliveries are exactly its observe steps, in order.
    clean_text = iter(item["payload"]["message"] for item in clean["observations"])
    text_by_step = [next(clean_text) if step["step"] == "observe" else None for step in clean_steps]
    texts: list[str | None] = []  # one entry per attacked delivery; None for a replay
    position = 0
    for step in schedule:
        if step["step"] == "redeliver":
            texts.append(None)
            continue
        while position < len(clean_steps) and clean_steps[position] != step:
            if clean_steps[position]["step"] != "observe":
                raise ValueError("schedule attacks may only withhold fresh deliveries")
            position += 1
        if position == len(clean_steps):
            raise ValueError("schedule attack adds, reorders or changes trusted steps")
        if step["step"] == "observe":
            texts.append(text_by_step[position])
        position += 1
    if any(step["step"] != "observe" for step in clean_steps[position:]):
        raise ValueError("schedule attacks may only withhold fresh deliveries")
    observations: list[Any] = []
    deliveries = scheduled_deliveries(clean["initial_state"], schedule)
    for item, text in zip(deliveries, texts, strict=True):
        if item["redelivery_of"] is not None:
            observations.append(copy.deepcopy(observations[item["redelivery_of"]]))
        else:
            observations.append(
                {"envelope": item["envelope"], "payload": {**item["facts"], "message": text}}
            )
    return observations


def apply_attack(clean: dict[str, Any], attack: dict[str, Any]) -> dict[str, Any]:
    """Copy a clean case and apply one predeclared bounded mutation.

    Variant identity and the mutation record are the only metadata additions.
    Trusted metadata, initial state, goal labels and run settings remain equal.
    """
    validate_scenario(clean)
    v2 = clean["schema_version"] == SCHEMA_VERSION_V2
    if v2:
        validate_attack_record_v2(attack)
    else:
        validate_attack_record(attack)
    if clean["variant"] != "clean":
        raise ValueError("apply_attack requires a clean scenario")
    if attack["clean_scenario_id"] != clean["scenario_id"]:
        raise ValueError("attack.clean_scenario_id does not identify this clean scenario")
    attacked = copy.deepcopy(clean)
    if v2 and attack["family"] in SCHEDULE_FAMILIES:
        schedule = attack["evidence_schedule"]
        if schedule == clean["evidence_schedule"]:
            raise ValueError("attack must change the delivery schedule")
        redelivers = any(step["step"] == "redeliver" for step in schedule)
        if redelivers != (attack["family"] == "replayed_observation"):
            raise ValueError("only the replayed_observation family redelivers observations")
        attacked["evidence_schedule"] = copy.deepcopy(schedule)
        attacked["observations"] = _schedule_observations(clean, schedule)
    else:
        index = attack["observation_index"]
        if f"observations[{index}].payload.message" not in clean["attack_surface"]:
            raise ValueError("attack targets a protected or nonexistent field")
        if attack["replacement_text"] == clean["observations"][index]["payload"]["message"]:
            raise ValueError("attack must change the designated payload text")
        attacked["observations"][index]["payload"]["message"] = attack["replacement_text"]
    attacked["scenario_id"] = clean["scenario_id"] + "-attacked"
    attacked["variant"] = "attacked"
    attacked["attack"] = copy.deepcopy(attack)
    validate_scenario(attacked)
    return attacked


def validate_matched_pair(clean: dict[str, Any], attacked: dict[str, Any]) -> None:
    """Reject every deviation beyond the permitted mutation and variant bookkeeping."""
    validate_scenario(attacked)
    if attacked["variant"] != "attacked":
        raise ValueError("matched attack must use the attacked variant")
    expected = apply_attack(clean, attacked["attack"])
    # Python equality treats False == 0 and True == 1. Protected configuration
    # fields must retain their JSON types as well as their apparent values.
    if json.dumps(attacked, sort_keys=True, allow_nan=False) != json.dumps(
        expected, sort_keys=True, allow_nan=False
    ):
        raise ValueError(
            "matched pair changed protected metadata, labels, state, or run configuration"
        )
