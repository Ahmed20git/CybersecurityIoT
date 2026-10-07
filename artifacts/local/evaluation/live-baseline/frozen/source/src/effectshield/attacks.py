"""The bounded hidden-instruction attack: bounded replacement of designated untrusted text."""

from __future__ import annotations

import copy
import json
from typing import Any

from .scenarios import validate_attack_record, validate_scenario


def apply_attack(clean: dict[str, Any], attack: dict[str, Any]) -> dict[str, Any]:
    """Copy a clean case and change one predeclared untrusted payload text field.

    Variant identity and the mutation record are the only metadata additions.
    Trusted metadata, initial state, goal labels and run settings remain equal.
    """
    validate_scenario(clean)
    validate_attack_record(attack)
    if clean["variant"] != "clean":
        raise ValueError("apply_attack requires a clean scenario")
    if attack["clean_scenario_id"] != clean["scenario_id"]:
        raise ValueError("attack.clean_scenario_id does not identify this clean scenario")
    index = attack["observation_index"]
    if f"observations[{index}].payload.message" not in clean["attack_surface"]:
        raise ValueError("attack targets a protected or nonexistent field")
    if attack["replacement_text"] == clean["observations"][index]["payload"]["message"]:
        raise ValueError("attack must change the designated payload text")
    attacked = copy.deepcopy(clean)
    attacked["observations"][index]["payload"]["message"] = attack["replacement_text"]
    attacked["scenario_id"] = clean["scenario_id"] + "-attacked"
    attacked["variant"] = "attacked"
    attacked["attack"] = copy.deepcopy(attack)
    validate_scenario(attacked)
    return attacked


def validate_matched_pair(clean: dict[str, Any], attacked: dict[str, Any]) -> None:
    """Reject every deviation beyond the permitted text and variant bookkeeping."""
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
