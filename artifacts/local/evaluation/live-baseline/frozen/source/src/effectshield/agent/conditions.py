"""Versioned comparison-condition configurations for the bounded agent.

A condition is the complete, declared treatment: the prompt variant the model
sees and the enforcement the trusted harness applies. Everything else (model,
settings, limits, scenario, evidence) is shared and must match across
conditions. The safety-prompt condition carries no hidden deterministic shield;
only the full EffectShield condition declares enforcement.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .continuation import CONTINUATION_PROTOCOL_VERSION

CONDITION_SCHEMA_VERSION = "agent-condition/v1"
CONDITION_IDS = ("unprotected", "safety_prompt_only", "effectshield")
ENFORCEMENT_KINDS = ("none", "effectshield")
DECISION_STATUSES = ("pending", "approved")
# Fields that may legitimately differ between conditions. Any other difference
# in a run manifest is an undeclared treatment difference (AGT-03).
TREATMENT_FIELDS = (
    "condition_id",
    "condition_version",
    "prompt_version",
    "safety_instruction",
    "enforcement",
)
_FIELDS = {
    "schema_version",
    "condition_id",
    "condition_version",
    "prompt_version",
    "safety_instruction",
    "enforcement",
    "continuation_protocol",
    "decision_status",
}
_MAX_INSTRUCTION_CHARS = 4_000


class ConditionError(ValueError):
    """A condition document is malformed or declares an inconsistent treatment."""


@dataclass(frozen=True)
class Condition:
    condition_id: str
    condition_version: str
    prompt_version: str
    safety_instruction: str | None
    enforcement: str
    continuation_protocol: str
    decision_status: str

    @property
    def requires_mediator(self) -> bool:
        return self.enforcement != "none"

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": CONDITION_SCHEMA_VERSION,
            "condition_id": self.condition_id,
            "condition_version": self.condition_version,
            "prompt_version": self.prompt_version,
            "safety_instruction": self.safety_instruction,
            "enforcement": self.enforcement,
            "continuation_protocol": self.continuation_protocol,
            "decision_status": self.decision_status,
        }


def _text(document: dict[str, Any], key: str) -> str:
    value = document.get(key)
    if not isinstance(value, str) or not value.strip() or len(value) > 200:
        raise ConditionError(f"{key} must be a non-empty string of at most 200 characters")
    return value


def parse_condition(document: object) -> Condition:
    """Strictly validate one condition; treatment shape is fixed per condition ID."""
    if not isinstance(document, dict):
        raise ConditionError("Condition must be a JSON object")
    if set(document) != _FIELDS:
        raise ConditionError(f"Condition fields must be exactly {sorted(_FIELDS)}")
    if document["schema_version"] != CONDITION_SCHEMA_VERSION:
        raise ConditionError("Unsupported condition schema_version")
    condition_id = _text(document, "condition_id")
    if condition_id not in CONDITION_IDS:
        raise ConditionError(f"condition_id must be one of {CONDITION_IDS}")
    if document["continuation_protocol"] != CONTINUATION_PROTOCOL_VERSION:
        raise ConditionError("Condition names an unsupported continuation protocol")
    if document["decision_status"] not in DECISION_STATUSES:
        raise ConditionError("decision_status must be pending or approved")
    enforcement = document["enforcement"]
    if enforcement not in ENFORCEMENT_KINDS:
        raise ConditionError(f"enforcement must be one of {ENFORCEMENT_KINDS}")
    instruction = document["safety_instruction"]
    if instruction is not None and (
        not isinstance(instruction, str)
        or not instruction.strip()
        or len(instruction) > _MAX_INSTRUCTION_CHARS
    ):
        raise ConditionError("safety_instruction must be null or bounded non-empty text")
    expected = {
        "unprotected": (False, "none"),
        "safety_prompt_only": (True, "none"),
        "effectshield": (False, "effectshield"),
    }[condition_id]
    if (instruction is not None, enforcement) != expected:
        raise ConditionError(
            f"{condition_id} must declare safety_instruction "
            f"{'text' if expected[0] else 'null'} and enforcement {expected[1]}"
        )
    return Condition(
        condition_id=condition_id,
        condition_version=_text(document, "condition_version"),
        prompt_version=_text(document, "prompt_version"),
        safety_instruction=instruction,
        enforcement=enforcement,
        continuation_protocol=document["continuation_protocol"],
        decision_status=document["decision_status"],
    )


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ConditionError(f"Duplicate condition key: {key}")
        result[key] = value
    return result


def load_condition(path: str | Path) -> Condition:
    text = Path(path).read_text(encoding="utf-8")
    return parse_condition(json.loads(text, object_pairs_hook=_reject_duplicates))


def load_conditions(directory: str | Path) -> dict[str, Condition]:
    """Load exactly the three named conditions and check their prompt pairing."""
    conditions: dict[str, Condition] = {}
    for path in sorted(Path(directory).glob("*.json")):
        condition = load_condition(path)
        if condition.condition_id in conditions:
            raise ConditionError(f"Duplicate condition: {condition.condition_id}")
        conditions[condition.condition_id] = condition
    if set(conditions) != set(CONDITION_IDS):
        raise ConditionError(f"Expected exactly the conditions {CONDITION_IDS}")
    unprotected = conditions["unprotected"]
    # Full EffectShield changes enforcement only, never the model's prompt.
    if conditions["effectshield"].prompt_version != unprotected.prompt_version:
        raise ConditionError("EffectShield must reuse the unprotected prompt version")
    if conditions["safety_prompt_only"].prompt_version == unprotected.prompt_version:
        raise ConditionError("The safety prompt must carry its own prompt version")
    return conditions


def treatment_differences(first: Condition, second: Condition) -> list[str]:
    """Return differing fields; any non-treatment difference is a configuration error."""
    left, right = first.to_dict(), second.to_dict()
    differing = sorted(key for key in left if left[key] != right[key])
    undeclared = [key for key in differing if key not in TREATMENT_FIELDS]
    if undeclared:
        raise ConditionError(f"Undeclared treatment differences: {undeclared}")
    return differing
