"""Versioned mediator policy, rule identifiers and ablation presets (MED-01, MED-12, MED-13).

A policy is the complete parameter set the deterministic rules read. Only three
presets exist for experiments: the full policy and the two contract ablations.
Each preset fixes every parameter, so an ablation can differ from the full
policy only in the rules it disables. ``CUSTOM`` exists for unit tests and must
carry its own version string so it can never be mistaken for a preset.

Parameter values are drafts: the sensor TTL and its inclusive boundary are
Proposed D06, and the repair bound is Proposed D08. The 16-30 C thermostat range
is the contract's rule 7.
"""

from __future__ import annotations

import math
from collections.abc import Mapping
from dataclasses import dataclass
from enum import IntEnum, StrEnum
from types import MappingProxyType
from typing import Any

from effectshield.domain.devices import (
    THERMOSTAT_DEVICE_MAX_C,
    THERMOSTAT_DEVICE_MIN_C,
    is_json_number,
)
from effectshield.simulator.core import MAX_TRANSACTION_ACTIONS

MEDIATOR_POLICY_VERSION = "mediator-policy-draft/v1"
CUSTOM_POLICY_VERSION = "mediator-policy-custom/test"
SUPPORTED_POLICY_VERSIONS = frozenset({MEDIATOR_POLICY_VERSION, CUSTOM_POLICY_VERSION})


class RuleId(IntEnum):
    """The contract's enforcement rules 1-8."""

    TYPED_ACTION = 1
    DEVICE_AUTHORIZATION = 2
    INSTRUCTION_PROVENANCE = 3
    FRESHNESS = 4
    REPLAY = 5
    DOOR_ACCESS = 6
    THERMOSTAT_BOUNDS = 7
    SEQUENCE = 8


RULE_VERSIONS: Mapping[RuleId, str] = MappingProxyType(
    {
        RuleId.TYPED_ACTION: "rule1-typed-action/v1",
        RuleId.DEVICE_AUTHORIZATION: "rule2-device-authorization/v1",
        RuleId.INSTRUCTION_PROVENANCE: "rule3-instruction-provenance/v1",
        RuleId.FRESHNESS: "rule4-freshness/v1",
        RuleId.REPLAY: "rule5-replay/v1",
        RuleId.DOOR_ACCESS: "rule6-door-access/v1",
        RuleId.THERMOSTAT_BOUNDS: "rule7-thermostat-bounds/v1",
        RuleId.SEQUENCE: "rule8-sequence/v1",
    }
)

ALL_RULES: frozenset[RuleId] = frozenset(RuleId)
# Identity and the typed boundary are never ablated: without them no other
# rule has an action or an authority to reason about.
MANDATORY_RULES: frozenset[RuleId] = frozenset({RuleId.TYPED_ACTION, RuleId.DEVICE_AUTHORIZATION})


class Ablation(StrEnum):
    FULL = "full"
    NO_PROVENANCE = "no_provenance"
    NO_FRESHNESS_REPLAY = "no_freshness_replay"
    CUSTOM = "custom"


ABLATION_RULES: Mapping[Ablation, frozenset[RuleId]] = MappingProxyType(
    {
        Ablation.FULL: ALL_RULES,
        Ablation.NO_PROVENANCE: ALL_RULES - {RuleId.INSTRUCTION_PROVENANCE},
        Ablation.NO_FRESHNESS_REPLAY: ALL_RULES - {RuleId.FRESHNESS, RuleId.REPLAY},
    }
)

DEFAULT_SENSOR_TTL_MS = 60_000
DEFAULT_THERMOSTAT_MIN_C = 16.0
DEFAULT_THERMOSTAT_MAX_C = 30.0
DEFAULT_MAX_REPAIR_ACTIONS = 2


class PolicyError(ValueError):
    """A policy is malformed, inconsistent with its preset or of an unsupported version."""


def _is_int(value: object) -> bool:
    return type(value) is int


@dataclass(frozen=True, slots=True)
class MediatorPolicy:
    """Immutable, versioned mediator parameters.

    ``sensor_ttl_ms`` is inclusive (Proposed D06): evidence exactly ``ttl`` old is
    fresh and ``ttl + 1`` is expired. ``max_repair_actions`` bounds a repaired
    transaction (Proposed D08).
    """

    ablation: Ablation = Ablation.FULL
    enabled_rules: frozenset[RuleId] = ALL_RULES
    sensor_ttl_ms: int = DEFAULT_SENSOR_TTL_MS
    thermostat_min_c: float = DEFAULT_THERMOSTAT_MIN_C
    thermostat_max_c: float = DEFAULT_THERMOSTAT_MAX_C
    max_repair_actions: int = DEFAULT_MAX_REPAIR_ACTIONS
    version: str = MEDIATOR_POLICY_VERSION

    def __post_init__(self) -> None:
        try:
            ablation = Ablation(self.ablation)
            rules = frozenset(_rule_id(rule) for rule in self.enabled_rules)
        except (TypeError, ValueError) as exc:
            raise PolicyError(f"malformed ablation or rule set: {exc}") from exc
        object.__setattr__(self, "ablation", ablation)
        object.__setattr__(self, "enabled_rules", rules)
        # Normalize integral Celsius bounds so fingerprints compare by value.
        for name in ("thermostat_min_c", "thermostat_max_c"):
            value = getattr(self, name)
            if is_json_number(value):
                object.__setattr__(self, name, float(value))
        self.validate()

    def validate(self) -> None:
        """Raise :class:`PolicyError` unless this is a preset or a well-formed test policy.

        Called on construction and again before every decision, so a policy
        mutated after construction fails closed (MED-12).
        """
        if not isinstance(self.ablation, Ablation):
            raise PolicyError("ablation must be an Ablation")
        rules = self.enabled_rules
        if not isinstance(rules, frozenset) or not all(isinstance(r, RuleId) for r in rules):
            raise PolicyError("enabled_rules must be a frozenset of RuleId")
        if not MANDATORY_RULES <= rules:
            raise PolicyError("rules 1 and 2 cannot be disabled")
        if not isinstance(self.version, str) or self.version not in SUPPORTED_POLICY_VERSIONS:
            raise PolicyError(f"unsupported policy version {self.version!r}")
        self._validate_parameters()
        if self.ablation is Ablation.CUSTOM:
            if self.version != CUSTOM_POLICY_VERSION:
                raise PolicyError(f"custom policies must use version {CUSTOM_POLICY_VERSION}")
            return
        preset = (
            ABLATION_RULES[self.ablation],
            DEFAULT_SENSOR_TTL_MS,
            DEFAULT_THERMOSTAT_MIN_C,
            DEFAULT_THERMOSTAT_MAX_C,
            DEFAULT_MAX_REPAIR_ACTIONS,
            MEDIATOR_POLICY_VERSION,
        )
        actual = (
            rules,
            self.sensor_ttl_ms,
            self.thermostat_min_c,
            self.thermostat_max_c,
            self.max_repair_actions,
            self.version,
        )
        if actual != preset:
            raise PolicyError(f"{self.ablation.value} policy differs from its frozen preset")

    def _validate_parameters(self) -> None:
        if not _is_int(self.sensor_ttl_ms) or self.sensor_ttl_ms <= 0:
            raise PolicyError("sensor_ttl_ms must be a positive int")
        low, high = self.thermostat_min_c, self.thermostat_max_c
        for value in (low, high):
            if type(value) is not float or not math.isfinite(value):
                raise PolicyError("thermostat bounds must be finite floats")
        if not THERMOSTAT_DEVICE_MIN_C <= low < high <= THERMOSTAT_DEVICE_MAX_C:
            raise PolicyError("thermostat bounds must satisfy device min <= min < max <= max")
        repair = self.max_repair_actions
        if not _is_int(repair) or not 1 <= repair <= MAX_TRANSACTION_ACTIONS:
            raise PolicyError(f"max_repair_actions must be an int in 1..{MAX_TRANSACTION_ACTIONS}")

    def fingerprint(self) -> dict[str, Any]:
        """The full JSON-ready parameter set, recorded in every decision."""
        return {
            "version": self.version,
            "ablation": self.ablation.value,
            "enabled_rules": sorted(int(rule) for rule in self.enabled_rules),
            "sensor_ttl_ms": self.sensor_ttl_ms,
            "thermostat_min_c": self.thermostat_min_c,
            "thermostat_max_c": self.thermostat_max_c,
            "max_repair_actions": self.max_repair_actions,
        }


def _rule_id(value: object) -> RuleId:
    # RuleId(True) would silently mean rule 1.
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"rule identifiers must be ints, got {type(value).__name__}")
    return RuleId(value)


def policy_for(ablation: Ablation | str) -> MediatorPolicy:
    """The frozen preset for the full policy or one of the two contract ablations."""
    try:
        chosen = Ablation(ablation)
    except ValueError as exc:
        raise PolicyError(f"unknown ablation {ablation!r}") from exc
    if chosen is Ablation.CUSTOM:
        raise PolicyError("custom policies have no preset; construct one explicitly")
    return MediatorPolicy(ablation=chosen, enabled_rules=ABLATION_RULES[chosen])
