"""Deterministic EffectShield mediator: rules 1-8, repair and protected execution (WP-07 to WP-09).

Every semantic choice that settles part of D04-D08 is a Proposed draft and is
labelled as such where it is made. Nothing here calls a model, reads payload
text or values for a decision, or holds the environment capability.
"""

from effectshield.mediator.decision import (
    ESCALATION_CODES,
    REPAIRABLE_CODES,
    VERDICT_SEVERITY,
    Decision,
    ReasonCode,
    RuleFinding,
    Verdict,
    aggregate_verdict,
    finding_verdict,
    primary_reason,
    sort_findings,
    summarize_submission,
)
from effectshield.mediator.evidence import DeliveryRecord, DeliveryStatus, EvidenceLedger
from effectshield.mediator.executor import MediatedOutcome, ProtectedExecutor, outcome_record
from effectshield.mediator.mediator import Mediator, TaskIntent
from effectshield.mediator.policy import (
    ABLATION_RULES,
    CUSTOM_POLICY_VERSION,
    MEDIATOR_POLICY_VERSION,
    RULE_VERSIONS,
    SUPPORTED_POLICY_VERSIONS,
    Ablation,
    MediatorPolicy,
    PolicyError,
    RuleId,
    policy_for,
)
from effectshield.mediator.repair import RepairResult, plan_repair
from effectshield.mediator.rules import (
    DOOR_ACCESS_OPERATIONS,
    RULE_TABLE,
    RuleContext,
    RuleFn,
    check_device_authorization,
    check_door_access,
    check_freshness,
    check_instruction_provenance,
    check_replay,
    check_sequence,
    check_thermostat_bounds,
    is_door_access,
    resolve_evidence,
)

__all__ = [
    "ABLATION_RULES",
    "CUSTOM_POLICY_VERSION",
    "DOOR_ACCESS_OPERATIONS",
    "ESCALATION_CODES",
    "MEDIATOR_POLICY_VERSION",
    "REPAIRABLE_CODES",
    "RULE_TABLE",
    "RULE_VERSIONS",
    "SUPPORTED_POLICY_VERSIONS",
    "VERDICT_SEVERITY",
    "Ablation",
    "Decision",
    "DeliveryRecord",
    "DeliveryStatus",
    "EvidenceLedger",
    "MediatedOutcome",
    "Mediator",
    "MediatorPolicy",
    "PolicyError",
    "ProtectedExecutor",
    "ReasonCode",
    "RepairResult",
    "RuleContext",
    "RuleFinding",
    "RuleFn",
    "RuleId",
    "TaskIntent",
    "Verdict",
    "aggregate_verdict",
    "check_device_authorization",
    "check_door_access",
    "check_freshness",
    "check_instruction_provenance",
    "check_replay",
    "check_sequence",
    "check_thermostat_bounds",
    "finding_verdict",
    "is_door_access",
    "outcome_record",
    "plan_repair",
    "policy_for",
    "primary_reason",
    "resolve_evidence",
    "sort_findings",
    "summarize_submission",
]
