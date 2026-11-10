"""Mediator verdicts, stable reason codes, findings and decision records (MED-01, MED-12, MED-13).

A :class:`Decision` keeps every failed check, not only the one reported to the
agent, so logs show which rules fired regardless of evaluation order. The
aggregation below is the precedence rule (MED-13): findings are sorted by
``(rule, code, detail)``; the verdict is the most severe finding; the primary
reason is the first sorted finding with that verdict. Reason codes are
agent-visible through ``blocked``/``escalated`` feedback, so they name the
device or fact the agent can act on and never rule internals.
"""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Any

from effectshield.domain.actions import ActionProposal

from .policy import RuleId

PREVIEW_LIMIT = 256


class Verdict(StrEnum):
    ALLOW = "allow"
    BLOCK = "block"
    REPAIR = "repair"
    ESCALATE = "escalate"
    ERROR = "error"


VERDICT_SEVERITY: Mapping[Verdict, int] = MappingProxyType(
    {
        Verdict.ERROR: 4,
        Verdict.ESCALATE: 3,
        Verdict.BLOCK: 2,
        Verdict.REPAIR: 1,
        Verdict.ALLOW: 0,
    }
)


class ReasonCode(StrEnum):
    ALLOWED = "allowed"
    READ_ALLOWED_BY_POLICY = "read_allowed_by_policy"
    # Rule 1
    SCHEMA_INVALID = "schema_invalid"
    # Rule 2
    IDENTITY_MISSING = "identity_missing"
    IDENTITY_INVALID = "identity_invalid"
    DEVICE_OUT_OF_SCOPE = "device_out_of_scope"
    # Rule 3
    OPERATION_NOT_AUTHORIZED = "operation_not_authorized"
    EVIDENCE_UNKNOWN_ORIGIN = "evidence_unknown_origin"
    # Rule 4
    PRESENCE_EVIDENCE_EXPIRED = "presence_evidence_expired"
    PRESENCE_EVIDENCE_FUTURE_TIME = "presence_evidence_future_time"
    PRESENCE_EVIDENCE_SUPERSEDED = "presence_evidence_superseded"
    # Rule 5
    PRESENCE_EVIDENCE_REPLAYED = "presence_evidence_replayed"
    PRESENCE_EVIDENCE_CONSUMED = "presence_evidence_consumed"
    # Rule 6
    PRESENCE_EVIDENCE_MISSING = "presence_evidence_missing"
    PRESENCE_NOT_CONFIRMED = "presence_not_confirmed"
    # Rule 7
    SETPOINT_OUT_OF_BOUNDS = "setpoint_out_of_bounds"
    THERMOSTAT_UNSAFE_CURRENT_SETPOINT = "thermostat_unsafe_current_setpoint"
    # Rule 8
    PRECONDITION_UNMET = "precondition_unmet"
    HISTORY_INCONSISTENT = "history_inconsistent"
    # Repair (WP-09)
    REPAIRED_CLAMP = "repaired_clamp"
    REPAIRED_PREREQUISITE = "repaired_prerequisite"
    REPAIR_NOT_TASK_PRESERVING = "repair_not_task_preserving"
    REPAIR_UNAVAILABLE = "repair_unavailable"
    REPAIR_AMBIGUOUS = "repair_ambiguous"
    REPAIR_TOO_LONG = "repair_too_long"
    REPAIR_FAILED_REVALIDATION = "repair_failed_revalidation"
    REPAIR_NO_EFFECT = "repair_no_effect"
    # Fail-closed meta outcomes (MED-12)
    MEDIATOR_ERROR = "mediator_error"
    POLICY_INVALID = "policy_invalid"
    TRUSTED_CONTEXT_MALFORMED = "trusted_context_malformed"
    # Execution (SIM-09)
    STALE_DECISION = "stale_decision"


ESCALATE_CODES = frozenset({ReasonCode.IDENTITY_MISSING, ReasonCode.IDENTITY_INVALID})
ERROR_CODES = frozenset(
    {
        ReasonCode.MEDIATOR_ERROR,
        ReasonCode.POLICY_INVALID,
        ReasonCode.TRUSTED_CONTEXT_MALFORMED,
    }
)
REPAIRABLE_CODES = frozenset({ReasonCode.SETPOINT_OUT_OF_BOUNDS, ReasonCode.PRECONDITION_UNMET})
# Findings that record an escalation even when the verdict is an ordinary block.
ESCALATION_CODES = (
    ESCALATE_CODES
    | ERROR_CODES
    | {
        ReasonCode.DEVICE_OUT_OF_SCOPE,
        ReasonCode.OPERATION_NOT_AUTHORIZED,
    }
)


@dataclass(frozen=True, slots=True)
class RuleFinding:
    """One failed check.

    ``rule`` is ``None`` for checks outside rules 1-8: fail-closed mediator
    errors, repair revalidation of a physically invalid sequence and
    execution-time staleness.
    """

    rule: RuleId | None
    code: ReasonCode
    detail: str
    repairable: bool = False
    escalation: bool = False

    def sort_key(self) -> tuple[int, str, str]:
        return (0 if self.rule is None else int(self.rule), self.code.value, self.detail)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule": None if self.rule is None else int(self.rule),
            "code": self.code.value,
            "detail": self.detail,
            "repairable": self.repairable,
            "escalation": self.escalation,
        }


def finding(rule: RuleId | None, code: ReasonCode, detail: str) -> RuleFinding:
    """A finding whose repairable/escalation flags follow the reason-code table."""
    return RuleFinding(
        rule,
        code,
        detail,
        repairable=code in REPAIRABLE_CODES,
        escalation=code in ESCALATION_CODES,
    )


def finding_verdict(item: RuleFinding) -> Verdict:
    if item.code in ERROR_CODES:
        return Verdict.ERROR
    if item.code in ESCALATE_CODES:
        return Verdict.ESCALATE
    return Verdict.BLOCK


def sort_findings(findings: Iterable[RuleFinding]) -> tuple[RuleFinding, ...]:
    return tuple(sorted(findings, key=RuleFinding.sort_key))


def aggregate_verdict(findings: Iterable[RuleFinding]) -> Verdict:
    """The most severe finding's verdict; ``ALLOW`` when nothing failed."""
    verdicts = [finding_verdict(item) for item in findings]
    return max(verdicts, key=VERDICT_SEVERITY.__getitem__, default=Verdict.ALLOW)


def primary_reason(findings: Iterable[RuleFinding], verdict: Verdict) -> ReasonCode:
    """The first sorted finding whose verdict equals the aggregate verdict."""
    for item in sort_findings(findings):
        if finding_verdict(item) is verdict:
            return item.code
    raise ValueError(f"no finding has verdict {verdict.value}")


def summarize_submission(proposal: object) -> dict[str, Any]:
    """A bounded, deterministic record of exactly what was submitted to rule 1."""
    kind: str
    data: bytes
    preview: str
    if isinstance(proposal, ActionProposal):
        kind = "proposal"
        try:
            text = json.dumps(proposal.to_dict(), sort_keys=True, separators=(",", ":"))
        except (TypeError, ValueError, AttributeError, RecursionError):
            text = type(proposal).__qualname__
        data, preview = text.encode("utf-8"), text[:PREVIEW_LIMIT]
    elif isinstance(proposal, str):
        kind = "str"
        data = proposal.encode("utf-8", "surrogatepass")
        # Lone surrogates cannot be written as UTF-8 later; escape them in the preview.
        preview = proposal[:PREVIEW_LIMIT].encode("utf-8", "backslashreplace").decode("utf-8")
    elif isinstance(proposal, bytes):
        kind = "bytes"
        data = proposal
        preview = base64.b64encode(proposal[:PREVIEW_LIMIT]).decode("ascii")
    elif isinstance(proposal, Mapping):
        kind = "mapping"
        try:
            text = json.dumps(dict(proposal), sort_keys=True, separators=(",", ":"))
        except Exception:  # an arbitrary Mapping may fail in any way; record its type only
            text = type(proposal).__qualname__
        data = text.encode("utf-8", "surrogatepass")
        preview = text[:PREVIEW_LIMIT].encode("utf-8", "backslashreplace").decode("utf-8")
    else:
        kind = "other"
        text = type(proposal).__qualname__
        data, preview = text.encode("utf-8"), text[:PREVIEW_LIMIT]
    return {
        "kind": kind,
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
        "preview": preview,
    }


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({str(key): _freeze(item) for key, item in value.items()})
    if isinstance(value, list | tuple):
        return tuple(_freeze(item) for item in value)
    return value


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw(item) for item in value]
    return value


@dataclass(frozen=True, slots=True)
class Decision:
    """The complete, immutable record of one mediator decision (MED-13, LOG-02).

    ``executed_actions`` are the effects this decision approves: the action for
    an allowed effect, the candidate for a repair, otherwise nothing.
    ``supersedes`` is set only on the executor's final record when execution
    changed the outcome (for example a stale state version).
    """

    verdict: Verdict
    reason_code: ReasonCode
    findings: tuple[RuleFinding, ...]
    action: ActionProposal | None
    submitted: Mapping[str, Any]
    executed_actions: tuple[ActionProposal, ...]
    repair_candidate: tuple[ActionProposal, ...] | None
    state_version: int | None
    time_ms: int | None
    request_id: str | None
    evidence_ids: tuple[str, ...]
    escalation: bool
    rules_evaluated: tuple[int, ...]
    policy: Mapping[str, Any]
    rule_versions: Mapping[str, str]
    annotations: tuple[str, ...]
    is_read: bool
    supersedes: Mapping[str, Any] | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "findings", tuple(self.findings))
        object.__setattr__(self, "executed_actions", tuple(self.executed_actions))
        if self.repair_candidate is not None:
            object.__setattr__(self, "repair_candidate", tuple(self.repair_candidate))
        object.__setattr__(self, "evidence_ids", tuple(self.evidence_ids))
        object.__setattr__(self, "rules_evaluated", tuple(self.rules_evaluated))
        object.__setattr__(self, "annotations", tuple(self.annotations))
        object.__setattr__(self, "submitted", _freeze(self.submitted))
        object.__setattr__(self, "policy", _freeze(self.policy))
        object.__setattr__(self, "rule_versions", _freeze(self.rule_versions))
        if self.supersedes is not None:
            object.__setattr__(self, "supersedes", _freeze(self.supersedes))

    @property
    def allowed(self) -> bool:
        """True when this decision approves an effect or a read."""
        return self.verdict in {Verdict.ALLOW, Verdict.REPAIR}

    def to_dict(self) -> dict[str, Any]:
        """A fresh JSON-ready copy with deterministic content."""
        return {
            "verdict": self.verdict.value,
            "reason_code": self.reason_code.value,
            "findings": [item.to_dict() for item in self.findings],
            "action": None if self.action is None else self.action.to_dict(),
            "submitted": _thaw(self.submitted),
            "executed_actions": [action.to_dict() for action in self.executed_actions],
            "repair_candidate": (
                None
                if self.repair_candidate is None
                else [action.to_dict() for action in self.repair_candidate]
            ),
            "state_version": self.state_version,
            "time_ms": self.time_ms,
            "request_id": self.request_id,
            "evidence_ids": list(self.evidence_ids),
            "escalation": self.escalation,
            "rules_evaluated": list(self.rules_evaluated),
            "policy": _thaw(self.policy),
            "rule_versions": _thaw(self.rule_versions),
            "annotations": list(self.annotations),
            "is_read": self.is_read,
            "supersedes": None if self.supersedes is None else _thaw(self.supersedes),
        }
