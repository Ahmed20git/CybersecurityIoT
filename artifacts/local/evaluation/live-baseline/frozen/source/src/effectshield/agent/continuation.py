"""Frozen continuation protocol: what the agent sees and does after each outcome.

The trusted harness reports exactly one outcome per proposal. Allowed effects
surface as the simulator's own result (committed, observed or rejected). A
mediator may instead block, repair, abstain or escalate. Blocks and rejections
are visible refusals: the agent may propose again, but only within the same
call/step/token/time budget, and consecutive refusals end the run so retry
loops terminate. Abstention and escalation end the run without another call.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

CONTINUATION_PROTOCOL_VERSION = "continuation-draft/v1"
MAX_CONSECUTIVE_REFUSALS = 2


class Outcome(StrEnum):
    COMMITTED = "committed"
    OBSERVED = "observed"
    REJECTED = "rejected"
    BLOCKED = "blocked"
    REPAIRED = "repaired"
    ABSTAINED = "abstained"
    ESCALATED = "escalated"


_TRANSACTION = {
    "status",
    "transaction_id",
    "version_before",
    "version_after",
    "reason_code",
    "failed_index",
}
# Exact agent-visible fields per outcome; nothing else (rule internals, grader
# labels, simulator capabilities) can reach the model through feedback.
VISIBLE_FIELDS: dict[Outcome, set[str]] = {
    Outcome.COMMITTED: _TRANSACTION,
    Outcome.REJECTED: _TRANSACTION,
    Outcome.OBSERVED: {"status", "observation"},
    Outcome.BLOCKED: {"status", "reason_code", "state_version"},
    Outcome.REPAIRED: {
        "status",
        "transaction_id",
        "version_before",
        "version_after",
        "reason_code",
        "executed_actions",
    },
    Outcome.ABSTAINED: {"status", "reason_code"},
    Outcome.ESCALATED: {"status", "reason_code"},
}
REFUSALS = frozenset({Outcome.REJECTED, Outcome.BLOCKED})
# Terminal outcomes and the agent stop status each produces.
TERMINAL_STATUS = {Outcome.ABSTAINED: "abstained", Outcome.ESCALATED: "escalated"}


@dataclass(frozen=True)
class Directive:
    """How the agent proceeds after one reported outcome."""

    outcome: Outcome
    visible: dict[str, Any]
    terminal_status: str | None
    refusal: bool


def _reason(feedback: dict[str, Any], *, required: bool) -> None:
    value = feedback.get("reason_code")
    if value is None and not required:
        return
    if not isinstance(value, str) or not value or len(value) > 100:
        raise ValueError("Feedback reason_code must be a short non-empty string")


def interpret(feedback: object) -> Directive:
    """Validate harness feedback against the protocol; malformed feedback is a harness defect."""
    if not isinstance(feedback, dict):
        raise ValueError("Feedback must be an object")
    status = feedback.get("status")
    if not isinstance(status, str) or status not in set(Outcome):
        raise ValueError(f"Unsupported feedback status: {status!r}")
    outcome = Outcome(status)
    if set(feedback) != VISIBLE_FIELDS[outcome]:
        raise ValueError(
            f"{outcome.value} feedback fields must be exactly {sorted(VISIBLE_FIELDS[outcome])}"
        )
    if outcome in {Outcome.REJECTED, Outcome.BLOCKED, Outcome.ABSTAINED, Outcome.ESCALATED}:
        _reason(feedback, required=True)
    elif outcome is Outcome.REPAIRED:
        _reason(feedback, required=True)
        actions = feedback["executed_actions"]
        if not isinstance(actions, list) or not actions:
            raise ValueError("Repaired feedback must list the executed repair actions")
    return Directive(
        outcome=outcome,
        visible=deepcopy(feedback),
        terminal_status=TERMINAL_STATUS.get(outcome),
        refusal=outcome in REFUSALS,
    )
