"""Evaluation-runner wiring for the protected EffectShield condition.

Ahmed's :class:`~effectshield.experiments.mediated.MediatedBackend` decides every
proposal through the mediator and keeps the final decision records out of the
agent-visible transcript. This adapter streams each new record to the runner as
a ``mediator_decision`` event, ahead of the effects and messages that follow it,
so the runner can retain it beside the trace (LOG-02 record assembly). It adds
no policy logic and changes nothing the agent sees.

Repairs are derived here from the executed decisions only as transition
references; the independent grader still judges their safety and usefulness
from the simulator trace (EXP-01, EXP-03).
"""

from __future__ import annotations

from collections.abc import Iterator
from copy import deepcopy
from typing import Any

from effectshield.mediator import MEDIATOR_POLICY_VERSION, RULE_VERSIONS, Ablation, policy_for

from .mediated import MediatedBackend

DECISION_SCHEMA_VERSION = "mediator-decisions/v1"


def mediator_policy_record() -> dict[str, Any]:
    """The pinned full policy, recorded in every protected batch manifest (LOG-01)."""
    return {
        "version": MEDIATOR_POLICY_VERSION,
        "fingerprint": policy_for(Ablation.FULL).fingerprint(),
        "rule_versions": {str(int(rule)): version for rule, version in RULE_VERSIONS.items()},
    }


class ProtectedRunBackend(MediatedBackend):
    """Stream mediator decision records as runner events; behaviour is otherwise inherited."""

    def run(
        self, request: dict[str, Any], observations: list[dict[str, Any]], config: dict[str, Any]
    ) -> Iterator[dict[str, Any]]:
        emitted = 0
        for event in super().run(request, observations, config):
            # A record is appended before the backend yields any event caused by
            # that decision, so this ordering places it before its own effects.
            while emitted < len(self.decisions):
                yield {"type": "mediator_decision", "record": deepcopy(self.decisions[emitted])}
                emitted += 1
            yield event
        if emitted != len(self.decisions):
            raise ValueError("Mediator decision recorded after the run finished")


def repairs_from_decisions(
    decisions: list[dict[str, Any]], transitions: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Map repair decisions to committed transition indexes for the grader.

    A repair whose transaction committed is ``executed`` and cites the
    action-kind history entries of that transaction. A repair that was decided
    but superseded or rejected before commit is recorded as not executed.
    """
    index_by_sequence = {
        entry.get("sequence_no"): index
        for index, entry in enumerate(transitions)
        if isinstance(entry, dict)
    }
    repairs = []
    for record in decisions:
        original = (record.get("supersedes") or {}).get("verdict", record.get("verdict"))
        if original != "repair":
            continue
        execution = record.get("execution") or {}
        executed = record.get("outcome") == "repaired" and execution.get("status") == "committed"
        indexes = (
            [index_by_sequence.get(number) for number in execution.get("history_sequence_nos", [])]
            if executed
            else []
        )
        if any(index is None for index in indexes):
            raise ValueError("Repair decision cites a transition absent from the trace")
        repairs.append(
            {
                "executed": executed,
                "transition_indexes": indexes,
                "reason_code": record.get("reason_code"),
                "candidate": deepcopy(record.get("repair_candidate")),
            }
        )
    return repairs


def decision_summary(decisions: list[dict[str, Any]]) -> dict[str, Any]:
    """Per-run decision counts; grades remain the independent outcome measure."""
    verdicts: dict[str, int] = {}
    reasons: dict[str, int] = {}
    for record in decisions:
        verdicts[record["verdict"]] = verdicts.get(record["verdict"], 0) + 1
        reasons[record["reason_code"]] = reasons.get(record["reason_code"], 0) + 1
    return {
        "decisions": len(decisions),
        "verdicts": dict(sorted(verdicts.items())),
        "reason_codes": dict(sorted(reasons.items())),
        "escalations": sum(record.get("escalation") is True for record in decisions),
        "executed_repairs": sum(
            record.get("verdict") == "repair" and record.get("outcome") == "repaired"
            for record in decisions
        ),
    }
