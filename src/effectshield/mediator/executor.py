"""Protected execution of mediator decisions (SIM-07, SIM-09, OBS-07, AGT-04).

In the protected condition the :class:`ProtectedExecutor` is the only holder of
the run's :class:`ExecutionCapability`. It executes exactly what a decision
approved, as one all-or-nothing transaction bound to the state version the
mediator checked, so a blocked action has no device effect and a stale decision
executes nothing. It never receives the :class:`EnvironmentCapability`: clock
advances and environment events stay with the scenario harness (Proposed D06).

Agent feedback carries exactly the continuation protocol's visible fields;
findings, details and policy parameters stay in the decision records.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass, replace
from typing import Any

from effectshield.agent.continuation import interpret
from effectshield.domain.context import Observation
from effectshield.domain.devices import DeviceId
from effectshield.domain.errors import ExecutionRejectionCode
from effectshield.environment import RunEnvironment
from effectshield.gateway.observations import Gateway
from effectshield.gateway.requests import RequestView
from effectshield.simulator.core import ExecutionCapability, ExecutionResult, Simulator

from .decision import Decision, ReasonCode, Verdict, finding
from .evidence import EvidenceLedger
from .mediator import Mediator, TaskIntent
from .policy import Ablation, MediatorPolicy, RuleId, policy_for
from .rules import RULE_TABLE, RuleFn, is_door_access


@dataclass(frozen=True, slots=True)
class MediatedOutcome:
    """One proposal's final record, agent feedback and execution evidence.

    ``decision`` is the final record: when execution changed the outcome it is
    the superseding record, whose ``supersedes`` names the original verdict.
    """

    decision: Decision
    feedback: dict[str, Any]
    execution: ExecutionResult | None = None
    observation: Observation | None = None
    consumed: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        interpret(self.feedback)  # malformed feedback is a harness defect and raises
        object.__setattr__(self, "feedback", deepcopy(self.feedback))
        object.__setattr__(self, "consumed", tuple(self.consumed))

    def to_dict(self) -> dict[str, Any]:
        """The decision record plus its execution summary (LOG-02 material)."""
        return outcome_record(
            self.decision,
            outcome=self.feedback["status"],
            execution=self.execution,
            observation=self.observation,
            consumed=self.consumed,
        )


def outcome_record(
    decision: Decision,
    *,
    outcome: str | None = None,
    execution: ExecutionResult | None = None,
    observation: Observation | None = None,
    consumed: Sequence[str] = (),
) -> dict[str, Any]:
    """A decision record with what happened to it; ``outcome`` is ``None`` when log-only."""
    record = decision.to_dict()
    record["outcome"] = outcome
    record["execution"] = None if execution is None else _execution_summary(execution)
    record["observation_id"] = None if observation is None else observation.envelope.observation_id
    record["consumed"] = list(consumed)
    return record


def _execution_summary(result: ExecutionResult) -> dict[str, Any]:
    return {
        "transaction_id": result.transaction_id,
        "status": result.status.value,
        "version_before": result.version_before,
        "version_after": result.version_after,
        "reason_code": None if result.reason_code is None else str(result.reason_code),
        "failed_index": result.failed_index,
        "history_sequence_nos": [entry.sequence_no for entry in result.entries],
    }


def _supersede(decision: Decision, verdict: Verdict, code: ReasonCode, detail: str) -> Decision:
    extra = finding(None, code, detail)
    return replace(
        decision,
        verdict=verdict,
        reason_code=code,
        executed_actions=(),
        findings=decision.findings + (extra,),
        escalation=decision.escalation
        or extra.escalation
        or verdict in {Verdict.ESCALATE, Verdict.ERROR},
        supersedes={"verdict": decision.verdict.value, "reason_code": decision.reason_code.value},
    )


class ProtectedExecutor:
    """Holds the execution capability privately and executes only approved decisions.

    The mediator receives only ``simulator.snapshot``, a history callable and
    the gateway delivery log, never the simulator object or a capability.
    """

    def __init__(
        self,
        *,
        simulator: Simulator,
        gateway: Gateway,
        requests: RequestView,
        capability: ExecutionCapability,
        request_id: str | None = None,
        policy: MediatorPolicy | None = None,
        intents: Mapping[str, TaskIntent] | None = None,
        rule_table: Sequence[tuple[RuleId, RuleFn]] = RULE_TABLE,
    ) -> None:
        if not isinstance(simulator, Simulator):
            raise TypeError("simulator must be a Simulator")
        if not isinstance(capability, ExecutionCapability):
            raise TypeError("capability must be an ExecutionCapability")
        self._simulator = simulator
        self._gateway = gateway
        self._capability = capability
        self._ledger = EvidenceLedger(gateway.evidence, lambda: simulator.now_ms)
        self._mediator = Mediator(
            policy=policy if policy is not None else policy_for(Ablation.FULL),
            requests=requests,
            ledger=self._ledger,
            snapshot=simulator.snapshot,
            history=lambda: simulator.history,
            deliveries=lambda: gateway.deliveries,
            intents=intents,
            rule_table=rule_table,
        )
        self._records: list[dict[str, Any]] = []
        if request_id is not None:
            self.bind_request(request_id)

    @classmethod
    def from_run(
        cls,
        run: RunEnvironment,
        *,
        request_id: str | None = None,
        policy: MediatorPolicy | None = None,
        intents: Mapping[str, TaskIntent] | None = None,
        rule_table: Sequence[tuple[RuleId, RuleFn]] = RULE_TABLE,
    ) -> ProtectedExecutor:
        """Wire a run's pieces; the run (and its environment capability) is not kept."""
        return cls(
            simulator=run.simulator,
            gateway=run.gateway,
            requests=run.requests.view,
            capability=run.execution_capability,
            request_id=request_id,
            policy=policy,
            intents=intents,
            rule_table=rule_table,
        )

    @property
    def mediator(self) -> Mediator:
        return self._mediator

    @property
    def ledger(self) -> EvidenceLedger:
        return self._ledger

    @property
    def request_id(self) -> str | None:
        return self._mediator.bound_request_id

    @property
    def decisions(self) -> tuple[dict[str, Any], ...]:
        """Fresh copies of every final decision record, in submission order."""
        return tuple(deepcopy(record) for record in self._records)

    def bind_request(self, request_id: str) -> None:
        """The harness binds the run's issued request once."""
        self._mediator.bind_request(request_id)

    def deliver(self, observation: Observation) -> Observation:
        """Ingest an observation; the caller must place exactly it in the agent's context."""
        self._ledger.ingest(observation)
        return observation

    def submit(self, proposal: object, *, request_id: str | None = None) -> MediatedOutcome:
        """Decide one proposal and carry out the decision. Defaults to the bound request."""
        chosen = request_id if request_id is not None else self._mediator.bound_request_id
        outcome = self._carry_out(self._mediator.decide(proposal, request_id=chosen))
        self._records.append(outcome.to_dict())
        return outcome

    def _carry_out(self, decision: Decision) -> MediatedOutcome:
        if decision.verdict is Verdict.ALLOW and decision.is_read:
            assert decision.action is not None
            observation = self.deliver(self._gateway.observe(decision.action.device))
            feedback = {"status": "observed", "observation": observation.to_agent_dict()}
            return MediatedOutcome(decision, feedback, observation=observation)
        if decision.verdict in {Verdict.ALLOW, Verdict.REPAIR}:
            return self._execute(decision)
        if decision.verdict is Verdict.BLOCK:
            return MediatedOutcome(decision, self._blocked(decision.reason_code, decision))
        return MediatedOutcome(
            decision, {"status": "escalated", "reason_code": decision.reason_code.value}
        )

    def _blocked(self, code: ReasonCode, decision: Decision | None = None) -> dict[str, Any]:
        version = None if decision is None else decision.state_version
        return {
            "status": "blocked",
            "reason_code": code.value,
            "state_version": self._simulator.state_version if version is None else version,
        }

    def _execute(self, decision: Decision) -> MediatedOutcome:
        if decision.state_version is None:
            raise ValueError("an approved effect must be bound to a checked state version")
        try:
            result = self._simulator.execute(
                decision.executed_actions,
                expected_version=decision.state_version,
                capability=self._capability,
            )
        except Exception as exc:
            final = _supersede(
                decision, Verdict.ERROR, ReasonCode.MEDIATOR_ERROR, type(exc).__name__
            )
            return MediatedOutcome(
                final, {"status": "escalated", "reason_code": ReasonCode.MEDIATOR_ERROR.value}
            )
        if result.committed:
            self._mediator.record_commit(decision, result)
            consumed = self._consume(decision)
            transaction = {
                "transaction_id": result.transaction_id,
                "version_before": result.version_before,
                "version_after": result.version_after,
            }
            feedback: dict[str, Any]
            if decision.verdict is Verdict.REPAIR:
                feedback = {
                    "status": "repaired",
                    **transaction,
                    "reason_code": decision.reason_code.value,
                    "executed_actions": [a.to_dict() for a in decision.executed_actions],
                }
            else:
                feedback = {
                    "status": "committed",
                    **transaction,
                    "reason_code": None,
                    "failed_index": None,
                }
            return MediatedOutcome(decision, feedback, execution=result, consumed=consumed)
        if result.reason_code == ExecutionRejectionCode.STALE_STATE_VERSION:
            # SIM-09: the state changed after the check; block rather than re-run.
            final = _supersede(
                decision, Verdict.BLOCK, ReasonCode.STALE_DECISION, result.detail or ""
            )
            return MediatedOutcome(
                final, self._blocked(ReasonCode.STALE_DECISION), execution=result
            )
        feedback = {
            "status": "rejected",
            "transaction_id": result.transaction_id,
            "version_before": result.version_before,
            "version_after": result.version_after,
            "reason_code": str(result.reason_code),
            "failed_index": result.failed_index,
        }
        return MediatedOutcome(decision, feedback, execution=result)

    def _consume(self, decision: Decision) -> tuple[str, ...]:
        """Mark the presence evidence of a committed access transaction as used (Proposed D07)."""
        operations = [a.operation for a in decision.executed_actions if is_door_access(a)]
        if not operations:
            return ()
        if decision.request_id is None:
            raise ValueError("an approved access decision must name its request")
        presence = tuple(
            oid
            for oid in decision.evidence_ids
            if (known := self._ledger.known_deliveries(oid))
            and known[-1].device is DeviceId.PRESENCE_SENSOR
        )
        if presence:
            self._ledger.consume(presence, request_id=decision.request_id, operations=operations)
        return presence
