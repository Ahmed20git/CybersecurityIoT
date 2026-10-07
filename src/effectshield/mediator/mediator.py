"""The deterministic mediator between agent proposals and the simulator (MED-01 to MED-13).

The mediator decides; it never executes. It holds no simulator object and no
capability, only read-only callables for the current snapshot, the committed
history and the gateway delivery log, plus the read-only request and evidence
views. There is no model call, randomness, wall clock or I/O, so the same
action, trusted context, policy, state and ledger give the same decision,
reason codes and candidate effects (MED-01).

Authority comes only from the harness-issued request (rules 2-3). Evidence
references are pointers that never grant authority, and no decision reads
payload text or payload values. Any exception or malformed trusted context
fails closed with an ``error`` decision and no effect (MED-12).
"""

from __future__ import annotations

import json
import math
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from effectshield.domain.actions import ActionProposal, parse_action
from effectshield.domain.catalog import get_operation_spec
from effectshield.domain.context import RequestContext
from effectshield.domain.devices import HomeSnapshot, HomeState, is_json_number
from effectshield.domain.errors import ActionSchemaError, SchemaErrorCode
from effectshield.gateway.observations import Delivery
from effectshield.gateway.requests import RequestView
from effectshield.simulator.core import ExecutionResult, TraceEntry, TraceKind

from .decision import (
    Decision,
    ReasonCode,
    RuleFinding,
    Verdict,
    aggregate_verdict,
    finding,
    primary_reason,
    sort_findings,
    summarize_submission,
)
from .evidence import REPLAY_STATUSES, EvidenceLedger
from .policy import RULE_VERSIONS, MediatorPolicy, PolicyError, RuleId
from .repair import plan_repair
from .rules import (
    RULE_TABLE,
    RuleContext,
    RuleFn,
    identity_findings,
    resolve_evidence,
    trusted_record,
)

_RULE_VERSION_RECORD: Mapping[str, str] = MappingProxyType(
    {str(int(rule)): version for rule, version in RULE_VERSIONS.items()}
)
_READ_RULES = (int(RuleId.TYPED_ACTION), int(RuleId.DEVICE_AUTHORIZATION))


@dataclass(frozen=True, slots=True)
class TaskIntent:
    """Trusted, harness-issued task constraint used only for repair (Proposed D05/D08).

    Never derived from grader labels (``completion``, ``expected_result``) or
    parsed from ``request_text``. ``setpoint_range_c`` is the inclusive range of
    setpoints that still completes the request; ``None`` means no clamp can be
    shown to preserve the task.
    """

    request_id: str
    setpoint_range_c: tuple[float, float] | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.request_id, str) or not self.request_id:
            raise ValueError("request_id must be a non-empty string")
        if self.setpoint_range_c is None:
            return
        values = tuple(self.setpoint_range_c)
        if len(values) != 2 or not all(
            is_json_number(v) and math.isfinite(float(v)) for v in values
        ):
            raise ValueError("setpoint_range_c must be two finite numbers")
        low, high = float(values[0]), float(values[1])
        if low > high:
            raise ValueError("setpoint_range_c must be ordered (low, high)")
        object.__setattr__(self, "setpoint_range_c", (low, high))


class _MalformedContext(Exception):
    """Trusted context failed a structural check; decide fails closed."""

    def __init__(self, detail: str) -> None:
        super().__init__(detail)
        self.detail = detail


@dataclass
class _Progress:
    """What a failing decision had already established, for its error record."""

    action: ActionProposal | None = None
    snapshot: HomeSnapshot | None = None


class Mediator:
    """Pure policy decisions over read-only trusted context.

    ``bound_request_id`` is the request the harness issued for this run; any
    other request is conflicting authority (Proposed D05). ``intents`` supply
    the trusted task constraints that clamp repair needs.
    """

    def __init__(
        self,
        *,
        policy: MediatorPolicy,
        requests: RequestView,
        ledger: EvidenceLedger,
        snapshot: Callable[[], HomeSnapshot],
        history: Callable[[], tuple[TraceEntry, ...]],
        deliveries: Callable[[], tuple[Delivery, ...]],
        bound_request_id: str | None = None,
        intents: Mapping[str, TaskIntent] | None = None,
        rule_table: Sequence[tuple[RuleId, RuleFn]] = RULE_TABLE,
    ) -> None:
        self._policy = policy
        self._requests = requests
        self._ledger = ledger
        self._snapshot = snapshot
        self._history = history
        self._deliveries = deliveries
        self._bound_request_id = bound_request_id
        self._intents: Mapping[str, TaskIntent] = MappingProxyType(dict(intents or {}))
        self._rule_table = tuple(rule_table)
        self._committed: list[dict[str, Any]] = []

    @property
    def policy(self) -> MediatorPolicy:
        return self._policy

    @property
    def bound_request_id(self) -> str | None:
        return self._bound_request_id

    def bind_request(self, request_id: str) -> None:
        """Bind the run's harness-issued request. Allowed once."""
        if self._bound_request_id is not None:
            raise ValueError("this mediator is already bound to a request")
        if not isinstance(request_id, str) or self._requests.lookup(request_id) is None:
            raise ValueError("only an issued request can be bound")
        self._bound_request_id = request_id

    def record_commit(self, decision: Decision, result: ExecutionResult) -> None:
        """Executor bookkeeping: remember committed actions for rule 8's history check."""
        if not result.committed or not decision.allowed or decision.is_read:
            raise ValueError("only committed effect decisions are recorded")
        committed = [entry.action.to_dict() for entry in result.entries if entry.action]
        if committed != [action.to_dict() for action in decision.executed_actions]:
            raise ValueError("committed actions differ from the approved actions")
        self._committed.extend(committed)

    def decide(self, proposal: object, *, request_id: str | None) -> Decision:
        """Decide one proposal. Never raises; failures become ``error`` decisions."""
        resolved_id = request_id if isinstance(request_id, str) else None
        try:
            submitted = summarize_submission(proposal)
        except Exception:
            submitted = {"kind": "other", "sha256": "", "size": 0, "preview": ""}
        progress = _Progress()
        try:
            if not isinstance(self._policy, MediatorPolicy):
                raise PolicyError("policy must be a MediatorPolicy")
            self._policy.validate()
        except Exception as exc:
            return self._failure(
                ReasonCode.POLICY_INVALID, type(exc).__name__, submitted, resolved_id, progress
            )
        try:
            return self._decide(proposal, resolved_id, submitted, progress)
        except _MalformedContext as exc:
            return self._failure(
                ReasonCode.TRUSTED_CONTEXT_MALFORMED, exc.detail, submitted, resolved_id, progress
            )
        except Exception as exc:
            return self._failure(
                ReasonCode.MEDIATOR_ERROR, type(exc).__name__, submitted, resolved_id, progress
            )

    def _decide(
        self,
        proposal: object,
        request_id: str | None,
        submitted: dict[str, Any],
        progress: _Progress,
    ) -> Decision:
        policy = self._policy
        try:
            action = _typed_action(proposal)
        except ActionSchemaError as exc:
            schema = finding(RuleId.TYPED_ACTION, ReasonCode.SCHEMA_INVALID, exc.code.value)
            return self._record(
                Verdict.BLOCK,
                ReasonCode.SCHEMA_INVALID,
                (schema,),
                submitted=submitted,
                request_id=request_id,
                rules_evaluated=(int(RuleId.TYPED_ACTION),),
            )
        progress.action = action

        snapshot = self._snapshot()
        if (
            not isinstance(snapshot, HomeSnapshot)
            or not isinstance(snapshot.home, HomeState)
            or type(snapshot.state_version) is not int
            or type(snapshot.time_ms) is not int
        ):
            raise _MalformedContext("snapshot")
        progress.snapshot = snapshot
        self._check_delivery_log()
        request = self._resolve_request(request_id)

        spec = get_operation_spec(action.device, action.operation)
        if spec is None or not spec.mutates:
            findings = sort_findings(identity_findings(request, self._bound_request_id))
            verdict = aggregate_verdict(findings)
            return self._record(
                verdict,
                ReasonCode.READ_ALLOWED_BY_POLICY
                if verdict is Verdict.ALLOW
                else primary_reason(findings, verdict),
                findings,
                action=action,
                snapshot=snapshot,
                submitted=submitted,
                request_id=request_id,
                rules_evaluated=_READ_RULES,
                is_read=True,
            )

        cited, unknown, presence = resolve_evidence(self._ledger, action)
        consistent, history_detail = self._history_check(snapshot)
        ctx = RuleContext(
            policy=policy,
            request=request,
            bound_request_id=self._bound_request_id,
            state_version=snapshot.state_version,
            time_ms=snapshot.time_ms,
            ledger=self._ledger,
            cited=cited,
            unknown_refs=unknown,
            presence=presence,
            history_consistent=consistent,
            history_detail=history_detail,
        )
        findings = sort_findings(self._evaluate(ctx, action, snapshot.home))
        common: dict[str, Any] = {
            "action": action,
            "snapshot": snapshot,
            "submitted": submitted,
            "request_id": request_id,
            "rules_evaluated": tuple(sorted(int(rule) for rule in policy.enabled_rules)),
            "annotations": self._annotations(ctx, snapshot.home),
            "evidence_ids": tuple(sorted({d.observation_id for d in (*cited, *presence)})),
        }
        if not findings:
            return self._record(
                Verdict.ALLOW, ReasonCode.ALLOWED, (), executed_actions=(action,), **common
            )
        if not all(item.repairable for item in findings):
            verdict = aggregate_verdict(findings)
            return self._record(verdict, primary_reason(findings, verdict), findings, **common)

        intent = self._intents.get(request.request_id) if request is not None else None
        repair = plan_repair(
            action=action,
            findings=findings,
            ctx=ctx,
            home=snapshot.home,
            intent_range=None if intent is None else intent.setpoint_range_c,
            evaluate=self._evaluate,
        )
        if repair.repaired:
            assert repair.candidate is not None
            common["evidence_ids"] = tuple(sorted({*common["evidence_ids"], *repair.evidence_ids}))
            return self._record(
                Verdict.REPAIR,
                repair.code,
                findings,
                executed_actions=repair.candidate,
                repair_candidate=repair.candidate,
                **common,
            )
        return self._record(
            Verdict.BLOCK,
            repair.code,
            sort_findings((*findings, *repair.findings)),
            repair_candidate=repair.candidate,
            **common,
        )

    def _evaluate(
        self, ctx: RuleContext, action: ActionProposal, home: HomeState
    ) -> list[RuleFinding]:
        findings: list[RuleFinding] = []
        for rule, check in self._rule_table:
            if rule not in ctx.policy.enabled_rules:
                continue
            for item in check(ctx, action, home):
                if not isinstance(item, RuleFinding):
                    raise TypeError(f"rule {int(rule)} returned a non-finding")
                findings.append(item)
        return findings

    def _check_delivery_log(self) -> None:
        """MED-06: the ledger must have ingested exactly what the gateway delivered."""
        try:
            issued = tuple(self._deliveries())
        except TypeError as exc:
            raise _MalformedContext("delivery_log") from exc
        ingested = [d for d in self._ledger.deliveries if d.known_origin]
        if len(issued) != len(ingested):
            raise _MalformedContext("delivery_log")
        for gateway_entry, ledger_entry in zip(issued, ingested, strict=True):
            if (
                not isinstance(gateway_entry, Delivery)
                or gateway_entry.observation_id != ledger_entry.observation_id
                or gateway_entry.redelivery is not (ledger_entry.status in REPLAY_STATUSES)
            ):
                raise _MalformedContext("delivery_log")

    def _resolve_request(self, request_id: str | None) -> RequestContext | None:
        if request_id is None:
            return None
        request = self._requests.lookup(request_id)
        if request is None:
            return None
        if not isinstance(request, RequestContext) or request.request_id != request_id:
            raise _MalformedContext("request")
        return request

    def _history_check(self, snapshot: HomeSnapshot) -> tuple[bool, str]:
        """Rule 8 history consistency, computed once per decision from the real history."""
        try:
            entries = tuple(self._history())
        except TypeError as exc:
            raise _MalformedContext("history") from exc
        if not all(isinstance(entry, TraceEntry) for entry in entries):
            raise _MalformedContext("history")
        executed = [
            None if entry.action is None else entry.action.to_dict()
            for entry in entries
            if entry.kind is TraceKind.ACTION
        ]
        if executed != self._committed:
            return False, "executed_actions_differ_from_mediated_commits"
        if sum(1 for entry in entries if entry.changed) != snapshot.state_version:
            return False, "state_version_differs_from_history"
        if entries and entries[-1].after.to_dict() != snapshot.to_dict():
            return False, "snapshot_differs_from_history"
        return True, ""

    def _annotations(self, ctx: RuleContext, home: HomeState) -> tuple[str, ...]:
        """Non-blocking notes: payload/canonical disagreement and stale or replayed citations."""
        notes: set[str] = set()
        for delivery in (*ctx.cited, *ctx.presence):
            for prior in self._ledger.known_deliveries(delivery.observation_id):
                notes.update(
                    f"payload_mismatch:{prior.observation_id}:{key}"
                    for key in prior.payload_mismatch
                )
        required = {delivery.observation_id for delivery in ctx.presence}
        for delivery in ctx.cited:
            oid = delivery.observation_id
            if oid in required:
                continue
            record = trusted_record(delivery)
            issued_at = record.envelope.gateway_time_ms
            if (
                issued_at > ctx.time_ms
                or ctx.time_ms - issued_at > ctx.policy.sensor_ttl_ms
                or dict(record.canonical_facts) != home.device(record.envelope.device).to_dict()
            ):
                notes.add(f"stale_reference:{oid}")
            if self._ledger.is_replayed(oid):
                notes.add(f"replayed_reference:{oid}")
        return tuple(sorted(notes))

    def _policy_record(self) -> dict[str, Any]:
        try:
            record = self._policy.fingerprint()
            json.dumps(record, allow_nan=False)
        except Exception:
            return {"version": None, "malformed": True}
        return record

    def _record(
        self,
        verdict: Verdict,
        reason: ReasonCode,
        findings: tuple[RuleFinding, ...],
        *,
        submitted: dict[str, Any],
        request_id: str | None,
        rules_evaluated: tuple[int, ...],
        action: ActionProposal | None = None,
        snapshot: HomeSnapshot | None = None,
        executed_actions: tuple[ActionProposal, ...] = (),
        repair_candidate: tuple[ActionProposal, ...] | None = None,
        evidence_ids: tuple[str, ...] = (),
        annotations: tuple[str, ...] = (),
        is_read: bool = False,
    ) -> Decision:
        return Decision(
            verdict=verdict,
            reason_code=reason,
            findings=findings,
            action=action,
            submitted=submitted,
            executed_actions=executed_actions,
            repair_candidate=repair_candidate,
            state_version=None if snapshot is None else snapshot.state_version,
            time_ms=None if snapshot is None else snapshot.time_ms,
            request_id=request_id,
            evidence_ids=evidence_ids,
            escalation=verdict in {Verdict.ESCALATE, Verdict.ERROR}
            or any(item.escalation for item in findings),
            rules_evaluated=rules_evaluated,
            policy=self._policy_record(),
            rule_versions=_RULE_VERSION_RECORD,
            annotations=annotations,
            is_read=is_read,
        )

    def _failure(
        self,
        code: ReasonCode,
        detail: str,
        submitted: dict[str, Any],
        request_id: str | None,
        progress: _Progress,
    ) -> Decision:
        action = progress.action
        spec = None if action is None else get_operation_spec(action.device, action.operation)
        return self._record(
            Verdict.ERROR,
            code,
            (finding(None, code, detail),),
            submitted=submitted,
            request_id=request_id,
            rules_evaluated=(),
            action=action,
            snapshot=progress.snapshot,
            is_read=spec is not None and not spec.mutates,
        )


def _typed_action(proposal: object) -> ActionProposal:
    """Rule 1 (MED-02): always re-validate through the native parser."""
    if isinstance(proposal, ActionProposal):
        try:
            raw = json.dumps(proposal.to_dict())
        except (TypeError, ValueError, AttributeError, RecursionError) as exc:
            raise ActionSchemaError(SchemaErrorCode.WRONG_TYPE, "unserializable proposal") from exc
        return parse_action(raw)
    if isinstance(proposal, str | bytes):
        return parse_action(proposal)
    if isinstance(proposal, Mapping):
        try:
            raw = json.dumps(dict(proposal))
        except Exception as exc:
            raise ActionSchemaError(SchemaErrorCode.WRONG_TYPE, "unserializable mapping") from exc
        return parse_action(raw)
    raise ActionSchemaError(
        SchemaErrorCode.WRONG_TYPE, f"unsupported proposal type {type(proposal).__name__}"
    )
