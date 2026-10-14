"""Deterministic, task-preserving repair with full revalidation (WP-09, MED-10, MED-11).

Repair runs only when every finding is repairable, i.e. after authorization and
all non-repairable checks succeeded. Proposed D08 templates:

- clamp (rule 7 ``setpoint_out_of_bounds``): the setpoint clamped to policy
  bounds, only if it still lies inside the trusted task intent's accepted
  range. An exact 35 C request is never satisfied by 30 C;
- prerequisite (rule 8 ``precondition_unmet``): the named prerequisite before
  the original action, only if the request itself permits the prerequisite.

Proposed D05/D08 ablation boundary: the prerequisite permission check belongs to
the repair template, not to rule 3, so it applies under every policy, including
``no_provenance``. A repair is an effect the mediator itself adds, and the
mediator never adds an operation the trusted request did not permit. Under
``no_provenance`` a directly proposed ``door.unlock`` is therefore evaluated
without an operation check, while a ``door.open`` on a locked door is repaired
only when the request permits ``door.unlock`` (otherwise ``repair_unavailable``).
This is the fail-closed reading of design sections 6 and 7; the ablation removes
rule 3 from evaluation and revalidation, not repair-template authority.

A unique candidate must exist, fit ``max_repair_actions``, be physically
valid, pass every enabled rule at each predicted intermediate state and change
the state. A repair therefore cannot invent permission, presence or freshness,
and a later failing step means nothing executes (the executor commits the
candidate as one transaction).
"""

from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from dataclasses import dataclass, replace

from effectshield.domain.actions import ActionProposal
from effectshield.domain.catalog import get_operation_spec
from effectshield.domain.devices import DeviceId, HomeState, Operation
from effectshield.domain.errors import InvalidTransitionError
from effectshield.simulator.transitions import apply_sequence

from .decision import ReasonCode, RuleFinding, finding, sort_findings
from .rules import RuleContext, resolve_evidence

REPAIRED_CODES = frozenset({ReasonCode.REPAIRED_CLAMP, ReasonCode.REPAIRED_PREREQUISITE})

Evaluate = Callable[[RuleContext, ActionProposal, HomeState], list[RuleFinding]]


@dataclass(frozen=True, slots=True)
class RepairResult:
    """Outcome of one repair attempt.

    ``code`` is a ``repaired_*`` code on success, otherwise the repair failure
    code. ``candidate`` is recorded whenever a unique candidate was formed,
    including failed ones. ``findings`` are revalidation findings, each detail
    prefixed with its step index.
    """

    code: ReasonCode
    candidate: tuple[ActionProposal, ...] | None
    findings: tuple[RuleFinding, ...] = ()
    evidence_ids: tuple[str, ...] = ()

    @property
    def repaired(self) -> bool:
        return self.code in REPAIRED_CODES


@dataclass(frozen=True, slots=True)
class _Template:
    success: ReasonCode
    candidate: tuple[ActionProposal, ...] | None
    failure: ReasonCode | None


def _clamp(
    ctx: RuleContext, action: ActionProposal, intent_range: tuple[float, float] | None
) -> _Template:
    if action.device is not DeviceId.THERMOSTAT or action.operation is not Operation.SET_SETPOINT:
        return _Template(ReasonCode.REPAIRED_CLAMP, None, ReasonCode.REPAIR_UNAVAILABLE)
    policy = ctx.policy
    value = action.parameters["setpoint_c"]
    clamped = min(max(value, policy.thermostat_min_c), policy.thermostat_max_c)
    candidate = (
        ActionProposal(
            DeviceId.THERMOSTAT,
            Operation.SET_SETPOINT,
            {"setpoint_c": clamped},
            action.evidence_refs,
        ),
    )
    preserved = intent_range is not None and intent_range[0] <= clamped <= intent_range[1]
    failure = None if preserved else ReasonCode.REPAIR_NOT_TASK_PRESERVING
    return _Template(ReasonCode.REPAIRED_CLAMP, candidate, failure)


def _prerequisite(ctx: RuleContext, action: ActionProposal, detail: str) -> _Template:
    device_name, _, operation_name = detail.partition(".")
    try:
        device, operation = DeviceId(device_name), Operation(operation_name)
    except ValueError:
        return _Template(ReasonCode.REPAIRED_PREREQUISITE, None, ReasonCode.REPAIR_UNAVAILABLE)
    spec = get_operation_spec(device, operation)
    if spec is None or not spec.mutates or spec.parameters:
        return _Template(ReasonCode.REPAIRED_PREREQUISITE, None, ReasonCode.REPAIR_UNAVAILABLE)
    # The prerequisite cites the same evidence: one access episode for the transaction.
    candidate = (ActionProposal(device, operation, {}, action.evidence_refs), action)
    # Template authority, not rule 3: enforced even under no_provenance (Proposed D05/D08).
    permitted = ctx.request is not None and ctx.request.allows(device, operation)
    failure = None if permitted else ReasonCode.REPAIR_UNAVAILABLE
    return _Template(ReasonCode.REPAIRED_PREREQUISITE, candidate, failure)


def _key(candidate: Sequence[ActionProposal]) -> str:
    return json.dumps([step.to_dict() for step in candidate], sort_keys=True)


def plan_repair(
    *,
    action: ActionProposal,
    findings: Sequence[RuleFinding],
    ctx: RuleContext,
    home: HomeState,
    intent_range: tuple[float, float] | None,
    evaluate: Evaluate,
) -> RepairResult:
    """Form the unique repair candidate for ``findings`` and revalidate it from ``home``."""
    templates: list[_Template] = []
    for item in sort_findings(findings):
        if item.code is ReasonCode.SETPOINT_OUT_OF_BOUNDS:
            templates.append(_clamp(ctx, action, intent_range))
        elif item.code is ReasonCode.PRECONDITION_UNMET:
            templates.append(_prerequisite(ctx, action, item.detail))
        else:
            # A custom rule marked some other finding repairable: no template exists.
            return RepairResult(ReasonCode.REPAIR_UNAVAILABLE, None)
    for template in templates:
        if template.failure is not None:
            return RepairResult(template.failure, template.candidate)

    distinct: dict[str, _Template] = {}
    for template in templates:
        assert template.candidate is not None
        distinct.setdefault(_key(template.candidate), template)
    if len(distinct) != 1:
        return RepairResult(ReasonCode.REPAIR_AMBIGUOUS, None)
    (chosen,) = distinct.values()
    candidate = chosen.candidate
    assert candidate is not None
    if len(candidate) > ctx.policy.max_repair_actions:
        return RepairResult(ReasonCode.REPAIR_TOO_LONG, candidate)

    try:
        predicted = apply_sequence(home, candidate)
    except InvalidTransitionError as exc:
        failed = 0 if exc.index is None else exc.index
        invalid = finding(
            None, ReasonCode.REPAIR_FAILED_REVALIDATION, f"step {failed}: {exc.code.value}"
        )
        return RepairResult(ReasonCode.REPAIR_FAILED_REVALIDATION, candidate, (invalid,))

    revalidation: list[RuleFinding] = []
    evidence_ids: set[str] = set()
    for index, (step, before) in enumerate(zip(candidate, (home, *predicted[:-1]), strict=True)):
        cited, unknown, presence = resolve_evidence(ctx.ledger, step)
        evidence_ids.update(d.observation_id for d in (*cited, *presence))
        step_ctx = replace(ctx, cited=cited, unknown_refs=unknown, presence=presence)
        revalidation.extend(
            replace(item, detail=f"step {index}: {item.detail}")
            for item in evaluate(step_ctx, step, before)
        )
    if revalidation:
        return RepairResult(
            ReasonCode.REPAIR_FAILED_REVALIDATION, candidate, sort_findings(revalidation)
        )
    if predicted[-1] == home:
        return RepairResult(ReasonCode.REPAIR_NO_EFFECT, candidate)
    return RepairResult(chosen.success, candidate, (), tuple(sorted(evidence_ids)))
