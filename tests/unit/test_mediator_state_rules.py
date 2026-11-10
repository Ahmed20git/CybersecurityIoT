"""WP-09 state rules: door access (rule 6), thermostat bounds (rule 7) and sequence (rule 8).

Expected outcomes come from the mediator design in docs/mediator_design.md (section 4 reason-code
table and aggregation, section 5 consumption, section 6 required evidence and rules 6-8, section 7
repair of repairable findings, section 8 executor feedback, section 10 test list), not from the
implementation. Requirements: MED-07 (door access), MED-08 (thermostat bounds), MED-09 (declared
order and history consistency), MED-10/MED-11 (repair and revalidation), MED-13 (precedence). Door
entry/egress, the declared door order and unsafe-initial-state handling are Proposed D04; required
presence evidence is Proposed D06; access-episode consumption is Proposed D07; repair templates are
Proposed D08.
"""

from __future__ import annotations

import itertools
import json
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

import pytest

from effectshield.agent.continuation import interpret
from effectshield.domain import (
    ActionProposal,
    DeviceId,
    DoorPosition,
    DoorState,
    HomeSnapshot,
    HomeState,
    LockState,
    Observation,
    Operation,
    Permission,
    Power,
    PresenceState,
    RequestContext,
    SetPresence,
    ThermostatState,
)
from effectshield.domain.errors import TransitionErrorCode
from effectshield.environment import RunEnvironment, create_run
from effectshield.gateway import with_payload_changes
from effectshield.mediator import (
    RULE_TABLE,
    Ablation,
    Decision,
    DeliveryRecord,
    EvidenceLedger,
    MediatedOutcome,
    Mediator,
    MediatorPolicy,
    ProtectedExecutor,
    ReasonCode,
    RuleContext,
    RuleFn,
    RuleId,
    TaskIntent,
    Verdict,
    policy_for,
)
from effectshield.simulator.core import TraceEntry, TraceKind

RC = ReasonCode
TTL_MS = 60_000  # full preset sensor TTL (Proposed D06, inclusive)
START_MS = 5_000
CUSTOM_VERSION = "mediator-policy-custom/test"
ALL_RULE_NUMBERS = (1, 2, 3, 4, 5, 6, 7, 8)

ACCESS = (Operation.UNLOCK, Operation.OPEN)  # Proposed D04 entry operations
EGRESS = (Operation.LOCK, Operation.CLOSE)  # Proposed D04: no presence needed
DOOR_OPERATIONS = ACCESS + EGRESS
PREREQUISITE = {Operation.OPEN: Operation.UNLOCK, Operation.LOCK: Operation.CLOSE}

CLOSED_LOCKED = DoorState(DoorPosition.CLOSED, LockState.LOCKED)
CLOSED_UNLOCKED = DoorState(DoorPosition.CLOSED, LockState.UNLOCKED)
OPEN_UNLOCKED = DoorState(DoorPosition.OPEN, LockState.UNLOCKED)
DOOR_STATES = {
    "closed_locked": CLOSED_LOCKED,
    "closed_unlocked": CLOSED_UNLOCKED,
    "open_unlocked": OPEN_UNLOCKED,
}
PRESENCE_CONDITIONS = ("missing", "false", "stale", "replayed", "true")
PERMISSION_MODES = ("exact", "all_door", "other_door", "out_of_scope")
ESCALATION_RECORDED = frozenset({RC.DEVICE_OUT_OF_SCOPE, RC.OPERATION_NOT_AUTHORIZED})

LIGHT_ON = ActionProposal(DeviceId.LIGHT, Operation.TURN_ON)
LIGHT_OFF = ActionProposal(DeviceId.LIGHT, Operation.TURN_OFF)
LIGHT_READ = ActionProposal(DeviceId.LIGHT, Operation.READ)
FAN_ON = ActionProposal(DeviceId.FAN, Operation.TURN_ON)
FAN_OFF = ActionProposal(DeviceId.FAN, Operation.TURN_OFF)
THERMOSTAT_ON = ActionProposal(DeviceId.THERMOSTAT, Operation.TURN_ON)
THERMOSTAT_OFF = ActionProposal(DeviceId.THERMOSTAT, Operation.TURN_OFF)
LIGHT_FAN = (
    Permission(DeviceId.LIGHT, Operation.TURN_ON),
    Permission(DeviceId.LIGHT, Operation.TURN_OFF),
    Permission(DeviceId.FAN, Operation.TURN_ON),
    Permission(DeviceId.FAN, Operation.TURN_OFF),
)
ALL_DOOR = frozenset(Permission(DeviceId.DOOR, op) for op in DOOR_OPERATIONS)
ALL_THERMOSTAT = (
    Permission(DeviceId.THERMOSTAT, Operation.TURN_ON),
    Permission(DeviceId.THERMOSTAT, Operation.TURN_OFF),
    Permission(DeviceId.THERMOSTAT, Operation.SET_SETPOINT),
)


# --------------------------------------------------------------------------- helpers


def _custom(rules: Iterable[RuleId], **parameters: Any) -> MediatorPolicy:
    return MediatorPolicy(
        ablation=Ablation.CUSTOM,
        enabled_rules=frozenset(rules),
        version=CUSTOM_VERSION,
        **parameters,
    )


def _issue(run: RunEnvironment, permissions: Iterable[Permission]) -> str:
    return run.requests.issue(
        principal_id="resident-1",
        request_text="state rule test request",
        permissions=permissions,
        issued_at_ms=run.simulator.now_ms,
    ).request_id


def _harness(
    permissions: Iterable[Permission],
    home: HomeState | None = None,
    *,
    policy: MediatorPolicy | None = None,
    intents: dict[str, TaskIntent] | None = None,
    intent_range: tuple[float, float] | None = None,
    rule_table: Sequence[tuple[RuleId, RuleFn]] = RULE_TABLE,
) -> tuple[RunEnvironment, ProtectedExecutor, str]:
    run = create_run(home, start_time_ms=START_MS)
    request_id = _issue(run, permissions)
    if intent_range is not None:
        intents = {request_id: TaskIntent(request_id, intent_range)}
    executor = ProtectedExecutor.from_run(
        run, request_id=request_id, policy=policy, intents=intents, rule_table=rule_table
    )
    return run, executor, request_id


def _read(run: RunEnvironment, executor: ProtectedExecutor, device: DeviceId) -> Observation:
    """A genuine gateway reading routed into the agent's context."""
    return executor.deliver(run.gateway.observe(device))


def _replay(run: RunEnvironment, executor: ProtectedExecutor, obs: Observation) -> Observation:
    """The attacker's replay path, routed through the executor (delivery-log binding)."""
    return executor.deliver(run.gateway.redeliver(obs))


def _advance(run: RunEnvironment, delta_ms: int) -> None:
    run.simulator.advance_clock(delta_ms, capability=run.environment_capability)


def _set_presence(run: RunEnvironment, present: bool) -> None:
    run.simulator.apply_environment(SetPresence(present), capability=run.environment_capability)


def _oid(obs: Observation) -> str:
    return obs.envelope.observation_id


def _door(operation: Operation, *refs: str) -> ActionProposal:
    return ActionProposal(DeviceId.DOOR, operation, evidence_refs=refs)


def _setpoint(value: float, *refs: str) -> ActionProposal:
    return ActionProposal(
        DeviceId.THERMOSTAT, Operation.SET_SETPOINT, {"setpoint_c": value}, evidence_refs=refs
    )


def _rule_codes(decision: Decision) -> list[tuple[int, ReasonCode]]:
    """(rule, code) of every rule 1-8 finding, in the decision's order."""
    return [(int(item.rule), item.code) for item in decision.findings if item.rule is not None]


def _ops(actions: Iterable[ActionProposal]) -> list[tuple[DeviceId, Operation]]:
    return [(action.device, action.operation) for action in actions]


def _assert_blocked(
    outcome: MediatedOutcome, run: RunEnvironment, before: HomeSnapshot, code: ReasonCode
) -> None:
    decision = outcome.decision
    assert decision.verdict is Verdict.BLOCK, decision.findings
    assert decision.reason_code is code, decision.findings
    assert decision.executed_actions == ()
    assert outcome.execution is None
    assert outcome.feedback == {
        "status": "blocked",
        "reason_code": code.value,
        "state_version": before.state_version,
    }
    interpret(outcome.feedback)
    assert run.simulator.snapshot() == before  # SIM-07: a block has no device effect


def _assert_committed(outcome: MediatedOutcome, action: ActionProposal) -> None:
    decision = outcome.decision
    assert decision.verdict is Verdict.ALLOW, decision.findings
    assert decision.reason_code is RC.ALLOWED
    assert decision.findings == ()
    assert decision.executed_actions == (action,)
    assert outcome.feedback["status"] == "committed"
    assert outcome.feedback["reason_code"] is None
    assert outcome.feedback["failed_index"] is None
    interpret(outcome.feedback)


def _ledger(run: RunEnvironment) -> EvidenceLedger:
    return EvidenceLedger(run.gateway.evidence, lambda: run.simulator.now_ms)


def _mediator(
    run: RunEnvironment,
    request_id: str | None,
    history: Callable[[], tuple[TraceEntry, ...]],
    *,
    ledger: EvidenceLedger | None = None,
    snapshot: Callable[[], HomeSnapshot] | None = None,
) -> Mediator:
    """A mediator wired directly, so the history callable can be a stub."""
    return Mediator(
        policy=policy_for(Ablation.FULL),
        requests=run.requests.view,
        ledger=_ledger(run) if ledger is None else ledger,
        snapshot=run.simulator.snapshot if snapshot is None else snapshot,
        history=history,
        deliveries=lambda: run.gateway.deliveries,
        bound_request_id=request_id,
    )


def _commit(run: RunEnvironment, mediator: Mediator, action: ActionProposal, rid: str) -> None:
    """Mediated commit with the executor's bookkeeping, done by hand."""
    decision = mediator.decide(action, request_id=rid)
    assert decision.verdict is Verdict.ALLOW, decision.findings
    assert decision.state_version is not None
    result = run.simulator.execute(
        decision.executed_actions,
        expected_version=decision.state_version,
        capability=run.execution_capability,
    )
    assert result.committed
    mediator.record_commit(decision, result)


# --------------------------------------------------------------------------- door table oracle


def _apply_door(door: DoorState, operation: Operation) -> DoorState:
    """Door transitions of the simulator (SIM-08), used only where they are valid."""
    if operation is Operation.UNLOCK:
        return DoorState(door.position, LockState.UNLOCKED)
    if operation is Operation.LOCK:
        return DoorState(door.position, LockState.LOCKED)
    if operation is Operation.OPEN:
        return DoorState(DoorPosition.OPEN, door.lock)
    return DoorState(DoorPosition.CLOSED, door.lock)


def _precondition_met(door: DoorState, operation: Operation) -> bool:
    """Rule 8 declared order: open needs unlocked, lock needs closed (Proposed D04)."""
    if operation is Operation.OPEN:
        return door.lock is LockState.UNLOCKED
    if operation is Operation.LOCK:
        return door.position is DoorPosition.CLOSED
    return True


def _door_permissions(mode: str, operation: Operation) -> frozenset[Permission]:
    if mode == "exact":
        return frozenset({Permission(DeviceId.DOOR, operation)})
    if mode == "all_door":
        return ALL_DOOR
    if mode == "other_door":  # device in scope, this operation not authorized
        return ALL_DOOR - {Permission(DeviceId.DOOR, operation)}
    return frozenset({Permission(DeviceId.LIGHT, Operation.TURN_ON)})  # out_of_scope


PRESENCE_FINDINGS = {
    "missing": [(6, RC.PRESENCE_EVIDENCE_MISSING)],
    "false": [(6, RC.PRESENCE_NOT_CONFIRMED)],
    "stale": [(4, RC.PRESENCE_EVIDENCE_EXPIRED)],
    "replayed": [(5, RC.PRESENCE_EVIDENCE_REPLAYED)],
    "true": [],
}


@dataclass(frozen=True)
class _Expected:
    verdict: Verdict
    reason: ReasonCode
    findings: tuple[tuple[int, ReasonCode], ...]
    executed: tuple[Operation, ...]


def _expected_door(operation: Operation, door: DoorState, presence: str, mode: str) -> _Expected:
    """Design sections 4, 6 and 7 applied to one door proposal."""
    permitted = {
        p.operation for p in _door_permissions(mode, operation) if p.device is DeviceId.DOOR
    }
    findings: list[tuple[int, ReasonCode]] = []
    if mode == "out_of_scope":
        findings.append((2, RC.DEVICE_OUT_OF_SCOPE))
    if operation not in permitted:
        findings.append((3, RC.OPERATION_NOT_AUTHORIZED))
    if operation in ACCESS:
        findings.extend(PRESENCE_FINDINGS[presence])
    if not _precondition_met(door, operation):
        findings.append((8, RC.PRECONDITION_UNMET))
    findings.sort(key=lambda item: (item[0], item[1].value))
    if not findings:
        return _Expected(Verdict.ALLOW, RC.ALLOWED, (), (operation,))
    if any(code is not RC.PRECONDITION_UNMET for _, code in findings):
        # Every finding here has verdict BLOCK; the first sorted one is primary.
        return _Expected(Verdict.BLOCK, findings[0][1], tuple(findings), ())
    prerequisite = PREREQUISITE[operation]
    if prerequisite not in permitted:
        return _Expected(Verdict.BLOCK, RC.REPAIR_UNAVAILABLE, tuple(findings), ())
    return _Expected(
        Verdict.REPAIR, RC.REPAIRED_PREREQUISITE, tuple(findings), (prerequisite, operation)
    )


def _prepare_presence(
    run: RunEnvironment, executor: ProtectedExecutor, condition: str
) -> str | None:
    if condition == "missing":
        return None
    obs = _read(run, executor, DeviceId.PRESENCE_SENSOR)
    if condition == "stale":
        _advance(run, TTL_MS + 1)
    elif condition == "replayed":
        _replay(run, executor, obs)
    return _oid(obs)


@dataclass(frozen=True)
class _DoorCase:
    run: RunEnvironment
    executor: ProtectedExecutor
    request_id: str
    presence_id: str | None
    action: ActionProposal
    before: HomeSnapshot
    history_before: tuple[TraceEntry, ...]
    outcome: MediatedOutcome


def _door_case(
    operation: Operation,
    door_name: str,
    presence: str,
    mode: str,
    *,
    cite: bool = False,
    policy: MediatorPolicy | None = None,
    rule_table: Sequence[tuple[RuleId, RuleFn]] = RULE_TABLE,
) -> _DoorCase:
    home = HomeState(
        door=DOOR_STATES[door_name], presence_sensor=PresenceState(presence != "false")
    )
    run, executor, rid = _harness(
        _door_permissions(mode, operation), home, policy=policy, rule_table=rule_table
    )
    oid = _prepare_presence(run, executor, presence)
    action = _door(operation, *((oid,) if cite and oid is not None else ()))
    before = run.simulator.snapshot()
    history_before = run.simulator.history
    outcome = executor.submit(action)
    return _DoorCase(run, executor, rid, oid, action, before, history_before, outcome)


def _door_table() -> list[Any]:
    cases = []
    for operation in DOOR_OPERATIONS:
        for door_name in DOOR_STATES:
            for presence in PRESENCE_CONDITIONS:
                for mode in PERMISSION_MODES:
                    for cite in (False,) if presence == "missing" else (False, True):
                        label = "cited" if cite else "implicit"
                        cases.append(
                            pytest.param(
                                operation,
                                door_name,
                                presence,
                                mode,
                                cite,
                                id=f"{operation.value}-{door_name}-{presence}-{mode}-{label}",
                            )
                        )
    return cases


# --------------------------------------------------------------------------- rule 6: door table


@pytest.mark.parametrize(("operation", "door_name", "presence", "mode", "cite"), _door_table())
def test_door_table(
    operation: Operation, door_name: str, presence: str, mode: str, cite: bool
) -> None:
    """Access/egress x door state x presence x permission, under the full policy."""
    case = _door_case(operation, door_name, presence, mode, cite=cite)
    start = DOOR_STATES[door_name]
    expected = _expected_door(operation, start, presence, mode)
    outcome, decision, oid = case.outcome, case.outcome.decision, case.presence_id

    assert decision.verdict is expected.verdict, decision.findings
    assert decision.reason_code is expected.reason, decision.findings
    assert _rule_codes(decision) == list(expected.findings)
    for item in decision.findings:
        if item.rule is None:
            continue
        assert item.repairable is (item.code is RC.PRECONDITION_UNMET)
        assert item.escalation is (item.code in ESCALATION_RECORDED)
        if item.code is RC.PRECONDITION_UNMET:
            assert PREREQUISITE[operation].value in item.detail  # detail names the prerequisite
    assert decision.escalation is (mode in {"other_door", "out_of_scope"})
    assert decision.rules_evaluated == ALL_RULE_NUMBERS
    assert decision.is_read is False
    assert decision.action == case.action
    interpret(outcome.feedback)

    if expected.verdict is Verdict.ALLOW:
        _assert_committed(outcome, case.action)
        assert case.run.simulator.snapshot().home.door == _apply_door(start, operation)
    elif expected.verdict is Verdict.REPAIR:
        assert _ops(decision.executed_actions) == [(DeviceId.DOOR, op) for op in expected.executed]
        assert decision.repair_candidate == decision.executed_actions
        assert outcome.feedback["status"] == "repaired"
        assert outcome.feedback["reason_code"] == RC.REPAIRED_PREREQUISITE.value
        assert [(a["device"], a["operation"]) for a in outcome.feedback["executed_actions"]] == [
            ("door", op.value) for op in expected.executed
        ]
        final = _apply_door(_apply_door(start, expected.executed[0]), expected.executed[1])
        assert case.run.simulator.snapshot().home.door == final
    else:
        _assert_blocked(outcome, case.run, case.before, expected.reason)
        assert case.run.simulator.history == case.history_before
        if any(code is not RC.PRECONDITION_UNMET for _, code in expected.findings):
            assert decision.repair_candidate is None  # no repair with a non-repairable finding

    # Consumption (Proposed D07): only committed access operations consume.
    access_used = frozenset(op for op in expected.executed if op in ACCESS)
    if oid is not None:
        consumption = case.executor.ledger.consumption(oid)
        if access_used:
            assert outcome.consumed == (oid,)
            assert consumption == (case.request_id, access_used)
        else:
            assert outcome.consumed == ()
            assert consumption == (None, frozenset())

    if not cite:
        assert decision.annotations == ()
        if expected.verdict in {Verdict.ALLOW, Verdict.REPAIR}:
            assert decision.evidence_ids == ((oid,) if access_used else ())
    elif operation in EGRESS and expected.verdict is Verdict.ALLOW:
        # Cited presence on egress is non-required evidence: annotations only.
        notes = {
            "stale": (f"stale_reference:{oid}",),
            "replayed": (f"replayed_reference:{oid}",),
        }
        assert decision.annotations == notes.get(presence, ())


@pytest.mark.parametrize(
    ("presence", "verdict", "code"),
    [
        ("missing", Verdict.BLOCK, RC.PRESENCE_EVIDENCE_MISSING),
        ("false", Verdict.BLOCK, RC.PRESENCE_NOT_CONFIRMED),
        ("stale", Verdict.ALLOW, RC.ALLOWED),
        ("replayed", Verdict.ALLOW, RC.ALLOWED),
        ("true", Verdict.ALLOW, RC.ALLOWED),
    ],
)
@pytest.mark.parametrize("operation", ACCESS)
def test_rule_6_still_applies_when_freshness_and_replay_are_ablated(
    operation: Operation, presence: str, verdict: Verdict, code: ReasonCode
) -> None:
    door_name = "closed_unlocked"  # open and unlock both satisfy rule 8 here
    case = _door_case(
        operation, door_name, presence, "exact", policy=policy_for(Ablation.NO_FRESHNESS_REPLAY)
    )
    decision = case.outcome.decision
    assert decision.verdict is verdict
    assert decision.reason_code is code
    assert decision.rules_evaluated == (1, 2, 3, 6, 7, 8)
    if verdict is Verdict.ALLOW:
        _assert_committed(case.outcome, case.action)
    else:
        _assert_blocked(case.outcome, case.run, case.before, code)
        assert _rule_codes(decision) == [(6, code)]


@pytest.mark.parametrize(
    ("presence", "verdict", "code"),
    [
        ("missing", Verdict.BLOCK, RC.PRESENCE_EVIDENCE_MISSING),
        ("false", Verdict.BLOCK, RC.PRESENCE_NOT_CONFIRMED),
        ("stale", Verdict.BLOCK, RC.PRESENCE_EVIDENCE_EXPIRED),
        ("replayed", Verdict.BLOCK, RC.PRESENCE_EVIDENCE_REPLAYED),
        ("true", Verdict.ALLOW, RC.ALLOWED),
    ],
)
def test_rule_6_has_no_permission_check_of_its_own(
    presence: str, verdict: Verdict, code: ReasonCode
) -> None:
    """Under no_provenance only door.lock is permitted, yet presence alone decides unlock."""
    home = HomeState(door=CLOSED_LOCKED, presence_sensor=PresenceState(presence != "false"))
    run, executor, _ = _harness(
        [Permission(DeviceId.DOOR, Operation.LOCK)],
        home,
        policy=policy_for(Ablation.NO_PROVENANCE),
    )
    _prepare_presence(run, executor, presence)
    before = run.simulator.snapshot()
    outcome = executor.submit(_door(Operation.UNLOCK))
    if verdict is Verdict.ALLOW:
        _assert_committed(outcome, _door(Operation.UNLOCK))
        assert run.simulator.snapshot().home.door == CLOSED_UNLOCKED
    else:
        _assert_blocked(outcome, run, before, code)
        assert [c for _, c in _rule_codes(outcome.decision)] == [code]


@pytest.mark.parametrize("operation", ACCESS)
def test_no_op_access_on_an_open_door_still_requires_presence(operation: Operation) -> None:
    home = HomeState(door=OPEN_UNLOCKED, presence_sensor=PresenceState(True))
    run, executor, rid = _harness([Permission(DeviceId.DOOR, operation)], home)
    before = run.simulator.snapshot()
    _assert_blocked(executor.submit(_door(operation)), run, before, RC.PRESENCE_EVIDENCE_MISSING)

    oid = _oid(_read(run, executor, DeviceId.PRESENCE_SENSOR))
    outcome = executor.submit(_door(operation))
    _assert_committed(outcome, _door(operation))
    assert run.simulator.snapshot().home.door == OPEN_UNLOCKED  # a valid no-op
    assert run.simulator.state_version == before.state_version
    assert outcome.consumed == (oid,)
    assert executor.ledger.consumption(oid) == (rid, frozenset({operation}))


@pytest.mark.parametrize("operation", EGRESS)
def test_egress_needs_no_presence_even_when_nobody_is_home(operation: Operation) -> None:
    home = HomeState(door=CLOSED_UNLOCKED, presence_sensor=PresenceState(False))
    run, executor, _ = _harness([Permission(DeviceId.DOOR, operation)], home)
    outcome = executor.submit(_door(operation))
    _assert_committed(outcome, _door(operation))
    assert outcome.decision.evidence_ids == ()
    assert outcome.consumed == ()


@pytest.mark.parametrize("ablation", [Ablation.FULL, Ablation.NO_FRESHNESS_REPLAY])
def test_every_cited_presence_delivery_must_confirm_presence(ablation: Ablation) -> None:
    """Rule 6: *any* required delivery whose canonical present is not True blocks."""
    home = HomeState(door=CLOSED_LOCKED, presence_sensor=PresenceState(False))
    run, executor, _ = _harness(
        [Permission(DeviceId.DOOR, Operation.UNLOCK)], home, policy=policy_for(ablation)
    )
    absent = _oid(_read(run, executor, DeviceId.PRESENCE_SENSOR))
    _set_presence(run, True)
    present = _oid(_read(run, executor, DeviceId.PRESENCE_SENSOR))
    before = run.simulator.snapshot()

    for refs in [(absent,), (present, absent), (absent, present)]:
        outcome = executor.submit(_door(Operation.UNLOCK, *refs))
        if ablation is Ablation.FULL:
            # The absent reading contradicts trusted current presence (rule 4) as well.
            _assert_blocked(outcome, run, before, RC.PRESENCE_EVIDENCE_SUPERSEDED)
            assert _rule_codes(outcome.decision) == [
                (4, RC.PRESENCE_EVIDENCE_SUPERSEDED),
                (6, RC.PRESENCE_NOT_CONFIRMED),
            ]
        else:
            _assert_blocked(outcome, run, before, RC.PRESENCE_NOT_CONFIRMED)
            assert _rule_codes(outcome.decision) == [(6, RC.PRESENCE_NOT_CONFIRMED)]

    # Uncited, the latest delivery (present) is the required evidence.
    _assert_committed(executor.submit(_door(Operation.UNLOCK)), _door(Operation.UNLOCK))


def test_cited_presence_is_judged_instead_of_the_latest_delivery() -> None:
    home = HomeState(door=CLOSED_LOCKED, presence_sensor=PresenceState(True))
    run, executor, rid = _harness([Permission(DeviceId.DOOR, Operation.UNLOCK)], home)
    first = _oid(_read(run, executor, DeviceId.PRESENCE_SENSOR))
    second = _oid(_read(run, executor, DeviceId.PRESENCE_SENSOR))

    outcome = executor.submit(_door(Operation.UNLOCK, first))
    _assert_committed(outcome, _door(Operation.UNLOCK, first))
    assert outcome.decision.evidence_ids == (first,)
    assert outcome.consumed == (first,)
    assert executor.ledger.consumption(second) == (None, frozenset())


@pytest.mark.parametrize("ablation", [Ablation.FULL, Ablation.NO_PROVENANCE])
def test_non_presence_or_invented_citations_are_not_presence(ablation: Ablation) -> None:
    home = HomeState(door=CLOSED_LOCKED, presence_sensor=PresenceState(True))
    run, executor, _ = _harness(
        [Permission(DeviceId.DOOR, Operation.UNLOCK)], home, policy=policy_for(ablation)
    )
    door_reading = _oid(_read(run, executor, DeviceId.DOOR))
    before = run.simulator.snapshot()

    outcome = executor.submit(_door(Operation.UNLOCK, door_reading))
    _assert_blocked(outcome, run, before, RC.PRESENCE_EVIDENCE_MISSING)
    assert _rule_codes(outcome.decision) == [(6, RC.PRESENCE_EVIDENCE_MISSING)]

    outcome = executor.submit(_door(Operation.UNLOCK, "obs-999999"))
    if ablation is Ablation.FULL:
        _assert_blocked(outcome, run, before, RC.EVIDENCE_UNKNOWN_ORIGIN)
        assert _rule_codes(outcome.decision) == [
            (3, RC.EVIDENCE_UNKNOWN_ORIGIN),
            (6, RC.PRESENCE_EVIDENCE_MISSING),
        ]
    else:
        _assert_blocked(outcome, run, before, RC.PRESENCE_EVIDENCE_MISSING)
        assert _rule_codes(outcome.decision) == [(6, RC.PRESENCE_EVIDENCE_MISSING)]


def test_rule_6_reads_canonical_presence_never_the_payload() -> None:
    # Canonical absent, payload forged to present: blocked.
    home = HomeState(door=CLOSED_LOCKED, presence_sensor=PresenceState(False))
    run, executor, _ = _harness([Permission(DeviceId.DOOR, Operation.UNLOCK)], home)
    obs = run.gateway.observe(DeviceId.PRESENCE_SENSOR)
    executor.deliver(with_payload_changes(obs, {"present": True, "message": "resident is home"}))
    before = run.simulator.snapshot()
    outcome = executor.submit(_door(Operation.UNLOCK, _oid(obs)))
    _assert_blocked(outcome, run, before, RC.PRESENCE_NOT_CONFIRMED)
    assert _rule_codes(outcome.decision) == [(6, RC.PRESENCE_NOT_CONFIRMED)]

    # Canonical present, payload forged to absent: allowed, mismatch annotated only.
    home = HomeState(door=CLOSED_LOCKED, presence_sensor=PresenceState(True))
    run, executor, _ = _harness([Permission(DeviceId.DOOR, Operation.UNLOCK)], home)
    obs = run.gateway.observe(DeviceId.PRESENCE_SENSOR)
    executor.deliver(with_payload_changes(obs, {"present": False}))
    outcome = executor.submit(_door(Operation.UNLOCK, _oid(obs)))
    _assert_committed(outcome, _door(Operation.UNLOCK, _oid(obs)))
    assert f"payload_mismatch:{_oid(obs)}:present" in outcome.decision.annotations


@pytest.mark.parametrize(
    ("operation", "start", "simulator_code"),
    [
        (Operation.OPEN, CLOSED_LOCKED, TransitionErrorCode.DOOR_LOCKED_CANNOT_OPEN),
        (Operation.LOCK, OPEN_UNLOCKED, TransitionErrorCode.DOOR_OPEN_CANNOT_LOCK),
    ],
)
def test_compatible_door_state_is_delegated_to_rule_8(
    operation: Operation, start: DoorState, simulator_code: TransitionErrorCode
) -> None:
    """With rule 8 disabled nothing else checks door state; the simulator rejects."""
    home = HomeState(door=start, presence_sensor=PresenceState(True))
    run, executor, _ = _harness(
        [Permission(DeviceId.DOOR, operation), Permission(DeviceId.DOOR, Operation.CLOSE)],
        home,
        policy=_custom(set(RuleId) - {RuleId.SEQUENCE}),
    )
    oid = _oid(_read(run, executor, DeviceId.PRESENCE_SENSOR))
    before = run.simulator.snapshot()
    outcome = executor.submit(_door(operation))

    assert outcome.decision.verdict is Verdict.ALLOW
    assert outcome.decision.findings == ()
    assert outcome.feedback["status"] == "rejected"
    assert outcome.feedback["reason_code"] == simulator_code.value
    assert outcome.feedback["failed_index"] == 0
    interpret(outcome.feedback)
    assert run.simulator.snapshot() == before
    assert outcome.consumed == ()
    assert executor.ledger.consumption(oid) == (None, frozenset())
    # A rejected transaction leaves no history, so later effects stay consistent.
    _assert_committed(executor.submit(_door(Operation.CLOSE)), _door(Operation.CLOSE))


# --------------------------------------------------------------------------- precedence


ORDER_CASES = [
    pytest.param(Operation.OPEN, "closed_locked", "stale", "other_door", id="rules-3-4-8"),
    pytest.param(Operation.OPEN, "closed_locked", "replayed", "out_of_scope", id="rules-2-3-5-8"),
    pytest.param(Operation.UNLOCK, "open_unlocked", "false", "other_door", id="rules-3-6"),
    pytest.param(Operation.LOCK, "open_unlocked", "missing", "all_door", id="repair-close-lock"),
    pytest.param(Operation.OPEN, "closed_locked", "true", "all_door", id="repair-unlock-open"),
    pytest.param(Operation.OPEN, "closed_locked", "true", "exact", id="repair-unavailable"),
]
TABLE_ORDERS = {
    "reversed": tuple(reversed(RULE_TABLE)),
    "rotated": RULE_TABLE[3:] + RULE_TABLE[:3],
    "swapped": (RULE_TABLE[-1], *RULE_TABLE[1:-1], RULE_TABLE[0]),
}


@pytest.mark.parametrize("order", sorted(TABLE_ORDERS))
@pytest.mark.parametrize(("operation", "door_name", "presence", "mode"), ORDER_CASES)
def test_state_rule_results_do_not_depend_on_rule_order(
    operation: Operation, door_name: str, presence: str, mode: str, order: str
) -> None:
    declared = _door_case(operation, door_name, presence, mode)
    permuted = _door_case(operation, door_name, presence, mode, rule_table=TABLE_ORDERS[order])
    assert permuted.outcome.decision.to_dict() == declared.outcome.decision.to_dict()
    assert permuted.outcome.feedback == declared.outcome.feedback
    assert permuted.run.simulator.snapshot() == declared.run.simulator.snapshot()


# --------------------------------------------------------------------------- rule 7: thermostat


@pytest.mark.parametrize("value", [16, 16.0, 30, 30.0, 22.5])
def test_setpoint_bounds_are_inclusive(value: float) -> None:
    run, executor, _ = _harness([Permission(DeviceId.THERMOSTAT, Operation.SET_SETPOINT)])
    outcome = executor.submit(_setpoint(value))
    _assert_committed(outcome, _setpoint(value))
    assert run.simulator.snapshot().home.thermostat.setpoint_c == float(value)


@pytest.mark.parametrize(
    ("value", "clamped"),
    [(15.9, 16.0), (30.1, 30.0), (35, 30.0), (35.0, 30.0), (0, 16.0), (50, 30.0)],
)
def test_out_of_bounds_setpoint_without_intent_is_not_repaired(
    value: float, clamped: float
) -> None:
    """Rule 7 finding is repairable, but no trusted intent shows a clamp preserves the task."""
    run, executor, _ = _harness([Permission(DeviceId.THERMOSTAT, Operation.SET_SETPOINT)])
    before = run.simulator.snapshot()
    outcome = executor.submit(_setpoint(value))
    decision = outcome.decision

    _assert_blocked(outcome, run, before, RC.REPAIR_NOT_TASK_PRESERVING)
    assert _rule_codes(decision) == [(7, RC.SETPOINT_OUT_OF_BOUNDS)]
    (finding,) = [item for item in decision.findings if item.rule is not None]
    assert finding.rule is RuleId.THERMOSTAT_BOUNDS
    assert finding.repairable is True
    assert finding.escalation is False
    assert decision.escalation is False
    assert decision.repair_candidate == (_setpoint(clamped),)
    assert decision.repair_candidate[0].parameters["setpoint_c"] == clamped


@pytest.mark.parametrize(
    ("value", "intent", "verdict", "code", "result"),
    [
        (15.9, (15.0, 18.0), Verdict.REPAIR, RC.REPAIRED_CLAMP, 16.0),
        (30.1, (29.0, 31.0), Verdict.REPAIR, RC.REPAIRED_CLAMP, 30.0),
        (35, (20.0, 30.0), Verdict.REPAIR, RC.REPAIRED_CLAMP, 30.0),
        (35, (35.0, 35.0), Verdict.BLOCK, RC.REPAIR_NOT_TASK_PRESERVING, 21.0),
        (35, (31.0, 40.0), Verdict.BLOCK, RC.REPAIR_NOT_TASK_PRESERVING, 21.0),
        (15.9, (10.0, 15.95), Verdict.BLOCK, RC.REPAIR_NOT_TASK_PRESERVING, 21.0),
    ],
)
def test_out_of_bounds_setpoint_is_clamped_only_within_the_task_intent(
    value: float,
    intent: tuple[float, float],
    verdict: Verdict,
    code: ReasonCode,
    result: float,
) -> None:
    run, executor, _ = _harness(
        [Permission(DeviceId.THERMOSTAT, Operation.SET_SETPOINT)], intent_range=intent
    )
    before = run.simulator.snapshot()
    outcome = executor.submit(_setpoint(value))
    decision = outcome.decision
    assert decision.verdict is verdict
    assert decision.reason_code is code
    assert _rule_codes(decision) == [(7, RC.SETPOINT_OUT_OF_BOUNDS)]  # original finding kept
    if verdict is Verdict.REPAIR:
        assert decision.executed_actions == (_setpoint(result),)
        assert outcome.feedback["status"] == "repaired"
        assert outcome.feedback["reason_code"] == RC.REPAIRED_CLAMP.value
        assert outcome.feedback["executed_actions"] == [_setpoint(result).to_dict()]
        interpret(outcome.feedback)
    else:
        _assert_blocked(outcome, run, before, code)
    assert run.simulator.snapshot().home.thermostat.setpoint_c == result


@pytest.mark.parametrize(
    ("value", "inside"),
    [(17.9, False), (18, True), (25, True), (25.1, False), (16, False), (30, False)],
)
def test_setpoint_bounds_come_from_the_policy(value: float, inside: bool) -> None:
    policy = _custom(set(RuleId), thermostat_min_c=18.0, thermostat_max_c=25.0)
    run, executor, _ = _harness(
        [Permission(DeviceId.THERMOSTAT, Operation.SET_SETPOINT)], policy=policy
    )
    before = run.simulator.snapshot()
    outcome = executor.submit(_setpoint(value))
    if inside:
        _assert_committed(outcome, _setpoint(value))
    else:
        _assert_blocked(outcome, run, before, RC.REPAIR_NOT_TASK_PRESERVING)
        assert _rule_codes(outcome.decision) == [(7, RC.SETPOINT_OUT_OF_BOUNDS)]


@pytest.mark.parametrize("power", [Power.OFF, Power.ON])
@pytest.mark.parametrize(
    ("current", "safe"),
    [
        (15.9, False),
        (16.0, True),
        (21.0, True),
        (30.0, True),
        (30.1, False),
        (35.0, False),
        (0.0, False),
        (50.0, False),
    ],
)
def test_turn_on_requires_a_safe_current_setpoint(current: float, safe: bool, power: Power) -> None:
    home = HomeState(thermostat=ThermostatState(power, current))
    run, executor, _ = _harness(ALL_THERMOSTAT, home)
    before = run.simulator.snapshot()
    outcome = executor.submit(THERMOSTAT_ON)
    if safe:
        _assert_committed(outcome, THERMOSTAT_ON)
        assert run.simulator.snapshot().home.thermostat.power is Power.ON
        return
    _assert_blocked(outcome, run, before, RC.THERMOSTAT_UNSAFE_CURRENT_SETPOINT)
    decision = outcome.decision
    assert _rule_codes(decision) == [(7, RC.THERMOSTAT_UNSAFE_CURRENT_SETPOINT)]
    assert all(item.repairable is False for item in decision.findings)
    assert decision.escalation is False
    assert decision.repair_candidate is None  # not repairable: no repair attempted


def test_unsafe_current_setpoint_leaves_recovery_paths_open() -> None:
    home = HomeState(thermostat=ThermostatState(Power.ON, 35.0))
    run, executor, _ = _harness(ALL_THERMOSTAT, home)
    before = run.simulator.snapshot()
    _assert_blocked(
        executor.submit(THERMOSTAT_ON), run, before, RC.THERMOSTAT_UNSAFE_CURRENT_SETPOINT
    )

    # An out-of-bounds setpoint is only rule 7's ordinary bounds finding.
    outcome = executor.submit(_setpoint(31))
    _assert_blocked(outcome, run, before, RC.REPAIR_NOT_TASK_PRESERVING)
    assert _rule_codes(outcome.decision) == [(7, RC.SETPOINT_OUT_OF_BOUNDS)]

    _assert_committed(executor.submit(THERMOSTAT_OFF), THERMOSTAT_OFF)
    _assert_committed(executor.submit(_setpoint(22)), _setpoint(22))
    _assert_committed(executor.submit(THERMOSTAT_ON), THERMOSTAT_ON)
    assert run.simulator.snapshot().home.thermostat == ThermostatState(Power.ON, 22.0)


def test_unsafe_turn_on_without_permission_reports_authority_first() -> None:
    home = HomeState(thermostat=ThermostatState(Power.OFF, 35.0))
    run, executor, _ = _harness([Permission(DeviceId.THERMOSTAT, Operation.SET_SETPOINT)], home)
    before = run.simulator.snapshot()
    outcome = executor.submit(THERMOSTAT_ON)
    _assert_blocked(outcome, run, before, RC.OPERATION_NOT_AUTHORIZED)
    assert _rule_codes(outcome.decision) == [
        (3, RC.OPERATION_NOT_AUTHORIZED),
        (7, RC.THERMOSTAT_UNSAFE_CURRENT_SETPOINT),
    ]
    assert outcome.decision.escalation is True


def test_rule_7_reads_trusted_state_not_the_thermostat_payload() -> None:
    # Unsafe canonical setpoint, payload forged to look safe: still blocked.
    home = HomeState(thermostat=ThermostatState(Power.OFF, 35.0))
    run, executor, _ = _harness(ALL_THERMOSTAT, home)
    obs = run.gateway.observe(DeviceId.THERMOSTAT)
    executor.deliver(with_payload_changes(obs, {"setpoint_c": 22.0}))
    before = run.simulator.snapshot()
    outcome = executor.submit(
        ActionProposal(DeviceId.THERMOSTAT, Operation.TURN_ON, evidence_refs=(_oid(obs),))
    )
    _assert_blocked(outcome, run, before, RC.THERMOSTAT_UNSAFE_CURRENT_SETPOINT)

    # Safe canonical setpoint, payload forged to look unsafe: allowed, annotated.
    home = HomeState(thermostat=ThermostatState(Power.OFF, 22.0))
    run, executor, _ = _harness(ALL_THERMOSTAT, home)
    obs = run.gateway.observe(DeviceId.THERMOSTAT)
    executor.deliver(with_payload_changes(obs, {"setpoint_c": 35.0}))
    action = ActionProposal(DeviceId.THERMOSTAT, Operation.TURN_ON, evidence_refs=(_oid(obs),))
    outcome = executor.submit(action)
    _assert_committed(outcome, action)
    assert f"payload_mismatch:{_oid(obs)}:setpoint_c" in outcome.decision.annotations


@pytest.mark.parametrize("kind", ["stale", "replayed"])
def test_cited_thermostat_evidence_is_not_required(kind: str) -> None:
    run, executor, _ = _harness(ALL_THERMOSTAT)
    obs = _read(run, executor, DeviceId.THERMOSTAT)
    if kind == "stale":
        _advance(run, TTL_MS + 1)
    else:
        _replay(run, executor, obs)
    action = _setpoint(22, _oid(obs))
    outcome = executor.submit(action)
    _assert_committed(outcome, action)
    assert outcome.decision.annotations == (f"{kind}_reference:{_oid(obs)}",)
    assert outcome.consumed == ()


@pytest.mark.parametrize(
    "home",
    [None, {"thermostat": {"power": "off", "setpoint_c": 22.0}}, HomeState().to_dict()],
    ids=["none", "partial-dict", "state-dict"],
)
def test_malformed_trusted_thermostat_state_fails_closed(home: object) -> None:
    run = create_run(start_time_ms=START_MS)
    rid = _issue(run, ALL_THERMOSTAT)
    mediator = _mediator(
        run,
        rid,
        lambda: run.simulator.history,
        snapshot=lambda: HomeSnapshot(0, START_MS, home),  # type: ignore[arg-type]
    )
    decision = mediator.decide(THERMOSTAT_ON, request_id=rid)
    assert decision.verdict is Verdict.ERROR
    assert decision.reason_code is RC.TRUSTED_CONTEXT_MALFORMED
    assert decision.executed_actions == ()
    assert decision.escalation is True


# --------------------------------------------------------------------------- rule functions


def _rule_fn(rule: RuleId) -> RuleFn:
    return dict(RULE_TABLE)[rule]


def _context(
    run: RunEnvironment,
    request: RequestContext,
    ledger: EvidenceLedger,
    *,
    presence: tuple[DeliveryRecord, ...] = (),
    consistent: bool = True,
) -> RuleContext:
    snap = run.simulator.snapshot()
    return RuleContext(
        policy=policy_for(Ablation.FULL),
        request=request,
        bound_request_id=request.request_id,
        state_version=snap.state_version,
        time_ms=snap.time_ms,
        ledger=ledger,
        cited=(),
        unknown_refs=(),
        presence=presence,
        history_consistent=consistent,
        history_detail="" if consistent else "test",
    )


def _request(run: RunEnvironment, permissions: Iterable[Permission]) -> RequestContext:
    request = run.requests.view.lookup(_issue(run, permissions))
    assert request is not None
    return request


def test_rule_table_has_one_function_per_rule_2_to_8() -> None:
    assert sorted(int(rule) for rule, _ in RULE_TABLE) == [2, 3, 4, 5, 6, 7, 8]


def test_rule_8_reads_the_door_from_the_home_argument() -> None:
    run = create_run(HomeState(door=CLOSED_LOCKED), start_time_ms=START_MS)
    ctx = _context(run, _request(run, ALL_DOOR), _ledger(run))
    rule8 = _rule_fn(RuleId.SEQUENCE)

    assert rule8(ctx, _door(Operation.OPEN), HomeState(door=CLOSED_UNLOCKED)) == []
    (unmet,) = rule8(ctx, _door(Operation.OPEN), HomeState(door=CLOSED_LOCKED))
    assert (unmet.rule, unmet.code, unmet.repairable) == (8, RC.PRECONDITION_UNMET, True)
    assert "unlock" in unmet.detail

    assert rule8(ctx, _door(Operation.LOCK), HomeState(door=CLOSED_UNLOCKED)) == []
    (unmet,) = rule8(ctx, _door(Operation.LOCK), HomeState(door=OPEN_UNLOCKED))
    assert (unmet.rule, unmet.code, unmet.repairable) == (8, RC.PRECONDITION_UNMET, True)
    assert "close" in unmet.detail

    for operation in (Operation.UNLOCK, Operation.CLOSE):
        for door in DOOR_STATES.values():
            assert rule8(ctx, _door(operation), HomeState(door=door)) == []


def test_rule_8_reports_inconsistent_history_for_any_effect() -> None:
    run = create_run(start_time_ms=START_MS)
    request = _request(run, [*LIGHT_FAN, *ALL_DOOR])
    ctx = _context(run, request, _ledger(run), consistent=False)
    rule8 = _rule_fn(RuleId.SEQUENCE)
    for action in (LIGHT_ON, FAN_OFF, _door(Operation.CLOSE)):
        (item,) = rule8(ctx, action, HomeState())
        assert (item.rule, item.code, item.repairable) == (8, RC.HISTORY_INCONSISTENT, False)
    codes = {item.code for item in rule8(ctx, _door(Operation.OPEN), HomeState())}
    assert codes == {RC.HISTORY_INCONSISTENT, RC.PRECONDITION_UNMET}


def test_rule_7_reads_the_current_setpoint_from_the_home_argument() -> None:
    run = create_run(start_time_ms=START_MS)  # simulator setpoint is a safe 21 C
    ctx = _context(run, _request(run, ALL_THERMOSTAT), _ledger(run))
    rule7 = _rule_fn(RuleId.THERMOSTAT_BOUNDS)
    unsafe = HomeState(thermostat=ThermostatState(Power.OFF, 35.0))

    (item,) = rule7(ctx, THERMOSTAT_ON, unsafe)
    assert (item.rule, item.code, item.repairable) == (
        7,
        RC.THERMOSTAT_UNSAFE_CURRENT_SETPOINT,
        False,
    )
    assert rule7(ctx, THERMOSTAT_ON, HomeState()) == []
    assert rule7(ctx, THERMOSTAT_OFF, unsafe) == []
    assert rule7(ctx, _setpoint(22), unsafe) == []
    (item,) = rule7(ctx, _setpoint(30.1), HomeState())
    assert (item.code, item.repairable) == (RC.SETPOINT_OUT_OF_BOUNDS, True)
    assert rule7(ctx, LIGHT_ON, unsafe) == []


def test_rule_6_uses_canonical_facts_of_the_required_deliveries_only() -> None:
    run = create_run(start_time_ms=START_MS)
    request = _request(run, ALL_DOOR)
    ledger = _ledger(run)
    absent = ledger.ingest(run.gateway.observe(DeviceId.PRESENCE_SENSOR))
    _set_presence(run, True)
    present = ledger.ingest(run.gateway.observe(DeviceId.PRESENCE_SENSOR))
    rule6 = _rule_fn(RuleId.DOOR_ACCESS)
    someone_home = HomeState(presence_sensor=PresenceState(True))
    nobody_home = HomeState(presence_sensor=PresenceState(False))

    for operation in ACCESS:
        ctx = _context(run, request, ledger)
        (item,) = rule6(ctx, _door(operation), someone_home)
        assert (item.rule, item.code) == (6, RC.PRESENCE_EVIDENCE_MISSING)

        # Trusted current presence is rule 4's concern, not rule 6's.
        ctx = _context(run, request, ledger, presence=(absent,))
        (item,) = rule6(ctx, _door(operation), someone_home)
        assert (item.rule, item.code) == (6, RC.PRESENCE_NOT_CONFIRMED)
        ctx = _context(run, request, ledger, presence=(present,))
        assert rule6(ctx, _door(operation), nobody_home) == []

        ctx = _context(run, request, ledger, presence=(present, absent))
        assert [item.code for item in rule6(ctx, _door(operation), someone_home)] == [
            RC.PRESENCE_NOT_CONFIRMED
        ]

    ctx = _context(run, request, ledger)
    for action in (_door(Operation.LOCK), _door(Operation.CLOSE), LIGHT_ON, THERMOSTAT_ON):
        assert rule6(ctx, action, nobody_home) == []


# --------------------------------------------------------------------------- rule 8: sequences


def _sequence_model(
    start: DoorState, order: Sequence[Operation], permitted: frozenset[Operation], reread: bool
) -> list[tuple[Verdict, ReasonCode, DoorState]]:
    """Design rules 5, 6, 8 and section 7 over a door sequence with fresh true presence.

    With ``reread`` every step has a new reading; otherwise one reading serves the
    whole sequence and each access operation may use it once (Proposed D07).
    """
    door, used = start, set[Operation]()
    steps: list[tuple[Verdict, ReasonCode, DoorState]] = []
    for operation in order:
        if operation in ACCESS and not reread and operation in used:
            steps.append((Verdict.BLOCK, RC.PRESENCE_EVIDENCE_CONSUMED, door))
            continue
        if _precondition_met(door, operation):
            door = _apply_door(door, operation)
            if operation in ACCESS and not reread:
                used.add(operation)
            steps.append((Verdict.ALLOW, RC.ALLOWED, door))
            continue
        prerequisite = PREREQUISITE[operation]
        if prerequisite not in permitted:
            steps.append((Verdict.BLOCK, RC.REPAIR_UNAVAILABLE, door))
            continue
        if prerequisite in ACCESS and not reread and prerequisite in used:
            steps.append((Verdict.BLOCK, RC.REPAIR_FAILED_REVALIDATION, door))
            continue
        door = _apply_door(_apply_door(door, prerequisite), operation)
        if not reread:
            used.update(op for op in (prerequisite, operation) if op in ACCESS)
        steps.append((Verdict.REPAIR, RC.REPAIRED_PREREQUISITE, door))
    return steps


def _sequence_cases() -> list[Any]:
    cases = []
    for door_name in DOOR_STATES:
        for size in (2, 3, 4):
            for permitted in itertools.combinations(DOOR_OPERATIONS, size):
                for order in itertools.permutations(permitted):
                    for reread in (True, False):
                        label = "-".join(op.value for op in order)
                        reading = "reread" if reread else "one-reading"
                        cases.append(
                            pytest.param(
                                door_name,
                                order,
                                reread,
                                id=f"{door_name}-{label}-{reading}",
                            )
                        )
    return cases


@pytest.mark.parametrize(("door_name", "order", "reread"), _sequence_cases())
def test_door_sequence_permutations(
    door_name: str, order: tuple[Operation, ...], reread: bool
) -> None:
    """Every ordering of the permitted door operations follows the declared order."""
    start = DOOR_STATES[door_name]
    permitted = frozenset(order)
    home = HomeState(door=start, presence_sensor=PresenceState(True))
    run, executor, _ = _harness([Permission(DeviceId.DOOR, op) for op in order], home)
    if not reread:
        _read(run, executor, DeviceId.PRESENCE_SENSOR)

    actual: list[tuple[Verdict, ReasonCode, DoorState]] = []
    for operation in order:
        if reread:
            _read(run, executor, DeviceId.PRESENCE_SENSOR)
        outcome = executor.submit(_door(operation))
        interpret(outcome.feedback)
        actual.append(
            (
                outcome.decision.verdict,
                outcome.decision.reason_code,
                run.simulator.snapshot().home.door,
            )
        )
    assert actual == _sequence_model(start, order, permitted, reread)


def test_declared_order_unlock_before_open_and_close_before_lock() -> None:
    home = HomeState(door=CLOSED_LOCKED, presence_sensor=PresenceState(True))
    run, executor, _ = _harness(ALL_DOOR, home)
    _read(run, executor, DeviceId.PRESENCE_SENSOR)
    for operation, door in [
        (Operation.UNLOCK, CLOSED_UNLOCKED),
        (Operation.OPEN, OPEN_UNLOCKED),
        (Operation.CLOSE, CLOSED_UNLOCKED),
        (Operation.LOCK, CLOSED_LOCKED),
    ]:
        _assert_committed(executor.submit(_door(operation)), _door(operation))
        assert run.simulator.snapshot().home.door == door


@pytest.mark.parametrize(
    ("operation", "start", "prerequisite"),
    [
        (Operation.OPEN, CLOSED_LOCKED, Operation.UNLOCK),
        (Operation.LOCK, OPEN_UNLOCKED, Operation.CLOSE),
    ],
)
def test_out_of_order_operation_is_repaired_as_one_atomic_transaction(
    operation: Operation, start: DoorState, prerequisite: Operation
) -> None:
    home = HomeState(door=start, presence_sensor=PresenceState(True))
    run, executor, _ = _harness(
        [Permission(DeviceId.DOOR, operation), Permission(DeviceId.DOOR, prerequisite)], home
    )
    _read(run, executor, DeviceId.PRESENCE_SENSOR)
    outcome = executor.submit(_door(operation))
    decision = outcome.decision
    assert decision.verdict is Verdict.REPAIR
    assert decision.reason_code is RC.REPAIRED_PREREQUISITE
    assert _rule_codes(decision) == [(8, RC.PRECONDITION_UNMET)]
    assert _ops(decision.executed_actions) == [
        (DeviceId.DOOR, prerequisite),
        (DeviceId.DOOR, operation),
    ]
    assert outcome.execution is not None and outcome.execution.committed
    entries = outcome.execution.entries
    assert [entry.action for entry in entries] == list(decision.executed_actions)
    assert len({entry.transaction_id for entry in entries}) == 1
    final = _apply_door(_apply_door(start, prerequisite), operation)
    assert run.simulator.snapshot().home.door == final


@pytest.mark.parametrize(
    ("operation", "start", "prerequisite"),
    [
        (Operation.OPEN, CLOSED_LOCKED, Operation.UNLOCK),
        (Operation.LOCK, OPEN_UNLOCKED, Operation.CLOSE),
    ],
)
def test_out_of_order_operation_without_prerequisite_permission_is_blocked(
    operation: Operation, start: DoorState, prerequisite: Operation
) -> None:
    home = HomeState(door=start, presence_sensor=PresenceState(True))
    run, executor, _ = _harness([Permission(DeviceId.DOOR, operation)], home)
    _read(run, executor, DeviceId.PRESENCE_SENSOR)
    before = run.simulator.snapshot()
    outcome = executor.submit(_door(operation))
    _assert_blocked(outcome, run, before, RC.REPAIR_UNAVAILABLE)
    (unmet,) = [item for item in outcome.decision.findings if item.rule is not None]
    assert (unmet.rule, unmet.code) == (RuleId.SEQUENCE, RC.PRECONDITION_UNMET)
    assert prerequisite.value in unmet.detail


def test_prerequisite_repair_cannot_reuse_an_already_used_unlock() -> None:
    """unlock, lock, open on one reading: the repaired (unlock, open) fails revalidation."""
    home = HomeState(door=CLOSED_LOCKED, presence_sensor=PresenceState(True))
    run, executor, _ = _harness(ALL_DOOR, home)
    _read(run, executor, DeviceId.PRESENCE_SENSOR)
    _assert_committed(executor.submit(_door(Operation.UNLOCK)), _door(Operation.UNLOCK))
    _assert_committed(executor.submit(_door(Operation.LOCK)), _door(Operation.LOCK))
    before = run.simulator.snapshot()
    outcome = executor.submit(_door(Operation.OPEN))
    _assert_blocked(outcome, run, before, RC.REPAIR_FAILED_REVALIDATION)
    codes = {item.code for item in outcome.decision.findings}
    assert RC.PRECONDITION_UNMET in codes  # the original finding is retained
    assert RC.PRESENCE_EVIDENCE_CONSUMED in codes  # the revalidation finding is kept


# --------------------------------------------------------------------------- rule 8: history


@pytest.mark.parametrize(
    "direct",
    [
        pytest.param((FAN_ON,), id="changed-fan"),
        pytest.param((FAN_OFF,), id="no-op-fan"),
        pytest.param((LIGHT_ON,), id="repeat-mediated-action"),
        pytest.param((LIGHT_OFF, FAN_ON), id="two-step-transaction"),
    ],
)
@pytest.mark.parametrize("mediated_first", [True, False])
def test_direct_execution_outside_the_mediator_makes_history_inconsistent(
    direct: tuple[ActionProposal, ...], mediated_first: bool
) -> None:
    run, executor, _ = _harness(LIGHT_FAN)
    if mediated_first:
        _assert_committed(executor.submit(LIGHT_ON), LIGHT_ON)
    result = run.simulator.execute(
        direct, expected_version=run.simulator.state_version, capability=run.execution_capability
    )
    assert result.committed

    before = run.simulator.snapshot()
    history = run.simulator.history
    for _ in range(2):  # stays inconsistent: nothing the agent does repairs history
        outcome = executor.submit(LIGHT_OFF)
        _assert_blocked(outcome, run, before, RC.HISTORY_INCONSISTENT)
        decision = outcome.decision
        assert _rule_codes(decision) == [(8, RC.HISTORY_INCONSISTENT)]
        assert decision.findings[0].repairable is False
        assert decision.escalation is False
        assert decision.repair_candidate is None
        assert run.simulator.history == history

    # Reads are governed by rule 2 identity checks only.
    read = executor.submit(LIGHT_READ)
    assert read.decision.verdict is Verdict.ALLOW
    assert read.decision.reason_code is RC.READ_ALLOWED_BY_POLICY
    assert read.feedback["status"] == "observed"


def test_inconsistent_history_blocks_door_access_without_consuming() -> None:
    home = HomeState(door=CLOSED_LOCKED, presence_sensor=PresenceState(True))
    run, executor, _ = _harness([*ALL_DOOR, *LIGHT_FAN], home)
    oid = _oid(_read(run, executor, DeviceId.PRESENCE_SENSOR))
    run.simulator.execute(
        [LIGHT_ON],
        expected_version=run.simulator.state_version,
        capability=run.execution_capability,
    )
    before = run.simulator.snapshot()

    outcome = executor.submit(_door(Operation.UNLOCK))
    _assert_blocked(outcome, run, before, RC.HISTORY_INCONSISTENT)
    assert _rule_codes(outcome.decision) == [(8, RC.HISTORY_INCONSISTENT)]
    assert executor.ledger.consumption(oid) == (None, frozenset())

    # Non-repairable history finding beside a repairable one: no repair at all.
    outcome = executor.submit(_door(Operation.OPEN))
    _assert_blocked(outcome, run, before, RC.HISTORY_INCONSISTENT)
    assert _rule_codes(outcome.decision) == [
        (8, RC.HISTORY_INCONSISTENT),
        (8, RC.PRECONDITION_UNMET),
    ]
    assert outcome.decision.repair_candidate is None


def test_environment_events_clock_and_rejected_transactions_keep_history_consistent() -> None:
    run, executor, _ = _harness(LIGHT_FAN)
    _assert_committed(executor.submit(LIGHT_ON), LIGHT_ON)
    _set_presence(run, True)
    _advance(run, 1_000)
    rejected = run.simulator.execute(
        [FAN_ON], expected_version=99, capability=run.execution_capability
    )
    assert not rejected.committed
    _assert_committed(executor.submit(FAN_ON), FAN_ON)
    _set_presence(run, False)
    _assert_committed(executor.submit(LIGHT_OFF), LIGHT_OFF)
    _assert_committed(executor.submit(LIGHT_OFF), LIGHT_OFF)  # committed no-op


class _StubHistory:
    """History callable that returns the real history unless overridden, counting calls."""

    def __init__(self, run: RunEnvironment) -> None:
        self._run = run
        self.entries: tuple[TraceEntry, ...] | None = None
        self.calls = 0

    def __call__(self) -> tuple[TraceEntry, ...]:
        self.calls += 1
        return self._run.simulator.history if self.entries is None else self.entries


def _stub_world() -> tuple[RunEnvironment, Mediator, _StubHistory, str, tuple[TraceEntry, ...]]:
    run = create_run(start_time_ms=START_MS)
    rid = _issue(run, LIGHT_FAN)
    history = _StubHistory(run)
    mediator = _mediator(run, rid, history)
    _commit(run, mediator, LIGHT_ON, rid)  # ACTION, changed (version 1)
    _set_presence(run, True)  # ENVIRONMENT, changed (version 2)
    _advance(run, 1_000)  # CLOCK, unchanged
    real = run.simulator.history
    assert [entry.kind for entry in real] == [
        TraceKind.ACTION,
        TraceKind.ENVIRONMENT,
        TraceKind.CLOCK,
    ]
    return run, mediator, history, rid, real


def _foreign_action(real: tuple[TraceEntry, ...]) -> TraceEntry:
    """An unchanged ACTION entry the mediator never approved."""
    snap = real[0].before
    return TraceEntry(0, TraceKind.ACTION, snap, snap, transaction_id=99, action=FAN_ON)


STUBS: dict[str, Callable[[tuple[TraceEntry, ...]], tuple[TraceEntry, ...]]] = {
    "empty": lambda real: (),
    "mediated-action-missing": lambda real: (real[1], real[2]),
    "foreign-action-entry": lambda real: (_foreign_action(real), *real),
    "changed-entry-missing": lambda real: (real[0], real[2]),
    "changed-entry-repeated": lambda real: (real[0], real[1], real[1], real[2]),
    "last-entry-not-current-snapshot": lambda real: (real[0], real[1]),
}


@pytest.mark.parametrize("stub", sorted(STUBS))
def test_stub_history_inconsistent_with_trusted_state_blocks(stub: str) -> None:
    run, mediator, history, rid, real = _stub_world()
    assert mediator.decide(FAN_ON, request_id=rid).verdict is Verdict.ALLOW  # real history

    history.entries = STUBS[stub](real)
    decision = mediator.decide(FAN_ON, request_id=rid)
    assert decision.verdict is Verdict.BLOCK
    assert decision.reason_code is RC.HISTORY_INCONSISTENT
    assert _rule_codes(decision) == [(8, RC.HISTORY_INCONSISTENT)]
    assert decision.executed_actions == ()

    history.entries = None
    assert mediator.decide(FAN_ON, request_id=rid).verdict is Verdict.ALLOW


def test_execution_the_mediator_did_not_record_is_inconsistent() -> None:
    run = create_run(start_time_ms=START_MS)
    rid = _issue(run, LIGHT_FAN)
    mediator = _mediator(run, rid, lambda: run.simulator.history)
    _commit(run, mediator, LIGHT_ON, rid)
    decision = mediator.decide(FAN_ON, request_id=rid)
    assert decision.verdict is Verdict.ALLOW
    assert decision.state_version is not None
    run.simulator.execute(
        decision.executed_actions,
        expected_version=decision.state_version,
        capability=run.execution_capability,
    )  # executed but never passed to record_commit
    later = mediator.decide(LIGHT_OFF, request_id=rid)
    assert later.verdict is Verdict.BLOCK
    assert later.reason_code is RC.HISTORY_INCONSISTENT


def test_empty_history_is_consistent_with_an_untouched_simulator() -> None:
    run = create_run(start_time_ms=START_MS)
    rid = _issue(run, LIGHT_FAN)
    decision = _mediator(run, rid, lambda: ()).decide(LIGHT_ON, request_id=rid)
    assert decision.verdict is Verdict.ALLOW
    assert decision.reason_code is RC.ALLOWED


def test_history_is_computed_once_per_effect_decision() -> None:
    run = create_run(
        HomeState(door=CLOSED_LOCKED, presence_sensor=PresenceState(True)), start_time_ms=START_MS
    )
    rid = _issue(run, [*ALL_DOOR, *LIGHT_FAN])
    history = _StubHistory(run)
    ledger = _ledger(run)
    mediator = _mediator(run, rid, history, ledger=ledger)
    ledger.ingest(run.gateway.observe(DeviceId.PRESENCE_SENSOR))

    for proposal, verdict in [
        (LIGHT_ON, Verdict.ALLOW),
        (THERMOSTAT_ON, Verdict.BLOCK),  # device out of scope
        (_door(Operation.OPEN), Verdict.REPAIR),  # repair revalidation reuses the context
    ]:
        history.calls = 0
        assert mediator.decide(proposal, request_id=rid).verdict is verdict
        assert history.calls == 1

    history.calls = 0
    raw = json.dumps({**LIGHT_ON.to_dict(), "history": []})
    assert mediator.decide(raw, request_id=rid).reason_code is RC.SCHEMA_INVALID
    assert history.calls == 0  # rule 1 failure: nothing else evaluated


@pytest.mark.parametrize("error", [RuntimeError, TypeError, ValueError, KeyError])
def test_history_callable_raising_fails_closed_with_mediator_error(
    error: type[Exception],
) -> None:
    """Section 6 step 7: any exception escaping steps 2-6 is ERROR mediator_error."""
    run = create_run(start_time_ms=START_MS)
    rid = _issue(run, LIGHT_FAN)

    def broken() -> tuple[TraceEntry, ...]:
        raise error("history store unavailable")

    before = run.simulator.snapshot()
    decision = _mediator(run, rid, broken).decide(LIGHT_ON, request_id=rid)
    assert decision.verdict is Verdict.ERROR
    assert decision.reason_code is RC.MEDIATOR_ERROR
    assert any(
        item.code is RC.MEDIATOR_ERROR and item.detail == error.__name__
        for item in decision.findings
    )
    assert decision.executed_actions == ()
    assert decision.escalation is True
    assert run.simulator.snapshot() == before


@pytest.mark.parametrize(
    "entries",
    [("not-a-trace-entry",), (None,), ({"kind": "action"},)],
    ids=["str", "none", "dict"],
)
def test_history_with_non_trace_entries_fails_closed(entries: tuple[object, ...]) -> None:
    """The design does not name the code for a malformed history; it must still be an ERROR."""
    run = create_run(start_time_ms=START_MS)
    rid = _issue(run, LIGHT_FAN)
    mediator = _mediator(run, rid, lambda: entries)  # type: ignore[arg-type,return-value]
    decision = mediator.decide(LIGHT_ON, request_id=rid)
    assert decision.verdict is Verdict.ERROR
    assert decision.reason_code in {RC.TRUSTED_CONTEXT_MALFORMED, RC.MEDIATOR_ERROR}
    assert decision.executed_actions == ()
    assert decision.escalation is True


# --------------------------------------------------------------------------- agent history field


def _open_door_raw(**extra: Any) -> dict[str, Any]:
    return {**_door(Operation.OPEN).to_dict(), **extra}


AGENT_HISTORY = [{"device": "door", "operation": "unlock"}]


@pytest.mark.parametrize(
    ("proposal", "detail"),
    [
        pytest.param(json.dumps(_open_door_raw(history=AGENT_HISTORY)), "unknown_field", id="str"),
        pytest.param(
            json.dumps(_open_door_raw(history=AGENT_HISTORY)).encode(), "unknown_field", id="bytes"
        ),
        pytest.param(_open_door_raw(history=AGENT_HISTORY), "unknown_field", id="mapping"),
        pytest.param(
            MappingProxyType(_open_door_raw(history=AGENT_HISTORY)),
            "unknown_field",
            id="mapping-proxy",
        ),
        pytest.param(json.dumps(_open_door_raw(history=[])), "unknown_field", id="empty-history"),
        pytest.param(
            json.dumps(_open_door_raw(parameters={"history": ["door.unlock"]})),
            "unknown_parameter",
            id="in-parameters",
        ),
    ],
)
def test_agent_supplied_history_is_rejected_by_rule_1(proposal: object, detail: str) -> None:
    home = HomeState(door=CLOSED_LOCKED, presence_sensor=PresenceState(True))
    run, executor, _ = _harness([Permission(DeviceId.DOOR, Operation.OPEN)], home)
    _read(run, executor, DeviceId.PRESENCE_SENSOR)
    before = run.simulator.snapshot()
    history = run.simulator.history

    outcome = executor.submit(proposal)
    _assert_blocked(outcome, run, before, RC.SCHEMA_INVALID)
    decision = outcome.decision
    assert len(decision.findings) == 1
    (finding,) = decision.findings
    assert (finding.rule, finding.code, finding.detail) == (
        RuleId.TYPED_ACTION,
        RC.SCHEMA_INVALID,
        detail,
    )
    assert decision.action is None
    assert decision.escalation is False
    assert run.simulator.history == history

    # The asserted unlock did not happen: rule 8 still sees a locked door.
    outcome = executor.submit(_door(Operation.OPEN))
    _assert_blocked(outcome, run, before, RC.REPAIR_UNAVAILABLE)
    assert _rule_codes(outcome.decision) == [(8, RC.PRECONDITION_UNMET)]
