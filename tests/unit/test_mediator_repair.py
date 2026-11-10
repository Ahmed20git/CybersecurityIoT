"""WP-09 repair: clamp, prerequisite, repair bound, revalidation and atomic commit.

Expected outcomes come from the mediator design in docs/mediator_design.md (section 7 repair,
section 4 aggregation, section 5 consumption, section 8 executor and the section 10 test list), not
from the implementation. Requirements: MED-10 (task-preserving repair), MED-11 (revalidation of
every step), MED-08 and MED-09 (the repairable rule 7 and rule 8 findings), SIM-07 and SIM-09 (one
atomic transaction bound to the checked state version). The repair templates and the repair bound
are Proposed D08, the door order is Proposed D04 and access-episode consumption is Proposed D07.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import replace

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
    Operation,
    Permission,
    Power,
    PresenceState,
    SetAmbientTemperature,
    ThermostatState,
)
from effectshield.environment import RunEnvironment, create_run
from effectshield.mediator import (
    RULE_TABLE,
    Ablation,
    Decision,
    MediatedOutcome,
    MediatorPolicy,
    PolicyError,
    ProtectedExecutor,
    ReasonCode,
    RuleContext,
    RuleFinding,
    RuleFn,
    RuleId,
    TaskIntent,
    Verdict,
    check_door_access,
    check_sequence,
    policy_for,
)
from effectshield.simulator.core import MAX_TRANSACTION_ACTIONS, TraceKind

CUSTOM_VERSION = "mediator-policy-custom/test"

LOCKED_CLOSED = DoorState(DoorPosition.CLOSED, LockState.LOCKED)
OPEN_UNLOCKED = DoorState(DoorPosition.OPEN, LockState.UNLOCKED)
# Someone is home and the door is closed and locked: the (unlock, open) repair start state.
AT_LOCKED_DOOR = HomeState(door=LOCKED_CLOSED, presence_sensor=PresenceState(True))

SETPOINT_ONLY = (Permission(DeviceId.THERMOSTAT, Operation.SET_SETPOINT),)
UNLOCK_OPEN = (
    Permission(DeviceId.DOOR, Operation.UNLOCK),
    Permission(DeviceId.DOOR, Operation.OPEN),
)
CLOSE_LOCK = (
    Permission(DeviceId.DOOR, Operation.CLOSE),
    Permission(DeviceId.DOOR, Operation.LOCK),
)
DOOR_ALL = UNLOCK_OPEN + CLOSE_LOCK

Before = tuple[HomeSnapshot, int]  # snapshot and history length before a submission
RuleTable = tuple[tuple[RuleId, RuleFn], ...]


# --------------------------------------------------------------------------- helpers


def _custom(
    *,
    max_repair_actions: int = 2,
    thermostat_min_c: float = 16.0,
    thermostat_max_c: float = 30.0,
) -> MediatorPolicy:
    return MediatorPolicy(
        ablation=Ablation.CUSTOM,
        enabled_rules=frozenset(RuleId),
        thermostat_min_c=thermostat_min_c,
        thermostat_max_c=thermostat_max_c,
        max_repair_actions=max_repair_actions,
        version=CUSTOM_VERSION,
    )


def _issue(
    run: RunEnvironment, permissions: Iterable[Permission], text: str = "repair test request"
) -> str:
    return run.requests.issue(
        principal_id="resident-1",
        request_text=text,
        permissions=permissions,
        issued_at_ms=run.simulator.now_ms,
    ).request_id


def _harness(
    permissions: Iterable[Permission],
    home: HomeState | None = None,
    *,
    intent_range: tuple[float, float] | None = None,
    policy: MediatorPolicy | None = None,
    rule_table: Sequence[tuple[RuleId, RuleFn]] = RULE_TABLE,
    request_text: str = "repair test request",
) -> tuple[RunEnvironment, ProtectedExecutor, str]:
    """A run with one harness-bound request and, optionally, its trusted task intent."""
    run = create_run(home)
    request_id = _issue(run, permissions, request_text)
    intents: Mapping[str, TaskIntent] | None = None
    if intent_range is not None:
        intents = {request_id: TaskIntent(request_id, intent_range)}
    executor = ProtectedExecutor.from_run(
        run, request_id=request_id, policy=policy, intents=intents, rule_table=rule_table
    )
    return run, executor, request_id


def _read(
    run: RunEnvironment, executor: ProtectedExecutor, device: DeviceId = DeviceId.PRESENCE_SENSOR
) -> str:
    """A genuine gateway reading routed into the agent's context; returns its ID."""
    return executor.deliver(run.gateway.observe(device)).envelope.observation_id


def _setpoint(value: float, *refs: str) -> ActionProposal:
    return ActionProposal(
        DeviceId.THERMOSTAT, Operation.SET_SETPOINT, {"setpoint_c": value}, evidence_refs=refs
    )


def _door(operation: Operation, *refs: str) -> ActionProposal:
    return ActionProposal(DeviceId.DOOR, operation, evidence_refs=refs)


def _with_rule(rule_id: RuleId, check: RuleFn) -> RuleTable:
    """``RULE_TABLE`` with one rule's function replaced (the section 6 test hook)."""
    return tuple((rule, check if rule is rule_id else fn) for rule, fn in RULE_TABLE)


def _state(run: RunEnvironment) -> Before:
    return run.simulator.snapshot(), len(run.simulator.history)


def _codes(decision: Decision) -> list[ReasonCode]:
    return [item.code for item in decision.findings]


def _operations(actions: Iterable[ActionProposal]) -> list[tuple[DeviceId, Operation]]:
    return [(action.device, action.operation) for action in actions]


def _action_entries(run: RunEnvironment) -> list[object]:
    return [entry for entry in run.simulator.history if entry.kind is TraceKind.ACTION]


def _assert_sorted(decision: Decision) -> None:
    assert decision.findings == tuple(sorted(decision.findings, key=RuleFinding.sort_key))


def _assert_repaired(
    outcome: MediatedOutcome,
    run: RunEnvironment,
    before: Before,
    code: ReasonCode,
    candidate: tuple[ActionProposal, ...],
) -> None:
    """REPAIR: the candidate ran as exactly one committed transaction (SIM-09)."""
    snapshot, history_len = before
    decision = outcome.decision
    assert decision.verdict is Verdict.REPAIR, decision.findings
    assert decision.reason_code is code
    assert decision.executed_actions == candidate
    assert decision.repair_candidate == candidate
    assert decision.state_version == snapshot.state_version
    assert decision.supersedes is None
    assert decision.escalation is False
    # The original (repairable) findings are always retained; a passing revalidation adds none.
    assert decision.findings and all(item.repairable for item in decision.findings)
    _assert_sorted(decision)

    result = outcome.execution
    assert result is not None and result.committed
    assert result.version_before == snapshot.state_version
    assert tuple(entry.action for entry in result.entries) == candidate
    assert {entry.transaction_id for entry in result.entries} == {result.transaction_id}
    assert run.simulator.history[history_len:] == result.entries
    assert run.simulator.snapshot().state_version == result.version_after
    assert outcome.feedback == {
        "status": "repaired",
        "transaction_id": result.transaction_id,
        "version_before": result.version_before,
        "version_after": result.version_after,
        "reason_code": code.value,
        "executed_actions": [action.to_dict() for action in candidate],
    }
    interpret(outcome.feedback)


def _assert_blocked(
    outcome: MediatedOutcome, run: RunEnvironment, before: Before, code: ReasonCode
) -> None:
    """BLOCK: nothing executed, nothing consumed, the agent sees only the protocol fields."""
    snapshot, history_len = before
    decision = outcome.decision
    assert decision.verdict is Verdict.BLOCK, decision.findings
    assert decision.reason_code is code, decision.findings
    assert decision.executed_actions == ()
    assert decision.supersedes is None
    _assert_sorted(decision)
    assert outcome.execution is None
    assert outcome.consumed == ()
    assert outcome.feedback == {
        "status": "blocked",
        "reason_code": code.value,
        "state_version": snapshot.state_version,
    }
    interpret(outcome.feedback)
    assert run.simulator.snapshot() == snapshot  # SIM-07: no device effect
    assert len(run.simulator.history) == history_len


# ------------------------------------------------------------- clamp (rule 7) repair


@pytest.mark.parametrize(
    ("proposed", "intent_range", "clamped"),
    [
        (35.0, (25.0, 35.0), 30.0),
        (35.0, (30.0, 35.0), 30.0),  # clamped value on the intent's inclusive lower edge
        (30.1, (28.0, 31.0), 30.0),
        (12.5, (10.0, 16.0), 16.0),  # clamped value on the intent's inclusive upper edge
        (15.9, (15.0, 17.0), 16.0),
    ],
)
def test_clamp_inside_the_task_intent_range_is_repaired_and_committed(
    proposed, intent_range, clamped
):
    run, executor, _ = _harness(SETPOINT_ONLY, intent_range=intent_range)
    before = _state(run)
    original = _setpoint(proposed)

    outcome = executor.submit(original)

    _assert_repaired(outcome, run, before, ReasonCode.REPAIRED_CLAMP, (_setpoint(clamped),))
    decision = outcome.decision
    assert decision.action == original  # the typed original is kept
    assert [(item.rule, item.code) for item in decision.findings] == [
        (RuleId.THERMOSTAT_BOUNDS, ReasonCode.SETPOINT_OUT_OF_BOUNDS)
    ]
    assert run.simulator.snapshot().home.thermostat.setpoint_c == clamped
    assert run.simulator.snapshot().state_version == before[0].state_version + 1


@pytest.mark.parametrize(("proposed", "clamped"), [(35.0, 28.0), (10.0, 18.0)])
def test_clamp_uses_the_policy_bounds(proposed, clamped):
    policy = _custom(thermostat_min_c=18.0, thermostat_max_c=28.0)
    run, executor, _ = _harness(SETPOINT_ONLY, intent_range=(10.0, 35.0), policy=policy)
    before = _state(run)

    outcome = executor.submit(_setpoint(proposed))

    _assert_repaired(outcome, run, before, ReasonCode.REPAIRED_CLAMP, (_setpoint(clamped),))
    assert run.simulator.snapshot().home.thermostat.setpoint_c == clamped


@pytest.mark.parametrize(
    ("proposed", "intent_range", "clamped"),
    [
        (35.0, (35.0, 35.0), 30.0),  # an exact 35 C request
        (35.0, (30.5, 40.0), 30.0),
        (10.0, (10.0, 15.5), 16.0),
    ],
)
def test_clamp_outside_the_task_intent_range_is_not_task_preserving(
    proposed, intent_range, clamped
):
    run, executor, _ = _harness(SETPOINT_ONLY, intent_range=intent_range)
    before = _state(run)

    outcome = executor.submit(_setpoint(proposed))

    _assert_blocked(outcome, run, before, ReasonCode.REPAIR_NOT_TASK_PRESERVING)
    decision = outcome.decision
    assert decision.repair_candidate == (_setpoint(clamped),)  # the candidate is recorded
    assert ReasonCode.SETPOINT_OUT_OF_BOUNDS in _codes(decision)  # original finding retained
    assert decision.escalation is False


def test_exact_35_c_request_is_never_satisfied_by_30_c():
    run, executor, _ = _harness(
        SETPOINT_ONLY,
        intent_range=(35.0, 35.0),
        request_text="Set the thermostat to exactly 35 C.",
    )
    before = _state(run)

    outcome = executor.submit(_setpoint(35.0))

    _assert_blocked(outcome, run, before, ReasonCode.REPAIR_NOT_TASK_PRESERVING)
    assert run.simulator.snapshot().home.thermostat.setpoint_c == 21.0
    record = executor.decisions[-1]
    assert record["verdict"] == "block"
    assert record["reason_code"] == "repair_not_task_preserving"
    assert record["executed_actions"] == []
    assert record["repair_candidate"] == [_setpoint(30.0).to_dict()]


@pytest.mark.parametrize("variant", ["no_intents", "intent_of_another_request", "no_range"])
def test_clamp_without_a_trusted_intent_is_not_task_preserving(variant):
    run = create_run()
    # The request text names a reachable target, but an intent is never parsed from text.
    request_id = _issue(run, SETPOINT_ONLY, "Set the thermostat to 30 C.")
    other = _issue(run, SETPOINT_ONLY)
    intents: Mapping[str, TaskIntent] | None = {
        "no_intents": None,
        "intent_of_another_request": {other: TaskIntent(other, (25.0, 35.0))},
        "no_range": {request_id: TaskIntent(request_id)},
    }[variant]
    executor = ProtectedExecutor.from_run(run, request_id=request_id, intents=intents)
    before = _state(run)

    outcome = executor.submit(_setpoint(35.0))

    _assert_blocked(outcome, run, before, ReasonCode.REPAIR_NOT_TASK_PRESERVING)
    assert outcome.decision.repair_candidate == (_setpoint(30.0),)


@pytest.mark.parametrize(
    "variant",
    ["intent-of-unknown-request", "intent-of-another-issued-request", "not-a-task-intent", "list"],
)
def test_intent_not_filed_under_its_own_request_is_rejected(variant):
    # Regression: intents were looked up by key only, so an intent issued for another
    # request enabled a clamp repair (35 C committed as 30 C) for this one.
    run = create_run()
    request_id = _issue(run, SETPOINT_ONLY)
    other = _issue(run, SETPOINT_ONLY)
    intents = {
        "intent-of-unknown-request": {request_id: TaskIntent("req-9999", (25.0, 30.0))},
        "intent-of-another-issued-request": {request_id: TaskIntent(other, (25.0, 30.0))},
        "not-a-task-intent": {request_id: (25.0, 30.0)},
        "list": [TaskIntent(request_id, (25.0, 30.0))],
    }[variant]
    before = _state(run)

    with pytest.raises(ValueError, match="intent"):
        ProtectedExecutor.from_run(run, request_id=request_id, intents=intents)

    assert _state(run) == before


def test_intent_mutated_to_another_request_fails_closed_at_decision_time():
    run = create_run()
    request_id = _issue(run, SETPOINT_ONLY)
    intent = TaskIntent(request_id, (25.0, 30.0))
    executor = ProtectedExecutor.from_run(run, request_id=request_id, intents={request_id: intent})
    object.__setattr__(intent, "request_id", "req-9999")  # trusted context corrupted later
    before = _state(run)

    outcome = executor.submit(_setpoint(35.0))

    decision = outcome.decision
    assert decision.verdict is Verdict.ERROR
    assert decision.reason_code is ReasonCode.TRUSTED_CONTEXT_MALFORMED
    assert decision.executed_actions == ()
    assert decision.escalation is True
    assert outcome.execution is None
    assert outcome.feedback == {"status": "escalated", "reason_code": "trusted_context_malformed"}
    assert _state(run) == before


def test_clamp_candidate_keeps_the_original_evidence_refs():
    run, executor, _ = _harness(SETPOINT_ONLY, intent_range=(25.0, 35.0))
    reading = _read(run, executor, DeviceId.THERMOSTAT)
    before = _state(run)

    outcome = executor.submit(_setpoint(35.0, reading))

    candidate = (_setpoint(30.0, reading),)
    _assert_repaired(outcome, run, before, ReasonCode.REPAIRED_CLAMP, candidate)
    assert outcome.decision.executed_actions[0].evidence_refs == (reading,)


@pytest.mark.parametrize(
    ("current", "proposed", "intent_range"),
    [(30.0, 35.0, (25.0, 35.0)), (16.0, 10.0, (14.0, 20.0))],
)
def test_clamp_to_the_current_setpoint_is_a_no_op(current, proposed, intent_range):
    home = HomeState(thermostat=ThermostatState(setpoint_c=current))
    run, executor, _ = _harness(SETPOINT_ONLY, home, intent_range=intent_range)
    before = _state(run)

    outcome = executor.submit(_setpoint(proposed))

    _assert_blocked(outcome, run, before, ReasonCode.REPAIR_NO_EFFECT)
    assert ReasonCode.SETPOINT_OUT_OF_BOUNDS in _codes(outcome.decision)
    assert outcome.decision.escalation is False


@pytest.mark.parametrize(
    ("case", "primary", "escalation"),
    [
        ("setpoint_not_permitted", ReasonCode.OPERATION_NOT_AUTHORIZED, True),
        ("invented_reference", ReasonCode.EVIDENCE_UNKNOWN_ORIGIN, False),
    ],
)
def test_clamp_is_not_attempted_beside_a_non_repairable_finding(case, primary, escalation):
    permissions = (
        (Permission(DeviceId.THERMOSTAT, Operation.TURN_ON),)
        if case == "setpoint_not_permitted"
        else SETPOINT_ONLY
    )
    run, executor, _ = _harness(permissions, intent_range=(25.0, 35.0))
    refs = ("obs-000099",) if case == "invented_reference" else ()
    before = _state(run)

    outcome = executor.submit(_setpoint(35.0, *refs))

    _assert_blocked(outcome, run, before, primary)
    decision = outcome.decision
    assert decision.repair_candidate is None  # a repair cannot invent permission or evidence
    assert {primary, ReasonCode.SETPOINT_OUT_OF_BOUNDS} <= set(_codes(decision))
    assert decision.escalation is escalation


def test_conflicting_request_escalates_without_repair():
    run = create_run()
    bound = _issue(run, SETPOINT_ONLY)
    other = _issue(run, SETPOINT_ONLY)
    intents = {rid: TaskIntent(rid, (25.0, 35.0)) for rid in (bound, other)}
    executor = ProtectedExecutor.from_run(run, request_id=bound, intents=intents)
    before = _state(run)

    outcome = executor.submit(_setpoint(35.0), request_id=other)

    decision = outcome.decision
    assert decision.verdict is Verdict.ESCALATE
    assert decision.reason_code is ReasonCode.IDENTITY_INVALID
    assert decision.executed_actions == ()
    assert decision.repair_candidate is None
    assert decision.escalation is True
    assert outcome.feedback == {"status": "escalated", "reason_code": "identity_invalid"}
    interpret(outcome.feedback)
    assert _state(run) == before


# ------------------------------------------------------ prerequisite (rule 8) repair


@pytest.mark.parametrize("cite", [False, True], ids=["latest-presence", "cited-presence"])
def test_unlock_open_repair_from_locked_closed_commits_atomically(cite):
    run, executor, request_id = _harness(UNLOCK_OPEN, AT_LOCKED_DOOR)
    presence = _read(run, executor)
    before = _state(run)
    original = _door(Operation.OPEN, *([presence] if cite else []))

    outcome = executor.submit(original)

    decision = outcome.decision
    assert _operations(decision.executed_actions) == [
        (DeviceId.DOOR, Operation.UNLOCK),
        (DeviceId.DOOR, Operation.OPEN),
    ]
    assert decision.executed_actions[1] == original
    if not cite:
        assert decision.executed_actions == (_door(Operation.UNLOCK), original)
    _assert_repaired(
        outcome, run, before, ReasonCode.REPAIRED_PREREQUISITE, decision.executed_actions
    )
    assert decision.action == original
    [precondition] = decision.findings
    assert (precondition.rule, precondition.code) == (
        RuleId.SEQUENCE,
        ReasonCode.PRECONDITION_UNMET,
    )
    assert "unlock" in precondition.detail  # the detail names the prerequisite
    assert decision.evidence_ids == (presence,)  # covers both access steps

    after = run.simulator.snapshot()
    assert after.home.door == OPEN_UNLOCKED
    assert after.state_version == before[0].state_version + 2  # both steps, one transaction
    assert len(_action_entries(run)) == 2
    # Both access operations are recorded for this request at commit (Proposed D07).
    assert outcome.consumed == (presence,)
    assert executor.ledger.consumption(presence) == (
        request_id,
        frozenset({Operation.UNLOCK, Operation.OPEN}),
    )
    record = executor.decisions[-1]
    assert record["verdict"] == "repair"
    assert record["reason_code"] == "repaired_prerequisite"
    assert record["repair_candidate"] == [action.to_dict() for action in decision.executed_actions]


def test_repaired_access_episode_consumes_both_operations():
    run, executor, _ = _harness(UNLOCK_OPEN, AT_LOCKED_DOOR)
    presence = _read(run, executor)
    assert executor.submit(_door(Operation.OPEN)).decision.verdict is Verdict.REPAIR

    # Unlocking or opening the open, unlocked door is a no-op that still needs presence.
    for operation in (Operation.UNLOCK, Operation.OPEN):
        before = _state(run)
        outcome = executor.submit(_door(operation, presence))
        _assert_blocked(outcome, run, before, ReasonCode.PRESENCE_EVIDENCE_CONSUMED)


def test_close_then_lock_repair_needs_no_presence():
    run, executor, _ = _harness(CLOSE_LOCK, HomeState(door=OPEN_UNLOCKED))
    before = _state(run)
    original = _door(Operation.LOCK)

    outcome = executor.submit(original)

    candidate = (_door(Operation.CLOSE), original)
    _assert_repaired(outcome, run, before, ReasonCode.REPAIRED_PREREQUISITE, candidate)
    [precondition] = outcome.decision.findings
    assert precondition.code is ReasonCode.PRECONDITION_UNMET
    assert "close" in precondition.detail
    assert run.simulator.snapshot().home.door == LOCKED_CLOSED
    assert outcome.consumed == ()  # egress operations consume nothing


@pytest.mark.parametrize(
    ("permissions", "home", "operation"),
    [
        ((Permission(DeviceId.DOOR, Operation.OPEN),), AT_LOCKED_DOOR, Operation.OPEN),
        (
            (Permission(DeviceId.DOOR, Operation.LOCK),),
            HomeState(door=OPEN_UNLOCKED),
            Operation.LOCK,
        ),
    ],
    ids=["open-without-unlock", "lock-without-close"],
)
def test_prerequisite_the_request_does_not_permit_is_unavailable(permissions, home, operation):
    run, executor, _ = _harness(permissions, home)
    presence = _read(run, executor)
    before = _state(run)

    outcome = executor.submit(_door(operation))

    _assert_blocked(outcome, run, before, ReasonCode.REPAIR_UNAVAILABLE)
    assert ReasonCode.PRECONDITION_UNMET in _codes(outcome.decision)
    assert outcome.decision.escalation is False
    assert executor.ledger.consumption(presence) == (None, frozenset())


# Proposed D05/D08 ablation boundary: the prerequisite permission belongs to the repair
# template, not to rule 3, so no_provenance does not lift it (the fail-closed reading).
@pytest.mark.parametrize(
    "permitted",
    [Operation.OPEN, Operation.LOCK],
    ids=["only-open-permitted", "only-lock-permitted"],
)
def test_no_provenance_keeps_the_repair_templates_prerequisite_permission(permitted):
    policy = policy_for(Ablation.NO_PROVENANCE)
    run, executor, _ = _harness(
        (Permission(DeviceId.DOOR, permitted),), AT_LOCKED_DOOR, policy=policy
    )
    presence = _read(run, executor)
    before = _state(run)

    outcome = executor.submit(_door(Operation.OPEN))

    _assert_blocked(outcome, run, before, ReasonCode.REPAIR_UNAVAILABLE)
    decision = outcome.decision
    assert [(item.rule, item.code, item.detail) for item in decision.findings] == [
        (RuleId.SEQUENCE, ReasonCode.PRECONDITION_UNMET, "door.unlock")
    ]
    assert decision.repair_candidate == (_door(Operation.UNLOCK), _door(Operation.OPEN))
    assert decision.rules_evaluated == (1, 2, 4, 5, 6, 7, 8)
    assert run.simulator.snapshot().home.door == LOCKED_CLOSED
    assert executor.ledger.consumption(presence) == (None, frozenset())

    # Rule 3 itself is off: the agent's own unlock needs no operation permission.
    unlock = executor.submit(_door(Operation.UNLOCK))
    assert unlock.decision.verdict is Verdict.ALLOW
    assert run.simulator.snapshot().home.door.lock is LockState.UNLOCKED


def test_no_provenance_repairs_with_a_permitted_prerequisite_only():
    # Rule 3 is off for the original action (door.open is not permitted), but the
    # mediator-added prerequisite (door.unlock) is, so the repair commits.
    permissions = (Permission(DeviceId.DOOR, Operation.UNLOCK),)
    full_run, full, _ = _harness(permissions, AT_LOCKED_DOOR)
    _read(full_run, full)
    full_before = _state(full_run)
    _assert_blocked(
        full.submit(_door(Operation.OPEN)),
        full_run,
        full_before,
        ReasonCode.OPERATION_NOT_AUTHORIZED,
    )

    policy = policy_for(Ablation.NO_PROVENANCE)
    run, executor, _ = _harness(permissions, AT_LOCKED_DOOR, policy=policy)
    _read(run, executor)
    before = _state(run)

    outcome = executor.submit(_door(Operation.OPEN))

    candidate = (_door(Operation.UNLOCK), _door(Operation.OPEN))
    _assert_repaired(outcome, run, before, ReasonCode.REPAIRED_PREREQUISITE, candidate)
    assert run.simulator.snapshot().home.door == OPEN_UNLOCKED


@pytest.mark.parametrize(
    ("case", "primary", "escalation"),
    [
        ("presence_missing", ReasonCode.PRESENCE_EVIDENCE_MISSING, False),
        ("presence_false", ReasonCode.PRESENCE_NOT_CONFIRMED, False),
        ("open_not_permitted", ReasonCode.OPERATION_NOT_AUTHORIZED, True),
    ],
)
def test_prerequisite_repair_cannot_invent_presence_or_permission(case, primary, escalation):
    permissions = (
        (Permission(DeviceId.DOOR, Operation.UNLOCK),)
        if case == "open_not_permitted"
        else UNLOCK_OPEN
    )
    home = HomeState(door=LOCKED_CLOSED, presence_sensor=PresenceState(case != "presence_false"))
    run, executor, _ = _harness(permissions, home)
    if case != "presence_missing":
        _read(run, executor)
    before = _state(run)

    outcome = executor.submit(_door(Operation.OPEN))

    _assert_blocked(outcome, run, before, primary)
    decision = outcome.decision
    assert decision.repair_candidate is None  # a non-repairable finding means no repair
    assert {primary, ReasonCode.PRECONDITION_UNMET} <= set(_codes(decision))
    assert decision.escalation is escalation
    assert run.simulator.snapshot().home.door == LOCKED_CLOSED


# ------------------------------------------------------- revalidation (MED-11) of steps


def _consume_a_reading_for_unlock_then_relock(
    policy: MediatorPolicy | None = None,
) -> tuple[RunEnvironment, ProtectedExecutor, str, str]:
    run, executor, request_id = _harness(DOOR_ALL, AT_LOCKED_DOOR, policy=policy)
    first = _read(run, executor)
    assert executor.submit(_door(Operation.UNLOCK)).decision.verdict is Verdict.ALLOW
    assert executor.submit(_door(Operation.LOCK)).decision.verdict is Verdict.ALLOW
    assert run.simulator.snapshot().home.door == LOCKED_CLOSED
    return run, executor, request_id, first


def test_revalidation_runs_only_the_enabled_rules():
    # Without rule 5 the consumed reading is admissible again, so the same repair commits:
    # this is exactly what the no_freshness_replay ablation removes.
    policy = policy_for(Ablation.NO_FRESHNESS_REPLAY)
    run, executor, _, _ = _consume_a_reading_for_unlock_then_relock(policy)
    before = _state(run)

    outcome = executor.submit(_door(Operation.OPEN))

    executed = outcome.decision.executed_actions
    _assert_repaired(outcome, run, before, ReasonCode.REPAIRED_PREREQUISITE, executed)
    assert [action.operation for action in executed] == [Operation.UNLOCK, Operation.OPEN]
    assert run.simulator.snapshot().home.door == OPEN_UNLOCKED


def test_prerequisite_step_is_revalidated_and_cannot_reuse_consumed_presence():
    run, executor, request_id, first = _consume_a_reading_for_unlock_then_relock()
    assert executor.ledger.consumption(first) == (request_id, frozenset({Operation.UNLOCK}))
    before = _state(run)

    # door.open alone may still use the reading, but its unlock prerequisite may not.
    outcome = executor.submit(_door(Operation.OPEN))

    _assert_blocked(outcome, run, before, ReasonCode.REPAIR_FAILED_REVALIDATION)
    decision = outcome.decision
    assert ReasonCode.PRECONDITION_UNMET in _codes(decision)  # original finding retained
    consumed = [f for f in decision.findings if f.code is ReasonCode.PRESENCE_EVIDENCE_CONSUMED]
    assert len(consumed) == 1
    assert re.search(r"\b0\b", consumed[0].detail), consumed[0]  # step index of the unlock
    assert decision.escalation is False
    assert executor.ledger.consumption(first) == (request_id, frozenset({Operation.UNLOCK}))

    # A legitimate fresh re-read is admissible, so the same repair now succeeds.
    fresh = _read(run, executor)
    before = _state(run)
    outcome = executor.submit(_door(Operation.OPEN))
    executed = outcome.decision.executed_actions
    _assert_repaired(outcome, run, before, ReasonCode.REPAIRED_PREREQUISITE, executed)
    assert [action.operation for action in executed] == [Operation.UNLOCK, Operation.OPEN]
    assert outcome.decision.evidence_ids == (fresh,)
    assert executor.ledger.consumption(fresh) == (
        request_id,
        frozenset({Operation.UNLOCK, Operation.OPEN}),
    )


def _refuse_opening_an_unlocked_door(
    ctx: RuleContext, action: ActionProposal, home: HomeState
) -> list[RuleFinding]:
    """Custom rule 6 that fails only in the state the unlock step predicts."""
    found = list(check_door_access(ctx, action, home))
    if (
        action.device is DeviceId.DOOR
        and action.operation is Operation.OPEN
        and home.door.lock is LockState.UNLOCKED
    ):
        found.append(RuleFinding(RuleId.DOOR_ACCESS, ReasonCode.PRESENCE_NOT_CONFIRMED, "custom"))
    return found


def test_failing_later_step_leaves_no_partial_effect():
    table = _with_rule(RuleId.DOOR_ACCESS, _refuse_opening_an_unlocked_door)
    run, executor, _ = _harness(UNLOCK_OPEN, AT_LOCKED_DOOR, rule_table=table)
    presence = _read(run, executor)
    before = _state(run)

    outcome = executor.submit(_door(Operation.OPEN))

    _assert_blocked(outcome, run, before, ReasonCode.REPAIR_FAILED_REVALIDATION)
    decision = outcome.decision
    late = [f for f in decision.findings if f.code is ReasonCode.PRESENCE_NOT_CONFIRMED]
    assert len(late) == 1
    assert re.search(r"\b1\b", late[0].detail), late[0]  # step index of the open
    # The unlock step would pass on its own, yet nothing of the candidate ran.
    assert run.simulator.snapshot().home.door == LOCKED_CLOSED
    assert _action_entries(run) == []
    assert executor.ledger.consumption(presence) == (None, frozenset())
    assert executor.submit(_door(Operation.UNLOCK)).decision.verdict is Verdict.ALLOW


def _names_lock_as_the_prerequisite(
    ctx: RuleContext, action: ActionProposal, home: HomeState
) -> list[RuleFinding]:
    """Custom rule 8 naming a physically wrong prerequisite for opening a locked door."""
    return [
        replace(item, detail="door.lock") if item.code is ReasonCode.PRECONDITION_UNMET else item
        for item in check_sequence(ctx, action, home)
    ]


def test_physically_invalid_candidate_fails_revalidation():
    table = _with_rule(RuleId.SEQUENCE, _names_lock_as_the_prerequisite)
    run, executor, _ = _harness(DOOR_ALL, AT_LOCKED_DOOR, rule_table=table)
    presence = _read(run, executor)
    before = _state(run)

    # (lock, open) from closed+locked: opening a locked door is an invalid transition.
    outcome = executor.submit(_door(Operation.OPEN))

    _assert_blocked(outcome, run, before, ReasonCode.REPAIR_FAILED_REVALIDATION)
    assert ReasonCode.PRECONDITION_UNMET in _codes(outcome.decision)
    assert run.simulator.snapshot().home.door == LOCKED_CLOSED
    assert executor.ledger.consumption(presence) == (None, frozenset())


# ------------------------------------------------- uniqueness, bound and no-effect checks


def _open_also_needs_close(
    ctx: RuleContext, action: ActionProposal, home: HomeState
) -> list[RuleFinding]:
    found = list(check_sequence(ctx, action, home))
    if (
        action.device is DeviceId.DOOR
        and action.operation is Operation.OPEN
        and home.door.lock is LockState.LOCKED
    ):
        found.append(
            RuleFinding(
                RuleId.SEQUENCE, ReasonCode.PRECONDITION_UNMET, "door.close", repairable=True
            )
        )
    return found


def _setpoint_needs_power(
    ctx: RuleContext, action: ActionProposal, home: HomeState
) -> list[RuleFinding]:
    found = list(check_sequence(ctx, action, home))
    if (
        action.device is DeviceId.THERMOSTAT
        and action.operation is Operation.SET_SETPOINT
        and home.thermostat.power is Power.OFF
    ):
        found.append(
            RuleFinding(
                RuleId.SEQUENCE,
                ReasonCode.PRECONDITION_UNMET,
                "thermostat.turn_on",
                repairable=True,
            )
        )
    return found


def test_two_distinct_prerequisite_candidates_are_ambiguous():
    table = _with_rule(RuleId.SEQUENCE, _open_also_needs_close)
    run, executor, _ = _harness(DOOR_ALL, AT_LOCKED_DOOR, rule_table=table)
    presence = _read(run, executor)
    before = _state(run)

    # (unlock, open) and (close, open) are both candidates; the mediator must not choose.
    outcome = executor.submit(_door(Operation.OPEN))

    _assert_blocked(outcome, run, before, ReasonCode.REPAIR_AMBIGUOUS)
    assert _codes(outcome.decision).count(ReasonCode.PRECONDITION_UNMET) == 2
    assert outcome.decision.escalation is False
    assert executor.ledger.consumption(presence) == (None, frozenset())


def test_clamp_and_prerequisite_candidates_together_are_ambiguous():
    table = _with_rule(RuleId.SEQUENCE, _setpoint_needs_power)
    permissions = SETPOINT_ONLY + (Permission(DeviceId.THERMOSTAT, Operation.TURN_ON),)
    run, executor, _ = _harness(permissions, intent_range=(25.0, 35.0), rule_table=table)
    before = _state(run)

    # (set_setpoint 30,) and (turn_on, set_setpoint 35) are distinct candidates.
    outcome = executor.submit(_setpoint(35.0))

    _assert_blocked(outcome, run, before, ReasonCode.REPAIR_AMBIGUOUS)
    codes = _codes(outcome.decision)
    assert {ReasonCode.SETPOINT_OUT_OF_BOUNDS, ReasonCode.PRECONDITION_UNMET} <= set(codes)


def _repeat_sequence_findings(
    ctx: RuleContext, action: ActionProposal, home: HomeState
) -> list[RuleFinding]:
    found = list(check_sequence(ctx, action, home))
    return [*found, *found]


def test_identical_candidates_from_repeated_findings_are_not_ambiguous():
    table = _with_rule(RuleId.SEQUENCE, _repeat_sequence_findings)
    run, executor, _ = _harness(UNLOCK_OPEN, AT_LOCKED_DOOR, rule_table=table)
    _read(run, executor)
    before = _state(run)
    original = _door(Operation.OPEN)

    outcome = executor.submit(original)

    candidate = (_door(Operation.UNLOCK), original)
    _assert_repaired(outcome, run, before, ReasonCode.REPAIRED_PREREQUISITE, candidate)
    assert run.simulator.snapshot().home.door == OPEN_UNLOCKED


@pytest.mark.parametrize(
    ("permissions", "home", "operation"),
    [
        (UNLOCK_OPEN, AT_LOCKED_DOOR, Operation.OPEN),
        (CLOSE_LOCK, HomeState(door=OPEN_UNLOCKED), Operation.LOCK),
    ],
    ids=["unlock-open", "close-lock"],
)
def test_custom_repair_bound_of_one_rejects_two_step_repairs(permissions, home, operation):
    run, executor, _ = _harness(permissions, home, policy=_custom(max_repair_actions=1))
    presence = _read(run, executor)
    before = _state(run)

    outcome = executor.submit(_door(operation))

    _assert_blocked(outcome, run, before, ReasonCode.REPAIR_TOO_LONG)
    assert ReasonCode.PRECONDITION_UNMET in _codes(outcome.decision)
    assert outcome.decision.escalation is False
    assert executor.ledger.consumption(presence) == (None, frozenset())


def test_repair_bound_is_validated():
    assert policy_for(Ablation.FULL).max_repair_actions == 2  # Proposed D08 default
    for bound in (0, MAX_TRANSACTION_ACTIONS + 1):
        with pytest.raises(PolicyError):
            _custom(max_repair_actions=bound)
    assert _custom(max_repair_actions=MAX_TRANSACTION_ACTIONS).max_repair_actions == (
        MAX_TRANSACTION_ACTIONS
    )
    with pytest.raises(PolicyError):  # a preset cannot change its frozen repair bound
        MediatorPolicy(ablation=Ablation.FULL, max_repair_actions=1)


def test_custom_repair_bound_of_one_still_admits_a_one_step_clamp():
    policy = _custom(max_repair_actions=1)
    run, executor, _ = _harness(SETPOINT_ONLY, intent_range=(25.0, 35.0), policy=policy)
    before = _state(run)

    outcome = executor.submit(_setpoint(35.0))

    _assert_repaired(outcome, run, before, ReasonCode.REPAIRED_CLAMP, (_setpoint(30.0),))


# ------------------------------------------------ decision purity and atomic execution


def test_a_repair_decision_alone_changes_nothing():
    run, executor, request_id = _harness(UNLOCK_OPEN, AT_LOCKED_DOOR)
    presence = _read(run, executor)
    before = _state(run)

    first = executor.mediator.decide(_door(Operation.OPEN), request_id=request_id)
    second = executor.mediator.decide(_door(Operation.OPEN), request_id=request_id)

    assert first.verdict is Verdict.REPAIR
    assert first.reason_code is ReasonCode.REPAIRED_PREREQUISITE
    assert first.to_dict() == second.to_dict()  # MED-01: same inputs, same candidate
    assert _state(run) == before  # the mediator decides; only the executor executes
    assert executor.ledger.consumption(presence) == (None, frozenset())  # only commits consume


def test_state_change_after_a_repair_decision_executes_no_step():
    run = create_run(AT_LOCKED_DOOR)
    request_id = _issue(run, UNLOCK_OPEN)
    disturbed: list[bool] = []

    def sequence_then_disturb(
        ctx: RuleContext, action: ActionProposal, home: HomeState
    ) -> list[RuleFinding]:
        # The harness changes the world once, after the decision's snapshot was taken.
        if not disturbed:
            disturbed.append(True)
            run.simulator.apply_environment(
                SetAmbientTemperature(25.0), capability=run.environment_capability
            )
        return check_sequence(ctx, action, home)

    table = _with_rule(RuleId.SEQUENCE, sequence_then_disturb)
    executor = ProtectedExecutor.from_run(run, request_id=request_id, rule_table=table)
    presence = _read(run, executor)

    outcome = executor.submit(_door(Operation.OPEN))

    decision = outcome.decision
    assert decision.verdict is Verdict.BLOCK
    assert decision.reason_code is ReasonCode.STALE_DECISION
    assert decision.supersedes is not None
    assert dict(decision.supersedes) == {
        "verdict": "repair",
        "reason_code": "repaired_prerequisite",
    }
    assert decision.executed_actions == ()
    assert outcome.feedback["status"] == "blocked"
    assert outcome.feedback["reason_code"] == "stale_decision"
    interpret(outcome.feedback)
    snapshot = run.simulator.snapshot()
    assert snapshot.home.door == LOCKED_CLOSED  # neither the unlock nor the open ran
    assert snapshot.home.thermostat.ambient_c == 25.0
    assert _action_entries(run) == []
    assert outcome.consumed == ()
    assert executor.ledger.consumption(presence) == (None, frozenset())


def _repair_session() -> tuple[dict[str, object], ...]:
    run, executor, _ = _harness(
        UNLOCK_OPEN + SETPOINT_ONLY, AT_LOCKED_DOOR, intent_range=(25.0, 35.0)
    )
    _read(run, executor)
    for proposal in (_setpoint(35.0), _setpoint(10.0), _door(Operation.OPEN)):
        executor.submit(proposal)
    return executor.decisions


def test_repair_records_are_deterministic_across_runs():
    first, second = _repair_session(), _repair_session()

    assert first == second
    assert [record["reason_code"] for record in first] == [
        "repaired_clamp",
        "repair_not_task_preserving",
        "repaired_prerequisite",
    ]
