"""Pure rule functions for contract rules 2-8 (MED-03 to MED-09).

Each rule reads trusted context only: the harness-issued request, ledger
deliveries resolved to the gateway's canonical facts, and device state from the
``home`` argument. Rules never read payload text or payload values, and never
read the simulator directly: repair revalidation passes predicted states as
``home``. Rule 1 (the typed action boundary) runs before these in the mediator.

Every rule returns all of its failed checks; aggregation and precedence live in
:mod:`effectshield.mediator.decision`, so evaluation order cannot change a
result (MED-13).

Semantic drafts settled here:

- Proposed D04: ``door.unlock`` and ``door.open`` are access (entry)
  operations; ``door.lock`` and ``door.close`` are egress operations needing no
  presence. ``door.open`` requires an unlocked door, ``door.lock`` a closed one.
  A satisfied operation (unlocking an unlocked door) is a no-op that still needs
  presence. ``turn_on`` with a current setpoint outside policy bounds is unsafe;
  ``set_setpoint`` within bounds and ``turn_off`` remain available as recovery.
- Proposed D05: authority comes only from the request's exact
  ``Permission(device, operation)``; "conflicting authority" is any request
  other than the run's harness-bound request. Cited references never grant
  authority; they must merely have been delivered by the gateway.
- Proposed D06: presence is the only required evidence, and only for door
  access. Its gateway time is compared with the trusted simulator time using an
  inclusive TTL; canonical facts that disagree with trusted current state are
  superseded.
- Proposed D07: replayed deliveries and consumed access evidence are refused
  (see :mod:`effectshield.mediator.evidence`).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from effectshield.domain.actions import ActionProposal
from effectshield.domain.context import HARNESS_ISSUER, RequestContext
from effectshield.domain.devices import DeviceId, DoorPosition, HomeState, LockState, Operation
from effectshield.gateway.observations import EvidenceRecord

from .decision import ReasonCode, RuleFinding, finding
from .evidence import DeliveryRecord, EvidenceLedger
from .policy import MediatorPolicy, RuleId

DOOR_ACCESS_OPERATIONS = frozenset({Operation.UNLOCK, Operation.OPEN})
# Declared door order (Proposed D04): operation -> the prerequisite it needs first.
_DOOR_PREREQUISITES = {
    Operation.OPEN: Operation.UNLOCK,
    Operation.LOCK: Operation.CLOSE,
}


def is_door_access(action: ActionProposal) -> bool:
    return action.device is DeviceId.DOOR and action.operation in DOOR_ACCESS_OPERATIONS


@dataclass(frozen=True, slots=True)
class RuleContext:
    """Trusted inputs shared by every rule for one decision (or one repair step)."""

    policy: MediatorPolicy
    request: RequestContext | None
    bound_request_id: str | None
    state_version: int
    time_ms: int
    ledger: EvidenceLedger
    cited: tuple[DeliveryRecord, ...]
    """Latest known-origin delivery of each cited reference, in citation order."""
    unknown_refs: tuple[str, ...]
    """Cited references with no known-origin delivery."""
    presence: tuple[DeliveryRecord, ...]
    """Required presence evidence: door access only, otherwise empty."""
    history_consistent: bool
    history_detail: str


RuleFn = Callable[[RuleContext, ActionProposal, HomeState], list[RuleFinding]]


def resolve_evidence(
    ledger: EvidenceLedger, action: ActionProposal
) -> tuple[tuple[DeliveryRecord, ...], tuple[str, ...], tuple[DeliveryRecord, ...]]:
    """Resolve cited references and select required presence evidence for one action.

    Returns ``(cited, unknown_refs, presence)``. Door access requires the cited
    known-origin presence deliveries if any, else the latest delivered presence
    observation (replays included; rules 4-5 judge it).
    """
    cited: list[DeliveryRecord] = []
    unknown: list[str] = []
    for ref in action.evidence_refs:
        known = ledger.known_deliveries(ref)
        if known:
            cited.append(known[-1])
        else:
            unknown.append(ref)
    presence: tuple[DeliveryRecord, ...] = ()
    if is_door_access(action):
        presence = tuple(d for d in cited if d.device is DeviceId.PRESENCE_SENSOR)
        if not presence:
            latest = ledger.latest_known_delivery(DeviceId.PRESENCE_SENSOR)
            presence = () if latest is None else (latest,)
    return tuple(cited), tuple(unknown), presence


def trusted_record(delivery: DeliveryRecord) -> EvidenceRecord:
    if delivery.record is None:
        raise ValueError(f"{delivery.observation_id} has no trusted registry record")
    return delivery.record


def identity_findings(
    request: RequestContext | None, bound_request_id: str | None
) -> list[RuleFinding]:
    """Rule 2 identity checks, shared by reads and effects."""
    rule = RuleId.DEVICE_AUTHORIZATION
    if request is None:
        return [finding(rule, ReasonCode.IDENTITY_MISSING, "request")]
    problems = []
    if request.issuer != HARNESS_ISSUER:
        problems.append("issuer")
    if not isinstance(request.principal_id, str) or not request.principal_id:
        problems.append("principal")
    if bound_request_id is not None and request.request_id != bound_request_id:
        problems.append("bound_request")
    return [finding(rule, ReasonCode.IDENTITY_INVALID, problem) for problem in problems]


def check_device_authorization(
    ctx: RuleContext, action: ActionProposal, home: HomeState
) -> list[RuleFinding]:
    """Rule 2 (MED-03): trusted identity and device-scoped permission.

    An escalation is recorded but never creates permission, so re-proposing the
    same action is blocked again.
    """
    findings = identity_findings(ctx.request, ctx.bound_request_id)
    if ctx.request is not None and not any(
        permission.device is action.device for permission in ctx.request.permissions
    ):
        findings.append(
            finding(
                RuleId.DEVICE_AUTHORIZATION,
                ReasonCode.DEVICE_OUT_OF_SCOPE,
                action.device.value,
            )
        )
    return findings


def check_instruction_provenance(
    ctx: RuleContext, action: ActionProposal, home: HomeState
) -> list[RuleFinding]:
    """Rule 3 (MED-04, OBS-03): the operation must be in the trusted request scope.

    Payload instructions are ignored structurally: nothing here reads a payload.
    Cited references must be gateway-delivered, but a valid reference still
    grants nothing. This is exactly what the ``no_provenance`` ablation removes.
    Without a resolved request there is no authority at all.
    """
    rule = RuleId.INSTRUCTION_PROVENANCE
    findings: list[RuleFinding] = []
    if ctx.request is None or not ctx.request.allows(action.device, action.operation):
        findings.append(
            finding(
                rule,
                ReasonCode.OPERATION_NOT_AUTHORIZED,
                f"{action.device.value}.{action.operation.value}",
            )
        )
    for ref in ctx.unknown_refs:
        findings.append(finding(rule, ReasonCode.EVIDENCE_UNKNOWN_ORIGIN, ref))
    return findings


def check_freshness(ctx: RuleContext, action: ActionProposal, home: HomeState) -> list[RuleFinding]:
    """Rule 4 (MED-05, OBS-05): required evidence is fresh and not contradicted.

    The gateway time comes from the original envelope, so a replay keeps its old
    timestamp. Canonical facts that differ from trusted current presence are
    superseded, which also catches a replay hiding a newer genuine reading.
    """
    rule = RuleId.FRESHNESS
    findings: list[RuleFinding] = []
    current = home.presence_sensor.to_dict()
    for delivery in ctx.presence:
        record = trusted_record(delivery)
        issued_at = record.envelope.gateway_time_ms
        oid = delivery.observation_id
        if issued_at > ctx.time_ms:
            findings.append(finding(rule, ReasonCode.PRESENCE_EVIDENCE_FUTURE_TIME, oid))
        elif ctx.time_ms - issued_at > ctx.policy.sensor_ttl_ms:
            findings.append(finding(rule, ReasonCode.PRESENCE_EVIDENCE_EXPIRED, oid))
        if dict(record.canonical_facts) != current:
            findings.append(finding(rule, ReasonCode.PRESENCE_EVIDENCE_SUPERSEDED, oid))
    return findings


def check_replay(ctx: RuleContext, action: ActionProposal, home: HomeState) -> list[RuleFinding]:
    """Rule 5 (MED-06, OBS-06): required evidence is neither replayed nor consumed."""
    rule = RuleId.REPLAY
    findings: list[RuleFinding] = []
    request_id = None if ctx.request is None else ctx.request.request_id
    for delivery in ctx.presence:
        oid = delivery.observation_id
        if ctx.ledger.is_replayed(oid):
            findings.append(finding(rule, ReasonCode.PRESENCE_EVIDENCE_REPLAYED, oid))
        owner, used = ctx.ledger.consumption(oid)
        if owner is not None and (owner != request_id or action.operation in used):
            findings.append(finding(rule, ReasonCode.PRESENCE_EVIDENCE_CONSUMED, oid))
    return findings


def check_door_access(
    ctx: RuleContext, action: ActionProposal, home: HomeState
) -> list[RuleFinding]:
    """Rule 6 (MED-07): door access needs canonical, confirmed presence.

    Identity is rule 2's and operation authority rule 3's; compatible door
    state is rule 8's. Only canonical facts count, never the payload.
    """
    if not is_door_access(action):
        return []
    rule = RuleId.DOOR_ACCESS
    if not ctx.presence:
        return [finding(rule, ReasonCode.PRESENCE_EVIDENCE_MISSING, DeviceId.PRESENCE_SENSOR.value)]
    return [
        finding(rule, ReasonCode.PRESENCE_NOT_CONFIRMED, delivery.observation_id)
        for delivery in ctx.presence
        if trusted_record(delivery).canonical_facts.get("present") is not True
    ]


def check_thermostat_bounds(
    ctx: RuleContext, action: ActionProposal, home: HomeState
) -> list[RuleFinding]:
    """Rule 7 (MED-08): inclusive setpoint bounds and a safe current setpoint."""
    if action.device is not DeviceId.THERMOSTAT:
        return []
    rule = RuleId.THERMOSTAT_BOUNDS
    low, high = ctx.policy.thermostat_min_c, ctx.policy.thermostat_max_c
    if action.operation is Operation.SET_SETPOINT:
        value = action.parameters["setpoint_c"]
        if not low <= value <= high:
            return [finding(rule, ReasonCode.SETPOINT_OUT_OF_BOUNDS, f"setpoint_c={value!r}")]
    elif action.operation is Operation.TURN_ON:
        current = home.thermostat.setpoint_c
        if not low <= current <= high:
            return [
                finding(
                    rule,
                    ReasonCode.THERMOSTAT_UNSAFE_CURRENT_SETPOINT,
                    f"setpoint_c={current!r}",
                )
            ]
    return []


def check_sequence(ctx: RuleContext, action: ActionProposal, home: HomeState) -> list[RuleFinding]:
    """Rule 8 (MED-09): declared door order and executed history consistent with state."""
    rule = RuleId.SEQUENCE
    findings: list[RuleFinding] = []
    if action.device is DeviceId.DOOR and action.operation in _DOOR_PREREQUISITES:
        satisfied = (
            home.door.lock is LockState.UNLOCKED
            if action.operation is Operation.OPEN
            else home.door.position is DoorPosition.CLOSED
        )
        if not satisfied:
            prerequisite = _DOOR_PREREQUISITES[action.operation]
            findings.append(
                finding(
                    rule,
                    ReasonCode.PRECONDITION_UNMET,
                    f"{DeviceId.DOOR.value}.{prerequisite.value}",
                )
            )
    if not ctx.history_consistent:
        findings.append(finding(rule, ReasonCode.HISTORY_INCONSISTENT, ctx.history_detail))
    return findings


RULE_TABLE: tuple[tuple[RuleId, RuleFn], ...] = (
    (RuleId.DEVICE_AUTHORIZATION, check_device_authorization),
    (RuleId.INSTRUCTION_PROVENANCE, check_instruction_provenance),
    (RuleId.FRESHNESS, check_freshness),
    (RuleId.REPLAY, check_replay),
    (RuleId.DOOR_ACCESS, check_door_access),
    (RuleId.THERMOSTAT_BOUNDS, check_thermostat_bounds),
    (RuleId.SEQUENCE, check_sequence),
)
