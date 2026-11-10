"""The simulator: exclusive owner of device state and simulated time (SIM-02).

Mutation paths are guarded by capability objects created once per simulator:

- :class:`ExecutionCapability` executes agent-proposed effects. In the
  protected condition only the mediator's executor holds it (SIM-07); in the
  unprotected baseline the harness's direct executor holds it.
- :class:`EnvironmentCapability` lets the scenario harness advance the clock
  and apply trusted environment events.

The agent adapter receives neither. Python cannot enforce this against code in
the same process; the boundary is enforced by construction and checked by the
security tests.

Execution is a serialized, all-or-nothing transaction bound to the state
version the caller checked (SIM-09). If the state changed since, nothing
executes.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from effectshield.domain.actions import ActionProposal
from effectshield.domain.devices import HomeSnapshot, HomeState
from effectshield.domain.errors import (
    CapabilityError,
    ExecutionRejectionCode,
    InvalidTransitionError,
)
from effectshield.domain.events import EnvironmentEvent, SetAmbientTemperature, SetPresence
from effectshield.simulator.transitions import apply_environment_event, apply_sequence

# Upper bound on actions in one transaction. D08 will fix the repair bound;
# this is only the simulator's structural limit.
MAX_TRANSACTION_ACTIONS = 8


class ExecutionCapability:
    """Opaque token authorizing effect execution on one simulator."""

    __slots__ = ()


class EnvironmentCapability:
    """Opaque token authorizing clock advances and environment events."""

    __slots__ = ()


class TraceKind(StrEnum):
    ACTION = "action"
    ENVIRONMENT = "environment"
    CLOCK = "clock"


@dataclass(frozen=True, slots=True)
class TraceEntry:
    """One committed simulator change with before/after snapshots."""

    sequence_no: int
    kind: TraceKind
    before: HomeSnapshot
    after: HomeSnapshot
    transaction_id: int | None = None
    action: ActionProposal | None = None
    event: EnvironmentEvent | None = None

    @property
    def changed(self) -> bool:
        return self.before.home != self.after.home

    def to_dict(self) -> dict[str, Any]:
        return {
            "sequence_no": self.sequence_no,
            "kind": self.kind.value,
            "transaction_id": self.transaction_id,
            "action": self.action.to_dict() if self.action else None,
            "event": self.event.to_dict() if self.event else None,
            "changed": self.changed,
            "before": self.before.to_dict(),
            "after": self.after.to_dict(),
        }


class ExecutionStatus(StrEnum):
    COMMITTED = "committed"
    REJECTED = "rejected"


@dataclass(frozen=True, slots=True)
class ExecutionResult:
    """Outcome of one transaction. A rejected transaction changed nothing."""

    transaction_id: int
    status: ExecutionStatus
    version_before: int
    version_after: int
    entries: tuple[TraceEntry, ...] = ()
    reason_code: str | None = None
    failed_index: int | None = None
    detail: str | None = None

    @property
    def committed(self) -> bool:
        return self.status is ExecutionStatus.COMMITTED

    def to_dict(self) -> dict[str, Any]:
        return {
            "transaction_id": self.transaction_id,
            "status": self.status.value,
            "version_before": self.version_before,
            "version_after": self.version_after,
            "reason_code": self.reason_code,
            "failed_index": self.failed_index,
            "detail": self.detail,
            "entries": [entry.to_dict() for entry in self.entries],
        }


class Simulator:
    """Deterministic five-device smart-home simulator for one run."""

    def __init__(self, initial_home: HomeState, *, start_time_ms: int = 0) -> None:
        if not isinstance(initial_home, HomeState):
            raise TypeError("initial_home must be a HomeState")
        if type(start_time_ms) is not int or start_time_ms < 0:
            raise ValueError("start_time_ms must be a non-negative int")
        self._home = initial_home
        self._version = 0
        self._time_ms = start_time_ms
        self._history: list[TraceEntry] = []
        self._next_transaction_id = 1
        self._execution_capability = ExecutionCapability()
        self._environment_capability = EnvironmentCapability()
        self._capabilities_issued = False

    def issue_capabilities(self) -> tuple[ExecutionCapability, EnvironmentCapability]:
        """Hand out the two mutation capabilities. Callable exactly once."""
        if self._capabilities_issued:
            raise CapabilityError("capabilities for this simulator were already issued")
        self._capabilities_issued = True
        return self._execution_capability, self._environment_capability

    @property
    def state_version(self) -> int:
        return self._version

    @property
    def now_ms(self) -> int:
        return self._time_ms

    @property
    def history(self) -> tuple[TraceEntry, ...]:
        return tuple(self._history)

    def snapshot(self) -> HomeSnapshot:
        return HomeSnapshot(self._version, self._time_ms, self._home)

    def preview(self, actions: Sequence[ActionProposal]) -> tuple[HomeState, ...]:
        """Predict intermediate states from the current state without mutating."""
        return apply_sequence(self._home, tuple(actions))

    def execute(
        self,
        actions: Sequence[ActionProposal],
        *,
        expected_version: int,
        capability: ExecutionCapability,
    ) -> ExecutionResult:
        """Atomically execute ``actions`` if the state is still ``expected_version``."""
        if capability is not self._execution_capability:
            raise CapabilityError("execution requires this simulator's ExecutionCapability")
        batch = tuple(actions)
        for action in batch:
            if not isinstance(action, ActionProposal):
                raise TypeError("actions must be ActionProposal instances")

        transaction_id = self._next_transaction_id
        self._next_transaction_id += 1

        def reject(code: str, detail: str, failed_index: int | None = None) -> ExecutionResult:
            return ExecutionResult(
                transaction_id,
                ExecutionStatus.REJECTED,
                self._version,
                self._version,
                reason_code=code,
                failed_index=failed_index,
                detail=detail,
            )

        if not batch:
            return reject(ExecutionRejectionCode.EMPTY_TRANSACTION, "no actions")
        if len(batch) > MAX_TRANSACTION_ACTIONS:
            return reject(
                ExecutionRejectionCode.TRANSACTION_TOO_LONG,
                f"{len(batch)} > {MAX_TRANSACTION_ACTIONS}",
            )
        if expected_version != self._version:
            return reject(
                ExecutionRejectionCode.STALE_STATE_VERSION,
                f"checked version {expected_version}, current {self._version}",
            )
        try:
            states = apply_sequence(self._home, batch)
        except InvalidTransitionError as exc:
            return reject(exc.code, exc.detail, exc.index)

        version_before = self._version
        entries: list[TraceEntry] = []
        for action, after_home in zip(batch, states, strict=True):
            entries.append(
                self._commit(after_home, TraceKind.ACTION, transaction_id, action=action)
            )
        return ExecutionResult(
            transaction_id,
            ExecutionStatus.COMMITTED,
            version_before,
            self._version,
            entries=tuple(entries),
        )

    def advance_clock(self, delta_ms: int, *, capability: EnvironmentCapability) -> TraceEntry:
        """Advance simulated time. Time never moves backwards."""
        self._require_environment(capability)
        if type(delta_ms) is not int or delta_ms <= 0:
            raise ValueError("delta_ms must be a positive int")
        before = self.snapshot()
        self._time_ms += delta_ms
        return self._record(TraceKind.CLOCK, before)

    def apply_environment(
        self, event: EnvironmentEvent, *, capability: EnvironmentCapability
    ) -> TraceEntry:
        """Apply a trusted scenario event such as a presence change."""
        self._require_environment(capability)
        if not isinstance(event, SetPresence | SetAmbientTemperature):
            raise TypeError("event must be an EnvironmentEvent")
        return self._commit(
            apply_environment_event(self._home, event), TraceKind.ENVIRONMENT, event=event
        )

    def _require_environment(self, capability: EnvironmentCapability) -> None:
        if capability is not self._environment_capability:
            raise CapabilityError("this path requires the simulator's EnvironmentCapability")

    def _commit(
        self,
        new_home: HomeState,
        kind: TraceKind,
        transaction_id: int | None = None,
        *,
        action: ActionProposal | None = None,
        event: EnvironmentEvent | None = None,
    ) -> TraceEntry:
        before = self.snapshot()
        if new_home != self._home:
            self._home = new_home
            self._version += 1
        return self._record(kind, before, transaction_id, action=action, event=event)

    def _record(
        self,
        kind: TraceKind,
        before: HomeSnapshot,
        transaction_id: int | None = None,
        *,
        action: ActionProposal | None = None,
        event: EnvironmentEvent | None = None,
    ) -> TraceEntry:
        entry = TraceEntry(
            len(self._history) + 1,
            kind,
            before,
            self.snapshot(),
            transaction_id,
            action=action,
            event=event,
        )
        self._history.append(entry)
        return entry
