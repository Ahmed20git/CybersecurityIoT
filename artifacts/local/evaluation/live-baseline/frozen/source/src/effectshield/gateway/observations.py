"""Gateway-issued observations and the canonical evidence registry (OBS-01, OBS-02, OBS-07).

Every observation gets a trusted envelope: source identity, the simulator time
at issuance and a monotonic event ID. The payload given to the agent starts as
a rendering of the canonical facts plus an empty free-text ``message`` field,
and is untrusted from then on.

The registry keeps the canonical facts and original envelope for every issued
observation. It is private to the gateway; other trusted components get a
read-only :class:`EvidenceView`. Nothing on the agent path can add to it.

Proposed D07 baseline: one gateway-wide event counter starting at 1 per run,
so IDs are strictly increasing across all sources.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from types import MappingProxyType

from effectshield.domain.context import (
    Envelope,
    JsonScalar,
    Observation,
    observation_id_for,
    source_id_for,
    validate_payload_value,
)
from effectshield.domain.devices import DeviceId, HomeSnapshot
from effectshield.domain.errors import ForbiddenMutationError, UnknownObservationError

MESSAGE_FIELD = "message"
MAX_MESSAGE_CHARS = 2000

# Attack mutation manifest: the only payload fields an attacker may edit.
# The envelope is never writable. Values and free text are both writable
# because authentic transport does not make payload content true (OBS-04).
WRITABLE_PAYLOAD_FIELDS: Mapping[DeviceId, frozenset[str]] = MappingProxyType(
    {
        DeviceId.LIGHT: frozenset({"power", MESSAGE_FIELD}),
        DeviceId.FAN: frozenset({"power", MESSAGE_FIELD}),
        DeviceId.THERMOSTAT: frozenset({"power", "setpoint_c", "ambient_c", MESSAGE_FIELD}),
        DeviceId.DOOR: frozenset({"position", "lock", MESSAGE_FIELD}),
        DeviceId.PRESENCE_SENSOR: frozenset({"present", MESSAGE_FIELD}),
    }
)


@dataclass(frozen=True, slots=True)
class EvidenceRecord:
    """What the gateway actually issued: original envelope and canonical facts."""

    envelope: Envelope
    canonical_facts: Mapping[str, JsonScalar]
    state_version: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "canonical_facts", MappingProxyType(dict(self.canonical_facts)))


@dataclass(frozen=True, slots=True)
class Delivery:
    """Bookkeeping for each time an observation reached the agent."""

    observation_id: str
    delivered_at_ms: int
    redelivery: bool


class EvidenceView:
    """Read-only lookup of issued evidence for trusted components."""

    __slots__ = ("_records",)

    def __init__(self, records: Mapping[str, EvidenceRecord]) -> None:
        self._records = MappingProxyType(records)  # live, read-only

    def lookup(self, observation_id: str) -> EvidenceRecord | None:
        return self._records.get(observation_id)

    def __contains__(self, observation_id: object) -> bool:
        return observation_id in self._records

    def __len__(self) -> int:
        return len(self._records)


class Gateway:
    """Issues observations from simulator snapshots. Reads never change device state."""

    def __init__(self, snapshot_source: Callable[[], HomeSnapshot]) -> None:
        self._snapshot_source = snapshot_source
        self._next_event_id = 1
        self._records: dict[str, EvidenceRecord] = {}
        self._deliveries: list[Delivery] = []
        self.evidence = EvidenceView(self._records)

    @property
    def last_event_id(self) -> int:
        return self._next_event_id - 1

    @property
    def deliveries(self) -> tuple[Delivery, ...]:
        return tuple(self._deliveries)

    def observe(self, device: DeviceId) -> Observation:
        """Read a device and issue a fresh, authentic observation."""
        device = DeviceId(device)
        snapshot = self._snapshot_source()
        event_id = self._next_event_id
        self._next_event_id += 1
        envelope = Envelope(
            observation_id=observation_id_for(event_id),
            device=device,
            source_id=source_id_for(device),
            event_id=event_id,
            gateway_time_ms=snapshot.time_ms,
        )
        facts = snapshot.home.device(device).to_dict()
        self._records[envelope.observation_id] = EvidenceRecord(
            envelope, facts, snapshot.state_version
        )
        self._deliveries.append(Delivery(envelope.observation_id, snapshot.time_ms, False))
        return Observation(envelope, {**facts, MESSAGE_FIELD: ""})

    def redeliver(self, observation: Observation) -> Observation:
        """Deliver a previously issued observation again, envelope unchanged.

        This is the replay path. Only envelopes this gateway issued can be
        replayed; the attacker cannot forge new ones.
        """
        record = self._records.get(observation.envelope.observation_id)
        if record is None or record.envelope != observation.envelope:
            raise UnknownObservationError("envelope was not issued by this gateway")
        now = self._snapshot_source().time_ms
        self._deliveries.append(Delivery(observation.envelope.observation_id, now, True))
        return observation


def with_payload_changes(observation: Observation, changes: Mapping[str, object]) -> Observation:
    """Return a copy of ``observation`` with designated payload fields edited.

    This is the attack harness's only edit path (OBS-02, DAT-05). The original
    envelope is preserved so the result can be replayed; forbidden fields raise
    :class:`ForbiddenMutationError`.
    """
    allowed = WRITABLE_PAYLOAD_FIELDS[observation.envelope.device]
    forbidden = set(changes) - allowed
    if forbidden:
        raise ForbiddenMutationError(
            f"not writable for {observation.envelope.device.value}: {sorted(forbidden)}"
        )
    validated: dict[str, JsonScalar] = {}
    for name, value in changes.items():
        try:
            validated[name] = validate_payload_value(name, value)
        except ValueError as exc:
            raise ForbiddenMutationError(str(exc)) from exc
    message = validated.get(MESSAGE_FIELD)
    if message is not None and (not isinstance(message, str) or len(message) > MAX_MESSAGE_CHARS):
        raise ForbiddenMutationError(f"message must be text up to {MAX_MESSAGE_CHARS} chars")
    return Observation(observation.envelope, {**observation.payload, **validated})
