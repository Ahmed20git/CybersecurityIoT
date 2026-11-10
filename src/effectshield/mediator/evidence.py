"""Evidence ingestion ledger: authenticity, monotonic event IDs and consumption (OBS-05, OBS-06).

Ingestion is bookkeeping, not authorization (Proposed D07). Every observation
placed into the agent's context passes through :meth:`EvidenceLedger.ingest`,
which records whether the gateway issued it, whether its event ID advanced the
run's high-water mark, and which canonical facts its payload misstates. Rules 4
and 5 later decide whether a recorded delivery is admissible evidence.

Proposed D07 semantics:

- one gateway-wide event-ID scope per run; a new run gets a new ledger (SIM-03);
- the first authentic delivery with an ID above the high-water mark is
  ``accepted``; a later delivery of an already delivered ID is ``duplicate``;
  an authentic ID below the mark that was never delivered is ``out_of_order``;
- an envelope the gateway did not issue is ``unknown_origin`` and never usable;
- consumption ("access episode"): a presence observation may authorize each
  distinct door access operation once, for one request. Reads, non-access
  effects and blocked attempts never consume;
- delivery-log binding (MED-06): the ledger's known-origin deliveries must
  match the gateway's own delivery log (same length, same observation IDs in
  order, and a gateway redelivery exactly where the ledger recorded
  ``duplicate``/``out_of_order``), otherwise the mediator fails closed with
  ``trusted_context_malformed``.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from enum import StrEnum

from effectshield.domain.context import Observation, source_id_for
from effectshield.domain.devices import DeviceId, Operation
from effectshield.gateway.observations import EvidenceRecord, EvidenceView


class DeliveryStatus(StrEnum):
    ACCEPTED = "accepted"
    DUPLICATE = "duplicate"
    OUT_OF_ORDER = "out_of_order"
    UNKNOWN_ORIGIN = "unknown_origin"


REPLAY_STATUSES = frozenset({DeliveryStatus.DUPLICATE, DeliveryStatus.OUT_OF_ORDER})


@dataclass(frozen=True, slots=True)
class DeliveryRecord:
    """One observation delivery into the agent's context.

    ``record`` is the gateway's trusted registry entry; rules read canonical
    facts and the original envelope from it, never from the payload. For an
    ``unknown_origin`` delivery it is ``None``; ``device`` is then ``None`` if
    the forged envelope names no known device and ``event_id`` is 0 if it
    carries no integer event ID.
    """

    sequence_no: int
    observation_id: str
    device: DeviceId | None
    event_id: int
    status: DeliveryStatus
    record: EvidenceRecord | None
    delivered_at_ms: int
    payload_mismatch: tuple[str, ...] = ()

    @property
    def known_origin(self) -> bool:
        return self.status is not DeliveryStatus.UNKNOWN_ORIGIN


def _json_equal(left: object, right: object) -> bool:
    # Exact JSON equality: True is not 1 and 22 is not 22.0 on the wire.
    try:
        return json.dumps(left, sort_keys=True) == json.dumps(right, sort_keys=True)
    except (TypeError, ValueError):
        return False


class EvidenceLedger:
    """Per-run ingestion state over the gateway's read-only evidence registry."""

    def __init__(self, evidence: EvidenceView, clock: Callable[[], int]) -> None:
        self._evidence = evidence
        self._clock = clock
        self._deliveries: list[DeliveryRecord] = []
        self._high_water = 0
        self._consumption: dict[str, tuple[str, frozenset[Operation]]] = {}

    @property
    def deliveries(self) -> tuple[DeliveryRecord, ...]:
        return tuple(self._deliveries)

    @property
    def high_water_event_id(self) -> int:
        return self._high_water

    def ingest(self, observation: Observation) -> DeliveryRecord:
        """Record one delivery. Never raises for forged or replayed input."""
        if not isinstance(observation, Observation):
            raise TypeError("only Observation records can be delivered")
        envelope = observation.envelope
        sequence_no = len(self._deliveries) + 1
        delivered_at = self._clock()
        observation_id = getattr(envelope, "observation_id", None)
        record = self._evidence.lookup(observation_id) if isinstance(observation_id, str) else None
        event_id = getattr(envelope, "event_id", None)
        authentic = (
            record is not None
            and record.envelope == envelope
            and type(event_id) is int
            and event_id > 0
            and record.envelope.source_id == source_id_for(record.envelope.device)
        )
        if not authentic or record is None:
            delivery = DeliveryRecord(
                sequence_no=sequence_no,
                observation_id=observation_id if isinstance(observation_id, str) else "",
                device=_device_or_none(getattr(envelope, "device", None)),
                event_id=event_id if type(event_id) is int else 0,
                status=DeliveryStatus.UNKNOWN_ORIGIN,
                record=None,
                delivered_at_ms=delivered_at,
            )
        else:
            issued = record.envelope
            if issued.event_id > self._high_water:
                status = DeliveryStatus.ACCEPTED
                self._high_water = issued.event_id
            elif self.known_deliveries(issued.observation_id):
                status = DeliveryStatus.DUPLICATE
            else:
                status = DeliveryStatus.OUT_OF_ORDER
            mismatch = tuple(
                sorted(
                    key
                    for key, fact in record.canonical_facts.items()
                    if key not in observation.payload
                    or not _json_equal(observation.payload[key], fact)
                )
            )
            delivery = DeliveryRecord(
                sequence_no=sequence_no,
                observation_id=issued.observation_id,
                device=issued.device,
                event_id=issued.event_id,
                status=status,
                record=record,
                delivered_at_ms=delivered_at,
                payload_mismatch=mismatch,
            )
        self._deliveries.append(delivery)
        return delivery

    def known_deliveries(self, observation_id: str) -> tuple[DeliveryRecord, ...]:
        """Every gateway-issued delivery of ``observation_id``, in delivery order."""
        return tuple(
            d for d in self._deliveries if d.known_origin and d.observation_id == observation_id
        )

    def latest_known_delivery(self, device: DeviceId) -> DeliveryRecord | None:
        """The most recently delivered known-origin observation of ``device``, replays included.

        Staleness is deliberately not judged here: that is rules 4 and 5, so
        disabling them (ablation) really admits stale or replayed evidence.
        """
        for delivery in reversed(self._deliveries):
            if delivery.known_origin and delivery.device is device:
                return delivery
        return None

    def is_replayed(self, observation_id: str) -> bool:
        return any(
            d.status in REPLAY_STATUSES
            for d in self._deliveries
            if d.observation_id == observation_id
        )

    def consumption(self, observation_id: str) -> tuple[str | None, frozenset[Operation]]:
        """The request that used this evidence for access and the operations it authorized."""
        return self._consumption.get(observation_id, (None, frozenset()))

    def consume(
        self, observation_ids: Iterable[str], *, request_id: str, operations: Iterable[Operation]
    ) -> None:
        """Record access operations a committed transaction authorized with this evidence.

        The first request to use an observation owns it. A later use by another
        request (possible only with rule 5 ablated) leaves the owner unchanged.
        """
        used = frozenset(Operation(op) for op in operations)
        ids = tuple(observation_ids)
        for observation_id in ids:
            if not self.known_deliveries(observation_id):
                raise ValueError(f"{observation_id} was never delivered by the gateway")
        for observation_id in ids:
            owner, previous = self.consumption(observation_id)
            if owner is None or owner == request_id:
                self._consumption[observation_id] = (request_id, previous | used)


def _device_or_none(value: object) -> DeviceId | None:
    if isinstance(value, str) and value in set(DeviceId):
        return DeviceId(value)
    return None
