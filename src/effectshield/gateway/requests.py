"""Harness-issued request identity and permissions (OBS-01, SIM-06).

The scenario harness issues each authenticated user request here. Trusted
components resolve a request by ID through :class:`RequestView`; nothing the
agent writes can create or change a request or its permissions.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from types import MappingProxyType

from effectshield.domain.context import Permission, RequestContext


class RequestView:
    """Read-only lookup of issued requests."""

    __slots__ = ("_requests",)

    def __init__(self, requests: Mapping[str, RequestContext]) -> None:
        self._requests = MappingProxyType(requests)

    def lookup(self, request_id: str) -> RequestContext | None:
        return self._requests.get(request_id)

    def __len__(self) -> int:
        return len(self._requests)


class RequestRegistry:
    """Issues request contexts with sequential IDs, reset per run."""

    def __init__(self) -> None:
        self._requests: dict[str, RequestContext] = {}
        self.view = RequestView(self._requests)

    def issue(
        self,
        *,
        principal_id: str,
        request_text: str,
        permissions: Iterable[Permission],
        issued_at_ms: int,
    ) -> RequestContext:
        if not principal_id or not isinstance(principal_id, str):
            raise ValueError("principal_id must be a non-empty string")
        if not isinstance(request_text, str):
            raise ValueError("request_text must be a string")
        request_id = f"req-{len(self._requests) + 1:04d}"
        context = RequestContext(
            request_id=request_id,
            principal_id=principal_id,
            request_text=request_text,
            permissions=frozenset(permissions),
            issued_at_ms=issued_at_ms,
        )
        self._requests[request_id] = context
        return context
