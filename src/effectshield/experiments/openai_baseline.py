"""Reviewed fixed-snapshot live factory; construction performs no network I/O."""

from typing import Any

from effectshield.agent.conditions import parse_condition
from effectshield.agent.openai_client import OpenAIResponsesClient

from .baseline import BaselineBackend


def create_backend(condition: dict[str, Any] | None = None) -> BaselineBackend:
    """Create isolated model state; the runner still requires live approvals/budget.

    A named condition selects the treatment. The protected condition decides
    every proposal through the mediator; the others execute directly.
    """
    if condition is None:
        return BaselineBackend(model=OpenAIResponsesClient())
    parsed = parse_condition(condition)
    if parsed.requires_mediator:
        from .protected import ProtectedRunBackend

        return ProtectedRunBackend(model=OpenAIResponsesClient(), condition=parsed)
    return BaselineBackend(model=OpenAIResponsesClient(), condition=parsed)
