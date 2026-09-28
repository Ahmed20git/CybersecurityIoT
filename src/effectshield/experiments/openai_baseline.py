"""Reviewed fixed-snapshot live factory; construction performs no network I/O."""

from effectshield.agent.openai_client import OpenAIResponsesClient

from .baseline import BaselineBackend


def create_backend() -> BaselineBackend:
    """Create isolated model state; the runner still requires live approvals/budget."""
    return BaselineBackend(model=OpenAIResponsesClient())
