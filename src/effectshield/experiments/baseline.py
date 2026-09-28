"""Baseline integration: bounded proposal adapter plus trusted native execution.

The default ScriptedModel is an offline test double. Its authored proposals
exercise the adapter and feedback loop, never measure a language-model gate.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from copy import deepcopy
from pathlib import Path
from typing import Any

from effectshield.agent import BoundedAgent, CallEstimate, ModelClient, ModelResponse

from .backends import load_fixture_trace
from .replay import NativeEvaluationBackend
from .storage import canonical


class ScriptedModel:
    """Replay authored raw responses through the real adapter without inference."""

    kind = "fixture"
    model_version = "scripted-model-v1"
    model_date = "2026-09-28"
    seed_status = "supported"

    def __init__(self, proposals: list[dict[str, Any]]) -> None:
        self.responses = [canonical(action) for action in proposals]
        self.responses.append('{"finish":"completed"}')
        self.position = 0

    def reset(self) -> None:
        self.position = 0

    def estimate(self, messages: list[dict[str, Any]], remaining_tokens: int) -> CallEstimate:
        return CallEstimate(0, 0, 0.0, "USD")

    def generate(
        self, messages: list[dict[str, Any]], reservation: CallEstimate, config: dict[str, Any]
    ) -> ModelResponse:
        if self.position >= len(self.responses):
            raise ValueError("Scripted model exhausted after its finish response")
        text = self.responses[self.position]
        self.position += 1
        return ModelResponse(text, 0, 0, 0.0, "synthetic", "USD")


class BaselineBackend(NativeEvaluationBackend):
    """Run a provider-neutral bounded agent; capabilities stay on this trusted side."""

    def __init__(
        self,
        fixture_path: str | Path | None = None,
        scenario_id: str | None = None,
        *,
        model: ModelClient | None = None,
    ) -> None:
        super().__init__()
        self.expected_initial: dict[str, Any] | None = None
        if model is None:
            if fixture_path is None or scenario_id is None:
                raise ValueError("A scripted fixture or explicit reviewed model client is required")
            trace = load_fixture_trace(fixture_path, scenario_id)
            self.expected_initial = deepcopy(trace["initial_state"])
            model = ScriptedModel(trace["proposed_actions"])
        elif fixture_path is not None or scenario_id is not None:
            raise ValueError("Choose either scripted fixtures or a model client")
        self.model = model
        self.kind = model.kind

    def set_event_sink(self, sink: Callable[[dict[str, Any]], None]) -> None:
        """Persist provider audit events synchronously before remote submission."""
        bind = getattr(self.model, "set_event_sink", None)
        if callable(bind):
            bind(sink)

    def reset(self, initial_state: dict[str, Any], seed: int | None) -> dict[str, Any]:
        if self.expected_initial is not None and canonical(initial_state) != canonical(
            self.expected_initial
        ):
            raise ValueError("Scripted baseline fixture differs from requested initial state")
        self.model.reset()
        return super().reset(initial_state, seed)

    def run(
        self, request: dict[str, Any], observations: list[dict[str, Any]], config: dict[str, Any]
    ) -> Iterator[dict[str, Any]]:
        yield from self._prepare(request, observations)
        agent = BoundedAgent(request, observations, config, self.model)
        for message in agent.messages:
            yield {"type": "message", **deepcopy(message)}
        feedback = None
        while True:
            step = agent.step(feedback)
            # Persist known accounting before any externally supplied message
            # that the outer harness may reject for invalid shape or size.
            yield {"type": "usage", **deepcopy(agent.usage)}
            for message in step.messages:
                yield {"type": "message", **deepcopy(message)}
            if step.action is not None:
                yield {"type": "proposed_action", "action": step.action.to_dict()}
            if step.status != "proposed":
                yield from self._history_events()
                yield {
                    "type": "message",
                    "role": "tool",
                    "content": {"adapter_steps": agent.steps, "adapter_invocations": agent.calls},
                }
                yield self._finish(step.status, step.error)
                return
            assert step.action is not None
            result = yield from self._execute(step.action)
            feedback = (
                result
                if result["status"] == "observed"
                else {
                    key: result[key]
                    for key in (
                        "status",
                        "transaction_id",
                        "version_before",
                        "version_after",
                        "reason_code",
                        "failed_index",
                    )
                }
            )
            # A physical rejection is visible feedback. The bounded agent may
            # propose another structurally valid action within the same budget.
