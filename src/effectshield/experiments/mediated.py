"""Protected integration path: the bounded agent behind the EffectShield mediator (WP-07 to WP-09).

:class:`MediatedBackend` runs the ``effectshield`` condition with the same
bounded agent, prompt and budgets as the unprotected baseline. The only
treatment difference is enforcement: every proposal is decided by the mediator
and only the :class:`~effectshield.mediator.ProtectedExecutor` holds the
execution capability, so the inherited direct execution path is unreachable.

The policy is pinned to the full preset: running an ablation under the
``effectshield`` condition would be an undeclared treatment difference. Clamp
repair is disabled end to end (no task intents) until D05/D08 approve a trusted,
harness-issued intent field; intents are never derived from grader labels or
request text.

When the adapter stops with ``invalid_response``, only a rule-1 outcome is
logged (MED-02): a response the native parser rejects becomes a logged
``schema_invalid`` block. The adapter also stops with ``invalid_response`` for
text that parses (a provider stop status, malformed provider-visible messages);
that text was never proposed or executed, so no decision is logged for it and
no record can claim an approved effect (``executed_actions``) that never ran.
The stop itself stays in the run's finish event. This narrows design section 9's
"log ``decide(raw_text)``" to the rule-1 block it names.

This is a direct-drive path, not yet a runner backend. It emits only existing
runner event types and keeps decision records in :attr:`MediatedBackend.decisions`
rather than in agent-visible messages. Persisting them in run records (a
``mediator_decision`` event, ``trace.repairs`` indexes and the policy version)
and accepting the ``escalated`` termination are evaluation-runner integration
items.
"""

from __future__ import annotations

from collections.abc import Generator
from pathlib import Path
from typing import Any

from effectshield.agent import Condition, ModelClient
from effectshield.agent.baseline import AgentStep
from effectshield.domain.actions import ActionProposal
from effectshield.domain.context import Observation
from effectshield.mediator import (
    Ablation,
    MediatorPolicy,
    ProtectedExecutor,
    outcome_record,
    policy_for,
)

from .baseline import BaselineBackend


class MediatedBackend(BaselineBackend):
    """Run the full EffectShield condition with protected execution (direct drive only)."""

    def __init__(
        self,
        fixture_path: str | Path | None = None,
        scenario_id: str | None = None,
        *,
        model: ModelClient | None = None,
        condition: Condition,
        policy: MediatorPolicy | None = None,
    ) -> None:
        if not isinstance(condition, Condition) or condition.enforcement != "effectshield":
            raise ValueError("MediatedBackend runs only a condition with effectshield enforcement")
        full = policy_for(Ablation.FULL)
        if policy is not None and policy != full:
            raise ValueError("The effectshield condition runs only the full mediator policy")
        super().__init__(fixture_path, scenario_id, model=model)
        self.condition = condition
        self.policy = full
        self.executor: ProtectedExecutor | None = None
        self.decisions: list[dict[str, Any]] = []
        self._request_id: str | None = None

    def reset(self, initial_state: dict[str, Any], seed: int | None) -> dict[str, Any]:
        snapshot = super().reset(initial_state, seed)
        assert self.environment is not None
        self.executor = ProtectedExecutor.from_run(self.environment, policy=self.policy)
        self.decisions = []
        self._request_id = None
        return snapshot

    def _protected(self) -> ProtectedExecutor:
        if self.executor is None:
            raise ValueError("Reset a fresh environment before running the protected backend")
        return self.executor

    def _bind_request(self, request_id: str) -> None:
        self._protected().bind_request(request_id)
        self._request_id = request_id

    def _deliver(self, observation: Observation) -> Observation:
        return self._protected().deliver(observation)

    def _execute(self, proposal: ActionProposal) -> Generator[dict[str, Any], None, dict[str, Any]]:
        outcome = self._protected().submit(proposal, request_id=self._request_id)
        self.decisions.append(outcome.to_dict())
        yield from self._history_events()
        if outcome.observation is not None:
            assert self.environment is not None
            yield {
                "type": "observation",
                "receipt": {
                    "action": proposal.to_dict(),
                    "observation": outcome.observation.to_agent_dict(),
                    "snapshot": self.environment.simulator.snapshot().to_dict(),
                },
            }
        return outcome.feedback

    def _feedback(self, result: dict[str, Any]) -> dict[str, Any]:
        # The executor already produced exactly the continuation protocol fields.
        return result

    def _stopped(self, step: AgentStep) -> None:
        # MED-02: an unparseable response is a logged rule-1 block with no effect.
        # It is never executed and the agent has already stopped, so no feedback.
        if step.status != "invalid_response" or not isinstance(step.raw_text, str):
            return
        decision = self._protected().mediator.decide(step.raw_text, request_id=self._request_id)
        # The adapter also stops with a parseable text (a provider stop status or
        # malformed provider-visible messages). That text was never proposed, so
        # its rules 2-8 outcome must not be logged as an approved or blocked effect.
        if decision.action is None:
            self.decisions.append(outcome_record(decision))
