"""Trace-replay ablations of the mediator (EXP-05, EXP-06).

Each recorded proposal sequence from a verified condition batch is replayed,
unchanged and in order, through the full mediator and through the two contract
ablations (``no_provenance`` removes rule 3; ``no_freshness_replay`` removes
rules 4 and 5). Every replay starts from the scenario's reset state, issues the
same request and trusted task intent, and rebuilds the same evidence schedule
through the native gateway; the rebuilt deliveries must equal the recorded ones.
Canonical state advances per variant, so later proposals meet that variant's
state. The proposals do not adapt to blocks: this measures enforcement on a
fixed trace, not end-to-end agent behaviour (EXP-07 is the live comparison).
"""

from __future__ import annotations

import json
from collections.abc import Generator, Iterator
from copy import deepcopy
from pathlib import Path
from typing import Any

from effectshield.domain.actions import ActionProposal, parse_action
from effectshield.domain.context import Observation
from effectshield.domain.errors import ActionSchemaError
from effectshield.grading import grade
from effectshield.mediator import Ablation, ProtectedExecutor, TaskIntent, policy_for

from .audit import verify_evidence
from .replay import NativeEvaluationBackend
from .storage import canonical

ABLATION_SCHEMA_VERSION = "mediator-ablation/v1"
VARIANTS = (Ablation.FULL, Ablation.NO_PROVENANCE, Ablation.NO_FRESHNESS_REPLAY)


class AblationReplay(NativeEvaluationBackend):
    """Replay recorded proposals through one mediator policy; offline and deterministic."""

    def __init__(self, ablation: Ablation) -> None:
        super().__init__()
        self.policy = policy_for(ablation)
        self.executor: ProtectedExecutor | None = None
        self.decisions: list[dict[str, Any]] = []
        self._request_id: str | None = None

    def reset(self, initial_state: dict[str, Any], seed: int | None) -> dict[str, Any]:
        snapshot = super().reset(initial_state, seed)
        assert self.environment is not None
        self.executor = ProtectedExecutor.from_run(self.environment, policy=self.policy)
        self.decisions = []
        return snapshot

    def _bind_request(self, request_id: str) -> None:
        assert self.executor is not None
        intent = None
        if self._task_intent is not None:
            low, high = self._task_intent["setpoint_range_c"]
            intent = TaskIntent(request_id, (low, high))
        self.executor.bind_request(request_id, intent=intent)
        self._request_id = request_id

    def _deliver(self, observation: Observation) -> Observation:
        assert self.executor is not None
        return self.executor.deliver(observation)

    def _execute(self, proposal: ActionProposal) -> Generator[dict[str, Any], None, dict[str, Any]]:
        assert self.executor is not None and self.environment is not None
        outcome = self.executor.submit(proposal, request_id=self._request_id)
        self.decisions.append(outcome.to_dict())
        yield from self._history_events()
        if outcome.observation is not None:
            yield {
                "type": "observation",
                "receipt": {
                    "action": proposal.to_dict(),
                    "observation": outcome.observation.to_agent_dict(),
                    "snapshot": self.environment.simulator.snapshot().to_dict(),
                },
            }
        return outcome.feedback

    def replay(
        self,
        proposals: list[dict[str, Any]],
        request: dict[str, Any],
        observations: list[dict[str, Any]],
    ) -> Iterator[dict[str, Any]]:
        yield from self._prepare(request, observations)
        for recorded in proposals:
            yield {"type": "proposed_action", "action": deepcopy(recorded)}
            try:
                proposal = parse_action(canonical(recorded))
            except ActionSchemaError:
                continue  # a recorded invalid proposal never reaches the mediator
            yield from self._execute(proposal)
        yield from self._history_events()
        yield self._finish("completed")


def replay_trace(
    scenario: dict[str, Any], proposals: list[dict[str, Any]], ablation: Ablation
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Return the replayed native trace and the mediator decisions for one variant."""
    backend = AblationReplay(ablation)
    initial = backend.reset(deepcopy(scenario["initial_state"]), None)
    if "evidence_schedule" in scenario:
        backend.schedule_evidence(scenario["evidence_schedule"])
    if "task_intent" in scenario:
        backend.issue_task_intent(scenario["task_intent"], scenario["request"]["permissions"])
    events = list(backend.replay(proposals, scenario["request"], scenario["observations"]))
    history = [
        {k: v for k, v in e.items() if k != "type"}
        for e in events
        if e["type"] == "committed_transition"
    ]
    from .protected import repairs_from_decisions

    trace = {
        "schema_version": "evaluation-trace/v1",
        "initial_state": initial,
        "proposed_actions": [e["action"] for e in events if e["type"] == "proposed_action"],
        "executed_actions": [e["action"] for e in history if e["kind"] == "action"],
        "transitions": history,
        "observations": [e["receipt"] for e in events if e["type"] == "observation"],
        "final_state": events[-1]["final_state"],
        "complete": True,
        "termination": "completed",
        "repairs": repairs_from_decisions(backend.decisions, history),
    }
    return trace, backend.decisions


def ablate(bundle: str | Path) -> dict[str, Any]:
    """Replay every valid run of one verified batch through all three policies."""
    bundle = Path(bundle)
    verify_evidence(bundle)
    suite = json.loads((bundle / "suite.json").read_text())
    scenarios = {s["scenario_id"]: s for s in suite["scenarios"]}
    summary = json.loads((bundle / "summary.json").read_text())
    tallies = {
        variant.value: {
            "replayed": 0,
            "unsafe": 0,
            "attack_success": 0,
            "attack_known": 0,
            "task_completed": 0,
            "blocks": 0,
        }
        for variant in VARIANTS
    }
    runs, skipped = [], 0
    for run_id in summary["run_ids"]:
        record = json.loads((bundle / "runs" / run_id / "record.json").read_text())
        if not record["grade"]["trace_valid"]:
            skipped += 1  # EXP-06: only complete, valid source traces are eligible
            continue
        scenario = scenarios[record["scenario_id"]]
        proposals = json.loads((bundle / "runs" / run_id / "trace.json").read_text())[
            "proposed_actions"
        ]
        row: dict[str, Any] = {
            "source_run_id": run_id,
            "scenario_id": scenario["scenario_id"],
            "variant": scenario["variant"],
        }
        for variant in VARIANTS:
            trace, decisions = replay_trace(scenario, proposals, variant)
            result = grade(scenario, trace)
            if not result["trace_valid"]:
                raise ValueError(
                    f"Replay of {run_id} produced an invalid trace: {result['errors']}"
                )
            tally = tallies[variant.value]
            tally["replayed"] += 1
            tally["unsafe"] += result["unsafe_effect"] is True
            tally["task_completed"] += result["task_completed"] is True
            tally["blocks"] += sum(d["verdict"] in {"block", "escalate"} for d in decisions)
            if "attack_success" in result:
                tally["attack_known"] += 1
                tally["attack_success"] += result["attack_success"] is True
            row[variant.value] = {
                "unsafe_effect": result["unsafe_effect"],
                "task_completed": result["task_completed"],
                "attack_success": result.get("attack_success"),
                "reason_codes": [d["reason_code"] for d in decisions],
            }
        runs.append(row)
    return {
        "schema_version": ABLATION_SCHEMA_VERSION,
        "source_batch": summary["batch_id"],
        "source_condition": (summary.get("condition") or {}).get("condition_id"),
        "eligible_runs": len(runs),
        "skipped_invalid_runs": skipped,
        "notice": "Fixed proposal traces replayed offline; not end-to-end agent behaviour.",
        "variants": tallies,
        "runs": runs,
    }
