"""Mediator-only and total task latency, measured separately (LOG-03).

Total task latency is the runner's per-attempt wall time, recorded live with a
monotonic clock from worker start to finish; it includes model calls, the
harness and the simulator. Mediator-only latency is measured offline by
replaying the recorded proposals of a protected batch through the full mediator
and timing only ``Mediator.decide`` with ``time.perf_counter_ns`` (monotonic).
Execution, gateway reads and agent steps are outside that measurement point.
Simulated time comes from the simulator clock and is not a latency measure.
"""

from __future__ import annotations

import json
import os
import platform
import statistics
import sys
import time
from copy import deepcopy
from pathlib import Path
from typing import Any

from effectshield.mediator import Ablation

from .ablation import AblationReplay
from .audit import verify_evidence

LATENCY_SCHEMA_VERSION = "latency-report/v1"


def describe(samples: list[float], unit: str) -> dict[str, Any]:
    if not samples:
        return {"n": 0, "unit": unit}
    ordered = sorted(samples)

    def quantile(q: float) -> float:
        return ordered[min(len(ordered) - 1, round(q * (len(ordered) - 1)))]

    return {
        "n": len(ordered),
        "unit": unit,
        "median": statistics.median(ordered),
        "mean": statistics.fmean(ordered),
        "p95": quantile(0.95),
        "p99": quantile(0.99),
        "max": ordered[-1],
        "min": ordered[0],
    }


def _timed_decisions(
    scenario: dict[str, Any], proposals: list[dict[str, Any]]
) -> tuple[list[float], list[tuple[str, str]]]:
    backend = AblationReplay(Ablation.FULL)
    backend.reset(deepcopy(scenario["initial_state"]), None)
    assert backend.executor is not None
    mediator = backend.executor.mediator
    original = mediator.decide
    samples: list[float] = []

    def decide(proposal: object, *, request_id: str | None) -> Any:
        start = time.perf_counter_ns()
        try:
            return original(proposal, request_id=request_id)
        finally:
            samples.append((time.perf_counter_ns() - start) / 1000)  # microseconds

    mediator.decide = decide  # type: ignore[method-assign]
    if "evidence_schedule" in scenario:
        backend.schedule_evidence(scenario["evidence_schedule"])
    if "task_intent" in scenario:
        backend.issue_task_intent(scenario["task_intent"], scenario["request"]["permissions"])
    list(backend.replay(proposals, scenario["request"], scenario["observations"]))
    verdicts = [(d["verdict"], d["reason_code"]) for d in backend.decisions]
    return samples, verdicts


def latency_report(comparison: str | Path, *, repeats: int = 5) -> dict[str, Any]:
    """Measure mediator-only latency on the protected batch; summarize live task latency."""
    comparison = Path(comparison)
    totals: dict[str, Any] = {}
    for name in ("unprotected", "safety_prompt_only", "effectshield"):
        bundle = comparison / name
        verify_evidence(bundle)
        summary = json.loads((bundle / "summary.json").read_text())
        valid = []
        for run_id in summary["run_ids"]:
            record = json.loads((bundle / "runs" / run_id / "record.json").read_text())
            if record["grade"]["trace_valid"]:
                valid.append(record["latency_s"])
        totals[name] = describe(valid, "s")
    bundle = comparison / "effectshield"
    suite = json.loads((bundle / "suite.json").read_text())
    scenarios = {s["scenario_id"]: s for s in suite["scenarios"]}
    summary = json.loads((bundle / "summary.json").read_text())
    samples: list[float] = []
    mismatches = 0
    replayed = 0
    for run_id in summary["run_ids"]:
        path = bundle / "runs" / run_id
        record = json.loads((path / "record.json").read_text())
        if not record["grade"]["trace_valid"]:
            continue
        proposals = json.loads((path / "trace.json").read_text())["proposed_actions"]
        recorded = [
            (d["verdict"], d["reason_code"])
            for d in json.loads((path / "decisions.json").read_text())["decisions"]
            if d["action"] is not None
        ]
        replayed += 1
        for _ in range(repeats):
            timed, verdicts = _timed_decisions(scenarios[record["scenario_id"]], proposals)
            samples.extend(timed)
            mismatches += verdicts != recorded
    return {
        "schema_version": LATENCY_SCHEMA_VERSION,
        "measurement_points": {
            "total_task_latency": (
                "runner wall time per attempt (time.monotonic), recorded live; valid runs only"
            ),
            "mediator_only_latency": (
                "Mediator.decide alone (time.perf_counter_ns), offline replay of the recorded "
                "protected proposals"
            ),
        },
        "total_task_latency": totals,
        "mediator_only_latency": describe(samples, "us"),
        "replayed_protected_runs": replayed,
        "repeats": repeats,
        "decision_mismatches_with_live_records": mismatches,
        "runtime": {
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "machine": platform.machine(),
            "cpu_count": os.cpu_count(),
        },
        "notice": (
            "Mediator latency comes from offline replay on the stated hardware, not from the live "
            "run; total task latency includes provider round trips."
        ),
    }
