"""Preflight run accounting against the 432-run ceiling (EXP-04, D11, DAT-06).

Counts a proposed run matrix before any execution: unique run keys, maximum
attempts and reported cost under the protocol's retry and cost limits, and the
live attempts already consumed according to audited evidence bundles. Fixture
and scripted attempts never count toward the ceiling. The count approves
nothing; budget and protocol approvals remain separate human decisions.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from effectshield.agent.conditions import load_conditions
from effectshield.scenarios import load_suite, validate_splits

from .audit import verify_evidence
from .storage import _pairs

RUN_CEILING = 432
FINAL_MATRIX = {"base_tasks": 24, "forms": 2, "conditions": 3, "repetitions": 3}
NOTICE = "Preflight count only. It does not approve a protocol, budget or live run."


def consumed_live_attempts(bundles: list[Path]) -> dict[str, Any]:
    """Count finished live attempts in audited bundles; every attempt counts (D11)."""
    rows = []
    for bundle in bundles:
        verify_evidence(bundle)
        attempts = 0
        for line in (bundle / "ledger.jsonl").read_text().splitlines():
            row = json.loads(line, object_pairs_hook=_pairs)
            attempts += row["event"] == "finished" and row.get("backend_kind") == "live"
        rows.append({"bundle": bundle.name, "live_attempts": attempts})
    return {"bundles": rows, "total": sum(row["live_attempts"] for row in rows)}


def preflight(
    suite_path: Path,
    protocol: dict[str, Any],
    condition_directory: Path,
    *,
    repetitions: int,
    consumed: list[Path],
    split_suites: list[Path],
    ceiling: int = RUN_CEILING,
) -> dict[str, Any]:
    if type(repetitions) is not int or repetitions < 1:
        raise ValueError("Repetitions must be a positive integer")
    suite = load_suite(suite_path)
    loaded = {str(path): load_suite(path) for path in split_suites}
    loaded.setdefault(str(suite_path), suite)
    splits = validate_splits(loaded)
    conditions = sorted(load_conditions(condition_directory))
    keys = [
        (scenario["scenario_id"], condition, repetition)
        for condition in conditions
        for repetition in range(1, repetitions + 1)
        for scenario in suite["scenarios"]
    ]
    if len(set(keys)) != len(keys):
        raise ValueError("Planned run keys are not unique")
    scenarios = suite["scenarios"]
    planned = len(keys)
    max_attempts = planned * protocol["retry"]["max_attempts"]
    used = consumed_live_attempts(consumed)
    remaining = ceiling - used["total"]
    final_runs = 1
    for value in FINAL_MATRIX.values():
        final_runs *= value
    return {
        "schema_version": "run-preflight/v1",
        "suite": {
            "path": str(suite_path),
            "split": suite.get("split", "development"),
            "scenarios": len(scenarios),
            "base_tasks": sum(s["variant"] == "clean" for s in scenarios),
            "attacked": sum(s["variant"] == "attacked" for s in scenarios),
            "infeasible": sum(s.get("feasibility") == "infeasible" for s in scenarios),
        },
        "split_check": splits,
        "conditions": conditions,
        "repetitions": repetitions,
        "planned_runs": planned,
        "maximum_attempts": max_attempts,
        "maximum_reported_cost": {
            "amount": max_attempts * protocol["limits"]["max_cost"],
            "currency": protocol["limits"]["currency"],
            "basis": "attempts x per-attempt cost cap in the protocol",
        },
        "ceiling": {
            "runs": ceiling,
            "consumed_live_attempts": used,
            "remaining": remaining,
            "fits_after_retries": max_attempts <= remaining,
            "remaining_after_this_plan": remaining - max_attempts,
        },
        "final_matrix": {
            **FINAL_MATRIX,
            "runs": final_runs,
            "fits_remaining_without_this_plan": final_runs <= remaining,
            "fits_remaining_after_this_plan": final_runs <= remaining - max_attempts,
        },
        "notice": NOTICE,
    }
