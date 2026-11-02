"""Preflight run and spending accounting (EXP-04, D11, DAT-06).

Counts a proposed run matrix before any execution: unique run keys, maximum
attempts and reported cost under the protocol's retry and cost limits. Under
D11 (decided October 29, 2026) the 432-run ceiling covers only the frozen final
benchmark; rehearsal, gate and pilot attempts are reported separately, and all
live spending counts against the USD 2 budget. Spending is taken from audited
evidence bundles; fixture attempts cost nothing. The count approves nothing.
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
BUDGET_USD = 2.0
FINAL_MATRIX = {"base_tasks": 24, "forms": 2, "conditions": 3, "repetitions": 3}
NOTICE = "Preflight count only. It does not approve a protocol, budget or live run."


def consumed_live_attempts(bundles: list[Path]) -> dict[str, Any]:
    """Count finished live attempts and their known spending in audited bundles."""
    rows: list[dict[str, Any]] = []
    attempts_total, cost_total, unknown_total = 0, 0.0, 0
    for bundle in bundles:
        verify_evidence(bundle)
        attempts, cost, unknown = 0, 0.0, 0
        for line in (bundle / "ledger.jsonl").read_text().splitlines():
            row = json.loads(line, object_pairs_hook=_pairs)
            if row["event"] != "finished" or row.get("backend_kind") != "live":
                continue
            attempts += 1
            cost += row["usage"].get("cost") or 0.0
            unknown += row["usage"].get("accounting_complete", True) is not True
        attempts_total += attempts
        cost_total += cost
        unknown_total += unknown
        rows.append(
            {
                "bundle": str(bundle.relative_to(bundle.parents[1])),
                "live_attempts": attempts,
                "known_cost": round(cost, 10),
                "incomplete_accounting_runs": unknown,
            }
        )
    return {
        "bundles": rows,
        "total": attempts_total,
        "known_cost": round(cost_total, 10),
        "incomplete_accounting_runs": unknown_total,
    }


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
    # Key by resolved path so the planned suite is never counted twice.
    loaded = {str(Path(path).resolve()): load_suite(path) for path in split_suites}
    loaded.setdefault(str(Path(suite_path).resolve()), suite)
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
    max_cost = max_attempts * protocol["limits"]["max_cost"]
    counts_toward_ceiling = suite.get("split") == "test"
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
            "amount": max_cost,
            "currency": protocol["limits"]["currency"],
            "basis": "attempts x per-attempt cost cap in the protocol",
        },
        "ceiling": {
            "runs": ceiling,
            "scope": "frozen final benchmark only (D11, October 29, 2026)",
            "counted_from_this_plan": max_attempts if counts_toward_ceiling else 0,
            "fits": not counts_toward_ceiling or max_attempts <= ceiling,
        },
        "spending": {
            "budget": BUDGET_USD,
            "consumed_live": used,
            "remaining_known": round(BUDGET_USD - used["known_cost"], 10),
            "fits_after_this_plan": max_cost <= BUDGET_USD - used["known_cost"],
        },
        "final_matrix": {
            **FINAL_MATRIX,
            "runs": final_runs,
            "fits_ceiling": final_runs <= ceiling,
            "maximum_cost": final_runs * protocol["limits"]["max_cost"],
            "fits_budget_without_this_plan": final_runs * protocol["limits"]["max_cost"]
            <= BUDGET_USD - used["known_cost"],
            "fits_budget_after_this_plan": final_runs * protocol["limits"]["max_cost"]
            <= BUDGET_USD - used["known_cost"] - max_cost,
        },
        "notice": NOTICE,
    }
