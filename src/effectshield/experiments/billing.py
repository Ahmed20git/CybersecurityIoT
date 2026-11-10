"""Usage and cost reconciliation across all live evidence (LOG-04).

Sums provider-reported token usage and the tariff-based cost estimates of every
audited live bundle, counts the input-token preflight requests that the cost
estimate excludes, and, when a provider billing export is supplied, compares
estimated and actual charges per day. Estimates and actual charges are always
labelled separately; an unavailable actual charge stays ``null``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from effectshield.agent.openai_client import (
    CACHED_INPUT_USD_PER_MILLION,
    INPUT_USD_PER_MILLION,
    OUTPUT_USD_PER_MILLION,
    PRICE_VERSION,
)

from .audit import verify_evidence

BILLING_SCHEMA_VERSION = "billing-reconciliation/v1"


def _bundle_usage(bundle: Path) -> dict[str, Any]:
    verify_evidence(bundle)
    summary = json.loads((bundle / "summary.json").read_text())
    totals = {
        "attempts": 0,
        "calls": 0,
        "input_tokens": 0,
        "output_tokens": 0,
        "estimated_cost": 0.0,
        "incomplete_accounting_runs": 0,
        "count_requests": 0,
    }
    days: set[str] = set()
    for run_id in summary["run_ids"]:
        path = bundle / "runs" / run_id
        record = json.loads((path / "record.json").read_text())
        if record.get("backend_kind") != "live":
            continue
        usage = record["usage"]
        totals["attempts"] += 1
        days.add(record["started_at"][:10])
        for key in ("calls", "input_tokens", "output_tokens"):
            totals[key] += usage.get(key) or 0
        totals["estimated_cost"] += usage.get("cost") or 0.0
        totals["incomplete_accounting_runs"] += usage.get("accounting_complete", True) is not True
        for line in (path / "events.jsonl").read_text().splitlines():
            event = json.loads(line)["event"]
            content = event.get("content")
            if (
                event.get("type") == "message"
                and isinstance(content, dict)
                and content.get("provider_operation") == "input_token_count"
                and content.get("direction") == "request"
            ):
                totals["count_requests"] += 1
    totals["estimated_cost"] = round(totals["estimated_cost"], 10)
    return {"bundle": bundle.name, "days": sorted(days), **totals}


def reconcile(bundles: list[Path], actual: dict[str, Any] | None = None) -> dict[str, Any]:
    """``actual`` maps a UTC date (YYYY-MM-DD) to the billed USD amount for the project key."""
    rows = [_bundle_usage(Path(b)) | {"path": str(b)} for b in bundles]
    by_day: dict[str, float] = {}
    for row in rows:
        for day in row["days"]:
            by_day[day] = by_day.get(day, 0.0) + row["estimated_cost"] / len(row["days"])
    keys = (
        "attempts",
        "calls",
        "input_tokens",
        "output_tokens",
        "estimated_cost",
        "incomplete_accounting_runs",
        "count_requests",
    )
    total = {key: sum(row[key] for row in rows) for key in keys}
    total["estimated_cost"] = round(total["estimated_cost"], 10)
    days = []
    for day in sorted(by_day):
        billed = None if actual is None else actual.get(day)
        days.append(
            {
                "date": day,
                "estimated_cost": round(by_day[day], 10),
                "actual_cost": billed,
                "difference": None if billed is None else round(billed - by_day[day], 10),
            }
        )
    return {
        "schema_version": BILLING_SCHEMA_VERSION,
        "pricing": {
            "basis": PRICE_VERSION,
            "usd_per_million": {
                "input": str(INPUT_USD_PER_MILLION),
                "cached_input": str(CACHED_INPUT_USD_PER_MILLION),
                "output": str(OUTPUT_USD_PER_MILLION),
            },
            "count_requests": "assumed free; not included in estimated_cost",
        },
        "bundles": rows,
        "total": total,
        "days": days,
        "actual_source": None if actual is None else actual.get("_source"),
        "status": "reconciled" if actual is not None else "actual billing unavailable",
    }
