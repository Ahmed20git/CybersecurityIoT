"""Matched offline condition batches; no model-performance claims.

Plan v2 runs all three conditions, the protected one through the mediator.
Retained v1 plans (two baselines, EffectShield not run) still verify unchanged.
"""

from copy import deepcopy
from pathlib import Path
from typing import Any

from effectshield.agent.conditions import load_conditions, parse_condition, treatment_differences
from effectshield.scenarios import load_suite

from .audit import verify_evidence
from .baseline import ScriptedModel
from .freeze import validate_protocol
from .runner import run_suite
from .storage import canonical, digest, load_json, redact, write_json

BASELINES = ("unprotected", "safety_prompt_only")
CONDITION_ORDER = (*BASELINES, "effectshield")
PLAN_V1, PLAN_V2 = "baseline-comparison-plan/v1", "condition-comparison-plan/v2"
NOTICE = (
    "Scripted development comparison only. Authored responses do not measure prompt-only "
    "defense efficacy or live-model susceptibility. "
    "EffectShield was not executed: mediator pending."
)
NOTICE_V2 = (
    "Scripted development comparison only. Authored responses do not measure prompt-only "
    "defense efficacy or live-model susceptibility. EffectShield decides the same authored "
    "proposals through the mediator; a scripted model does not adapt to blocks, so "
    "protected task completion here is not a live-model utility estimate."
)


def scripted_protocol(config: dict[str, Any]) -> dict[str, Any]:
    """Keep limits and settings paired; record the actual offline model identity."""
    result = deepcopy(config)
    result["model"] = {
        "provider": "scripted-model",
        "version": ScriptedModel.model_version,
        "date": ScriptedModel.model_date,
        "settings": {},
        "seed": 0,
        "seed_status": "supported",
    }
    return result


def _without_prompt(protocol: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in protocol.items() if key != "prompt_version"}


def _records(
    directory: Path, summary: dict[str, Any]
) -> dict[tuple[str, int, int], dict[str, Any]]:
    result = {}
    for run_id in summary["run_ids"]:
        row = load_json(directory / "runs" / run_id / "record.json")
        key = (row["scenario_id"], row["repetition"], row["attempt"])
        if key in result:
            raise ValueError("Duplicate comparison cell")
        result[key] = row
    return result


def comparison_summary(directory: str | Path) -> dict[str, Any]:
    """Audit both bundles and verify matching against the saved pre-run plan."""
    directory = Path(directory)
    plan = load_json(directory / "comparison_plan.json")
    if plan.get("schema_version") not in (PLAN_V1, PLAN_V2):
        raise ValueError("Unsupported comparison plan")
    v1 = plan["schema_version"] == PLAN_V1
    executed = BASELINES if v1 else CONDITION_ORDER
    conditions = {name: parse_condition(value) for name, value in plan["conditions"].items()}
    if set(conditions) != {*BASELINES, "effectshield"}:
        raise ValueError("Comparison plan must identify all three conditions")
    for name, condition in conditions.items():
        if condition.condition_id != name:
            raise ValueError("Condition name differs from its plan key")
        treatment_differences(conditions["unprotected"], condition)
    manifests, summaries, records = {}, {}, {}
    for name in executed:
        bundle = directory / name
        verify_evidence(bundle)
        manifest = load_json(bundle / "manifest.json")
        if (
            canonical(manifest.get("condition")) != canonical(conditions[name].to_dict())
            or canonical(_without_prompt(manifest["protocol"]))
            != canonical(_without_prompt(plan["protocol"]))
            or manifest["suite_sha256"] != plan["suite_sha256"]
            or manifest.get("scripted_inputs_sha256") != plan["scripted_inputs_sha256"]
        ):
            raise ValueError("Baseline inputs differ from the comparison plan")
        manifests[name] = manifest
        summaries[name] = load_json(bundle / "summary.json")
        records[name] = _records(bundle, summaries[name])
    first = manifests[executed[0]]
    for other in executed[1:]:
        for field in (
            "suite_sha256",
            "planned_runs",
            "implementation_sha256",
            "code_revision",
            "runtime",
        ):
            if canonical(first[field]) != canonical(manifests[other][field]):
                raise ValueError(f"Undeclared cross-condition difference: {field}")
    keys = [set(records[name]) for name in executed]
    shared = set.intersection(*keys)
    missing = set.union(*keys) - shared
    cells = []
    for key in sorted(shared):
        paired = [records[name][key] for name in executed]
        for field in (
            "scenario_sha256",
            "model_config",
            "run_limits",
            "rule_version",
            "schema_version",
        ):
            if any(canonical(paired[0][field]) != canonical(row[field]) for row in paired[1:]):
                raise ValueError(f"Undeclared run difference: {field}")
        initial_prompts = []
        for name, row in zip(executed, paired, strict=True):
            messages = load_json(directory / name / "runs" / row["run_id"] / "messages.json")
            system = next((m["content"] for m in messages if m["role"] == "system"), None)
            initial_prompts.append(
                {
                    k: v
                    for k, v in system.items()
                    if k not in {"prompt_version", "safety_instruction"}
                }
                if system is not None
                else None
            )
        if all(prompt is not None for prompt in initial_prompts) and any(
            canonical(initial_prompts[0]) != canonical(prompt) for prompt in initial_prompts[1:]
        ):
            raise ValueError("Undeclared difference in initial system prompts")
        cells.append(
            {
                "scenario_id": key[0],
                "repetition": key[1],
                "attempt": key[2],
                "run_ids": {
                    name: row["run_id"] for name, row in zip(executed, paired, strict=True)
                },
                "assessable": all(row["grade"]["trace_valid"] for row in paired)
                and all(prompt is not None for prompt in initial_prompts),
            }
        )
    complete = (
        bool(cells)
        and not missing
        and all(cell["assessable"] for cell in cells)
        and all(not summary["missing_runs"] for summary in summaries.values())
    )
    reported = {
        name: {
            "status": "recorded",
            "batch_id": summaries[name]["batch_id"],
            "attempts": summaries[name]["attempts"],
            "criteria": summaries[name]["criteria"],
            "unsafe_attempts": summaries[name]["unsafe_attempts"],
            "missing_runs": summaries[name]["missing_runs"],
            "failures": summaries[name]["failures"],
            "execution_statuses": summaries[name]["status_counts"],
            "outcomes": {
                "task_completed": sum(
                    row["grade"]["task_completed"] is True for row in records[name].values()
                ),
                "safe_completion": sum(
                    row["grade"]["task_completed"] is True
                    and row["grade"]["unsafe_effect"] is False
                    for row in records[name].values()
                ),
                "unknown_safety": sum(
                    row["grade"]["unsafe_effect"] is None for row in records[name].values()
                ),
            },
            **({"mediator": summaries[name]["mediator"]} if "mediator" in summaries[name] else {}),
        }
        for name in executed
    }
    if v1:
        return {
            "schema_version": "baseline-comparison/v1",
            "plan_sha256": digest(plan),
            "status": "matched" if complete else "incomplete",
            "notice": NOTICE,
            "declared_treatment_differences": treatment_differences(
                conditions["unprotected"], conditions["safety_prompt_only"]
            ),
            "matched_cells": cells,
            "unmatched_cells": [list(key) for key in sorted(missing)],
            "conditions": {
                **reported,
                "effectshield": {"status": "not_run", "reason": "Mediator not implemented"},
            },
        }
    return {
        "schema_version": "condition-comparison/v2",
        "plan_sha256": digest(plan),
        "status": "matched" if complete else "incomplete",
        "notice": NOTICE_V2,
        "declared_treatment_differences": {
            name: treatment_differences(conditions["unprotected"], conditions[name])
            for name in CONDITION_ORDER[1:]
        },
        "matched_cells": cells,
        "unmatched_cells": [list(key) for key in sorted(missing)],
        "conditions": reported,
    }


def run_comparison(
    suite_path: Path,
    fixture_path: Path,
    config: dict[str, Any],
    condition_directory: Path,
    output: Path,
    *,
    invocation: list[str] | None = None,
) -> dict[str, Any]:
    """Run all three conditions on matched scripted inputs; protection is the mediator."""
    conditions = load_conditions(condition_directory)
    for condition in conditions.values():
        treatment_differences(conditions["unprotected"], condition)
    protocol = scripted_protocol(config)
    validate_protocol(protocol, official=False)
    suite = load_suite(suite_path)
    fixtures = load_json(fixture_path)
    if fixtures.get("schema_version") != "evaluation-fixtures/v1":
        raise ValueError("Unsupported scripted input schema")
    for scenario in suite["scenarios"]:
        trace = fixtures["traces"][scenario["scenario_id"]]
        if canonical(trace["initial_state"]) != canonical(scenario["initial_state"]):
            raise ValueError("Scripted input reset differs from scenario")
    inputs = [protocol, suite, fixtures, {name: c.to_dict() for name, c in conditions.items()}]
    if canonical(inputs) != canonical(redact(inputs)):
        raise ValueError("Comparison inputs contain recognizable credentials")
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    write_json(
        output / "comparison_plan.json",
        {
            "schema_version": PLAN_V2,
            "protocol": protocol,
            "suite_sha256": digest(suite),
            "scripted_inputs_sha256": digest(fixtures),
            "conditions": {name: condition.to_dict() for name, condition in conditions.items()},
            "notice": NOTICE_V2,
        },
    )
    for name in CONDITION_ORDER:
        selected = deepcopy(protocol)
        selected["prompt_version"] = conditions[name].prompt_version
        run_suite(
            suite_path,
            selected,
            output / name,
            mode="baseline",
            fixture_path=fixture_path,
            condition=conditions[name].to_dict(),
            invocation=invocation,
        )
    summary = comparison_summary(output)
    write_json(output / "comparison.json", summary)
    return summary


def verify_comparison(directory: str | Path) -> dict[str, Any]:
    result = comparison_summary(directory)
    if canonical(result) != canonical(load_json(Path(directory) / "comparison.json")):
        raise ValueError("Recomputed comparison differs from saved report")
    return {
        "verified": True,
        "status": result["status"],
        "matched_cells": len(result["matched_cells"]),
        "notice": result["notice"],
    }
