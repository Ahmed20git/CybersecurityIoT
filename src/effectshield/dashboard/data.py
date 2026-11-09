"""Read-only data layer for the results dashboard (DEL-03).

Everything here is derived from retained, verified evidence. Nothing grades,
decides policy or calls a model. Text that came from the agent, a device
payload or a scenario is returned unchanged as data and marked untrusted; the
view must render it as plain text, never as Markdown or HTML (LOG-06).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from effectshield.analysis import paired_bootstrap, task_rates
from effectshield.experiments.audit import verify_evidence
from effectshield.experiments.comparison import verify_comparison
from effectshield.experiments.freeze import verify_freeze

CONDITIONS = ("effectshield", "unprotected", "safety_prompt_only")
LABELS = {
    "effectshield": "EffectShield",
    "unprotected": "Unprotected",
    "safety_prompt_only": "Safety prompt only",
}
STUDY = "final-2026-11-04"
FREEZE = "final-freeze"
MEASURES = {
    "attacked_unsafe_effect": ("Attacked runs with an unsafe effect", "attacked", "unsafe_effect"),
    "attack_success": ("Attack success", "attacked", "attack_success"),
    "clean_completion": ("Clean task completion", "clean", "task_completed"),
    "clean_unsafe_effect": ("Clean runs with an unsafe effect", "clean", "unsafe_effect"),
    "attacked_completion": ("Attacked task completion", "attacked", "task_completed"),
}


def _json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def evidence_root(project: Path) -> Path:
    return project / "artifacts/local/evaluation"


def load_study(project: Path) -> dict[str, Any]:
    """Load the final study's retained outputs; raises if any expected file is missing."""
    root = evidence_root(project)
    study = root / STUDY
    manifests = {name: _json(study / name / "manifest.json") for name in CONDITIONS}
    summaries = {name: _json(study / name / "summary.json") for name in CONDITIONS}
    first = manifests["effectshield"]
    return {
        "analysis": _json(study / "analysis-v2.json"),
        "comparison": _json(study / "comparison.json"),
        "plan": _json(study / "comparison_plan.json"),
        "freeze": _json(root / FREEZE / "manifest.json"),
        "latency": _json(root / f"{STUDY}-latency.json"),
        "billing": _json(root / "billing-2026-11-06.json"),
        "ablations": {name: _json(root / f"{STUDY}-ablation-{name}.json") for name in CONDITIONS},
        "replay": _json(root / f"{STUDY}-review" / "recount.json"),
        "summaries": summaries,
        "provenance": {
            "model": first["protocol"]["model"]["version"],
            "protocol": first["protocol"]["protocol_version"],
            "code_revision": first["code_revision"],
            "implementation_sha256": first["implementation_sha256"],
            "freeze_id": first["freeze"]["freeze_id"],
            "created_at": first["created_at"],
            "repetitions": first["protocol"]["repetitions"],
            "planned_runs": sum(len(m["planned_runs"]) for m in manifests.values()),
            "attempts": sum(s["attempts"] for s in summaries.values()),
            "known_cost": round(
                sum(s["usage"]["cost"]["known_subtotal"] for s in summaries.values()), 7
            ),
        },
    }


def verify_study(project: Path) -> dict[str, Any]:
    """Re-run the integrity checks the dashboard relies on (hashes, regrading, freeze)."""
    root = evidence_root(project)
    comparison = verify_comparison(root / STUDY)
    freeze = verify_freeze(root / FREEZE)
    bundles = {name: verify_evidence(root / STUDY / name)["runs"] for name in CONDITIONS}
    return {
        "comparison_verified": comparison["verified"],
        "comparison_status": comparison["status"],
        "matched_cells": comparison["matched_cells"],
        "freeze_verified": freeze["freeze_id"] == load_study(project)["provenance"]["freeze_id"],
        "bundle_runs": bundles,
    }


def run_rows(project: Path) -> list[dict[str, Any]]:
    """One row per attempt with its independent grade (the explorer index)."""
    study = evidence_root(project) / STUDY
    rows = []
    for name in CONDITIONS:
        summary = _json(study / name / "summary.json")
        for run_id in summary["run_ids"]:
            record = _json(study / name / "runs" / run_id / "record.json")
            grade = record["grade"]
            rows.append(
                {
                    "condition": name,
                    "run_id": run_id,
                    "scenario_id": record["scenario_id"],
                    "task_id": record["task_id"],
                    "variant": record["variant"],
                    "family": record.get("attack_family", "none"),
                    "repetition": record["repetition"],
                    "status": record["status"],
                    "valid": grade["trace_valid"],
                    "task_completed": grade["task_completed"],
                    "unsafe_effect": grade["unsafe_effect"],
                    "attack_success": grade.get("attack_success"),
                    "latency_s": record["latency_s"],
                    "cost": record["usage"].get("cost"),
                }
            )
    return rows


def rate_table(rows: list[dict[str, Any]], *, replicates: int, seed: int) -> list[dict[str, Any]]:
    """Task-level rates with denominators and a task-cluster bootstrap 95% interval."""
    table = []
    for key, (title, variant, outcome) in MEASURES.items():
        for name in CONDITIONS:
            population = [r for r in rows if r["condition"] == name and r["variant"] == variant]
            by_task = task_rates(population, outcome)
            zero = dict.fromkeys(by_task, 0.0)
            interval = paired_bootstrap(by_task, zero, replicates=replicates, seed=seed)
            known = [r for r in population if isinstance(r.get(outcome), bool)]
            table.append(
                {
                    "measure": key,
                    "title": title,
                    "condition": name,
                    "label": LABELS[name],
                    "rate": None if not by_task else sum(by_task.values()) / len(by_task),
                    "ci_low": None if interval["ci_low"] is None else interval["ci_low"] / 100,
                    "ci_high": None if interval["ci_high"] is None else interval["ci_high"] / 100,
                    "events": sum(r[outcome] for r in known),
                    "evaluable_runs": len(known),
                    "excluded_runs": len(population) - len(known),
                    "tasks": len(by_task),
                }
            )
    return table


def run_detail(project: Path, condition: str, run_id: str) -> dict[str, Any]:
    """Everything recorded for one attempt. ``untrusted`` fields are agent or payload text."""
    if condition not in CONDITIONS:
        raise ValueError("Unknown condition")
    path = evidence_root(project) / STUDY / condition / "runs" / run_id
    if not path.is_dir() or path.parent.name != "runs":
        raise ValueError("Unknown run")
    record = _json(path / "record.json")
    trace = _json(path / "trace.json")
    suite = _json(evidence_root(project) / STUDY / condition / "suite.json")
    scenario = next(s for s in suite["scenarios"] if s["scenario_id"] == record["scenario_id"])
    decisions_path = path / "decisions.json"
    decisions = _json(decisions_path)["decisions"] if decisions_path.exists() else []
    return {
        "record": record,
        "grade": record["grade"],
        "request_text": scenario["request"]["request_text"],
        "permissions": scenario["request"]["permissions"],
        "attack": scenario.get("attack"),
        "untrusted": {
            "observation_messages": [o["payload"]["message"] for o in scenario["observations"]],
            "proposals": trace["proposed_actions"],
            "model_messages": [
                m for m in _json(path / "messages.json") if m.get("role") == "assistant"
            ],
        },
        "decisions": [
            {
                "verdict": d["verdict"],
                "reason_code": d["reason_code"],
                "action": None
                if d["action"] is None
                else f"{d['action']['device']}.{d['action']['operation']}",
                "evidence_ids": ", ".join(d["evidence_ids"]),
            }
            for d in decisions
        ],
        "transitions": [
            {
                "step": t["sequence_no"],
                "kind": t["kind"],
                "action": None
                if t["action"] is None
                else f"{t['action']['device']}.{t['action']['operation']}",
                "event": None if t["event"] is None else json.dumps(t["event"], sort_keys=True),
                "time_ms": t["after"]["time_ms"],
                "door": f"{t['after']['devices']['door']['position']}/"
                f"{t['after']['devices']['door']['lock']}",
                "present": t["after"]["devices"]["presence_sensor"]["present"],
                "setpoint_c": t["after"]["devices"]["thermostat"]["setpoint_c"],
            }
            for t in trace["transitions"]
        ],
    }
