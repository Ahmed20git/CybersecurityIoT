"""Verify a saved evidence bundle and independently regenerate its grades."""

import hashlib
import re
from pathlib import Path
from typing import Any

from effectshield.agent.conditions import parse_condition
from effectshield.grading import grade
from effectshield.scenarios import load_suite

from .report import summarize
from .storage import canonical, digest, load_json


def _verify_decisions(
    path: Path, trace: dict[str, Any], row: dict[str, Any], batch: dict[str, Any]
) -> None:
    """Protected runs must keep decision records that agree with the simulator trace."""
    from .protected import DECISION_SCHEMA_VERSION, decision_summary, repairs_from_decisions

    record_path = path / "decisions.json"
    if "mediator_policy" not in batch:
        if record_path.exists() or "mediator" in row:
            raise ValueError("Unprotected run contains mediator decision records")
        return
    document = load_json(record_path)
    if document.get("schema_version") != DECISION_SCHEMA_VERSION:
        raise ValueError("Unsupported mediator decision record")
    decisions = document["decisions"]
    if canonical(decision_summary(decisions)) != canonical(row.get("mediator")):
        raise ValueError("Mediator decision tallies differ from the run record")
    fingerprint = batch["mediator_policy"]["fingerprint"]
    if any(canonical(item["policy"]) != canonical(fingerprint) for item in decisions):
        raise ValueError("A decision used a policy other than the batch's pinned policy")
    executed = [
        action
        for item in decisions
        if (item.get("execution") or {}).get("status") == "committed"
        for action in item["executed_actions"]
    ]
    if canonical(executed) != canonical(trace["executed_actions"]):
        raise ValueError("Committed decisions differ from the trace's executed actions")
    try:
        expected = repairs_from_decisions(decisions, trace["transitions"])
    except ValueError:
        # The runner marks such a run invalid and records no repair references.
        if trace["repairs"] or trace["termination"] != "invalid_response":
            raise ValueError("Unresolvable repair decision was not marked invalid") from None
        return
    if canonical(expected) != canonical(trace["repairs"]):
        raise ValueError("Trace repairs differ from the recorded repair decisions")


def verify_evidence(directory: str | Path) -> dict[str, Any]:
    directory = Path(directory)
    manifest = load_json(directory / "evidence_manifest.json")
    files = manifest.get("files")
    if manifest.get("schema_version") != "evaluation-artifacts/v1" or not isinstance(files, dict):
        raise ValueError("Invalid evidence manifest")
    actual = {
        str(path.relative_to(directory))
        for path in directory.rglob("*")
        if path.is_file() and path != directory / "evidence_manifest.json"
    }
    if actual != set(files):
        raise ValueError("Evidence files are missing or added")
    for relative, expected in files.items():
        path = directory / relative
        if (
            path.is_symlink()
            or not path.resolve().is_relative_to(directory.resolve())
            or hashlib.sha256(path.read_bytes()).hexdigest() != expected
        ):
            raise ValueError("Evidence hash or path verification failed")
    suite = load_suite(directory / "suite.json")
    by_id = {scenario["scenario_id"]: scenario for scenario in suite["scenarios"]}
    batch = load_json(directory / "manifest.json")
    if batch.get("schema_version") != "evaluation-evidence/v1":
        raise ValueError("Unsupported batch evidence schema_version")
    if digest(suite) != batch.get("suite_sha256") or digest(batch["protocol"]) != batch.get(
        "protocol_sha256"
    ):
        raise ValueError("Batch suite/protocol identity does not match its records")
    condition = None
    if "condition" in batch or "condition_sha256" in batch:
        condition = parse_condition(batch.get("condition"))
        if (
            digest(condition.to_dict()) != batch.get("condition_sha256")
            or condition.prompt_version != batch["protocol"]["prompt_version"]
            or batch["mode"] not in ("baseline", "pilot")
            or condition.requires_mediator != ("mediator_policy" in batch)
            or ("scripted_inputs_sha256" in batch) != (batch["mode"] == "baseline")
            or (
                batch["mode"] == "baseline"
                and digest(load_json(directory / "scripted_inputs.json"))
                != batch["scripted_inputs_sha256"]
            )
        ):
            raise ValueError("Condition identity or execution mode differs from the batch")
    records: list[dict[str, Any]] = []
    ledger = directory / "ledger.jsonl"
    # Reuse the strict object parser per JSONL row without writing temporary files.
    import json

    from .storage import _pairs

    starts: dict[str, dict[str, Any]] = {}
    finished: set[str] = set()
    for line in ledger.read_text().splitlines():
        row = json.loads(line, object_pairs_hook=_pairs)
        run_id = row["run_id"]
        if not isinstance(run_id, str) or not re.fullmatch(r"[a-f0-9]{32}", run_id):
            raise ValueError("Invalid run ID in ledger")
        if row["event"] == "started":
            if run_id in starts:
                raise ValueError("Duplicate started run ID")
            starts[run_id] = row
        elif row["event"] == "finished":
            if run_id not in starts or run_id in finished:
                raise ValueError("Missing start or duplicate finish record")
            finished.add(run_id)
            if any(
                canonical(value) != canonical(row.get(key))
                for key, value in starts[run_id].items()
                if key not in {"event", "at"}
            ):
                raise ValueError("Started and finished attempt identity differs")
            path = directory / "runs" / run_id
            trace = load_json(path / "trace.json")
            if (
                digest(trace) != row.get("trace_sha256")
                or canonical(trace["proposed_actions"]) != canonical(row["proposed_actions"])
                or canonical(trace["executed_actions"]) != canonical(row["executed_actions"])
                or trace["termination"] != row["status"]
            ):
                raise ValueError("Trace identity/actions/status differ from ledger")
            actual_grade = grade(by_id[row["scenario_id"]], trace)
            if canonical(actual_grade) != canonical(row["grade"]):
                raise ValueError("Recomputed grade differs from ledger")
            if canonical(actual_grade) != canonical(load_json(path / "grade.json")):
                raise ValueError("Grade artifact differs from ledger")
            if canonical(row) != canonical(load_json(path / "record.json")):
                raise ValueError("Run metadata differs from ledger")
            _verify_decisions(path, trace, row, batch)
            if condition is not None:
                scenario = by_id[row["scenario_id"]]
                expected = {
                    "condition_id": condition.condition_id,
                    "condition_sha256": batch["condition_sha256"],
                    "prompt_version": condition.prompt_version,
                    "model_config": batch["protocol"]["model"],
                    "run_limits": batch["protocol"]["limits"],
                    "scenario_sha256": digest(scenario),
                    "batch_id": batch["batch_id"],
                    "mode": batch["mode"],
                    "backend_kind": "fixture" if batch["mode"] == "baseline" else "live",
                }
                if any(
                    canonical(row.get(key)) != canonical(value) for key, value in expected.items()
                ):
                    raise ValueError("Run condition/configuration differs from its batch")
                messages = load_json(path / "messages.json")
                systems = [
                    i for i, message in enumerate(messages) if message.get("role") == "system"
                ]
                if len(systems) > 1 or (actual_grade["trace_valid"] and len(systems) != 1):
                    raise ValueError("Condition evidence requires one initial system prompt")
                if systems:
                    index = systems[0]
                    system = messages[index]["content"]
                    if (
                        system.get("prompt_version") != condition.prompt_version
                        or system.get("safety_instruction") != condition.safety_instruction
                        or canonical(messages[index + 1 : index + 3])
                        != canonical(
                            [
                                {"role": "user", "content": scenario["request"]},
                                {"role": "tool", "content": scenario["observations"]},
                            ]
                        )
                    ):
                        raise ValueError(
                            "Condition prompt or initial model input differs from manifest"
                        )
            records.append(row)
        else:
            raise ValueError("Unknown ledger event")
    if set(starts) != finished:
        raise ValueError("Ledger contains unfinished attempts; inspect interruption evidence")
    summary = summarize(records, batch)
    if canonical(summary) != canonical(load_json(directory / "summary.json")):
        raise ValueError("Recomputed summary differs from saved report")
    return {
        "verified": True,
        "runs": len(records),
        "files": len(files),
        "mode": batch["mode"],
        "notice": "Artifact integrity/regrading is not a live gate pass.",
    }
