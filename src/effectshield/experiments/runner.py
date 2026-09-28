"""Run evaluation attempts in isolation, retaining partial and failed evidence."""

import hashlib
import importlib.util
import math
import multiprocessing
import platform
import queue
import subprocess
import sys
import time
import uuid
from copy import deepcopy
from pathlib import Path
from typing import Any

from effectshield.grading import grade
from effectshield.scenarios import load_suite

from .backends import FixtureBackend, load_backend
from .storage import append_jsonl, canonical, digest, load_json, now, redact, write_json

END_STATUSES = {"completed", "abstained", "invalid_response", "error", "timeout", "budget_exceeded"}
PUBLIC_EVENTS = {
    "proposed_action",
    "committed_transition",
    "observation",
    "message",
    "usage",
    "finish",
}


def _worker(
    channel: Any,
    acknowledged: Any,
    backend_spec: str | None,
    fixture_path: str | None,
    scenario: dict[str, Any],
    config: dict[str, Any],
) -> None:
    """Only the request, evidence and execution config reach the backend run method."""
    try:
        backend: Any
        if fixture_path and config["mode"] == "baseline":
            from .baseline import BaselineBackend

            backend = BaselineBackend(fixture_path, scenario["scenario_id"])
        elif fixture_path and config["mode"] == "simulator-replay":
            from .replay import SimulatorReplayBackend

            backend = SimulatorReplayBackend(fixture_path, scenario["scenario_id"])
        else:
            if fixture_path:
                backend = FixtureBackend(fixture_path, scenario["scenario_id"])
            else:
                if backend_spec is None:
                    raise ValueError("Backend factory is required")
                backend = load_backend(backend_spec)
        kind = getattr(backend, "kind", None)
        if kind not in {"fixture", "live"}:
            raise ValueError("Backend must declare kind fixture or live")
        if config["mode"] == "gate" and kind != "live":
            raise ValueError("Official gate requires a live backend; fixtures cannot pass")
        channel.put({"type": "backend", "kind": kind})
        reset = backend.reset(deepcopy(scenario["initial_state"]), config["model"]["seed"])
        channel.put({"type": "reset", "state": reset})
        if canonical(reset) != canonical(scenario["initial_state"]):
            raise ValueError("Backend failed deterministic reset/isolation check")
        public_config = {
            key: deepcopy(config[key]) for key in ("model", "limits", "prompt_version")
        }
        finished = False

        def publish(event: dict[str, Any]) -> None:
            nonlocal finished
            canonical(event)  # Reject NaN/non-JSON records before crossing the process boundary.
            if not isinstance(event, dict):
                raise ValueError("Backend events must be objects")
            if not isinstance(event.get("type"), str) or event["type"] not in PUBLIC_EVENTS:
                raise ValueError("Backend emitted an unsupported or reserved harness event")
            if finished:
                raise ValueError("Backend emitted events after finish")
            channel.put(event)
            acknowledged.get()  # Persist/check each event before requesting another operation.
            finished = event.get("type") == "finish"

        # The trusted provider connector can persist exact requests before a
        # synchronous network call, including calls interrupted by wall timeout.
        set_sink = getattr(backend, "set_event_sink", None)
        if callable(set_sink):
            set_sink(publish)
        for event in backend.run(
            deepcopy(scenario["request"]), deepcopy(scenario["observations"]), public_config
        ):
            publish(event)
        if not finished:
            raise ValueError("Backend ended without a finish record")
        channel.put({"type": "worker_done"})
    except BaseException as error:
        channel.put({"type": "worker_error", "error": f"{type(error).__name__}: {error}"})


def _usage(
    event: dict[str, Any],
    previous: dict[str, Any],
    limits: dict[str, Any],
) -> tuple[dict[str, Any], bool]:
    result = {
        key: event.get(key)
        for key in (
            "input_tokens",
            "output_tokens",
            "calls",
            "cost",
            "currency",
            "cost_status",
            "model_version",
            "model_date",
            "seed_status",
        )
    }
    complete = event.get("accounting_complete", True)
    if type(complete) is not bool or (previous.get("accounting_complete") is False and complete):
        raise ValueError("Incomplete usage accounting cannot become complete")
    result["accounting_complete"] = complete
    for key in ("input_tokens", "output_tokens", "calls", "cost"):
        value = result[key]
        if value is None and previous.get(key) is not None:
            raise ValueError(f"Cumulative usage {key} cannot erase an observed value")
        if value is not None:
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError(f"Invalid usage {key}")
            if not math.isfinite(value) or value < 0:
                raise ValueError(f"Invalid usage {key}")
            if key != "cost" and not isinstance(value, int):
                raise ValueError(f"Usage {key} must be an integer")
            if previous.get(key) is not None and value < previous[key]:
                raise ValueError(f"Cumulative usage {key} decreased")
    if result["currency"] != limits["currency"]:
        raise ValueError("Usage currency differs from configured budget")
    if result["cost_status"] not in {"actual", "estimated", "unavailable", "synthetic"}:
        raise ValueError("Unknown cost provenance")
    if result["seed_status"] not in {"supported", "unsupported"}:
        raise ValueError("Unknown seed support")
    if not result["model_version"] or not result["model_date"]:
        raise ValueError("Model version/date missing from usage")
    exceeded = (
        (result["calls"] is not None and result["calls"] > limits["max_calls"])
        or (result["cost"] is not None and result["cost"] > limits["max_cost"])
        or (sum(result[k] or 0 for k in ("input_tokens", "output_tokens")) > limits["max_tokens"])
    )
    return result, exceeded


def run_attempt(
    scenario: dict[str, Any],
    config: dict[str, Any],
    directory: Path,
    *,
    backend_spec: str | None = None,
    fixture_path: Path | None = None,
) -> dict[str, Any]:
    """Write event evidence as it arrives; retain incomplete prefixes after failures."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=False)
    trace: dict[str, Any] = {
        "schema_version": "evaluation-trace/v1",
        "initial_state": deepcopy(scenario["initial_state"]),
        "proposed_actions": [],
        "executed_actions": [],
        "transitions": [],
        "observations": [],
        "final_state": deepcopy(scenario["initial_state"]),
        "complete": False,
        "termination": "error",
        "repairs": [],
    }
    usage: dict[str, Any] = dict.fromkeys(
        (
            "input_tokens",
            "output_tokens",
            "calls",
            "cost",
            "model_version",
            "model_date",
            "seed_status",
        )
    )
    usage.update(currency=config["limits"]["currency"], cost_status="unavailable")
    context = multiprocessing.get_context("spawn")
    channel = context.Queue(maxsize=64)
    acknowledged = context.Queue(maxsize=1)
    process = context.Process(
        target=_worker,
        args=(
            channel,
            acknowledged,
            backend_spec,
            str(fixture_path) if fixture_path else None,
            deepcopy(scenario),
            deepcopy(config),
        ),
    )
    error = None
    backend_kind = None
    reset_verified = False
    finished = None
    event_count = 0
    started_at = now()
    start = time.monotonic()
    messages = [
        {"role": "user", "content": scenario["request"]["request_text"]},
        {"role": "tool", "content": deepcopy(scenario["observations"])},
    ]
    try:
        process.start()
        while True:
            elapsed = time.monotonic() - start
            remaining = config["limits"]["wall_timeout_s"] - elapsed
            if remaining <= 0:
                trace["termination"] = "timeout"
                error = "Wall-clock limit reached; partial events retained"
                break
            try:
                event = channel.get(timeout=min(remaining, 0.1))
            except queue.Empty:
                if not process.is_alive():
                    error = "Backend exited without a durable completion record"
                    break
                continue
            event_count += 1
            if event_count > 10000 or len(canonical(event)) > 1_000_000:
                raise ValueError("Backend event size/count limit exceeded")
            safe_event = redact(event)
            append_jsonl(directory / "events.jsonl", {"received_at": now(), "event": safe_event})
            event_type = event.get("type")
            if event_type == "backend":
                backend_kind = event["kind"]
            elif event_type == "reset":
                reset_verified = canonical(event["state"]) == canonical(scenario["initial_state"])
                if not reset_verified:
                    raise ValueError("Reset snapshot mismatch")
            elif event_type == "proposed_action":
                trace["proposed_actions"].append(safe_event["action"])
                if len(trace["proposed_actions"]) > config["limits"]["max_steps"]:
                    trace["termination"] = "budget_exceeded"
                    error = "Proposed-action limit exceeded"
                    break
            elif event_type == "committed_transition":
                # Retain native action, environment and clock entries without projection.
                transition = {key: value for key, value in safe_event.items() if key != "type"}
                trace["transitions"].append(transition)
                if transition.get("kind") == "action":
                    trace["executed_actions"].append(transition["action"])
                trace["final_state"] = deepcopy(transition["after"])
                if len(trace["transitions"]) > config["limits"]["max_steps"]:
                    trace["termination"] = "budget_exceeded"
                    error = "Committed-transition limit exceeded"
                    break
            elif event_type == "observation":
                trace["observations"].append(safe_event["receipt"])
                if len(trace["observations"]) > config["limits"]["max_steps"]:
                    trace["termination"] = "budget_exceeded"
                    error = "Observation limit exceeded"
                    break
            elif event_type == "usage":
                usage, exceeded = _usage(safe_event, usage, config["limits"])
                if exceeded:
                    trace["termination"] = "budget_exceeded"
                    error = "Reported usage exceeds approved per-attempt budget"
                    break
            elif event_type == "message":
                if safe_event.get("role") not in {"system", "user", "assistant", "tool"}:
                    raise ValueError("Invalid visible-message role")
                messages.append({"role": safe_event["role"], "content": safe_event["content"]})
            elif event_type == "finish":
                finished = event.get("status")
                if finished not in END_STATUSES:
                    raise ValueError("Unknown finish status")
                if backend_kind == "live" or "committed_count" in event or "final_state" in event:
                    if (
                        type(event.get("committed_count")) is not int
                        or event["committed_count"] != len(trace["transitions"])
                        or canonical(event.get("final_state")) != canonical(trace["final_state"])
                    ):
                        raise ValueError(
                            "Final simulator snapshot/commit count disagrees with trace"
                        )
                trace["termination"] = finished
                error = safe_event.get("error")
            elif event_type == "worker_done":
                if config["mode"] == "gate":
                    if any(
                        usage.get(key) is None
                        for key in ("input_tokens", "output_tokens", "calls", "cost")
                    ):
                        raise ValueError("Official live evidence has unknown usage/cost")
                    if (
                        usage["cost_status"] not in {"actual", "estimated"}
                        or usage["calls"] < 1
                        or usage.get("accounting_complete") is not True
                    ):
                        raise ValueError(
                            "Official live evidence requires actual calls "
                            "and complete usage accounting"
                        )
                    if any(
                        usage[key] != config["model"][config_key]
                        for key, config_key in (
                            ("model_version", "version"),
                            ("model_date", "date"),
                            ("seed_status", "seed_status"),
                        )
                    ):
                        raise ValueError("Live model provenance differs from frozen configuration")
                trace["complete"] = reset_verified and finished in {"completed", "abstained"}
                break
            elif event_type == "worker_error":
                trace["termination"] = "error"
                error = safe_event["error"]
                break
            else:
                raise ValueError("Unsupported backend event type")
            if event_type in PUBLIC_EVENTS:
                acknowledged.put(True)
    except KeyboardInterrupt:
        trace["termination"] = "interrupted"
        error = "User interrupted attempt; partial evidence retained"
    except (ValueError, KeyError, TypeError, OSError, OverflowError) as failure:
        trace["termination"] = "invalid_response"
        trace["complete"] = False
        error = redact(f"{type(failure).__name__}: {failure}")
    finally:
        if process.is_alive():
            process.terminate()
        if process.pid is not None:
            process.join(timeout=2)
        if process.is_alive():
            process.kill()
            process.join(timeout=2)
        channel.close()
        acknowledged.close()
    if backend_kind == "live" and trace["termination"] not in {"completed", "abstained"}:
        # A killed/failed worker may have submitted an unreported paid request.
        # Preserve known subtotals without treating them as complete billing.
        usage.update(accounting_complete=False, cost_status="unavailable")
    latency = time.monotonic() - start
    verdict = grade(scenario, trace)
    if not verdict["trace_valid"] and trace["termination"] == "completed":
        trace["termination"] = "invalid_response"
        trace["complete"] = False
        verdict = grade(scenario, trace)
    write_json(directory / "trace.json", trace)
    write_json(directory / "grade.json", verdict)
    write_json(directory / "messages.json", redact(messages))
    return {
        "status": trace["termination"],
        "error": error,
        "backend_kind": backend_kind,
        "reset_verified": reset_verified,
        "started_at": started_at,
        "ended_at": now(),
        "latency_s": latency,
        "usage": usage,
        "grade": verdict,
        "trace_sha256": digest(trace),
        "proposed_actions": trace["proposed_actions"],
        "executed_actions": trace["executed_actions"],
    }


def run_suite(
    suite_path: Path,
    config: dict[str, Any],
    output: Path,
    *,
    mode: str = "offline",
    backend_spec: str | None = None,
    fixture_path: Path | None = None,
    freeze_path: Path | None = None,
    invocation: list[str] | None = None,
) -> dict[str, Any]:
    """Each scheduled cell and every retry is retained; output paths are exclusive."""
    from .checks import grader_selfcheck
    from .freeze import implementation_hash, validate_protocol, verify_freeze
    from .report import summarize, write_report

    if mode not in {"offline", "simulator-replay", "baseline", "rehearsal", "gate"}:
        raise ValueError("Unknown experiment mode")
    if mode in {"simulator-replay", "baseline"} and not fixture_path:
        raise ValueError("Offline simulator/agent checks require fixture proposals")
    if mode == "gate" and (fixture_path or not freeze_path):
        raise ValueError("Official gate requires verified freeze and live backend")
    if not fixture_path and not backend_spec:
        raise ValueError("A fixture source or Ahmed's backend connector is required")
    if fixture_path and backend_spec:
        raise ValueError("Choose one backend")
    validate_protocol(config, official=mode == "gate")
    if (
        config["repetitions"] is None
        or config["attack_reliability_threshold"] is None
        or any(value is None for value in config["limits"].values())
    ):
        raise ValueError("Execution requires concrete repetitions, threshold and run limits")
    suite = load_suite(suite_path)
    if canonical(suite) != canonical(redact(suite)):
        raise ValueError(
            "Scenario suite contains recognizable credentials; redact before evaluation"
        )
    root = Path(__file__).resolve().parents[3]
    freeze_manifest = None
    if mode == "gate":
        assert freeze_path is not None and backend_spec is not None
        freeze_manifest = verify_freeze(Path(freeze_path))
        if freeze_manifest["implementation_sha256"] != implementation_hash(root):
            raise ValueError("Implementation changed after freeze; review and create a new freeze")
        if canonical(config) != canonical(load_json(Path(freeze_path) / "protocol.json")):
            raise ValueError("Protocol differs from frozen snapshot")
        if canonical(suite) != canonical(load_json(Path(freeze_path) / "suite.json")):
            raise ValueError("Suite differs from frozen snapshot")
        if backend_spec != config["backend_approval"]["module"]:
            raise ValueError("Backend differs from approved connector")
        module = backend_spec.split(":", 1)[0]
        if not module.startswith("effectshield."):
            raise ValueError("Official connector must live within the frozen effectshield package")
        specification = importlib.util.find_spec(module)
        if specification is None or not specification.origin:
            raise ValueError("Ahmed's connector module is not available")
        origin = Path(specification.origin).resolve()
        if not origin.is_relative_to(root / "src/effectshield"):
            raise ValueError("Live connector resolves outside the frozen source tree")
        snapshot_key = "source/" + str(origin.relative_to(root))
        if (
            freeze_manifest["files"].get(snapshot_key)
            != hashlib.sha256(origin.read_bytes()).hexdigest()
        ):
            raise ValueError("Live connector source is not covered by this freeze")
        selfcheck_path = Path(freeze_path) / "source/fixtures/evaluation/grader_cases.json"
    else:
        selfcheck_path = root / "fixtures/evaluation/grader_cases.json"
    if not fixture_path:
        for decision in ("D03", "D04", "D05", "D10", "D11", "D13"):
            if config["decision_status"][decision] != "approved":
                raise ValueError(f"Live rehearsal/gate blocked by pending {decision}")
        if backend_spec != config["backend_approval"]["module"]:
            raise ValueError("Live connector is not the approved module")
        if not all(config["model"][key] for key in ("provider", "version", "date")):
            raise ValueError("Live provider/version/date not configured")
    selfcheck = grader_selfcheck(selfcheck_path)
    output = Path(output)
    if output.exists():
        raise FileExistsError("Evidence output already exists; never overwrite an earlier attempt")
    if mode == "gate":
        assert freeze_path is not None and freeze_manifest is not None
        claim_gate_once(Path(freeze_path), freeze_manifest["freeze_id"], output)
    output.mkdir(parents=True, exist_ok=False)
    batch_id = uuid.uuid4().hex
    effective = deepcopy(config)
    effective["mode"] = mode
    scenarios = suite["scenarios"]
    planned = [
        {
            "scenario_id": scenario["scenario_id"],
            "task_id": scenario["task_id"],
            "variant": scenario["variant"],
            "repetition": repetition,
        }
        for repetition in range(1, config["repetitions"] + 1)
        for scenario in scenarios
    ]
    commit = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True)
    manifest = {
        "schema_version": "evaluation-evidence/v1",
        "batch_id": batch_id,
        "mode": mode,
        "created_at": now(),
        "suite_sha256": digest(suite),
        "protocol_sha256": digest(config),
        "protocol": deepcopy(config),
        "planned_runs": planned,
        "code_revision": commit.stdout.strip() if commit.returncode == 0 else None,
        "freeze": freeze_manifest,
        "label": (
            "bounded baseline with scripted model"
            if mode == "baseline"
            else "recorded proposals executed by simulator"
            if mode == "simulator-replay"
            else "fixture evaluation"
            if fixture_path
            else mode
        ),
        "grader_selfcheck": selfcheck["passed"],
        "grader_fixture_check": selfcheck,
        "implementation_sha256": implementation_hash(root),
        "runtime": {"python": sys.version, "platform": platform.platform()},
        "maximum_attempts": len(planned) * config["retry"]["max_attempts"],
        "maximum_reported_cost": len(planned)
        * config["retry"]["max_attempts"]
        * config["limits"]["max_cost"],
        "command": invocation,
        "execution_inputs": {
            "suite": str(Path(suite_path).resolve()),
            "backend": backend_spec,
            "fixtures": str(Path(fixture_path).resolve()) if fixture_path else None,
            "freeze": str(Path(freeze_path).resolve()) if freeze_path else None,
        },
    }
    write_json(output / "manifest.json", manifest)
    write_json(output / "suite.json", suite)
    records = []
    for cell in planned:
        scenario = next(s for s in scenarios if s["scenario_id"] == cell["scenario_id"])
        for attempt in range(1, config["retry"]["max_attempts"] + 1):
            run_id = uuid.uuid4().hex
            prefix = {
                **cell,
                "attempt": attempt,
                "run_id": run_id,
                "batch_id": batch_id,
                "mode": mode,
                "scenario_sha256": digest(scenario),
                "prompt_version": config["prompt_version"],
                "schema_version": scenario["schema_version"],
                "rule_version": scenario["policy"]["version"],
                "model_config": config["model"],
                "run_limits": config["limits"],
            }
            append_jsonl(output / "ledger.jsonl", {**prefix, "event": "started", "at": now()})
            result = run_attempt(
                scenario,
                effective,
                output / "runs" / run_id,
                backend_spec=backend_spec,
                fixture_path=fixture_path,
            )
            record = {**prefix, **result, "event": "finished", "evidence": f"runs/{run_id}"}
            append_jsonl(output / "ledger.jsonl", record)
            write_json(output / "runs" / run_id / "record.json", record)
            records.append(record)
            if result["status"] in {"completed", "abstained", "interrupted"}:
                break
        if records[-1]["status"] == "interrupted":
            break
    summary = summarize(records, manifest)
    write_report(output, summary)
    evidence = {
        "schema_version": "evaluation-artifacts/v1",
        "files": {
            str(p.relative_to(output)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(output.rglob("*"))
            if p.is_file()
        },
    }
    write_json(output / "evidence_manifest.json", evidence)
    return summary


def claim_gate_once(freeze_path: Path, freeze_id: str, output: Path) -> None:
    """Prevent silent fresh batches under one frozen protocol after viewing outcomes."""
    marker = freeze_path.parent / (freeze_path.name + ".gate-started.json")
    write_json(
        marker,
        {
            "freeze_id": freeze_id,
            "started_at": now(),
            "output": str(output.resolve()),
            "notice": (
                "Retain this marker. A new gate needs a reviewed protocol deviation and new freeze."
            ),
        },
    )
