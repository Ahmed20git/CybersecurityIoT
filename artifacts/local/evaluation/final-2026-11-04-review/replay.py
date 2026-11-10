"""Independent recount and offline re-execution of the November 4 final study."""
import json, sys
from collections import defaultdict
from copy import deepcopy
from pathlib import Path
from effectshield.agent.conditions import parse_condition
from effectshield.experiments.baseline import BaselineBackend, ScriptedModel
from effectshield.experiments.protected import ProtectedRunBackend, repairs_from_decisions
from effectshield.grading import grade

ROOT = Path("artifacts/local/evaluation/final-2026-11-04")
suite = {s["scenario_id"]: s for s in json.load(open("scenarios/test/final.json"))["scenarios"]}
out = {}
for cond in ("unprotected", "safety_prompt_only", "effectshield"):
    bundle = ROOT / cond
    manifest = json.load(open(bundle / "manifest.json"))
    condition = parse_condition(manifest["condition"])
    frozen_suite = {s["scenario_id"]: s for s in json.load(open(bundle / "suite.json"))["scenarios"]}
    assert frozen_suite == suite, "bundle suite differs from scenarios/test/final.json"
    rows, regrade_mismatch, replay_mismatch, replayed = [], [], [], 0
    for run in sorted((bundle / "runs").iterdir()):
        rec = json.load(open(run / "record.json"))
        trace = json.load(open(run / "trace.json"))
        scen = suite[rec["scenario_id"]]
        g = grade(scen, trace)
        saved = json.load(open(run / "grade.json"))
        if g != saved:
            regrade_mismatch.append(rec["run_id"])
        rows.append((rec, g))
        if not g["trace_valid"]:
            continue
        # Offline re-execution: same scenario, same recorded proposals, scripted model.
        model = ScriptedModel(deepcopy(trace["proposed_actions"]))
        backend = (ProtectedRunBackend if condition.requires_mediator else BaselineBackend)(model=model, condition=condition)
        backend.reset(deepcopy(scen["initial_state"]), 0)
        backend.schedule_evidence(deepcopy(scen["evidence_schedule"]))
        if "task_intent" in scen:
            backend.issue_task_intent(deepcopy(scen["task_intent"]), list(scen["request"]["permissions"]))
        cfg = {"model": {"provider": "scripted-model", "version": ScriptedModel.model_version, "date": ScriptedModel.model_date, "settings": {}, "seed": 0, "seed_status": "supported"},
               "limits": deepcopy(rec["run_limits"]), "prompt_version": rec["prompt_version"]}
        cfg["limits"]["max_cost"] = max(cfg["limits"].get("max_cost", 0), 1.0)
        events = list(backend.run(deepcopy(scen["request"]), deepcopy(scen["observations"]), cfg))
        hist = [{k: v for k, v in e.items() if k != "type"} for e in events if e["type"] == "committed_transition"]
        executed = [h["action"] for h in hist if h["kind"] == "action"]
        final = events[-1]["final_state"]
        same = executed == trace["executed_actions"] and final == trace["final_state"]
        if condition.requires_mediator:
            decisions = [e["record"] for e in events if e["type"] == "mediator_decision"]
            saved_dec = json.load(open(run / "decisions.json"))
            saved_dec = saved_dec.get("decisions", saved_dec) if isinstance(saved_dec, dict) else saved_dec
            key = lambda ds: [(d["verdict"], d["reason_code"]) for d in ds]
            same = same and key(decisions) == key(saved_dec)
        replayed += 1
        if not same:
            replay_mismatch.append((rec["scenario_id"], rec["run_id"]))
    # Independent task-level rates: mean over repetitions within a task, then over tasks.
    def task_rate(variant, field):
        per = defaultdict(list)
        n = k = 0
        for rec, g in rows:
            if rec["variant"] != variant or not g["trace_valid"] or g.get(field) is None:
                continue
            per[rec["task_id"]].append(bool(g[field])); n += 1; k += bool(g[field])
        rate = sum(sum(v) / len(v) for v in per.values()) / len(per) if per else None
        return {"runs": f"{k}/{n}", "task_rate": round(rate, 3) if rate is not None else None, "tasks": len(per)}
    out[cond] = {
        "runs": len(rows), "invalid": sum(not g["trace_valid"] for _, g in rows),
        "regrade_mismatches": len(regrade_mismatch), "replayed_valid_runs": replayed, "replay_mismatches": replay_mismatch,
        "attacked_unsafe": task_rate("attacked", "unsafe_effect"),
        "attack_success": task_rate("attacked", "attack_success"),
        "clean_completion": task_rate("clean", "task_completed"),
        "clean_unsafe": task_rate("clean", "unsafe_effect"),
        "attacked_completion": task_rate("attacked", "task_completed"),
    }
json.dump(out, open(sys.argv[1], "w"), indent=2)
print(json.dumps(out, indent=1))
