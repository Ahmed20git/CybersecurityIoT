"""Trace-replay ablations on retained live evidence (EXP-05, EXP-06), offline."""

from pathlib import Path

from effectshield.experiments.ablation import ablate, replay_trace
from effectshield.experiments.storage import load_json
from effectshield.grading import grade
from effectshield.mediator import Ablation

ROOT = Path(__file__).resolve().parents[2]
PILOT = ROOT / "artifacts/local/evaluation/pilot-2026-10-29"


def test_each_ablation_removes_exactly_its_checks_on_the_same_proposals():
    report = ablate(PILOT / "unprotected")
    assert report["eligible_runs"] == 12 and report["skipped_invalid_runs"] == 0
    variants = report["variants"]
    assert variants["full"]["unsafe"] == 0
    # Rule 2 device scope still stops the injected unlock without provenance checks.
    assert variants["no_provenance"]["unsafe"] == 0
    # Without rules 4-5 the stale and replayed "present" readings authorize unlocks.
    assert variants["no_freshness_replay"]["unsafe"] == 2
    unsafe_without_freshness = {
        row["scenario_id"] for row in report["runs"] if row["no_freshness_replay"]["unsafe_effect"]
    }
    assert unsafe_without_freshness <= {
        s for s in unsafe_without_freshness if "stale" in s or "replay" in s
    }


def test_full_replay_of_protected_proposals_reproduces_the_recorded_grade():
    bundle = PILOT / "effectshield"
    scenarios = {s["scenario_id"]: s for s in load_json(bundle / "suite.json")["scenarios"]}
    for run_id in load_json(bundle / "summary.json")["run_ids"]:
        record = load_json(bundle / "runs" / run_id / "record.json")
        if not record["grade"]["trace_valid"]:
            continue
        scenario = scenarios[record["scenario_id"]]
        proposals = load_json(bundle / "runs" / run_id / "trace.json")["proposed_actions"]
        trace, _ = replay_trace(scenario, proposals, Ablation.FULL)
        recorded = load_json(bundle / "runs" / run_id / "trace.json")
        assert trace["executed_actions"] == recorded["executed_actions"]
        assert grade(scenario, trace)["unsafe_effect"] == record["grade"]["unsafe_effect"]
