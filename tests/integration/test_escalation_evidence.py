"""A completed escalation is an observed outcome, not an infrastructure error."""

from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from effectshield.experiments.audit import verify_evidence
from effectshield.experiments.runner import run_suite
from effectshield.experiments.storage import load_json, write_json
from effectshield.grading import grade
from effectshield.scenarios import load_suite

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize("effects", ["none", "authorized", "unsafe"])
def test_escalation_preserves_independent_completion_safety_and_retry_accounting(effects):
    suite = load_suite(ROOT / "scenarios/development/baseline.json")
    scenario = suite["scenarios"][0]
    suite["scenarios"] = [scenario]
    fixtures = load_json(ROOT / "fixtures/evaluation/runs.json")
    trace = deepcopy(
        fixtures["traces"]["light-on-clean-attacked" if effects == "unsafe" else "light-on-clean"]
    )
    trace["termination"] = "escalated"
    if effects == "none":
        trace.update(proposed_actions=[], executed_actions=[], transitions=[])
        trace["final_state"] = deepcopy(trace["initial_state"])
    fixtures["traces"] = {scenario["scenario_id"]: trace}
    expected = grade(scenario, trace)
    assert expected["trace_valid"]
    assert expected["task_completed"] is (effects != "none")
    assert expected["unsafe_effect"] is (effects == "unsafe")
    with TemporaryDirectory() as temporary:
        root = Path(temporary)
        write_json(root / "suite.json", suite)
        write_json(root / "fixtures.json", fixtures)
        config = load_json(ROOT / "configs/evaluation/gate.json")
        config["repetitions"] = 1
        config["retry"]["max_attempts"] = 3
        result = run_suite(
            root / "suite.json", config, root / "output", fixture_path=root / "fixtures.json"
        )
        assert result["status_counts"] == {"escalated": 1}
        assert result["attempts"] == 1 and result["retries"] == 0
        assert result["failures"] == []
        assert result["criteria"]["automatic_grading"]["invalid_traces"] == 0
        assert result["unsafe_attempts"] == (1 if effects == "unsafe" else 0)
        assert result["criteria"]["benign_completion"]["successes"] == (
            0 if effects == "none" else 1
        )
        assert result["criteria"]["benign_completion"]["total"] == 1
        assert verify_evidence(root / "output")["verified"]


def test_incomplete_escalation_cannot_establish_safety():
    scenario = load_suite(ROOT / "scenarios/development/baseline.json")["scenarios"][0]
    trace = deepcopy(load_json(ROOT / "fixtures/evaluation/runs.json")["traces"]["light-on-clean"])
    trace.update(termination="escalated", complete=False)
    verdict = grade(scenario, trace)
    assert not verdict["trace_valid"]
    assert verdict["unsafe_effect"] is None
    assert verdict["task_completed"] is None
