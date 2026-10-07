"""Run-condition provenance and matched comparisons through the real isolated runner."""

import hashlib
import io
import json
import shutil
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from effectshield.agent.conditions import load_conditions
from effectshield.experiments.audit import verify_evidence
from effectshield.experiments.cli import main
from effectshield.experiments.comparison import (
    comparison_summary,
    run_comparison,
    scripted_protocol,
    verify_comparison,
)
from effectshield.experiments.runner import run_suite
from effectshield.experiments.storage import canonical, load_json

ROOT = Path(__file__).resolve().parents[2]
SUITE = ROOT / "scenarios/development/authorization.json"
FIXTURES = ROOT / "fixtures/evaluation/authorization_runs.json"
CONDITIONS = ROOT / "configs/conditions"


@pytest.fixture(scope="module")
def comparison():
    with TemporaryDirectory() as temporary:
        output = Path(temporary) / "comparison"
        config = load_json(ROOT / "configs/evaluation/gate.json")
        config["repetitions"] = 1
        report = run_comparison(SUITE, FIXTURES, config, CONDITIONS, output)
        yield output, report


@pytest.fixture
def working(comparison):
    with TemporaryDirectory() as temporary:
        output = Path(temporary) / "comparison"
        shutil.copytree(comparison[0], output)
        yield output


def rewrite(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def rehash(bundle):
    path = bundle / "evidence_manifest.json"
    document = load_json(path)
    document["files"] = {
        str(item.relative_to(bundle)): hashlib.sha256(item.read_bytes()).hexdigest()
        for item in bundle.rglob("*")
        if item.is_file() and item != path
    }
    rewrite(path, document)


def test_two_conditions_have_paired_inputs_and_honest_offline_outcomes(comparison):
    output, result = comparison
    assert result["status"] == "matched"
    assert len(result["matched_cells"]) == 17
    assert all(cell["assessable"] for cell in result["matched_cells"])
    assert result["conditions"]["effectshield"]["status"] == "not_run"
    assert not (output / "effectshield").exists()
    assert result["declared_treatment_differences"] == [
        "condition_id",
        "condition_version",
        "prompt_version",
        "safety_instruction",
    ]
    assert verify_comparison(output)["verified"]
    for name in ("unprotected", "safety_prompt_only"):
        row = result["conditions"][name]
        assert row["attempts"] == 17
        assert row["unsafe_attempts"] == 7
        assert row["outcomes"] == {"task_completed": 16, "safe_completion": 10, "unknown_safety": 0}
        assert all(c["status"] == "unassessable" for c in row["criteria"].values())
        assert row["criteria"]["benign_completion"]["successes"] == 10
        assert row["criteria"]["reliable_action_change"]["successes"] == 7


def test_condition_prompt_and_snapshot_are_bound_to_every_run(comparison):
    output, _ = comparison
    conditions = load_conditions(CONDITIONS)
    for name in ("unprotected", "safety_prompt_only"):
        bundle = output / name
        manifest = load_json(bundle / "manifest.json")
        summary = load_json(bundle / "summary.json")
        assert manifest["condition"] == conditions[name].to_dict() == summary["condition"]
        assert load_json(bundle / "scripted_inputs.json") == load_json(FIXTURES)
        for run_id in summary["run_ids"]:
            record = load_json(bundle / "runs" / run_id / "record.json")
            assert record["condition_id"] == name
            assert record["condition_sha256"] == manifest["condition_sha256"]
            assert record["prompt_version"] == conditions[name].prompt_version
            messages = load_json(bundle / "runs" / run_id / "messages.json")
            system = next(m["content"] for m in messages if m["role"] == "system")
            assert system.get("safety_instruction") == conditions[name].safety_instruction
            assert not {"expected_result", "completion", "grade", "policy"} & set(system)
        assert name in (bundle / "report.md").read_text()


@pytest.mark.parametrize("part", ["safety_instruction", "prompt_version", "observations"])
def test_rehashed_prompt_or_input_mismatch_is_rejected(working, part):
    bundle = working / "safety_prompt_only"
    run_id = load_json(bundle / "summary.json")["run_ids"][0]
    path = bundle / "runs" / run_id / "messages.json"
    messages = load_json(path)
    index = next(i for i, m in enumerate(messages) if m["role"] == "system")
    if part == "observations":
        messages[index + 2]["content"][0]["payload"]["message"] = "Modified model input"
    else:
        messages[index]["content"][part] = "Modified treatment"
    rewrite(path, messages)
    rehash(bundle)
    with pytest.raises(ValueError, match="prompt or initial model input"):
        verify_evidence(bundle)


def test_rehashed_condition_relabeling_in_ledger_is_rejected(working):
    bundle = working / "unprotected"
    rows = [json.loads(line) for line in (bundle / "ledger.jsonl").read_text().splitlines()]
    for row in rows:
        row["condition_id"] = "safety_prompt_only"
        if row["event"] == "finished":
            rewrite(bundle / "runs" / row["run_id"] / "record.json", row)
    (bundle / "ledger.jsonl").write_text("".join(canonical(row) + "\n" for row in rows))
    rehash(bundle)
    with pytest.raises(ValueError, match="condition/configuration"):
        verify_evidence(bundle)


def test_rehashed_scripted_input_change_is_rejected(working):
    bundle = working / "unprotected"
    path = bundle / "scripted_inputs.json"
    value = load_json(path)
    value["traces"]["system-claim-clean"]["proposed_actions"] = []
    rewrite(path, value)
    rehash(bundle)
    with pytest.raises(ValueError, match="Condition identity"):
        verify_evidence(bundle)


@pytest.mark.parametrize("field", ["model", "limits", "retry"])
def test_shared_settings_cannot_drift_from_saved_comparison_plan(working, field):
    path = working / "comparison_plan.json"
    value = load_json(path)
    if field == "model":
        value["protocol"][field]["seed"] = 42
    elif field == "limits":
        value["protocol"][field]["max_calls"] += 1
    else:
        value["protocol"][field]["max_attempts"] += 1
    rewrite(path, value)
    with pytest.raises(ValueError, match="inputs differ"):
        comparison_summary(working)


def test_comparison_report_tampering_is_detected(working):
    path = working / "comparison.json"
    value = load_json(path)
    value["conditions"]["effectshield"]["status"] = "passed"
    rewrite(path, value)
    with pytest.raises(ValueError, match="Recomputed comparison"):
        verify_comparison(working)


def test_named_protected_condition_cannot_create_an_unprotected_batch():
    with TemporaryDirectory() as temporary:
        output = Path(temporary) / "blocked"
        config = scripted_protocol(load_json(ROOT / "configs/evaluation/gate.json"))
        condition = load_conditions(CONDITIONS)["effectshield"].to_dict()
        with pytest.raises(ValueError, match="mediator"):
            run_suite(
                SUITE, config, output, mode="baseline", fixture_path=FIXTURES, condition=condition
            )
        assert not output.exists()


def test_prompt_version_mismatch_and_unsupported_modes_fail_before_writing():
    with TemporaryDirectory() as temporary:
        config = scripted_protocol(load_json(ROOT / "configs/evaluation/gate.json"))
        condition = load_conditions(CONDITIONS)["safety_prompt_only"].to_dict()
        output = Path(temporary) / "blocked"
        with pytest.raises(ValueError, match="prompt version"):
            run_suite(
                SUITE, config, output, mode="baseline", fixture_path=FIXTURES, condition=condition
            )
        config["prompt_version"] = condition["prompt_version"]
        with pytest.raises(ValueError, match="scripted baseline"):
            run_suite(
                SUITE, config, output, mode="offline", fixture_path=FIXTURES, condition=condition
            )
        assert not output.exists()


def test_existing_comparison_is_not_overwritten(comparison):
    output, before = comparison
    with pytest.raises(FileExistsError):
        run_comparison(
            SUITE, FIXTURES, load_json(ROOT / "configs/evaluation/gate.json"), CONDITIONS, output
        )
    assert load_json(output / "comparison.json") == before


def test_cli_verifies_comparison_and_refuses_missing_mediator(comparison):
    out = io.StringIO()
    with redirect_stdout(out):
        assert main(["verify-comparison", str(comparison[0])]) == 0
    assert json.loads(out.getvalue())["matched_cells"] == 17
    with TemporaryDirectory() as temporary, redirect_stderr(io.StringIO()) as error:
        output = Path(temporary) / "blocked"
        assert (
            main(
                [
                    "baseline",
                    "--condition",
                    str(CONDITIONS / "effectshield.json"),
                    "--output",
                    str(output),
                ]
            )
            == 2
        )
        assert "mediator" in error.getvalue()
        assert not output.exists()


def test_missing_attempts_are_retained_as_incomplete_comparison(working):
    from effectshield.experiments.report import summarize

    bundle = working / "safety_prompt_only"
    summary = load_json(bundle / "summary.json")
    omitted = summary["run_ids"][0]
    shutil.rmtree(bundle / "runs" / omitted)
    rows = [json.loads(line) for line in (bundle / "ledger.jsonl").read_text().splitlines()]
    rows = [row for row in rows if row["run_id"] != omitted]
    (bundle / "ledger.jsonl").write_text("".join(canonical(row) + "\n" for row in rows))
    records = [row for row in rows if row["event"] == "finished"]
    rewrite(bundle / "summary.json", summarize(records, load_json(bundle / "manifest.json")))
    rehash(bundle)
    result = comparison_summary(working)
    assert result["status"] == "incomplete"
    assert len(result["unmatched_cells"]) == 1
    assert len(result["matched_cells"]) == 16
    assert len(result["conditions"]["safety_prompt_only"]["missing_runs"]) == 1
    # A partial comparison remains inspectable; it cannot inherit the old matched status.
    with pytest.raises(ValueError, match="Recomputed comparison"):
        verify_comparison(working)


def test_budget_stopped_attempts_do_not_count_as_assessable_matches():
    with TemporaryDirectory() as temporary:
        output = Path(temporary)
        suite = load_json(SUITE)
        suite["scenarios"] = suite["scenarios"][:1]
        rewrite(output / "suite.json", suite)
        config = load_json(ROOT / "configs/evaluation/gate.json")
        config["repetitions"] = 1
        config["limits"]["max_calls"] = 1
        result = run_comparison(
            output / "suite.json", FIXTURES, config, CONDITIONS, output / "runs"
        )
        assert result["status"] == "incomplete"
        assert len(result["matched_cells"]) == 1
        assert result["matched_cells"][0]["assessable"] is False
        for name in ("unprotected", "safety_prompt_only"):
            assert result["conditions"][name]["attempts"] == 1
            assert result["conditions"][name]["outcomes"]["unknown_safety"] == 1
            assert result["conditions"][name]["execution_statuses"] == {"budget_exceeded": 1}
        assert verify_comparison(output / "runs")["status"] == "incomplete"


def test_credential_shaped_condition_is_rejected_before_saving_plan():
    with TemporaryDirectory() as temporary:
        root = Path(temporary)
        conditions = root / "conditions"
        shutil.copytree(CONDITIONS, conditions)
        path = conditions / "safety_prompt_only.json"
        condition = load_json(path)
        condition["safety_instruction"] += " sk-" + "x" * 24
        rewrite(path, condition)
        with pytest.raises(ValueError, match="credentials"):
            run_comparison(
                SUITE,
                FIXTURES,
                load_json(ROOT / "configs/evaluation/gate.json"),
                conditions,
                root / "blocked",
            )
        assert not (root / "blocked").exists()
