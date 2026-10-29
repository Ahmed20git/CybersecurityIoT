"""Final-study freeze bindings and block-randomized condition order (EXP-09, DAT-07)."""

import json
import shutil
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from effectshield.experiments.audit import verify_evidence
from effectshield.experiments.comparison import run_comparison, verify_comparison
from effectshield.experiments.final import run_final
from effectshield.experiments.freeze import (
    FINAL_DECISIONS,
    FreezeError,
    approval_hashes,
    freeze_protocol,
    verify_freeze,
)
from effectshield.experiments.storage import load_json

ROOT = Path(__file__).resolve().parents[2]
FINAL = ROOT / "scenarios/test/final.json"
CONDITIONS = ROOT / "configs/conditions"


def small_suite(directory):
    suite = load_json(FINAL)
    suite["scenarios"] = suite["scenarios"][:4]  # two base tasks, clean and attacked
    path = directory / "suite.json"
    path.write_text(json.dumps(suite))
    return path


def test_block_randomized_comparison_records_and_follows_its_order():
    config = load_json(ROOT / "configs/evaluation/final.json")
    config["repetitions"] = 2
    with TemporaryDirectory() as temporary:
        root = Path(temporary)
        output = root / "comparison"
        result = run_comparison(
            small_suite(root),
            ROOT / "fixtures/evaluation/final_runs.json",
            config,
            CONDITIONS,
            output,
            order_seed=11,
        )
        assert result["status"] == "matched" and len(result["matched_cells"]) == 8
        assert verify_comparison(output)["verified"]
        blocks = load_json(output / "comparison_plan.json")["execution_order"]["blocks"]
        assert len(blocks) == 8
        assert all(sorted(b["conditions"]) == sorted(blocks[0]["conditions"]) for b in blocks)
        assert len({tuple(b["conditions"]) for b in blocks}) > 1  # order is actually shuffled
        started = []
        for name in ("unprotected", "safety_prompt_only", "effectshield"):
            assert verify_evidence(output / name)["verified"]
            for line in (output / name / "ledger.jsonl").read_text().splitlines():
                row = json.loads(line)
                if row["event"] == "started":
                    started.append((row["at"], row["repetition"], row["scenario_id"], name))
        executed = [(rep, scenario, name) for _, rep, scenario, name in sorted(started)]
        planned = [
            (b["repetition"], b["scenario_id"], name) for b in blocks for name in b["conditions"]
        ]
        assert executed == planned


def test_frozen_final_needs_a_live_connector_and_seeded_order():
    with TemporaryDirectory() as temporary, pytest.raises(ValueError, match="seeded run order"):
        run_comparison(
            FINAL,
            None,
            load_json(ROOT / "configs/evaluation/final.json"),
            CONDITIONS,
            Path(temporary) / "x",
            backend_spec="effectshield.experiments.openai_baseline:create_backend",
            freeze_path=Path(temporary),
        )


class FinalFreeze:
    def __init__(self, root, *, d12="approved", decisions=FINAL_DECISIONS):
        # A synthetic project root, as in the unit freeze tests: the freeze binds the
        # source tree that contains the protocol file.
        project = root / "project"
        source = project / "src/effectshield/stand_in.py"
        source.parent.mkdir(parents=True)
        source.write_text("# Test-only frozen implementation.\n")
        (project / "docs").mkdir()
        (project / "docs/evaluation_interface.md").write_text("Test-only interface.\n")
        cases = project / "fixtures/evaluation/grader_cases.json"
        cases.parent.mkdir(parents=True)
        cases.write_text('{"schema_version":"test-only/v1","cases":[]}\n')
        config = load_json(ROOT / "configs/evaluation/final.json")
        config["decision_status"]["D12"] = d12
        self.config = project / "configs/final.json"
        self.config.parent.mkdir()
        self.config.write_text(json.dumps(config))
        self.approval = root / "approval.json"
        hashes = approval_hashes(project, self.config, FINAL, CONDITIONS)
        self.approval.write_text(
            json.dumps(
                {
                    "approved_by": "Synthetic test identity",
                    "approved_at": "2026-11-02T10:00:00+04:00",
                    "decisions": list(decisions),
                    "notes": "Synthetic test fixture only; not a project approval",
                    **hashes,
                }
            )
        )
        self.output = root / "frozen"

    def freeze(self, conditions=CONDITIONS):
        return freeze_protocol(self.config, FINAL, self.output, self.approval, conditions)


def test_final_freeze_binds_conditions_and_final_decisions():
    with TemporaryDirectory() as temporary:
        frozen = FinalFreeze(Path(temporary))
        manifest = frozen.freeze()
        assert "conditions_sha256" in manifest and manifest["suite_schema_version"].endswith("v2")
        for name in ("unprotected", "safety_prompt_only", "effectshield"):
            assert (frozen.output / "conditions" / f"{name}.json").exists()
        assert verify_freeze(frozen.output)["freeze_id"] == manifest["freeze_id"]
        path = frozen.output / "conditions/effectshield.json"
        condition = load_json(path)
        condition["condition_version"] = "tampered"
        path.write_text(json.dumps(condition))
        with pytest.raises(FreezeError):
            verify_freeze(frozen.output)


@pytest.mark.parametrize("problem", ["d12_pending", "approval_without_d12", "no_conditions"])
def test_final_freeze_refuses_unresolved_decisions_or_missing_conditions(problem):
    with TemporaryDirectory() as temporary:
        root = Path(temporary)
        if problem == "d12_pending":
            frozen = FinalFreeze(root, d12="pending")
        elif problem == "approval_without_d12":
            frozen = FinalFreeze(root, decisions=[d for d in FINAL_DECISIONS if d != "D12"])
        else:
            frozen = FinalFreeze(root)
        with pytest.raises(FreezeError):
            frozen.freeze(None if problem == "no_conditions" else CONDITIONS)
        assert not frozen.output.exists()


def test_final_runs_only_from_a_final_freeze_and_never_overwrites():
    with TemporaryDirectory() as temporary:
        root = Path(temporary)
        frozen = FinalFreeze(root)
        frozen.freeze()
        existing = root / "existing"
        existing.mkdir()
        with pytest.raises(FileExistsError):
            run_final(frozen.output, existing)
        assert not (root / "frozen.gate-started.json").exists()  # nothing claimed
        gate_like = root / "gate-freeze"
        shutil.copytree(frozen.output, gate_like)
        manifest = load_json(gate_like / "manifest.json")
        manifest.pop("conditions_sha256")
        (gate_like / "manifest.json").write_text(json.dumps(manifest))
        with pytest.raises((ValueError, FreezeError)):
            run_final(gate_like, root / "out")
