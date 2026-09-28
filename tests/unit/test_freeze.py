"""Freeze safeguards, using temporary human-approval fixtures only."""

import copy
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from effectshield.experiments.freeze import (
    REQUIRED_DECISIONS,
    FreezeError,
    approval_hashes,
    freeze_protocol,
    implementation_hash,
    validate_protocol,
    verify_freeze,
)


class FreezeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "project"
        self.source = self.root / "src/effectshield/grading/outcomes.py"
        self.source.parent.mkdir(parents=True)
        self.source.write_text("# Test-only frozen grading implementation.\n")
        self.interface = self.root / "docs/evaluation_interface.md"
        self.interface.parent.mkdir(parents=True)
        self.interface.write_text("Test-only evaluation-trace/v1 interface.\n")
        cases = self.root / "fixtures/evaluation/grader_cases.json"
        cases.parent.mkdir(parents=True)
        cases.write_text('{"schema_version":"test-only/v1","cases":[]}\n')
        self.config_path = self.root / "configs/evaluation/gate.json"
        self.config_path.parent.mkdir(parents=True)
        self.suite_path = self.root / "scenarios/development/baseline.json"
        self.suite_path.parent.mkdir(parents=True)
        self.suite_path.write_text(
            json.dumps(
                {
                    "schema_version": "evaluation-scenario/v1",
                    "suite_version": "test-only/v1",
                    "scenarios": [{"scenario_id": "synthetic", "expected_result": "safe"}],
                }
            )
        )
        self.config = {
            "schema_version": "evaluation-protocol/v1",
            "protocol_version": "test-only/v1",
            "prompt_version": "test-prompt/v1",
            "repetitions": 3,
            "action_change": "executed",
            "attack_reliability_threshold": 0.8,
            "benign_threshold": 0.7,
            "model": {
                "provider": "test-only",
                "version": "test-model-v1",
                "date": "2026-09-21",
                "settings": {"temperature": 0},
                "seed": None,
                "seed_status": "unsupported",
            },
            "limits": {
                "max_steps": 8,
                "max_calls": 4,
                "max_tokens": 10240,
                "wall_timeout_s": 30,
                "max_cost": 0.0,
                "currency": "USD",
            },
            "retry": {"max_attempts": 1},
            "failure_handling": "all_attempts_in_denominator",
            "evidence_root": "artifacts/test-only",
            "backend_approval": {"module": "test_backend:factory", "kind": "live"},
            "decision_status": dict.fromkeys(REQUIRED_DECISIONS, "approved"),
        }
        self.approval_path = self.root / "test-only-approval.json"
        self.output = Path(self.temp.name) / "freeze"
        self.write_config()

    def write_config(self):
        self.config_path.write_text(json.dumps(self.config))

    def approve(self):
        # Synthetic test input; this never constitutes a project human approval.
        value = {
            "approved_by": "Synthetic test identity",
            "approved_at": "2026-09-21T12:00:00+04:00",
            "decisions": list(REQUIRED_DECISIONS),
            "notes": "Synthetic test fixture only",
            **approval_hashes(self.root, self.config_path, self.suite_path),
        }
        self.approval_path.write_text(json.dumps(value))
        return value

    def freeze(self):
        return freeze_protocol(self.config_path, self.suite_path, self.output, self.approval_path)

    def test_approval_required_even_with_all_decisions_marked_approved(self):
        with self.assertRaises(FreezeError):
            freeze_protocol(self.config_path, self.suite_path, self.output)
        self.assertFalse(self.output.exists())

    def test_unknown_protocol_or_scenario_format_cannot_be_frozen(self):
        config = copy.deepcopy(self.config)
        config["schema_version"] = "unknown-protocol/v99"
        with self.assertRaises(FreezeError):
            validate_protocol(config, official=True)
        suite = json.loads(self.suite_path.read_text())
        suite["schema_version"] = "unknown-scenario/v99"
        self.suite_path.write_text(json.dumps(suite))
        self.approve()
        with self.assertRaises(FreezeError):
            self.freeze()
        self.assertFalse(self.output.exists())

    def test_pending_decision_blocks_freeze_before_creating_output(self):
        self.config["decision_status"]["D09"] = "pending"
        self.write_config()
        self.approve()
        with self.assertRaises(FreezeError):
            self.freeze()
        self.assertFalse(self.output.exists())

    def test_incomplete_or_undated_approval_is_rejected(self):
        for field, value in (
            ("decisions", ["D09"]),
            ("approved_by", ""),
            ("approved_at", "2026-09-21T12:00:00"),
        ):
            with self.subTest(field=field):
                approval = self.approve()
                approval[field] = value
                self.approval_path.write_text(json.dumps(approval))
                with self.assertRaises(FreezeError):
                    self.freeze()
                self.assertFalse(self.output.exists())

    def test_rejected_after_any_reviewed_input_changes(self):
        cases = self.root / "fixtures/evaluation/grader_cases.json"
        for path in (self.config_path, self.suite_path, self.source, self.interface, cases):
            with self.subTest(path=path.name):
                self.approve()
                original = path.read_bytes()
                path.write_bytes(original + b"\n")
                try:
                    with self.assertRaises(FreezeError):
                        self.freeze()
                    self.assertFalse(self.output.exists())
                finally:
                    path.write_bytes(original)

    def test_freeze_round_trip_preserves_bytes_and_is_portable(self):
        self.approve()
        manifest = self.freeze()
        self.assertEqual(manifest["implementation_sha256"], implementation_hash(self.root))
        for name, original in (
            ("protocol.json", self.config_path),
            ("suite.json", self.suite_path),
            ("approval.json", self.approval_path),
        ):
            self.assertEqual((self.output / name).read_bytes(), original.read_bytes())
        self.assertIn("source/docs/evaluation_interface.md", manifest["files"])
        self.assertIn("source/fixtures/evaluation/grader_cases.json", manifest["files"])
        moved = Path(self.temp.name) / "moved"
        shutil.move(str(self.output), moved)
        shutil.rmtree(self.root)
        self.assertEqual(verify_freeze(moved), manifest)
        self.assertNotIn(str(self.root), json.dumps(manifest))

    def test_existing_output_is_never_overwritten(self):
        self.approve()
        first = self.freeze()
        before = (self.output / "manifest.json").read_bytes()
        with self.assertRaises(FreezeError):
            self.freeze()
        self.assertEqual((self.output / "manifest.json").read_bytes(), before)
        self.assertEqual(verify_freeze(self.output), first)

    def test_missing_extra_modified_and_symlinked_evidence_are_rejected(self):
        self.approve()
        self.freeze()
        original = (self.output / "suite.json").read_bytes()
        for kind in ("missing", "extra", "modified", "symlink"):
            with self.subTest(kind=kind):
                target = self.output / "suite.json"
                if kind == "missing":
                    target.unlink()
                elif kind == "extra":
                    (self.output / "extra.txt").write_text("extra")
                elif kind == "modified":
                    target.write_bytes(original + b"\n")
                else:
                    target.unlink()
                    target.symlink_to(self.suite_path)
                with self.assertRaises(FreezeError):
                    verify_freeze(self.output)
                if kind == "extra":
                    (self.output / "extra.txt").unlink()
                if target.is_symlink():
                    target.unlink()
                target.write_bytes(original)
        verify_freeze(self.output)

    def test_manifest_mutation_is_detected(self):
        self.approve()
        self.freeze()
        path = self.output / "manifest.json"
        manifest = json.loads(path.read_text())
        manifest["run_semantics"]["repetitions"] = 99
        path.write_text(json.dumps(manifest))
        with self.assertRaises(FreezeError):
            verify_freeze(self.output)

    def test_implementation_digest_binds_names_and_bytes_but_not_cache_files(self):
        first = implementation_hash(self.root)
        cache = self.source.parent / "__pycache__/outcomes.cpython-313.pyc"
        cache.parent.mkdir()
        cache.write_bytes(b"regenerable cache")
        self.assertEqual(implementation_hash(self.root), first)
        self.source.rename(self.source.with_name("renamed.py"))
        self.assertNotEqual(implementation_hash(self.root), first)

    def test_source_symlinks_are_rejected(self):
        (self.source.parent / "linked.py").symlink_to(self.source)
        with self.assertRaises(FreezeError):
            implementation_hash(self.root)

    def test_recognizable_credentials_in_source_are_rejected_without_echoing(self):
        sentinel = "sk-" + "x" * 24
        self.source.write_text('API_KEY = "' + sentinel + '"\n')
        with self.assertRaises(FreezeError) as caught:
            implementation_hash(self.root)
        self.assertNotIn(sentinel, str(caught.exception))
        self.assertFalse(self.output.exists())

    def test_draft_accepts_pending_provider_but_official_does_not(self):
        self.config["model"].update(provider=None, version=None, date=None)
        self.config["backend_approval"]["module"] = None
        self.config["decision_status"] = dict.fromkeys(REQUIRED_DECISIONS, "pending")
        validate_protocol(self.config)
        with self.assertRaises(FreezeError):
            validate_protocol(self.config, official=True)

    def test_numeric_boundaries_reject_nonfinite_boolean_and_wrong_units(self):
        edits = [
            (("repetitions",), True),
            (("repetitions",), 0),
            (("repetitions",), 1.5),
            (("attack_reliability_threshold",), float("nan")),
            (("attack_reliability_threshold",), 1.01),
            (("benign_threshold",), 0.8),
            (("limits", "wall_timeout_s"), 0),
            (("limits", "max_cost"), -1),
            (("limits", "max_calls"), True),
            (("limits", "max_tokens"), float("inf")),
            (("retry", "max_attempts"), 0),
            (("model", "seed"), False),
            (("model", "settings", "temperature"), float("nan")),
        ]
        for keys, value in edits:
            with self.subTest(keys=keys, value=value):
                config = copy.deepcopy(self.config)
                target = config
                for key in keys[:-1]:
                    target = target[key]
                target[keys[-1]] = value
                with self.assertRaises(FreezeError):
                    validate_protocol(config)

    def test_seed_support_status_cannot_contradict_the_seed(self):
        self.config["model"]["seed"] = 0
        with self.assertRaisesRegex(FreezeError, "unsupported seed must be null"):
            validate_protocol(self.config)
        self.config["model"]["seed_status"] = "supported"
        validate_protocol(self.config)
        self.config["model"]["seed"] = None
        with self.assertRaises(FreezeError):
            validate_protocol(self.config)

    def test_credentials_and_duplicate_json_keys_are_not_snapshotted(self):
        self.config["model"]["settings"]["api_key"] = "synthetic-secret-sentinel"
        self.write_config()
        self.approve()
        with self.assertRaises(FreezeError):
            self.freeze()
        self.assertFalse(self.output.exists())
        del self.config["model"]["settings"]["api_key"]
        self.write_config()
        self.config_path.write_text(self.config_path.read_text()[:-1] + ',"repetitions":8}')
        self.approve()
        with self.assertRaises(FreezeError):
            self.freeze()
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()
