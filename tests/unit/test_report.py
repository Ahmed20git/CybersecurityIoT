"""Scientific denominator and action comparison checks without live experiments."""

import copy
import tempfile
import unittest
from pathlib import Path

from effectshield.domain import ActionProposal, DeviceId, Operation
from effectshield.experiments.report import summarize, write_report
from effectshield.experiments.storage import load_json

ROOT = Path(__file__).resolve().parents[2]


class ReportTests(unittest.TestCase):
    def setUp(self):
        protocol = load_json(ROOT / "configs/evaluation/gate.json")
        protocol["repetitions"] = 1
        self.manifest = {
            "protocol": protocol,
            "mode": "offline",
            "batch_id": "synthetic-batch",
            "freeze": None,
            "grader_selfcheck": True,
            "code_revision": None,
            "suite_sha256": "synthetic-suite-hash",
            "protocol_sha256": "synthetic-protocol-hash",
            "planned_runs": [
                {
                    "scenario_id": "case-clean",
                    "task_id": "case",
                    "variant": "clean",
                    "repetition": 1,
                },
                {
                    "scenario_id": "case-attacked",
                    "task_id": "case",
                    "variant": "attacked",
                    "repetition": 1,
                },
            ],
        }
        self.light = ActionProposal(DeviceId.LIGHT, Operation.TURN_ON).to_dict()
        self.door = ActionProposal(DeviceId.DOOR, Operation.UNLOCK).to_dict()

    def record(self, variant, *, attempt=1, valid=True, completed=True):
        return {
            "scenario_id": f"case-{variant}",
            "task_id": "case",
            "variant": variant,
            "repetition": 1,
            "attempt": attempt,
            "run_id": f"{variant}-{attempt}",
            "model_config": copy.deepcopy(self.manifest["protocol"]["model"]),
            "run_limits": copy.deepcopy(self.manifest["protocol"]["limits"]),
            "grade": {
                "trace_valid": valid,
                "task_completed": completed if valid else None,
                "unsafe_effect": False,
            },
            "proposed_actions": [copy.deepcopy(self.light)],
            "executed_actions": [copy.deepcopy(self.light)],
            "usage": {
                "input_tokens": 4,
                "output_tokens": 2,
                "calls": 1,
                "cost": 0.01,
                "cost_status": "synthetic",
            },
            "backend_kind": "fixture",
            "latency_s": 0.5,
            "status": "completed" if valid else "error",
            "reset_verified": True,
            "error": None if valid else "synthetic failed attempt",
        }

    def test_proposed_and_executed_changes_are_separate(self):
        clean, attacked = self.record("clean"), self.record("attacked")
        attacked["proposed_actions"].append(self.door)
        summary = summarize([clean, attacked], self.manifest)
        self.assertEqual(summary["action_changes"]["proposed"]["successes"], 1)
        self.assertEqual(summary["action_changes"]["executed"]["successes"], 0)
        attacked["executed_actions"].append(self.door)
        summary = summarize([clean, attacked], self.manifest)
        self.assertEqual(summary["action_changes"]["executed"]["successes"], 1)

    def test_invalid_and_missing_pairs_remain_in_denominator(self):
        for records in (
            [self.record("clean"), self.record("attacked", valid=False)],
            [self.record("clean")],
            [],
        ):
            with self.subTest(records=len(records)):
                summary = summarize(records, self.manifest)
                for measure in ("proposed", "executed"):
                    self.assertEqual(summary["action_changes"][measure]["total"], 1)
                    self.assertEqual(summary["action_changes"][measure]["unassessable"], 1)
                    self.assertEqual(summary["action_changes"][measure]["successes"], 0)
                self.assertEqual(summary["criteria"]["benign_completion"]["total"], 1)

    def test_retries_do_not_replace_failed_observations(self):
        records = [
            self.record("clean", valid=False),
            self.record("clean", attempt=2),
            self.record("attacked"),
        ]
        summary = summarize(records, self.manifest)
        criterion = summary["criteria"]["benign_completion"]
        self.assertEqual(
            (criterion["successes"], criterion["total"], criterion["rate"]), (1, 2, 0.5)
        )
        self.assertEqual(summary["retries"], 1)
        self.assertEqual(summary["action_changes"]["executed"]["total"], 2)
        self.assertEqual(summary["action_changes"]["executed"]["unassessable"], 2)
        self.assertEqual(summary["usage"]["calls"]["total"], 3)

    def test_mismatched_configuration_makes_pair_unassessable(self):
        clean, attacked = self.record("clean"), self.record("attacked")
        attacked["model_config"]["settings"]["temperature"] = 1
        summary = summarize([clean, attacked], self.manifest)
        self.assertFalse(summary["matched_pairs"][0]["assessable"])

    def test_configuration_json_type_change_is_not_a_matched_pair(self):
        clean, attacked = self.record("clean"), self.record("attacked")
        attacked["model_config"]["settings"]["temperature"] = False
        summary = summarize([clean, attacked], self.manifest)
        self.assertFalse(summary["matched_pairs"][0]["assessable"])

    def test_unknown_usage_never_becomes_zero_cost(self):
        clean, attacked = self.record("clean"), self.record("attacked")
        attacked["usage"]["cost"] = None
        attacked["usage"]["cost_status"] = "unavailable"
        summary = summarize([clean, attacked], self.manifest)
        self.assertIsNone(summary["usage"]["cost"]["total"])
        self.assertEqual(summary["usage"]["cost"]["known_subtotal"], 0.01)
        self.assertEqual(summary["usage"]["cost"]["unknown_runs"], 1)
        summary = summarize([clean], self.manifest)
        self.assertIsNone(summary["usage"]["calls"]["total"])
        self.assertEqual(summary["usage"]["calls"]["unknown_runs"], 1)

    def test_every_offline_and_rehearsal_gate_criterion_is_unassessable(self):
        clean, attacked = self.record("clean"), self.record("attacked")
        attacked["executed_actions"].append(self.door)
        for mode in ("offline", "rehearsal"):
            with self.subTest(mode=mode):
                self.manifest["mode"] = mode
                summary = summarize([clean, attacked], self.manifest)
                self.assertFalse(summary["official_live_evidence"])
                self.assertTrue(
                    all(
                        result["status"] == "unassessable"
                        for result in summary["criteria"].values()
                    )
                )

    def test_incomplete_accounting_preserves_known_subtotal_without_claiming_total(self):
        clean, attacked = self.record("clean"), self.record("attacked")
        attacked["usage"]["accounting_complete"] = False
        summary = summarize([clean, attacked], self.manifest)
        for field, subtotal in (
            ("input_tokens", 8),
            ("output_tokens", 4),
            ("calls", 2),
            ("cost", 0.02),
        ):
            with self.subTest(field=field):
                self.assertIsNone(summary["usage"][field]["total"])
                self.assertEqual(summary["usage"][field]["known_subtotal"], subtotal)
                self.assertEqual(summary["usage"][field]["unknown_runs"], 1)

    def test_report_and_machine_summary_agree_without_overwrite(self):
        summary = summarize([self.record("clean"), self.record("attacked")], self.manifest)
        with tempfile.TemporaryDirectory() as directory:
            write_report(directory, summary)
            self.assertEqual(load_json(Path(directory) / "summary.json"), summary)
            report = (Path(directory) / "report.md").read_text()
            self.assertIn("1/1", report)
            self.assertIn("unassessable", report)
            self.assertIn("clean-1", report)
            self.assertIn("attacked-1", report)
            with self.assertRaises(FileExistsError):
                write_report(directory, summary)


if __name__ == "__main__":
    unittest.main()
