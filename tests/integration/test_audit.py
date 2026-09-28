"""Independent checks of saved offline evidence and regenerated outcomes."""

import hashlib
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from effectshield.domain import ActionProposal, DeviceId, Operation
from effectshield.experiments.audit import verify_evidence
from effectshield.experiments.runner import run_suite
from effectshield.experiments.storage import digest, load_json
from effectshield.grading import grade

ROOT = Path(__file__).resolve().parents[2]


class EvidenceAuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        cls.base = Path(cls.temp.name) / "unchanged-offline-bundle"
        config = load_json(ROOT / "configs/evaluation/gate.json")
        config["repetitions"] = 1
        cls.summary = run_suite(
            ROOT / "scenarios/development/baseline.json",
            config,
            cls.base,
            mode="offline",
            fixture_path=ROOT / "fixtures/evaluation/runs.json",
        )

    def setUp(self):
        self.working = tempfile.TemporaryDirectory(dir=self.temp.name)
        self.addCleanup(self.working.cleanup)
        self.bundle = Path(self.working.name) / "bundle"
        shutil.copytree(self.base, self.bundle)

    def write_json(self, relative, value):
        (self.bundle / relative).write_text(json.dumps(value, indent=2) + "\n")

    def ledger(self):
        return [
            json.loads(line) for line in (self.bundle / "ledger.jsonl").read_text().splitlines()
        ]

    def write_ledger(self, rows):
        (self.bundle / "ledger.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rows))

    def rehash_test_mutations(self):
        """Update only the synthetic fixture manifest to test semantic checks."""
        path = self.bundle / "evidence_manifest.json"
        manifest = load_json(path)
        manifest["files"] = {
            item.relative_to(self.bundle).as_posix(): hashlib.sha256(item.read_bytes()).hexdigest()
            for item in self.bundle.rglob("*")
            if item.is_file() and item != path
        }
        self.write_json("evidence_manifest.json", manifest)

    def first_finished(self):
        return next(row for row in self.ledger() if row["event"] == "finished")

    def test_unchanged_offline_evidence_regrades_all_attempts_and_summary(self):
        result = verify_evidence(self.bundle)
        self.assertTrue(result["verified"])
        self.assertEqual(result["runs"], self.summary["attempts"])
        self.assertGreater(result["runs"], 0)
        self.assertEqual(result["mode"], "offline")
        self.assertIn("not a live gate pass", result["notice"])
        self.assertTrue(
            all(item["status"] == "unassessable" for item in self.summary["criteria"].values())
        )

    def test_changed_grade_trace_summary_and_report_bytes_are_rejected(self):
        run_id = self.first_finished()["run_id"]
        for relative in (
            f"runs/{run_id}/grade.json",
            f"runs/{run_id}/trace.json",
            "summary.json",
            "report.md",
        ):
            with self.subTest(file=relative):
                path = self.bundle / relative
                original = path.read_bytes()
                path.write_bytes(original + b"\n")
                with self.assertRaises(ValueError):
                    verify_evidence(self.bundle)
                path.write_bytes(original)

    def test_added_missing_and_symlinked_files_are_rejected(self):
        extra = self.bundle / "unlisted.txt"
        extra.write_text("unexpected evidence")
        with self.assertRaises(ValueError):
            verify_evidence(self.bundle)
        extra.unlink()
        report = self.bundle / "report.md"
        original = report.read_bytes()
        report.unlink()
        with self.assertRaises(ValueError):
            verify_evidence(self.bundle)
        report.symlink_to(self.base / "report.md")
        with self.assertRaises(ValueError):
            verify_evidence(self.bundle)
        report.unlink()
        report.write_bytes(original)
        self.assertTrue(verify_evidence(self.bundle)["verified"])

    def test_rehashed_grade_still_has_to_match_independent_regrading(self):
        relative = f"runs/{self.first_finished()['run_id']}/grade.json"
        verdict = load_json(self.bundle / relative)
        verdict["task_completed"] = not verdict["task_completed"]
        self.write_json(relative, verdict)
        self.rehash_test_mutations()
        with self.assertRaises(ValueError):
            verify_evidence(self.bundle)

    def test_rehashed_trace_must_still_match_its_recorded_digest(self):
        row = self.first_finished()
        relative = f"runs/{row['run_id']}/trace.json"
        trace = load_json(self.bundle / relative)
        trace["proposed_actions"].append(
            ActionProposal(DeviceId.PRESENCE_SENSOR, Operation.READ).to_dict()
        )
        suite = load_json(self.bundle / "suite.json")
        scenario = next(s for s in suite["scenarios"] if s["scenario_id"] == row["scenario_id"])
        self.assertEqual(grade(scenario, trace), row["grade"])
        self.assertNotEqual(digest(trace), row["trace_sha256"])
        self.write_json(relative, trace)
        self.rehash_test_mutations()
        with self.assertRaises(ValueError):
            verify_evidence(self.bundle)

    def test_rehashed_action_trace_must_match_action_lists_in_records(self):
        rows = self.ledger()
        row = next(item for item in rows if item["event"] == "finished")
        relative = f"runs/{row['run_id']}/trace.json"
        trace = load_json(self.bundle / relative)
        trace["proposed_actions"].append(
            ActionProposal(DeviceId.PRESENCE_SENSOR, Operation.READ).to_dict()
        )
        self.write_json(relative, trace)
        row["trace_sha256"] = digest(trace)
        self.write_ledger(rows)
        self.write_json(f"runs/{row['run_id']}/record.json", row)
        self.rehash_test_mutations()
        with self.assertRaises(ValueError):
            verify_evidence(self.bundle)

    def test_rehashed_summary_still_has_to_match_ledger_accounting(self):
        summary = load_json(self.bundle / "summary.json")
        summary["attempts"] += 1
        self.write_json("summary.json", summary)
        self.rehash_test_mutations()
        with self.assertRaises(ValueError):
            verify_evidence(self.bundle)

    def test_duplicate_starts_and_finishes_rejected_after_rehashing(self):
        original = self.ledger()
        for event in ("started", "finished"):
            with self.subTest(event=event):
                duplicate = next(row for row in original if row["event"] == event)
                self.write_ledger([*original, duplicate])
                self.rehash_test_mutations()
                with self.assertRaises(ValueError):
                    verify_evidence(self.bundle)

    def test_missing_start_or_finish_rejected_after_rehashing(self):
        original = self.ledger()
        for event in ("started", "finished"):
            with self.subTest(event=event):
                removed = next(row for row in original if row["event"] == event)
                self.write_ledger([row for row in original if row is not removed])
                self.rehash_test_mutations()
                with self.assertRaises(ValueError):
                    verify_evidence(self.bundle)

    def test_started_cell_cannot_change_before_its_finish(self):
        rows = self.ledger()
        next(row for row in rows if row["event"] == "started")["repetition"] += 1
        self.write_ledger(rows)
        self.rehash_test_mutations()
        with self.assertRaises(ValueError):
            verify_evidence(self.bundle)

    def test_rehashed_suite_must_match_batch_scenario_hash(self):
        suite = load_json(self.bundle / "suite.json")
        suite["suite_version"] += "-changed"
        self.write_json("suite.json", suite)
        self.rehash_test_mutations()
        with self.assertRaises(ValueError):
            verify_evidence(self.bundle)

    def test_non_uuid_ledger_run_id_is_rejected_before_resolving_paths(self):
        rows = self.ledger()
        rows[0]["run_id"] = "../outside"
        self.write_ledger(rows)
        self.rehash_test_mutations()
        with self.assertRaises(ValueError):
            verify_evidence(self.bundle)


if __name__ == "__main__":
    unittest.main()
