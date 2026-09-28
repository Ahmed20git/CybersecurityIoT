"""Offline integration and failure retention through real child-process runs."""

import copy
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from effectshield.experiments.runner import claim_gate_once, run_attempt, run_suite
from effectshield.experiments.storage import digest, load_json
from effectshield.scenarios import load_suite

ROOT = Path(__file__).resolve().parents[2]
SUITE = ROOT / "scenarios/development/baseline.json"
FIXTURES = ROOT / "fixtures/evaluation/runs.json"


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.config = load_json(ROOT / "configs/evaluation/gate.json")
        self.config["repetitions"] = 1
        self.scenarios = load_suite(SUITE)["scenarios"]
        self.clean = self.scenarios[0]
        self.attacked = self.scenarios[-1]

    def attempt(self, factory, *, attacked=False, name="attempt"):
        config = copy.deepcopy(self.config)
        config["mode"] = "offline"
        return run_attempt(
            self.attacked if attacked else self.clean,
            config,
            self.directory / name,
            backend_spec=f"tests.support_backends:{factory}",
        )

    def test_complete_offline_workflow_writes_verifiable_evidence(self):
        output = self.directory / "offline"
        summary = run_suite(SUITE, self.config, output, fixture_path=FIXTURES)
        self.assertEqual(summary["attempts"], 11)
        self.assertEqual(summary["criteria"]["benign_completion"]["successes"], 10)
        self.assertEqual(summary["criteria"]["benign_completion"]["total"], 10)
        self.assertEqual(summary["unsafe_attempts"], 1)
        self.assertEqual(summary["action_changes"]["executed"]["successes"], 1)
        self.assertTrue(summary["reset_checks_passed"])
        self.assertEqual(len(set(summary["run_ids"])), 11)
        self.assertTrue(
            all(value["status"] == "unassessable" for value in summary["criteria"].values())
        )
        self.assertEqual(summary["usage"]["cost"]["total"], 0)
        ledger = [json.loads(line) for line in (output / "ledger.jsonl").read_text().splitlines()]
        self.assertEqual(len(ledger), 22)
        for start, finish in zip(ledger[::2], ledger[1::2], strict=True):
            self.assertEqual((start["event"], finish["event"]), ("started", "finished"))
            self.assertEqual(start["run_id"], finish["run_id"])
            evidence = output / finish["evidence"]
            self.assertEqual(digest(load_json(evidence / "trace.json")), finish["trace_sha256"])
            self.assertEqual(load_json(evidence / "grade.json"), finish["grade"])
            for filename in ("events.jsonl", "messages.json", "record.json"):
                self.assertTrue((evidence / filename).is_file())
        self.assertEqual(load_json(output / "summary.json"), summary)
        self.assertIn("not a live gate pass", (output / "report.md").read_text())
        artifacts = load_json(output / "evidence_manifest.json")
        for name, expected_hash in artifacts["files"].items():
            self.assertEqual(
                hashlib.sha256((output / name).read_bytes()).hexdigest(), expected_hash
            )

    def test_existing_output_and_attempt_directory_are_never_overwritten(self):
        output = self.directory / "already-there"
        output.mkdir()
        sentinel = output / "keep.txt"
        sentinel.write_text("existing evidence")
        with self.assertRaises(FileExistsError):
            run_suite(SUITE, self.config, output, fixture_path=FIXTURES)
        with self.assertRaises(FileExistsError):
            self.attempt("isolation_factory", name="already-there")
        self.assertEqual(sentinel.read_text(), "existing evidence")
        self.assertEqual(list(output.iterdir()), [sentinel])

    def test_rehearsal_writes_separate_explicitly_nonofficial_evidence(self):
        suite = load_suite(SUITE)
        suite["scenarios"] = [self.clean, self.attacked]
        path = self.directory / "matched-development-subset.json"
        path.write_text(json.dumps(suite))
        output = self.directory / "rehearsal"
        summary = run_suite(path, self.config, output, mode="rehearsal", fixture_path=FIXTURES)
        self.assertEqual(summary["mode"], "rehearsal")
        self.assertEqual(summary["attempts"], 2)
        self.assertFalse(summary["official_live_evidence"])
        self.assertTrue(
            all(result["status"] == "unassessable" for result in summary["criteria"].values())
        )
        self.assertEqual(load_json(output / "manifest.json")["mode"], "rehearsal")
        self.assertIn("Mode: **rehearsal**", (output / "report.md").read_text())

    def test_fresh_process_and_deepcopy_isolate_every_attempt(self):
        original = copy.deepcopy(self.clean)
        original_config = copy.deepcopy(self.config)
        for number in (1, 2):
            result = self.attempt("isolation_factory", name=f"isolated-{number}")
            self.assertEqual(result["status"], "completed")
            self.assertTrue(result["reset_verified"])
            self.assertTrue(result["grade"]["task_completed"])
            messages = load_json(self.directory / f"isolated-{number}/messages.json")
            self.assertEqual(messages[-1]["content"], "instance=1")
        self.assertEqual(self.clean, original)
        self.assertEqual(self.config, original_config)

    def test_reset_requires_exact_json_types(self):
        result = self.attempt("bad_reset_factory")
        self.assertFalse(result["reset_verified"])
        self.assertFalse(result["grade"]["trace_valid"])
        self.assertIn("mismatch", result["error"].lower())
        self.assertEqual(result["executed_actions"], [])

    def test_partial_unsafe_effect_survives_backend_failure(self):
        result = self.attempt("partial_unsafe_factory", attacked=True)
        self.assertEqual(result["status"], "error")
        self.assertIs(result["grade"]["unsafe_effect"], True)
        self.assertFalse(result["grade"]["trace_valid"])
        self.assertEqual(len(result["executed_actions"]), 2)
        trace = load_json(self.directory / "attempt/trace.json")
        self.assertFalse(trace["complete"])
        self.assertEqual(trace["final_state"]["devices"]["door"]["lock"], "unlocked")
        self.assertEqual(len(trace["transitions"]), 2)

    def test_timeout_retains_committed_prefix(self):
        self.config["limits"]["wall_timeout_s"] = 2
        result = self.attempt("timeout_factory", attacked=True)
        self.assertEqual(result["status"], "timeout")
        self.assertIs(result["grade"]["unsafe_effect"], True)
        self.assertEqual(len(result["executed_actions"]), 2)
        self.assertFalse(load_json(self.directory / "attempt/trace.json")["complete"])

    def test_timeout_during_later_live_marked_call_keeps_known_subtotals(self):
        self.config["limits"].update(wall_timeout_s=2, max_cost=1.0)
        result = self.attempt("live_marked_timeout_factory")
        self.assertEqual(result["status"], "timeout")
        self.assertEqual(result["usage"]["input_tokens"], 5)
        self.assertEqual(result["usage"]["cost"], 0.1)
        self.assertEqual(result["usage"]["calls"], 1)
        self.assertIs(result["usage"]["accounting_complete"], False)
        self.assertEqual(result["usage"]["cost_status"], "unavailable")

    def test_exact_in_flight_request_is_durable_before_timeout_kills_worker(self):
        self.config["limits"]["wall_timeout_s"] = 2
        result = self.attempt("audit_sink_timeout_factory")
        self.assertEqual(result["status"], "timeout")
        messages = load_json(self.directory / "attempt/messages.json")
        submitted = [
            message["content"]
            for message in messages
            if isinstance(message.get("content"), dict)
            and message["content"].get("provider_operation") == "generation"
            and message["content"].get("direction") == "request"
        ]
        self.assertEqual(len(submitted), 1)
        self.assertEqual(submitted[0]["body"]["model"], "synthetic-timeout-model")
        self.assertIn(self.clean["request"]["request_text"], json.dumps(submitted[0]))
        events = [
            json.loads(line)
            for line in (self.directory / "attempt/events.jsonl").read_text().splitlines()
        ]
        self.assertTrue(any(event["event"].get("content") == submitted[0] for event in events))

    def test_invalid_response_and_malformed_event_are_retained(self):
        for factory in ("invalid_response_factory", "malformed_factory"):
            with self.subTest(factory=factory):
                result = self.attempt(factory, name=factory)
                self.assertEqual(result["status"], "invalid_response")
                self.assertFalse(result["grade"]["trace_valid"])
                self.assertTrue(result["error"])
                self.assertTrue((self.directory / factory / "events.jsonl").is_file())

    def test_reserved_events_cannot_forge_worker_completion(self):
        result = self.attempt("reserved_factory")
        self.assertEqual(result["status"], "error")
        self.assertIn("reserved", result["error"])
        self.assertFalse(result["grade"]["trace_valid"])

    def test_usage_cannot_erase_known_value_then_restart_lower(self):
        result = self.attempt("erased_usage_factory")
        self.assertEqual(result["status"], "invalid_response")
        self.assertIn("cannot erase", result["error"])
        self.assertEqual(result["usage"]["input_tokens"], 5)
        self.assertFalse(result["grade"]["trace_valid"])

    def test_known_partial_token_count_still_enforces_budget(self):
        result = self.attempt("token_budget_factory")
        self.assertEqual(result["status"], "budget_exceeded")
        self.assertEqual(result["usage"]["input_tokens"], self.config["limits"]["max_tokens"] + 1)
        self.assertIsNone(result["usage"]["output_tokens"])
        self.assertFalse(result["grade"]["trace_valid"])

    def test_environment_credential_redacted_without_losing_unsafe_prefix(self):
        credential = "synthetic-provider-value-unique-274891"
        with patch.dict(os.environ, {"WEEK4_TEST_API_KEY": credential}):
            result = self.attempt("secret_error_factory", attacked=True)
        self.assertIs(result["grade"]["unsafe_effect"], True)
        self.assertNotIn(credential, json.dumps(result))
        self.assertIn("[REDACTED]", result["error"])
        for path in (self.directory / "attempt").iterdir():
            self.assertNotIn(credential, path.read_text())

    def test_retries_retain_failures_and_count_all_attempts(self):
        fixture = load_json(FIXTURES)
        fixture["traces"][self.clean["scenario_id"]]["termination"] = "error"
        path = self.directory / "error-fixture.json"
        path.write_text(json.dumps(fixture))
        self.config["retry"]["max_attempts"] = 2
        output = self.directory / "retries"
        summary = run_suite(SUITE, self.config, output, fixture_path=path)
        self.assertEqual(summary["attempts"], 12)
        self.assertEqual(summary["retries"], 1)
        self.assertEqual(summary["criteria"]["benign_completion"]["successes"], 9)
        self.assertEqual(summary["criteria"]["benign_completion"]["total"], 11)
        self.assertEqual(summary["status_counts"]["error"], 2)
        self.assertEqual(len(summary["failures"]), 2)
        self.assertEqual(summary["action_changes"]["executed"]["total"], 2)
        ledger = [json.loads(line) for line in (output / "ledger.jsonl").read_text().splitlines()]
        self.assertEqual(len(ledger), 24)

    def test_gate_without_freeze_is_rejected_before_output_creation(self):
        output = self.directory / "not-a-gate"
        with self.assertRaisesRegex(ValueError, "freeze"):
            run_suite(
                SUITE,
                self.config,
                output,
                mode="gate",
                backend_spec="tests.support_backends:isolation_factory",
            )
        self.assertFalse(output.exists())

    def test_one_freeze_cannot_silently_start_a_second_gate_batch(self):
        frozen = self.directory / "frozen"
        frozen.mkdir()
        original = self.directory / "first-gate"
        claim_gate_once(frozen, "synthetic-freeze-for-unit-test", original)
        marker = self.directory / "frozen.gate-started.json"
        evidence = marker.read_bytes()
        with self.assertRaises(FileExistsError):
            claim_gate_once(
                frozen, "synthetic-freeze-for-unit-test", self.directory / "second-gate"
            )
        self.assertEqual(marker.read_bytes(), evidence)
        self.assertEqual(load_json(marker)["output"], str(original.resolve()))


if __name__ == "__main__":
    unittest.main()
