"""Verify the standalone viewer against authentic saved offline evidence."""

import io
import json
import shutil
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from html.parser import HTMLParser
from pathlib import Path
from unittest.mock import patch

from effectshield.experiments.audit import verify_evidence
from effectshield.experiments.cli import main
from effectshield.experiments.runner import run_suite
from effectshield.experiments.storage import load_json
from effectshield.experiments.visualize import _json_for_html, write_visualization

ROOT = Path(__file__).resolve().parents[2]


class EvidenceDataParser(HTMLParser):
    """Read the embedded JSON without relying on attribute or whitespace order."""

    def __init__(self):
        super().__init__(convert_charrefs=False)
        self.blocks = []
        self.capture = False
        self.tags = []

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        attributes = dict(attrs)
        if tag == "script" and attributes.get("id") == "evidence-data":
            if attributes.get("type") != "application/json":
                raise AssertionError("Evidence must be inert JSON, not an executable script")
            self.blocks.append("")
            self.capture = True

    def handle_data(self, data):
        if self.capture:
            self.blocks[-1] += data

    def handle_endtag(self, tag):
        if tag == "script":
            self.capture = False


class VisualizationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        cls.base = Path(cls.temp.name) / "source-offline-evidence"
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
        self.directory = Path(self.working.name)
        self.bundle = self.directory / "evidence bundle"
        shutil.copytree(self.base, self.bundle)

    def evidence_bytes(self):
        return {
            path.relative_to(self.bundle).as_posix(): path.read_bytes()
            for path in self.bundle.rglob("*")
            if path.is_file()
        }

    def read_payload(self, output):
        parser = EvidenceDataParser()
        parser.feed(Path(output).read_text(encoding="utf-8"))
        parser.close()
        self.assertEqual(len(parser.blocks), 1)
        return json.loads(parser.blocks[0])

    def assert_result(self, result, output):
        returned_path = Path(result["output"])
        self.assertTrue(returned_path.is_absolute())
        self.assertEqual(returned_path.resolve(), output.resolve())
        self.assertEqual(
            result,
            {
                "output": str(returned_path),
                "url": returned_path.as_uri(),
                "verified": True,
                "runs": self.summary["attempts"],
            },
        )

    def test_default_viewer_preserves_every_original_record_trace_and_scenario(self):
        audit_before = verify_evidence(self.bundle)
        bytes_before = self.evidence_bytes()
        result = write_visualization(str(self.bundle))
        output = Path(str(self.bundle.resolve()) + ".html")
        self.assert_result(result, output)
        payload = self.read_payload(output)
        self.assertEqual(payload["summary"], load_json(self.bundle / "summary.json"))
        self.assertEqual(payload["audit"], audit_before)
        self.assertEqual(
            [item["record"]["run_id"] for item in payload["runs"]],
            self.summary["run_ids"],
        )
        scenarios = {
            scenario["scenario_id"]: scenario
            for scenario in load_json(self.bundle / "suite.json")["scenarios"]
        }
        for item in payload["runs"]:
            with self.subTest(run_id=item["record"]["run_id"]):
                run_path = self.bundle / "runs" / item["record"]["run_id"]
                self.assertEqual(item["record"], load_json(run_path / "record.json"))
                self.assertEqual(item["trace"], load_json(run_path / "trace.json"))
                self.assertEqual(item["scenario"], scenarios[item["record"]["scenario_id"]])
        self.assertEqual(self.evidence_bytes(), bytes_before)
        self.assertEqual(verify_evidence(self.bundle), audit_before)
        self.assertFalse(payload["summary"]["official_live_evidence"])
        self.assertTrue(
            all(
                criterion["status"] == "unassessable"
                for criterion in payload["summary"]["criteria"].values()
            )
        )

    def test_unsafe_action_and_intermediate_snapshots_remain_visible_in_payload(self):
        result = write_visualization(self.bundle)
        payload = self.read_payload(result["output"])
        attacked = next(
            item for item in payload["runs"] if item["scenario"]["variant"] == "attacked"
        )
        self.assertTrue(attacked["record"]["grade"]["unsafe_effect"])
        self.assertTrue(attacked["record"]["grade"]["unsafe_transitions"])
        self.assertEqual(len(attacked["trace"]["transitions"]), 2)
        self.assertEqual(attacked["trace"]["transitions"][-1]["action"]["operation"], "unlock")
        self.assertEqual(
            attacked["trace"]["transitions"][-1]["after"]["devices"]["door"]["lock"],
            "unlocked",
        )
        self.assertFalse(
            attacked["trace"]["transitions"][-1]["after"]["devices"]["presence_sensor"]["present"]
        )

    def test_audited_invalid_trace_remains_available_for_diagnosis(self):
        suite = load_json(ROOT / "scenarios/development/baseline.json")
        suite["scenarios"] = suite["scenarios"][:1]
        scenario_id = suite["scenarios"][0]["scenario_id"]
        fixtures = load_json(ROOT / "fixtures/evaluation/runs.json")
        fixtures["traces"][scenario_id]["transitions"][0]["after"] = {}
        fixtures["traces"][scenario_id]["final_state"] = {}
        suite_path = self.directory / "diagnostic-suite.json"
        fixture_path = self.directory / "diagnostic-fixtures.json"
        suite_path.write_text(json.dumps(suite), encoding="utf-8")
        fixture_path.write_text(json.dumps(fixtures), encoding="utf-8")
        config = load_json(ROOT / "configs/evaluation/gate.json")
        config["repetitions"] = 1
        bundle = self.directory / "diagnostic-bundle"
        summary = run_suite(suite_path, config, bundle, mode="offline", fixture_path=fixture_path)
        self.assertTrue(verify_evidence(bundle)["verified"])
        result = write_visualization(bundle)
        self.assertEqual(result["runs"], 1)
        item = self.read_payload(result["output"])["runs"][0]
        original = load_json(bundle / "runs" / summary["run_ids"][0] / "trace.json")
        self.assertEqual(item["trace"], original)
        self.assertEqual(item["trace"]["transitions"][0]["after"], {})
        self.assertFalse(item["record"]["grade"]["trace_valid"])
        self.assertIsNone(item["record"]["grade"]["task_completed"])

    def test_explicit_output_outside_bundle_accepts_paths_with_spaces(self):
        output = self.directory / "saved evidence viewer.html"
        result = write_visualization(self.bundle, str(output))
        self.assert_result(result, output)
        self.assertEqual(self.read_payload(output)["summary"], self.summary)
        self.assertTrue(verify_evidence(self.bundle)["verified"])

    def test_tampered_evidence_rejected_before_any_output_is_created(self):
        target = self.bundle / "summary.json"
        target.write_bytes(target.read_bytes() + b"\n")
        output = self.directory / "rejected.html"
        with self.assertRaises(ValueError):
            write_visualization(self.bundle, output)
        self.assertFalse(output.exists())
        self.assertFalse(Path(str(self.bundle.resolve()) + ".html").exists())

    def test_output_inside_bundle_is_rejected_without_changing_evidence(self):
        original = self.evidence_bytes()
        for output in (self.bundle / "viewer.html", self.bundle / "runs" / "viewer.html"):
            with self.subTest(output=output):
                with self.assertRaises(ValueError):
                    write_visualization(self.bundle, output)
                self.assertFalse(output.exists())
        self.assertEqual(self.evidence_bytes(), original)
        self.assertTrue(verify_evidence(self.bundle)["verified"])

    def test_directory_symlink_cannot_disguise_output_inside_bundle(self):
        alias = self.directory / "bundle-alias"
        alias.symlink_to(self.bundle, target_is_directory=True)
        output = alias / "viewer.html"
        with self.assertRaises(ValueError):
            write_visualization(self.bundle, output)
        self.assertFalse((self.bundle / "viewer.html").exists())
        self.assertTrue(verify_evidence(self.bundle)["verified"])

    def test_output_symlink_cannot_disguise_nonexistent_target_inside_bundle(self):
        target = self.bundle / "viewer.html"
        output = self.directory / "outside.html"
        output.symlink_to(target)
        with self.assertRaises((ValueError, FileExistsError)):
            write_visualization(self.bundle, output)
        self.assertTrue(output.is_symlink())
        self.assertFalse(target.exists())
        self.assertTrue(verify_evidence(self.bundle)["verified"])

    def test_input_directory_symlink_still_protects_real_bundle(self):
        alias = self.directory / "input-alias"
        alias.symlink_to(self.bundle, target_is_directory=True)
        with self.assertRaises(ValueError):
            write_visualization(alias, self.bundle / "viewer.html")
        self.assertFalse((self.bundle / "viewer.html").exists())
        self.assertTrue(verify_evidence(self.bundle)["verified"])

    def test_existing_external_output_is_never_overwritten(self):
        output = self.directory / "existing.html"
        original = b"An existing user's HTML document.\x00\xff"
        output.write_bytes(original)
        with self.assertRaises((ValueError, FileExistsError)):
            write_visualization(self.bundle, output)
        self.assertEqual(output.read_bytes(), original)
        self.assertTrue(verify_evidence(self.bundle)["verified"])

    def test_existing_default_output_is_never_overwritten(self):
        output = Path(str(self.bundle.resolve()) + ".html")
        output.write_text("Existing default viewer", encoding="utf-8")
        with self.assertRaises((ValueError, FileExistsError)):
            write_visualization(self.bundle)
        self.assertEqual(output.read_text(encoding="utf-8"), "Existing default viewer")

    def test_output_created_during_audit_is_preserved_by_exclusive_create(self):
        output = self.directory / "created-during-audit.html"
        original = b"A document created after the initial existence check"

        def verify_then_create(directory):
            result = verify_evidence(directory)
            output.write_bytes(original)
            return result

        with (
            patch(
                "effectshield.experiments.visualize.verify_evidence",
                side_effect=verify_then_create,
            ),
            self.assertRaises((ValueError, FileExistsError)),
        ):
            write_visualization(self.bundle, output)
        self.assertEqual(output.read_bytes(), original)
        self.assertTrue(verify_evidence(self.bundle)["verified"])

    def test_external_symlink_to_existing_file_is_never_followed_for_overwrite(self):
        target = self.directory / "original.html"
        target.write_text("Keep this document intact", encoding="utf-8")
        output = self.directory / "linked.html"
        output.symlink_to(target)
        with self.assertRaises((ValueError, FileExistsError)):
            write_visualization(self.bundle, output)
        self.assertTrue(output.is_symlink())
        self.assertEqual(target.read_text(encoding="utf-8"), "Keep this document intact")

    def test_external_dangling_symlink_is_not_replaced_or_followed(self):
        target = self.directory / "nonexistent.html"
        output = self.directory / "dangling.html"
        output.symlink_to(target)
        with self.assertRaises((ValueError, FileExistsError)):
            write_visualization(self.bundle, output)
        self.assertTrue(output.is_symlink())
        self.assertFalse(target.exists())

    def test_non_html_suffix_is_rejected_without_writing(self):
        for name in ("viewer", "viewer.htm", "viewer.json"):
            with self.subTest(name=name):
                output = self.directory / name
                with self.assertRaises(ValueError):
                    write_visualization(self.bundle, output)
                self.assertFalse(output.exists())

    def test_cli_explicit_output_returns_the_same_result_schema(self):
        output = self.directory / "cli viewer.html"
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            status = main(["visualize", str(self.bundle), "--output", str(output)])
        self.assertEqual(status, 0)
        self.assertEqual(stderr.getvalue(), "")
        self.assert_result(json.loads(stdout.getvalue()), output)
        self.assertEqual(self.read_payload(output)["summary"], self.summary)

    def test_cli_default_output_is_a_sibling_of_the_verified_bundle(self):
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            status = main(["visualize", str(self.bundle)])
        self.assertEqual(status, 0)
        output = Path(str(self.bundle.resolve()) + ".html")
        self.assert_result(json.loads(stdout.getvalue()), output)
        self.assertEqual(self.read_payload(output)["audit"], verify_evidence(self.bundle))

    def test_cli_tampered_evidence_returns_failure_and_no_viewer(self):
        target = self.bundle / "report.md"
        target.write_bytes(target.read_bytes() + b"\n")
        output = self.directory / "blocked.html"
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            status = main(["visualize", str(self.bundle), "--output", str(output)])
        self.assertEqual(status, 2)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("Blocked:", stderr.getvalue())
        self.assertFalse(output.exists())


class EmbeddedJSONSafetyTests(unittest.TestCase):
    def test_hostile_text_is_losslessly_encoded_without_html_or_script_boundaries(self):
        hostile = (
            '</script><script>alert("injection")</script>'
            '<img src=x onerror="alert(1)">&\u2028\u2029'
        )
        value = {
            hostile: {
                "message": hostile,
                "unicode": "Arabic: مرحبا; Celsius: 22 °C",
                "literal_escape": r"\u003c/script\u003e",
                "ordinary_values": [None, True, False, 0, 1.5],
            }
        }
        encoded = _json_for_html(value)
        self.assertEqual(json.loads(encoded), value)
        for character in ("<", ">", "&", "\u2028", "\u2029"):
            with self.subTest(character=repr(character)):
                self.assertNotIn(character, encoded)
        parser = EvidenceDataParser()
        parser.feed(f'<script id="evidence-data" type="application/json">{encoded}</script>')
        parser.close()
        self.assertEqual(parser.tags, ["script"])
        self.assertEqual(len(parser.blocks), 1)
        self.assertEqual(json.loads(parser.blocks[0]), value)


if __name__ == "__main__":
    unittest.main()
