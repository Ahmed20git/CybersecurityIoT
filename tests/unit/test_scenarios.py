"""Behavioral checks for development labels and evaluation input validation."""

import copy
import json
import tempfile
import unittest
from pathlib import Path

from effectshield.scenarios import (
    get_scenarios,
    load_suite,
    validate_action,
    validate_scenario,
    validate_state,
)

ROOT = Path(__file__).resolve().parents[2]
SUITE = ROOT / "scenarios/development/baseline.json"


class ScenarioTests(unittest.TestCase):
    def setUp(self):
        self.suite = load_suite(SUITE)
        self.scenarios = get_scenarios(self.suite)
        self.clean = copy.deepcopy(self.scenarios[0])

    def test_development_coverage_and_presence_completion(self):
        clean = [case for case in self.scenarios if case["variant"] == "clean"]
        self.assertEqual(len(clean), 10)
        self.assertTrue(all(case["split"] == "development" for case in self.scenarios))
        for device in ("light", "fan", "thermostat", "door", "presence_sensor"):
            cases = [
                case for case in clean if case["observations"][0]["envelope"]["device"] == device
            ]
            self.assertEqual(len(cases), 2, device)
        presence = [
            case
            for case in clean
            if case["observations"][0]["envelope"]["device"] == "presence_sensor"
        ]
        for case in presence:
            self.assertEqual(case["request"]["permissions"], [])
            self.assertEqual(
                case["completion"]["executed_contains"],
                [
                    {
                        "schema_version": "1.0",
                        "device": "presence_sensor",
                        "operation": "read",
                        "parameters": {},
                        "evidence_refs": [],
                    }
                ],
            )

    def test_records_are_isolated_from_loaded_suite(self):
        self.scenarios[0]["initial_state"]["devices"]["light"]["power"] = "on"
        self.assertEqual(
            self.suite["scenarios"][0]["initial_state"]["devices"]["light"]["power"], "off"
        )

    def test_static_fixtures_are_explicit_complete_chains(self):
        fixture = json.loads((ROOT / "fixtures/evaluation/runs.json").read_text())
        self.assertEqual(fixture["schema_version"], "evaluation-fixtures/v1")
        self.assertEqual(set(fixture["traces"]), {case["scenario_id"] for case in self.scenarios})
        for scenario in self.scenarios:
            trace = fixture["traces"][scenario["scenario_id"]]
            self.assertTrue(trace["complete"])
            self.assertEqual(trace["initial_state"], scenario["initial_state"])
            previous = trace["initial_state"]
            for index, transition in enumerate(trace["transitions"]):
                self.assertEqual(transition["sequence_no"], index + 1)
                self.assertEqual(transition["before"], previous)
                validate_action(transition["action"])
                validate_state(transition["after"])
                previous = transition["after"]
            self.assertEqual(trace["final_state"], previous)
            self.assertEqual(
                trace["executed_actions"], [item["action"] for item in trace["transitions"]]
            )

    def test_nonfinite_and_boolean_as_number_states_rejected(self):
        for bad_value in (float("nan"), float("inf"), float("-inf"), 10**1000, True, "22"):
            with self.subTest(value=bad_value):
                state = copy.deepcopy(self.clean["initial_state"])
                state["devices"]["thermostat"]["setpoint_c"] = bad_value
                with self.assertRaises(ValueError):
                    validate_state(state)

    def test_incomplete_or_unknown_state_fields_rejected(self):
        state = copy.deepcopy(self.clean["initial_state"])
        del state["devices"]["presence_sensor"]
        with self.assertRaises(ValueError):
            validate_state(state)
        state = copy.deepcopy(self.clean["initial_state"])
        state["devices"]["door"]["online"] = True
        with self.assertRaises(ValueError):
            validate_state(state)

    def test_unsupported_action_or_parameters_rejected(self):
        def native(device, operation, parameters):
            return {
                "schema_version": "1.0",
                "device": device,
                "operation": operation,
                "parameters": parameters,
                "evidence_refs": [],
            }

        invalid = [
            native("camera", "read", {}),
            native("presence_sensor", "turn_on", {}),
            native("door", "unlock", {"force": True}),
            native("fan", "turn_on", {"on": True}),
            native("thermostat", "set_setpoint", {"setpoint_c": float("nan")}),
            native([], "turn_on", {}),
        ]
        for action in invalid:
            with self.subTest(action=action), self.assertRaises(ValueError):
                validate_action(action)

    def test_invalid_scenario_labels_and_run_config_rejected(self):
        mutations = [
            ("split", "final"),
            ("variant", "unknown"),
            ("completion", {"state_equals": {"camera.on": True}, "executed_contains": []}),
            ("completion", {"state_equals": {"light.power": 1}, "executed_contains": []}),
            ("completion", {"state_equals": {}, "executed_contains": []}),
            ("expected_result", {"task_completed": True, "unsafe_effect": True}),
            ("attack_surface", ["initial_state.devices.door.lock"]),
            ("attack_surface", ["observations[9].payload.message"]),
        ]
        for key, value in mutations:
            with self.subTest(key=key, value=value):
                scenario = copy.deepcopy(self.clean)
                scenario[key] = value
                with self.assertRaises(ValueError):
                    validate_scenario(scenario)
        for key, value in (
            ("max_steps", True),
            ("max_cost", -1),
            ("max_tokens", 0),
            ("wall_timeout_s", float("inf")),
        ):
            with self.subTest(limit=key):
                scenario = copy.deepcopy(self.clean)
                scenario["run_config"]["limits"][key] = value
                with self.assertRaises(ValueError):
                    validate_scenario(scenario)

    def test_seed_and_observation_provenance_types_rejected(self):
        bad = copy.deepcopy(self.clean)
        bad["run_config"]["model"]["seed_status"] = "unsupported"
        with self.assertRaises(ValueError):
            validate_scenario(bad)
        bad = copy.deepcopy(self.clean)
        bad["observations"][0]["envelope"]["gateway_time_ms"] = "2026-09-21T09:00:00"
        with self.assertRaises(ValueError):
            validate_scenario(bad)
        bad = copy.deepcopy(self.clean)
        bad["request"]["permissions"] = ["light.turn_on", "light.turn_on"]
        with self.assertRaises(ValueError):
            validate_scenario(bad)

    def test_duplicate_ids_and_missing_matched_case_rejected(self):
        duplicate = copy.deepcopy(self.suite)
        duplicate["scenarios"].append(copy.deepcopy(duplicate["scenarios"][0]))
        with self.assertRaisesRegex(ValueError, "duplicate scenario_id"):
            get_scenarios(duplicate)
        unmatched = copy.deepcopy(self.suite)
        unmatched["scenarios"] = unmatched["scenarios"][1:]
        with self.assertRaisesRegex(ValueError, "no matching clean"):
            get_scenarios(unmatched)

    def test_json_duplicate_keys_and_nonfinite_constants_rejected(self):
        documents = [
            '{"schema_version":"a","schema_version":"b"}',
            json.dumps(self.suite).replace('"max_cost": 0.0', '"max_cost": NaN', 1),
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "suite.json"
            for document in documents:
                path.write_text(document)
                with self.assertRaises(ValueError):
                    load_suite(path)


if __name__ == "__main__":
    unittest.main()
