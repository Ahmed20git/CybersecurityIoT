"""Prove the hidden-instruction attack cannot cross its metadata boundary."""

import copy
import unittest
from pathlib import Path

from effectshield.attacks import apply_attack, validate_matched_pair
from effectshield.scenarios import load_suite

ROOT = Path(__file__).resolve().parents[2]


class AttackBoundaryTests(unittest.TestCase):
    def setUp(self):
        cases = load_suite(ROOT / "scenarios/development/baseline.json")["scenarios"]
        self.attacked = next(case for case in cases if case["variant"] == "attacked")
        self.clean = next(
            case
            for case in cases
            if case["scenario_id"] == self.attacked["attack"]["clean_scenario_id"]
        )
        self.attack = copy.deepcopy(self.attacked["attack"])

    def test_one_payload_changes_without_mutating_input(self):
        original_clean = copy.deepcopy(self.clean)
        original_attack = copy.deepcopy(self.attack)
        attacked = apply_attack(self.clean, self.attack)
        self.assertEqual(attacked, self.attacked)
        self.assertEqual(self.clean, original_clean)
        self.assertEqual(self.attack, original_attack)
        validate_matched_pair(self.clean, attacked)
        attacked["initial_state"]["devices"]["door"]["lock"] = "unlocked"
        attacked["attack"]["replacement_text"] = "edited"
        self.assertEqual(self.clean, original_clean)
        self.assertEqual(self.attack, original_attack)

    def test_protected_fields_remain_equal(self):
        attacked = apply_attack(self.clean, self.attack)
        for field in (
            "task_id",
            "initial_state",
            "request",
            "policy",
            "completion",
            "expected_result",
            "run_config",
            "attack_surface",
            "split",
            "schema_version",
        ):
            self.assertEqual(attacked[field], self.clean[field], field)
        for field in (
            "source_id",
            "gateway_time_ms",
            "event_id",
            "observation_id",
            "device",
            "issuer",
        ):
            self.assertEqual(
                attacked["observations"][0]["envelope"][field],
                self.clean["observations"][0]["envelope"][field],
            )
        self.assertNotEqual(
            attacked["observations"][0]["payload"]["message"],
            self.clean["observations"][0]["payload"]["message"],
        )

    def test_unknown_attack_fields_cannot_select_trusted_targets(self):
        for key in (
            "path",
            "initial_state",
            "request",
            "permissions",
            "policy",
            "timestamp",
            "event_id",
        ):
            with self.subTest(key=key):
                attack = copy.deepcopy(self.attack)
                attack[key] = "attacker controlled"
                with self.assertRaises(ValueError):
                    apply_attack(self.clean, attack)

    def test_wrong_case_and_invalid_or_undeclared_indices_rejected(self):
        for index in (-1, 1, True, "0", None):
            with self.subTest(index=index):
                attack = copy.deepcopy(self.attack)
                attack["observation_index"] = index
                with self.assertRaises(ValueError):
                    apply_attack(self.clean, attack)
        attack = copy.deepcopy(self.attack)
        attack["clean_scenario_id"] = "different-clean"
        with self.assertRaises(ValueError):
            apply_attack(self.clean, attack)
        clean = copy.deepcopy(self.clean)
        clean["attack_surface"] = []
        with self.assertRaises(ValueError):
            apply_attack(clean, self.attack)

    def test_bounded_payload_and_real_change_required(self):
        for text in (
            "",
            " " * 10,
            "x" * 2001,
            None,
            self.clean["observations"][0]["payload"]["message"],
        ):
            with self.subTest(length=len(text) if isinstance(text, str) else None):
                attack = copy.deepcopy(self.attack)
                attack["replacement_text"] = text
                with self.assertRaises(ValueError):
                    apply_attack(self.clean, attack)

    def test_matched_pair_rejects_protected_metadata_tampering(self):
        changes = (
            lambda case: case["request"].update(principal_id="other-user"),
            lambda case: case["request"].update(permissions=["light.turn_on", "door.unlock"]),
            lambda case: case["observations"][0]["envelope"].update(gateway_time_ms=1000),
            lambda case: case["observations"][0]["envelope"].update(event_id=2),
            lambda case: case["observations"][0]["envelope"].update(source_id="different-source"),
            lambda case: case["initial_state"]["devices"]["presence_sensor"].update(present=True),
            lambda case: case["policy"].update(door_requires_presence=False),
            lambda case: case["completion"]["state_equals"].update({"light.power": "off"}),
            lambda case: case["run_config"]["model"]["settings"].update(temperature=1),
            lambda case: case["run_config"]["model"]["settings"].update(temperature=False),
        )
        for change in changes:
            attacked = copy.deepcopy(self.attacked)
            change(attacked)
            with self.assertRaises(ValueError):
                validate_matched_pair(self.clean, attacked)

    def test_attacked_case_cannot_be_used_as_clean_input(self):
        with self.assertRaises(ValueError):
            apply_attack(self.attacked, self.attack)


if __name__ == "__main__":
    unittest.main()
