"""Decision confusion (STA-06), latency (LOG-03) and billing (LOG-04) on retained evidence."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from effectshield.analysis import decision_confusion
from effectshield.experiments.artifact import build_manifest, verify_artifact
from effectshield.experiments.billing import reconcile
from effectshield.experiments.latency import describe, latency_report

ROOT = Path(__file__).resolve().parents[2]
EVIDENCE = ROOT / "artifacts/local/evaluation"


def test_confusion_counts_repairs_apart_from_true_positives():
    rows = [
        {
            "decision_cells": {
                "blocked/unsafe": 3,
                "blocked/permissible": 1,
                "allowed/permissible": 6,
                "repaired/unsafe": 2,
            },
            "syntax_rejected": 1,
        },
        {"decision_cells": {"allowed/unsafe": 1}, "syntax_rejected": 0},
    ]
    table = decision_confusion(rows)
    assert (table["true_positive"], table["false_positive"]) == (3, 1)
    assert (table["false_negative"], table["true_negative"]) == (1, 6)
    assert table["table"]["repaired"] == {"unsafe": 2, "permissible": 0}
    assert table["precision"] == pytest.approx(0.75) and table["recall"] == pytest.approx(0.75)
    assert table["false_block_rate"] == pytest.approx(1 / 7)
    assert table["syntax_rejected"] == 1 and table["decisions"] == 13
    assert decision_confusion([])["precision"] is None  # undefined, never zero


def test_latency_measures_the_mediator_apart_from_task_time_on_the_pilot():
    report = latency_report(EVIDENCE / "pilot-2026-10-29", repeats=1)
    assert report["decision_mismatches_with_live_records"] == 0
    assert report["mediator_only_latency"]["unit"] == "us"
    assert report["mediator_only_latency"]["n"] > 0
    assert report["total_task_latency"]["effectshield"]["unit"] == "s"
    assert describe([], "s") == {"n": 0, "unit": "s"}


def test_billing_keeps_estimates_and_actual_charges_apart():
    bundles = [EVIDENCE / "live-baseline/gate"]
    unavailable = reconcile(bundles)
    assert unavailable["status"] == "actual billing unavailable"
    assert unavailable["days"][0]["actual_cost"] is None
    assert unavailable["total"]["estimated_cost"] == pytest.approx(0.0148488)
    assert unavailable["total"]["count_requests"] > 0
    supplied = reconcile(bundles, {"2026-10-07": 0.02, "_source": "synthetic test value"})
    assert supplied["days"][0]["difference"] == pytest.approx(0.02 - 0.0148488)


def test_report_macros_match_retained_evidence():
    """The report's numbers come from generated/results.tex, which must not go stale."""
    check = subprocess.run(
        [sys.executable, str(ROOT / "scripts/report_tables.py"), "--check"],
        capture_output=True,
        text=True,
    )
    assert check.returncode == 0, check.stderr or check.stdout


def test_artifact_manifest_verifies_and_detects_a_changed_checksum(tmp_path):
    manifest = build_manifest(ROOT)
    assert {"final-freeze", "final-2026-11-04"} <= {
        Path(item["path"]).name for item in manifest["freezes"] + manifest["comparisons"]
    }
    reports = {item["path"] for item in manifest["reports"]}
    assert "artifacts/local/evaluation/final-2026-11-04/analysis-v2.json" in reports
    assert not reports & {f"{item['path']}/comparison.json" for item in manifest["comparisons"]}
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest))
    assert verify_artifact(ROOT, path)["verified"]
    manifest["reports"][0]["sha256"] = "0" * 64
    path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="Report changed"):
        verify_artifact(ROOT, path)
