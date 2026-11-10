"""Results dashboard (DEL-03): data faithful to the analysis, untrusted text never rendered."""

import ast
from pathlib import Path

import pytest

from effectshield.dashboard.data import load_study, rate_table, run_detail, run_rows

ROOT = Path(__file__).resolve().parents[2]
APP = ROOT / "src/effectshield/dashboard/app.py"
RENDERING = {
    "markdown",
    "caption",
    "title",
    "subheader",
    "header",
    "info",
    "warning",
    "error",
    "success",
    "write",
    "html",
}


@pytest.fixture(scope="module")
def rows():
    return run_rows(ROOT)


def test_dashboard_rates_match_the_retained_analysis(rows):
    analysis = load_study(ROOT)["analysis"]["conditions"]
    table = rate_table(rows, replicates=200, seed=1)
    for entry in table:
        stored = analysis[entry["condition"]][entry["measure"]]
        assert entry["rate"] == pytest.approx(stored["rate"])
        assert entry["events"] == stored["successes"]
        assert entry["evaluable_runs"] == stored["evaluable_runs"]
        assert entry["excluded_runs"] == stored["excluded_runs"]
        if entry["rate"] not in (None,):
            assert entry["ci_low"] <= entry["rate"] <= entry["ci_high"]
    assert len(rows) == 432


def test_run_detail_returns_untrusted_text_as_data_and_rejects_unknown_runs(rows):
    valid = next(r for r in rows if r["condition"] == "effectshield" and r["valid"])
    detail = run_detail(ROOT, "effectshield", valid["run_id"])
    assert set(detail["untrusted"]) == {"observation_messages", "proposals", "model_messages"}
    with pytest.raises(ValueError):
        run_detail(ROOT, "admin", valid["run_id"])
    with pytest.raises(ValueError):
        run_detail(ROOT, "effectshield", "../../final-freeze")


def test_evidence_text_never_reaches_markdown_or_html():
    tree = ast.parse(APP.read_text())
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        assert all(k.arg != "unsafe_allow_html" for k in node.keywords)
        name = node.func.attr if isinstance(node.func, ast.Attribute) else None
        if name in RENDERING:
            names = {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}
            assert not names & {"detail", "message", "record", "scenario"}, ast.unparse(node)
            lookups = {
                n.slice.value
                for n in ast.walk(node)
                if isinstance(n, ast.Subscript) and isinstance(n.slice, ast.Constant)
            }
            assert "untrusted" not in lookups, ast.unparse(node)


def test_app_runs_headless_without_exceptions():
    testing = pytest.importorskip("streamlit.testing.v1")
    app = testing.AppTest.from_file(str(APP), default_timeout=300)
    app.run()
    assert not app.exception
    assert any("EffectShield" in title.value for title in app.title)
