"""Build a standalone, offline view of verified saved evaluation evidence."""

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

from .audit import verify_evidence
from .storage import load_json


def _json_for_html(value: Any) -> str:
    """Keep untrusted strings inside an inert JSON script element."""
    encoded = json.dumps(value, ensure_ascii=False, allow_nan=False)
    for character in ("<", ">", "&", "\u2028", "\u2029"):
        encoded = encoded.replace(character, f"\\u{ord(character):04x}")
    return encoded


def write_visualization(directory: str | Path, output: str | Path | None = None) -> dict[str, Any]:
    """Audit first; create a derived HTML file without modifying any evidence."""
    directory = Path(directory).resolve()
    destination = Path(output).absolute() if output is not None else Path(f"{directory}.html")
    if destination.resolve().is_relative_to(directory):
        raise ValueError("Visualizations must be saved outside the evidence directory")
    if destination.suffix.lower() != ".html":
        raise ValueError("Visualization output must have an .html extension")
    if destination.exists() or destination.is_symlink():
        raise ValueError("Visualization output already exists; choose a new --output path")
    audit = verify_evidence(directory)
    summary = load_json(directory / "summary.json")
    scenarios = {
        item["scenario_id"]: item for item in load_json(directory / "suite.json")["scenarios"]
    }
    runs = []
    for run_id in summary["run_ids"]:
        path = directory / "runs" / run_id
        record = load_json(path / "record.json")
        runs.append(
            {
                "record": record,
                "trace": load_json(path / "trace.json"),
                "scenario": scenarios[record["scenario_id"]],
            }
        )
    template = Path(__file__).with_name("visualization.html").read_text(encoding="utf-8")
    script = template.split('<script id="viewer-script">', 1)[1].split("</script>", 1)[0]
    script_hash = base64.b64encode(hashlib.sha256(script.encode()).digest()).decode("ascii")
    html = template.replace("__SCRIPT_HASH__", script_hash).replace(
        "__EVIDENCE_DATA__", _json_for_html({"summary": summary, "audit": audit, "runs": runs})
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    # Exclusive creation also protects an existing file/symlink created during the audit.
    with destination.open("x", encoding="utf-8") as stream:
        stream.write(html)
    return {
        "output": str(destination),
        "url": destination.as_uri(),
        "verified": audit["verified"],
        "runs": audit["runs"],
    }
