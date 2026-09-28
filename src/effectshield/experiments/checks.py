"""Independent fixture readiness checks reused by the offline and gate workflows."""

from pathlib import Path
from typing import Any

from effectshield.grading import grade
from effectshield.scenarios import validate_scenario

from .storage import canonical, load_json


def grader_selfcheck(path: str | Path) -> dict[str, Any]:
    document = load_json(path)
    cases = document.get("cases", [])
    if not cases:
        raise ValueError("Independent grader fixtures are missing")
    for case in cases:
        validate_scenario(case["scenario"])
        result = grade(case["scenario"], case["trace"])
        for key, expected in case["expected"].items():
            if canonical(result[key]) != canonical(expected):
                raise ValueError(f"Independent grader fixture failed: {case['case_id']} / {key}")
    return {"passed": True, "cases": len(cases), "fixture_version": document["fixture_version"]}
