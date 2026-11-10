"""Artifact manifest for the retained evidence (LOG-05, LOG-07).

Lists every retained evidence bundle, comparison, freeze and derived report under
the evidence root with its checksum and identity, plus the code revision and the
pinned dependency files. ``verify_artifact`` recomputes every checksum and re-runs
the bundle, comparison and freeze audits, so a reader can confirm the package
before reproducing any table.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any

from .audit import verify_evidence
from .comparison import verify_comparison
from .freeze import verify_freeze

ARTIFACT_SCHEMA_VERSION = "evidence-artifact/v1"
LOCKFILES = ("requirements-dev.txt", "requirements-dashboard.txt", "pyproject.toml")


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _relative(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def build_manifest(project: Path) -> dict[str, Any]:
    project = Path(project)
    evidence = project / "artifacts/local/evaluation"
    bundles, comparisons, freezes, reports = [], [], [], []
    covered: set[Path] = set()
    for manifest in sorted(evidence.rglob("evidence_manifest.json")):
        bundle = manifest.parent
        batch = json.loads((bundle / "manifest.json").read_text())
        files = json.loads(manifest.read_text())["files"]
        bundles.append(
            {
                "path": _relative(bundle, project),
                "batch_id": batch["batch_id"],
                "mode": batch["mode"],
                "condition": (batch.get("condition") or {}).get("condition_id"),
                "files": len(files),
                "evidence_manifest_sha256": _sha(manifest),
            }
        )
        covered.update(bundle.rglob("*"))
    for plan in sorted(evidence.rglob("comparison_plan.json")):
        root = plan.parent
        comparisons.append(
            {
                "path": _relative(root, project),
                "plan_sha256": _sha(plan),
                "comparison_sha256": _sha(root / "comparison.json"),
            }
        )
        covered.update({plan, root / "comparison.json"})
    for manifest in sorted(evidence.rglob("manifest.json")):
        document = json.loads(manifest.read_text())
        if document.get("schema_version") == "evaluation-freeze/v1":
            freezes.append(
                {
                    "path": _relative(manifest.parent, project),
                    "freeze_id": document["freeze_id"],
                    "implementation_sha256": document["implementation_sha256"],
                }
            )
            covered.update(manifest.parent.rglob("*"))
    for path in sorted(evidence.rglob("*")):
        if path.is_file() and path not in covered and path.name != "ARTIFACT_MANIFEST.json":
            reports.append({"path": _relative(path, project), "sha256": _sha(path)})
    revision = subprocess.run(
        ["git", "rev-parse", "HEAD"], capture_output=True, text=True, cwd=project
    )
    # Uncommitted source changes mean the revision alone does not identify the code.
    changes = subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=no", "--", "src", "scripts"],
        capture_output=True,
        text=True,
        cwd=project,
    )
    return {
        "schema_version": ARTIFACT_SCHEMA_VERSION,
        "code_revision": revision.stdout.strip() if revision.returncode == 0 else None,
        "source_matches_revision": (
            changes.stdout.strip() == "" if changes.returncode == 0 else None
        ),
        "dependency_files": {
            name: _sha(project / name) for name in LOCKFILES if (project / name).exists()
        },
        "bundles": bundles,
        "comparisons": comparisons,
        "freezes": freezes,
        "reports": reports,
        "notice": (
            "Team evidence package (D13). Some retained files embed the original local "
            "machine path; release beyond the team requires a reviewed decision."
        ),
    }


def verify_artifact(project: Path, manifest_path: Path) -> dict[str, Any]:
    """Recompute every listed checksum and re-run every audit."""
    project = Path(project)
    manifest = json.loads(Path(manifest_path).read_text())
    if manifest.get("schema_version") != ARTIFACT_SCHEMA_VERSION:
        raise ValueError("Unsupported artifact manifest")
    for bundle in manifest["bundles"]:
        path = project / bundle["path"]
        if _sha(path / "evidence_manifest.json") != bundle["evidence_manifest_sha256"]:
            raise ValueError(f"Evidence manifest changed: {bundle['path']}")
        verify_evidence(path)
    for comparison in manifest["comparisons"]:
        path = project / comparison["path"]
        if (
            _sha(path / "comparison_plan.json") != comparison["plan_sha256"]
            or _sha(path / "comparison.json") != comparison["comparison_sha256"]
        ):
            raise ValueError(f"Comparison changed: {comparison['path']}")
        verify_comparison(path)
    for freeze in manifest["freezes"]:
        if verify_freeze(project / freeze["path"])["freeze_id"] != freeze["freeze_id"]:
            raise ValueError(f"Freeze identity changed: {freeze['path']}")
    for report in manifest["reports"]:
        if _sha(project / report["path"]) != report["sha256"]:
            raise ValueError(f"Report changed: {report['path']}")
    return {
        "verified": True,
        "bundles": len(manifest["bundles"]),
        "comparisons": len(manifest["comparisons"]),
        "freezes": len(manifest["freezes"]),
        "reports": len(manifest["reports"]),
    }
