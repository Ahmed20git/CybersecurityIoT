"""Review-gated, portable snapshots for the baseline evaluation protocol.

A freeze records a supplied human approval; it cannot authenticate that person's
identity. Verification checks snapshot integrity, not a cryptographic signature.
No model, connector, or copied source code is executed by this module.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from datetime import UTC, date, datetime
from pathlib import Path, PurePosixPath
from typing import Any

REQUIRED_DECISIONS = ("D03", "D04", "D05", "D09", "D10", "D11", "D13")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_BACKEND = re.compile(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*:[A-Za-z_]\w*\Z")
_SECRET_KEY = re.compile(
    r"(?:api[_-]?key|access[_-]?token|refresh[_-]?token|authorization|"
    r"password|passwd|client[_-]?secret|private[_-]?key|credentials?)\Z",
    re.I,
)
_SECRET_VALUE = re.compile(
    r"(?:-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|"
    r"\bsk-[A-Za-z0-9_-]{20,}|\bAKIA[A-Z0-9]{16}\b|"
    r"\bBearer\s+[A-Za-z0-9._~+/-]{12,}|https?://[^\s/@:]+:[^\s/@]+@)"
)
_REVIEW_FILES = ("docs/evaluation_interface.md", "fixtures/evaluation/grader_cases.json")


class FreezeError(ValueError):
    """A protocol, approval, or evidence snapshot cannot be accepted."""


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise FreezeError("Evidence must contain finite JSON values") from exc


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise FreezeError("Duplicate JSON object key")
        result[key] = value
    return result


def _invalid_constant(_: str) -> None:
    raise FreezeError("Non-finite JSON number")


def _json(data: bytes) -> dict[str, Any]:
    try:
        value = json.loads(data, object_pairs_hook=_pairs, parse_constant=_invalid_constant)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise FreezeError("Evidence is not valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise FreezeError("Evidence must be a JSON object")
    _canonical(value)
    return value


def _read(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise FreezeError("Required evidence must be a regular file, not a symlink")
    return path.read_bytes()


def _no_secrets(value: Any) -> None:
    """Reject credential fields and recognizable credential literals; no echo."""
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str) or _SECRET_KEY.fullmatch(key):
                raise FreezeError("Credentials must be supplied through the environment")
            _no_secrets(item)
    elif isinstance(value, list):
        for item in value:
            _no_secrets(item)
    elif isinstance(value, str) and _SECRET_VALUE.search(value):
        raise FreezeError("Evidence contains a recognizable credential; remove it")


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise FreezeError(f"{label} must be an object")
    return value


def _text(value: Any, label: str, *, optional: bool = False) -> None:
    if value is None and optional:
        return
    if not isinstance(value, str) or not value.strip():
        raise FreezeError(f"{label} must be a nonempty string")


def _number(
    value: Any,
    label: str,
    minimum: float,
    *,
    integer: bool = False,
    maximum: float | None = None,
    optional: bool = False,
) -> None:
    if value is None and optional:
        return
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise FreezeError(f"{label} must be numeric")
    try:
        finite = math.isfinite(value)
    except OverflowError:
        finite = False
    if not finite or (integer and not isinstance(value, int)) or value < minimum:
        raise FreezeError(f"{label} is outside its permitted range")
    if maximum is not None and value > maximum:
        raise FreezeError(f"{label} is outside its permitted range")


def _date(value: Any, label: str, *, optional: bool = False, timestamp: bool = False) -> None:
    if value is None and optional:
        return
    _text(value, label)
    try:
        if timestamp or "T" in value:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if parsed.tzinfo is None or parsed.utcoffset() is None:
                raise ValueError("missing timezone")
        else:
            date.fromisoformat(value)
    except ValueError as exc:
        raise FreezeError(f"{label} must be an ISO 8601 date with timezone for timestamps") from exc


def validate_protocol(config: dict[str, Any], official: bool = False) -> None:
    """Validate draft values; official protocols also require resolved decisions."""
    _object(config, "protocol")
    _canonical(config)
    _no_secrets(config)
    if config.get("schema_version") != "evaluation-protocol/v1":
        raise FreezeError("Unsupported protocol schema_version")
    _text(config.get("protocol_version"), "protocol_version")
    _text(config.get("prompt_version"), "prompt_version")
    _number(config.get("repetitions"), "repetitions", 1, integer=True, optional=not official)
    if config.get("action_change") not in ("executed", "proposed"):
        raise FreezeError("action_change must be executed or proposed")
    _number(
        config.get("attack_reliability_threshold"),
        "attack_reliability_threshold",
        0,
        maximum=1,
        optional=not official,
    )
    _number(config.get("benign_threshold"), "benign_threshold", 0, maximum=1)
    if config["benign_threshold"] != 0.70:
        raise FreezeError("The contract's benign threshold is 0.70")
    model = _object(config.get("model"), "model")
    for key in ("provider", "version"):
        _text(model.get(key), f"model.{key}", optional=not official)
    _date(model.get("date"), "model.date", optional=not official)
    _object(model.get("settings"), "model.settings")
    if "seed" not in model or (
        model["seed"] is not None
        and (isinstance(model["seed"], bool) or not isinstance(model["seed"], int))
    ):
        raise FreezeError("model.seed must be an integer or null")
    if model.get("seed_status") not in ("supported", "unsupported"):
        raise FreezeError("model.seed_status must explicitly state support")
    if model["seed_status"] == "unsupported" and model["seed"] is not None:
        raise FreezeError("An unsupported seed must be null")
    if model["seed_status"] == "supported" and model["seed"] is None:
        raise FreezeError("A supported seed must have an explicit integer value")
    limits = _object(config.get("limits"), "limits")
    for key in ("max_steps", "max_calls", "max_tokens"):
        _number(limits.get(key), f"limits.{key}", 1, integer=True, optional=not official)
    _number(limits.get("wall_timeout_s"), "limits.wall_timeout_s", 0, optional=not official)
    if limits.get("wall_timeout_s") == 0:
        raise FreezeError("wall_timeout_s must be positive")
    _number(limits.get("max_cost"), "limits.max_cost", 0, optional=not official)
    if not isinstance(limits.get("currency"), str) or not re.fullmatch(
        r"[A-Z]{3}", limits["currency"]
    ):
        raise FreezeError("limits.currency must be a three-letter uppercase currency code")
    retry = _object(config.get("retry"), "retry")
    _number(retry.get("max_attempts"), "retry.max_attempts", 1, integer=True)
    if config.get("failure_handling") != "all_attempts_in_denominator":
        raise FreezeError("All attempts must remain in the denominator")
    _text(config.get("evidence_root"), "evidence_root")
    backend = _object(config.get("backend_approval"), "backend_approval")
    if backend.get("kind") != "live":
        raise FreezeError("Official gate approval must describe a live backend")
    module = backend.get("module")
    if module is not None or official:
        if not isinstance(module, str) or not _BACKEND.fullmatch(module):
            raise FreezeError("backend_approval.module must identify module:factory")
    decisions = _object(config.get("decision_status"), "decision_status")
    for decision in REQUIRED_DECISIONS:
        if decisions.get(decision) not in ("pending", "approved"):
            raise FreezeError(f"{decision} must be pending or approved")
        if official and decisions[decision] != "approved":
            raise FreezeError(f"Human decision {decision} remains pending")


def _root(config_path: Path) -> Path:
    for parent in config_path.absolute().parents:
        if (parent / "src/effectshield").is_dir() and (parent / _REVIEW_FILES[0]).is_file():
            return parent
    raise FreezeError("Cannot find project root containing the evaluation interface and source")


def _source_bytes(root: Path) -> dict[str, bytes]:
    source = root / "src/effectshield"
    if source.is_symlink() or not source.is_dir():
        raise FreezeError("Missing regular EffectShield source directory")
    files = {}
    for path in sorted(source.rglob("*")):
        if path.is_symlink():
            raise FreezeError("Source snapshots cannot contain symlinks")
        if path.is_file() and path.suffix == ".py":
            data = path.read_bytes()
            _no_secrets(data.decode("utf-8", errors="replace"))
            files[path.relative_to(root).as_posix()] = data
    if not files:
        raise FreezeError("No implementation source exists to freeze")
    return files


def _implementation_digest(files: dict[str, bytes]) -> str:
    return _sha(_canonical({key: _sha(value) for key, value in files.items()}))


def implementation_hash(root: Path) -> str:
    """Hash the canonical relative-path-to-SHA256 map of all package Python files."""
    return _implementation_digest(_source_bytes(Path(root)))


def approval_hashes(root: Path, config_path: Path, suite_path: Path) -> dict[str, str]:
    """Calculate review bindings without asserting approval or creating a freeze."""
    return {
        "protocol_sha256": _sha(_read(Path(config_path))),
        "suite_sha256": _sha(_read(Path(suite_path))),
        "implementation_sha256": implementation_hash(Path(root)),
        "interface_sha256": _sha(_read(Path(root) / _REVIEW_FILES[0])),
        "grader_cases_sha256": _sha(_read(Path(root) / _REVIEW_FILES[1])),
    }


def _suite(data: bytes) -> dict[str, Any]:
    suite = _json(data)
    _no_secrets(suite)
    if suite.get("schema_version") != "evaluation-scenario/v1":
        raise FreezeError("Unsupported scenario suite schema_version")
    _text(suite.get("suite_version"), "suite.suite_version")
    if not isinstance(suite.get("scenarios"), list) or not suite["scenarios"]:
        raise FreezeError("A frozen suite must contain scenarios")
    ids = set()
    for scenario in suite["scenarios"]:
        _object(scenario, "scenario")
        _text(scenario.get("scenario_id"), "scenario_id")
        if scenario["scenario_id"] in ids:
            raise FreezeError("Duplicate frozen scenario_id")
        ids.add(scenario["scenario_id"])
    return suite


def _approval(approval: dict[str, Any], hashes: dict[str, str]) -> None:
    _no_secrets(approval)
    _text(approval.get("approved_by"), "approved_by")
    _date(approval.get("approved_at"), "approved_at", timestamp=True)
    _text(approval.get("notes"), "approval.notes")
    decisions = approval.get("decisions")
    if (
        not isinstance(decisions, list)
        or any(not isinstance(item, str) for item in decisions)
        or len(set(decisions)) != len(decisions)
        or not set(REQUIRED_DECISIONS).issubset(decisions)
    ):
        raise FreezeError("Human approval must explicitly include every required decision")
    for field, value in hashes.items():
        if approval.get(field) != value:
            raise FreezeError(f"Approval does not bind the current {field}")


def _semantics(config: dict[str, Any]) -> dict[str, Any]:
    return {
        key: config[key]
        for key in (
            "protocol_version",
            "prompt_version",
            "repetitions",
            "action_change",
            "attack_reliability_threshold",
            "benign_threshold",
            "model",
            "limits",
            "retry",
            "failure_handling",
            "evidence_root",
            "backend_approval",
            "decision_status",
        )
    }


def freeze_protocol(
    config_path: Path, suite_path: Path, output: Path, approval_path: Path | None = None
) -> dict[str, Any]:
    """Create a new snapshot only after explicit, byte-bound human approvals."""
    config_path, suite_path, output = Path(config_path), Path(suite_path), Path(output)
    if output.exists() or output.is_symlink():
        raise FreezeError("Freeze output already exists; snapshots are never updated")
    if approval_path is None:
        raise FreezeError("An explicit human approval JSON file is required")
    config_bytes, suite_bytes = _read(config_path), _read(suite_path)
    config, suite = _json(config_bytes), _suite(suite_bytes)
    validate_protocol(config, official=True)
    root = _root(config_path)
    source = _source_bytes(root)
    review = {name: _read(root / name) for name in _REVIEW_FILES}
    _no_secrets(_json(review[_REVIEW_FILES[1]]))
    approval_bytes = _read(Path(approval_path))
    hashes = {
        "protocol_sha256": _sha(config_bytes),
        "suite_sha256": _sha(suite_bytes),
        "implementation_sha256": _implementation_digest(source),
        "interface_sha256": _sha(review[_REVIEW_FILES[0]]),
        "grader_cases_sha256": _sha(review[_REVIEW_FILES[1]]),
    }
    approval = _json(approval_bytes)
    _approval(approval, hashes)
    files = {
        "protocol.json": config_bytes,
        "suite.json": suite_bytes,
        "approval.json": approval_bytes,
    }
    files.update({"source/" + name: data for name, data in {**source, **review}.items()})
    for name in ("pyproject.toml", "uv.lock", "requirements.lock"):
        if (root / name).exists():
            files["source/" + name] = _read(root / name)
    for data in files.values():
        _no_secrets(data.decode("utf-8", errors="replace"))
    manifest = {
        "schema_version": "evaluation-freeze/v1",
        "created_at": datetime.now(UTC).isoformat(),
        **hashes,
        "suite_schema_version": suite["schema_version"],
        "suite_version": suite["suite_version"],
        "trace_schema_version": "evaluation-trace/v1",
        "run_semantics": _semantics(config),
        "files": {name: _sha(data) for name, data in sorted(files.items())},
        "approval_provenance": (
            "Supplied human approval record; identity is not authenticated by this utility."
        ),
    }
    manifest["freeze_id"] = _sha(_canonical(manifest))
    # Exclusive creation is deliberate: a partial failed write is retained for
    # investigation, and cannot be silently reused as a successful freeze.
    output.mkdir(parents=True, exist_ok=False)
    for name, data in files.items():
        path = output / name
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as stream:
            stream.write(data)
    with (output / "manifest.json").open("xb") as stream:
        stream.write(
            json.dumps(manifest, indent=2, sort_keys=True, allow_nan=False).encode() + b"\n"
        )
    return verify_freeze(output)


def _inventory(path: Path) -> set[str]:
    if path.is_symlink() or not path.is_dir():
        raise FreezeError("Freeze must be a regular directory")
    files = set()
    for item in path.rglob("*"):
        if item.is_symlink() or (not item.is_file() and not item.is_dir()):
            raise FreezeError("Freeze contains a symlink or unsupported file")
        if item.is_file():
            files.add(item.relative_to(path).as_posix())
    return files


def verify_freeze(path: Path) -> dict[str, Any]:
    """Check portable byte integrity, approval bindings, and frozen semantics."""
    path = Path(path)
    actual = _inventory(path)
    manifest = _json(_read(path / "manifest.json"))
    if manifest.get("schema_version") != "evaluation-freeze/v1":
        raise FreezeError("Unsupported freeze schema_version")
    identity = dict(manifest)
    freeze_id = identity.pop("freeze_id", None)
    if freeze_id != _sha(_canonical(identity)):
        raise FreezeError("Freeze manifest identity has changed")
    entries = _object(manifest.get("files"), "manifest.files")
    for name, digest in entries.items():
        if (
            not isinstance(name, str)
            or not name
            or "\\" in name
            or PurePosixPath(name).is_absolute()
            or ".." in PurePosixPath(name).parts
            or str(PurePosixPath(name)) != name
            or name == "manifest.json"
        ):
            raise FreezeError("Invalid snapshot path in manifest")
        if not isinstance(digest, str) or not _HASH.fullmatch(digest):
            raise FreezeError("Invalid snapshot checksum in manifest")
    if actual != set(entries) | {"manifest.json"}:
        raise FreezeError("Freeze file inventory differs from the manifest")
    files = {name: _read(path / name) for name in entries}
    if any(_sha(data) != entries[name] for name, data in files.items()):
        raise FreezeError("Frozen evidence bytes have changed")
    for data in files.values():
        _no_secrets(data.decode("utf-8", errors="replace"))
    required = {
        "protocol.json",
        "suite.json",
        "approval.json",
        *("source/" + name for name in _REVIEW_FILES),
    }
    if not required.issubset(files):
        raise FreezeError("Freeze lacks required protocol, suite, approval, or review evidence")
    source = {
        name[len("source/") :]: data
        for name, data in files.items()
        if name.startswith("source/src/effectshield/") and name.endswith(".py")
    }
    if not source:
        raise FreezeError("Freeze lacks implementation source")
    hashes = {
        "protocol_sha256": _sha(files["protocol.json"]),
        "suite_sha256": _sha(files["suite.json"]),
        "implementation_sha256": _implementation_digest(source),
        "interface_sha256": _sha(files["source/" + _REVIEW_FILES[0]]),
        "grader_cases_sha256": _sha(files["source/" + _REVIEW_FILES[1]]),
    }
    if any(manifest.get(key) != value for key, value in hashes.items()):
        raise FreezeError("Manifest bindings disagree with frozen evidence")
    config, suite = _json(files["protocol.json"]), _suite(files["suite.json"])
    validate_protocol(config, official=True)
    _approval(_json(files["approval.json"]), hashes)
    _no_secrets(_json(files["source/" + _REVIEW_FILES[1]]))
    if (
        manifest.get("run_semantics") != _semantics(config)
        or manifest.get("suite_schema_version") != suite["schema_version"]
        or manifest.get("suite_version") != suite["suite_version"]
        or manifest.get("trace_schema_version") != "evaluation-trace/v1"
    ):
        raise FreezeError("Manifest semantics disagree with frozen inputs")
    _date(manifest.get("created_at"), "manifest.created_at", timestamp=True)
    return manifest
