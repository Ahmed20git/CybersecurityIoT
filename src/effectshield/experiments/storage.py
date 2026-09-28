"""Strict JSON, durable evidence writes and credential-safe visible records."""

import hashlib
import json
import os
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, NoReturn


def now() -> str:
    return datetime.now(UTC).isoformat()


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON field: {key}")
        result[key] = value
    return result


def load_json(path: str | Path) -> Any:
    def invalid_constant(value: str) -> NoReturn:
        raise ValueError(f"Non-finite JSON number: {value}")

    return json.loads(
        Path(path).read_text(encoding="utf-8"),
        object_pairs_hook=_pairs,
        parse_constant=invalid_constant,
    )


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def write_json(path: str | Path, value: Any) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def append_jsonl(path: str | Path, value: Any) -> None:
    with Path(path).open("a", encoding="utf-8") as stream:
        stream.write(canonical(value) + "\n")
        stream.flush()
        os.fsync(stream.fileno())


_SECRET_KEY = re.compile(r"(?i)^(authorization|api[_-]?key|access[_-]?token|password|secret)$")
_TOKEN = re.compile(
    r"\b(?:sk-[\w-]{16,}|gh[pousr]_[\w]{20,}|AKIA[A-Z0-9]{16})\b"
    r"|(?i:bearer\s+[\w.\-/+=]{12,})"
)
_ENV_SECRET = re.compile(r"(?i)(api[_-]?key|token|secret|password|passwd|credential)")


def redact(value: Any) -> Any:
    """Conservative defense in depth; connectors must never emit credentials."""
    if isinstance(value, dict):
        return {
            key: "[REDACTED]" if _SECRET_KEY.match(str(key)) else redact(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, str):
        value = _TOKEN.sub("[REDACTED]", value)
        for key, secret in os.environ.items():
            if _ENV_SECRET.search(key) and secret:
                value = value.replace(secret, "[REDACTED]")
        return value
    return value
