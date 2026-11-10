"""Static fixture replay and loading of a future trusted inference connector."""

from collections.abc import Iterable
from copy import deepcopy
from importlib import import_module
from pathlib import Path
from typing import Any, Protocol, cast

from .storage import canonical, load_json

FIXTURE_SCHEMA_VERSION = "evaluation-fixtures/v1"


class Backend(Protocol):
    kind: str

    def reset(self, initial_state: dict[str, Any], seed: int | None) -> dict[str, Any]: ...

    def run(
        self, request: dict[str, Any], observations: list[dict[str, Any]], config: dict[str, Any]
    ) -> Iterable[dict[str, Any]]: ...


def load_fixture_trace(fixture_path: str | Path, scenario_id: str) -> dict[str, Any]:
    document = load_json(fixture_path)
    if document.get("schema_version") != FIXTURE_SCHEMA_VERSION:
        raise ValueError("Unsupported evaluation fixture version")
    return cast(dict[str, Any], deepcopy(document["traces"][scenario_id]))


def synthetic_usage(config: dict[str, Any], *, replay: bool = False) -> dict[str, Any]:
    """Explicitly zero inference usage, never a model-performance observation."""
    model = config["model"]
    return {
        "type": "usage",
        "input_tokens": 0,
        "output_tokens": 0,
        "calls": 0,
        "cost": 0.0,
        "currency": config["limits"]["currency"],
        "cost_status": "synthetic",
        "model_version": model.get("version")
        or ("recorded-proposals-v1" if replay else "static-fixture-v1"),
        "model_date": model.get("date") or "not-applicable",
        "seed_status": model["seed_status"],
    }


def load_backend(specification: str) -> Backend:
    module, separator, factory = specification.partition(":")
    if not separator or not module or not factory or "." in factory:
        raise ValueError("Backend must be a trusted module:factory")
    return cast(Backend, getattr(import_module(module), factory)())


class FixtureBackend:
    kind = "fixture"

    def __init__(self, fixture_path: str | Path, scenario_id: str) -> None:
        self.trace = load_fixture_trace(fixture_path, scenario_id)

    def reset(self, initial_state: dict[str, Any], seed: int | None) -> dict[str, Any]:
        if canonical(initial_state) != canonical(self.trace["initial_state"]):
            raise ValueError("Fixture initial state differs from requested reset")
        return cast(dict[str, Any], deepcopy(self.trace["initial_state"]))

    def run(
        self, request: dict[str, Any], observations: list[dict[str, Any]], config: dict[str, Any]
    ) -> Iterable[dict[str, Any]]:
        yield synthetic_usage(config)
        for action in self.trace["proposed_actions"]:
            yield {"type": "proposed_action", "action": deepcopy(action)}
        for transition in self.trace["transitions"]:
            yield {"type": "committed_transition", **deepcopy(transition)}
        for receipt in self.trace["observations"]:
            yield {"type": "observation", "receipt": deepcopy(receipt)}
        yield {
            "type": "finish",
            "status": self.trace["termination"],
            "final_state": deepcopy(self.trace["final_state"]),
            "committed_count": len(self.trace["transitions"]),
        }
