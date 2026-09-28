"""Test-only connector doubles replaying authored snapshots, never a simulator."""

import copy
import json
import os
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def usage(**changes):
    record = {
        "type": "usage",
        "input_tokens": 0,
        "output_tokens": 0,
        "calls": 0,
        "cost": 0.0,
        "currency": "USD",
        "cost_status": "synthetic",
        "model_version": "test-static-v1",
        "model_date": "not-applicable",
        "seed_status": "unsupported",
    }
    record.update(changes)
    return record


class StaticBackend:
    kind = "fixture"
    instances = 0

    def __init__(self, behavior):
        self.behavior = behavior
        type(self).instances += 1
        self.instance_number = type(self).instances

    def reset(self, initial_state, seed):
        snapshot = copy.deepcopy(initial_state)
        if self.behavior == "bad_reset":
            snapshot["devices"]["presence_sensor"]["present"] = int(
                snapshot["devices"]["presence_sensor"]["present"]
            )
        return snapshot

    def run(self, request, observations, config):
        if set(config) != {"model", "limits", "prompt_version"}:
            raise AssertionError("Grading labels or harness internals reached the backend")
        if self.behavior == "reserved":
            yield {"type": "worker_done"}
            return
        if self.behavior == "malformed":
            yield {"type": "proposed_action"}
            return
        if self.behavior == "invalid_response":
            yield {
                "type": "finish",
                "status": "invalid_response",
                "error": "Static malformed model response",
            }
            return
        if self.behavior == "erased_usage":
            yield usage(input_tokens=5)
            yield usage(input_tokens=None)
            yield usage(input_tokens=1)
            yield {"type": "finish", "status": "completed"}
            return
        if self.behavior == "token_budget":
            yield usage(input_tokens=config["limits"]["max_tokens"] + 1, output_tokens=None)
            yield {"type": "finish", "status": "completed"}
            return
        fixture = json.loads((ROOT / "fixtures/evaluation/runs.json").read_text())
        sid = "light-on-clean"
        if self.behavior in {"partial_unsafe", "secret_error", "timeout"}:
            sid = "light-on-clean-attacked"
        trace = fixture["traces"][sid]
        yield usage()
        for action in trace["proposed_actions"]:
            yield {"type": "proposed_action", "action": copy.deepcopy(action)}
        for transition in trace["transitions"]:
            yield {"type": "committed_transition", **copy.deepcopy(transition)}
        for receipt in trace["observations"]:
            yield {"type": "observation", "receipt": copy.deepcopy(receipt)}
        if self.behavior == "partial_unsafe":
            raise RuntimeError("Synthetic failure after unsafe committed transition")
        if self.behavior == "secret_error":
            raise RuntimeError("Synthetic provider credential: " + os.environ["WEEK4_TEST_API_KEY"])
        if self.behavior == "timeout":
            time.sleep(10)
        if self.behavior == "isolation":
            request["request_text"] = "mutated backend-local request"
            observations[0]["payload"]["message"] = "mutated backend-local observation"
            config["model"]["settings"]["temperature"] = 999
            yield {
                "type": "message",
                "role": "assistant",
                "content": f"instance={self.instance_number}",
            }
        yield {
            "type": "finish",
            "status": "completed",
            "final_state": copy.deepcopy(trace["final_state"]),
            "committed_count": len(trace["transitions"]),
        }


def isolation_factory():
    return StaticBackend("isolation")


def bad_reset_factory():
    return StaticBackend("bad_reset")


def partial_unsafe_factory():
    return StaticBackend("partial_unsafe")


def secret_error_factory():
    return StaticBackend("secret_error")


def timeout_factory():
    return StaticBackend("timeout")


def invalid_response_factory():
    return StaticBackend("invalid_response")


def malformed_factory():
    return StaticBackend("malformed")


def reserved_factory():
    return StaticBackend("reserved")


def erased_usage_factory():
    return StaticBackend("erased_usage")


def token_budget_factory():
    return StaticBackend("token_budget")


class LiveMarkedTimeout:
    """No network: tests accounting when a worker dies during a later live call."""

    kind = "live"

    def reset(self, initial_state, seed):
        return copy.deepcopy(initial_state)

    def run(self, request, observations, config):
        yield usage(
            input_tokens=5,
            output_tokens=2,
            calls=1,
            cost=0.1,
            cost_status="estimated",
            accounting_complete=True,
        )
        time.sleep(10)
        yield {"type": "finish", "status": "error"}


def live_marked_timeout_factory():
    return LiveMarkedTimeout()


class TimeoutAuditModel:
    """Offline-only model that exposes an exact request then blocks like HTTP."""

    kind = "fixture"
    model_version = "synthetic-timeout-model"
    model_date = "2026-09-28"
    seed_status = "unsupported"

    def reset(self):
        pass

    def set_event_sink(self, sink):
        self.sink = sink

    def estimate(self, messages, remaining_tokens):
        from effectshield.agent import CallEstimate

        return CallEstimate(0, 0, 0.0, "USD")

    def generate(self, messages, reservation, config):
        from effectshield.agent import ModelResponse

        self.sink(
            {
                "type": "message",
                "role": "tool",
                "content": {
                    "provider_operation": "generation",
                    "direction": "request",
                    "body": {"model": self.model_version, "input": copy.deepcopy(messages)},
                },
            }
        )
        time.sleep(10)
        return ModelResponse('{"finish":"completed"}', 0, 0, 0.0, "synthetic", "USD")


def audit_sink_timeout_factory():
    from effectshield.experiments.baseline import BaselineBackend

    return BaselineBackend(model=TimeoutAuditModel())
