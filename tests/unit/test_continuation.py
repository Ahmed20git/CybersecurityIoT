"""Continuation after allow, block, repair, abstention and escalation, offline."""

from copy import deepcopy
from pathlib import Path

import pytest

from effectshield.agent import BoundedAgent, CallEstimate, ModelResponse, load_conditions
from effectshield.agent.continuation import (
    CONTINUATION_PROTOCOL_VERSION,
    MAX_CONSECUTIVE_REFUSALS,
    Outcome,
    interpret,
)
from effectshield.experiments.storage import canonical, load_json
from effectshield.scenarios import load_suite

ROOT = Path(__file__).resolve().parents[2]
ACTION = canonical(
    {
        "schema_version": "1.0",
        "device": "light",
        "operation": "turn_on",
        "parameters": {},
        "evidence_refs": [],
    }
)
FINISH = '{"finish":"completed"}'


class FakeModel:
    """Deterministic offline client; counts every submitted call."""

    kind = "fixture"
    model_version = "continuation-fake-v1"
    model_date = "2026-10-05"
    seed_status = "supported"

    def __init__(self, responses):
        self.responses = list(responses)
        self.invocations = []

    def reset(self):
        self.invocations = []

    def estimate(self, messages, remaining_tokens):
        return CallEstimate(1, 1, 0.0, "USD")

    def generate(self, messages, reservation, config):
        self.invocations.append(deepcopy(messages))
        return ModelResponse(self.responses.pop(0), 1, 1, 0.0, "synthetic", "USD")


def setup(responses, *, condition=None, clock=None, **limits):
    case = load_suite(ROOT / "scenarios/development/baseline.json")["scenarios"][0]
    config = load_json(ROOT / "configs/evaluation/gate.json")
    config["limits"].update(max_tokens=100, **limits)
    extra = {}
    if condition is not None:
        extra["condition"] = condition
        config["prompt_version"] = condition.prompt_version
    if clock is not None:
        extra["clock"] = clock
    model = FakeModel(responses)
    return BoundedAgent(case["request"], case["observations"], config, model, **extra), model


def transaction(status, version=1, reason=None):
    return {
        "status": status,
        "transaction_id": f"tx-{version}",
        "version_before": version - 1 if status == "committed" else version,
        "version_after": version if status == "committed" else version,
        "reason_code": reason,
        "failed_index": 0 if status == "rejected" else None,
    }


BLOCKED = {"status": "blocked", "reason_code": "rule_authority", "state_version": 0}
REPAIRED = {
    "status": "repaired",
    "transaction_id": "tx-1",
    "version_before": 0,
    "version_after": 1,
    "reason_code": "rule_thermostat_range",
    "executed_actions": [canonical({"device": "light"})],
}


def test_protocol_is_versioned_and_bounded():
    assert CONTINUATION_PROTOCOL_VERSION == "continuation-draft/v1"
    assert MAX_CONSECUTIVE_REFUSALS >= 1


@pytest.mark.parametrize(
    ("feedback", "outcome", "terminal", "refusal"),
    [
        (transaction("committed"), Outcome.COMMITTED, None, False),
        ({"status": "observed", "observation": {}}, Outcome.OBSERVED, None, False),
        (transaction("rejected", reason="door_locked"), Outcome.REJECTED, None, True),
        (BLOCKED, Outcome.BLOCKED, None, True),
        (REPAIRED, Outcome.REPAIRED, None, False),
        (
            {"status": "abstained", "reason_code": "ambiguous"},
            Outcome.ABSTAINED,
            "abstained",
            False,
        ),
        (
            {"status": "escalated", "reason_code": "needs_user"},
            Outcome.ESCALATED,
            "escalated",
            False,
        ),
    ],
)
def test_each_outcome_has_a_fixed_directive(feedback, outcome, terminal, refusal):
    directive = interpret(feedback)
    assert directive.outcome is outcome
    assert directive.terminal_status == terminal
    assert directive.refusal is refusal
    assert directive.visible == feedback


@pytest.mark.parametrize(
    "feedback",
    [
        None,
        [],
        {"status": "allowed"},
        {"status": "committed", "version_after": 1},
        {**BLOCKED, "rule_internals": {"expected_result": "unsafe"}},
        {**BLOCKED, "reason_code": ""},
        {**BLOCKED, "reason_code": None},
        transaction("rejected"),
        {**REPAIRED, "executed_actions": []},
        {"status": "escalated"},
    ],
)
def test_malformed_feedback_is_a_harness_defect(feedback):
    with pytest.raises(ValueError):
        interpret(feedback)


def test_allowed_effect_continues_to_completion():
    agent, model = setup([ACTION, FINISH])
    assert agent.step().status == "proposed"
    assert agent.step(transaction("committed")).status == "completed"
    assert len(model.invocations) == 2


def test_block_is_visible_and_agent_may_continue_within_the_same_budget():
    agent, model = setup([ACTION, ACTION, FINISH])
    assert agent.step().status == "proposed"
    assert agent.step(BLOCKED).status == "proposed"
    assert model.invocations[-1][-1] == {"role": "tool", "content": BLOCKED}
    assert agent.step(transaction("committed")).status == "completed"
    assert agent.calls == 3


def test_block_never_buys_extra_calls_beyond_the_matched_budget():
    agent, model = setup([ACTION, ACTION, FINISH], max_calls=2)
    agent.step()
    agent.step(BLOCKED)
    stopped = agent.step(transaction("committed"))
    assert stopped.status == "budget_exceeded"
    assert len(model.invocations) == 2


def test_consecutive_refusals_terminate_retry_loops_without_another_call():
    agent, model = setup([ACTION] * 10, max_calls=10, max_steps=10)
    agent.step()
    agent.step(BLOCKED)
    stopped = agent.step(transaction("rejected", reason="door_locked"))
    assert stopped.status == "budget_exceeded"
    assert stopped.error == "Consecutive refusal limit reached"
    assert len(model.invocations) == MAX_CONSECUTIVE_REFUSALS
    assert stopped.messages[-1]["content"]["status"] == "rejected"


def test_success_resets_the_refusal_count():
    agent, model = setup([ACTION, ACTION, ACTION, ACTION, FINISH], max_calls=10)
    agent.step()
    assert agent.step(BLOCKED).status == "proposed"
    assert agent.step(REPAIRED).status == "proposed"
    assert agent.step(BLOCKED).status == "proposed"
    assert agent.step(transaction("committed", version=2)).status == "completed"


@pytest.mark.parametrize("status", ["abstained", "escalated"])
def test_mediator_abstention_and_escalation_stop_without_a_call(status):
    agent, model = setup([ACTION, FINISH])
    agent.step()
    stopped = agent.step({"status": status, "reason_code": "needs_user"})
    assert stopped.status == status
    assert "needs_user" in stopped.error
    assert len(model.invocations) == 1
    with pytest.raises(ValueError, match="stopped"):
        agent.step()


def test_wall_clock_limit_stops_before_the_next_call():
    now = [100.0]
    agent, model = setup([ACTION, FINISH], clock=lambda: now[0], wall_timeout_s=30)
    assert agent.step().status == "proposed"
    now[0] = 130.0
    stopped = agent.step(transaction("committed"))
    assert stopped.status == "timeout"
    assert len(model.invocations) == 1


def test_safety_prompt_condition_adds_only_its_instruction():
    conditions = load_conditions(ROOT / "configs/conditions")
    plain, plain_model = setup([FINISH], condition=conditions["unprotected"])
    guarded, guarded_model = setup([FINISH], condition=conditions["safety_prompt_only"])
    plain.step()
    guarded.step()
    plain_system = plain_model.invocations[0][0]["content"]
    guarded_system = guarded_model.invocations[0][0]["content"]
    assert "safety_instruction" not in plain_system
    assert (
        guarded_system["safety_instruction"] == conditions["safety_prompt_only"].safety_instruction
    )
    differing = {key for key in guarded_system if guarded_system[key] != plain_system.get(key)}
    assert differing == {"safety_instruction", "prompt_version"}
    assert plain_model.invocations[0][1:] == guarded_model.invocations[0][1:]


def test_condition_prompt_version_must_match_the_run_configuration():
    condition = load_conditions(ROOT / "configs/conditions")["safety_prompt_only"]
    case = load_suite(ROOT / "scenarios/development/baseline.json")["scenarios"][0]
    config = load_json(ROOT / "configs/evaluation/gate.json")
    with pytest.raises(ValueError, match="prompt version"):
        BoundedAgent(
            case["request"], case["observations"], config, FakeModel([]), condition=condition
        )
