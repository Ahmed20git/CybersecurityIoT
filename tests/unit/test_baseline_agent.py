"""Bounded adapter behavior using deterministic, non-network model clients."""

from copy import deepcopy
from pathlib import Path

import pytest

from effectshield.agent import BoundedAgent, CallEstimate, ModelResponse
from effectshield.experiments.storage import canonical, load_json
from effectshield.scenarios import load_suite

ROOT = Path(__file__).resolve().parents[2]


class TestModel:
    __test__ = False
    kind = "live"  # Test-only simulated accounting; this object has no network code.
    model_version = "synthetic-unit-model-v1"
    model_date = "2026-09-28"
    seed_status = "supported"

    def __init__(self, responses, estimate=None):
        self.responses = list(responses)
        self.reservation = estimate or CallEstimate(5, 3, 0.2, "USD")
        self.invocations = []

    def reset(self):
        self.invocations = []

    def estimate(self, messages, remaining_tokens):
        self.estimated_messages = deepcopy(messages)
        return self.reservation

    def generate(self, messages, reservation, config):
        self.invocations.append((deepcopy(messages), reservation, config))
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


def response(text, **changes):
    values = {
        "text": text,
        "input_tokens": 4,
        "output_tokens": 2,
        "cost": 0.1,
        "cost_status": "actual",
        "currency": "USD",
    }
    values.update(changes)
    return ModelResponse(**values)


def setup_agent(responses, *, estimate=None):
    case = load_suite(ROOT / "scenarios/development/baseline.json")["scenarios"][0]
    config = load_json(ROOT / "configs/evaluation/gate.json")
    config["model"].update(
        provider="unit-test-only",
        version=TestModel.model_version,
        date=TestModel.model_date,
        seed=0,
        seed_status="supported",
    )
    config["limits"].update(max_tokens=100, max_cost=1.0)
    model = TestModel(responses, estimate)
    agent = BoundedAgent(case["request"], case["observations"], config, model)
    return agent, model, case


def native_action():
    return canonical(
        {
            "schema_version": "1.0",
            "device": "light",
            "operation": "turn_on",
            "parameters": {},
            "evidence_refs": [],
        }
    )


def committed(version_after=1):
    return {
        "status": "committed",
        "transaction_id": f"tx-{version_after}",
        "version_before": version_after - 1,
        "version_after": version_after,
        "reason_code": None,
        "failed_index": None,
    }


def test_valid_native_action_visible_feedback_and_finish_are_bounded():
    agent, model, case = setup_agent(
        [response(native_action()), response('{"finish":"completed"}')]
    )
    step = agent.step()
    assert step.status == "proposed"
    assert step.action.to_dict()["operation"] == "turn_on"
    feedback = committed()
    finished = agent.step(feedback)
    assert finished.status == "completed"
    assert model.invocations[-1][0][-1] == {"role": "tool", "content": feedback}
    assert agent.usage["calls"] == 2
    assert agent.usage["input_tokens"] == 8
    assert agent.usage["cost"] == 0.2
    assert agent.calls == 2 and agent.steps == 1
    assert not hasattr(agent, "environment")
    assert not hasattr(agent, "execution_capability")
    assert not any(
        key in canonical(model.invocations[0][0])
        for key in ("expected_result", "state_equals", "thermostat_min_c")
    )
    assert case["request"]["request_text"] in canonical(model.invocations[0][0])
    with pytest.raises(ValueError, match="stopped"):
        agent.step()


@pytest.mark.parametrize(
    "raw",
    [
        "not JSON",
        '{"device":"light","operation":"turn_on","parameters":{}}',
        '{"schema_version":"1.0","device":"light","operation":"turn_on","parameters":{},"identity":"forged"}',
        '{"finish":"completed","finish":"abstained"}',
        '{"finish":"unknown"}',
        '{"finish":"completed","action":{}}',
        '{"finish":NaN}',
        "x" * 4097,
    ],
)
def test_invalid_output_stops_without_a_proposal(raw):
    agent, model, _ = setup_agent([response(raw)])
    step = agent.step()
    assert step.status == "invalid_response"
    assert step.action is None
    assert step.raw_text == raw
    assert agent.usage["calls"] == 1
    assert len(model.invocations) == 1


@pytest.mark.parametrize(
    "estimate",
    [
        CallEstimate(100, 1, 0.2, "USD"),
        CallEstimate(5, 3, 2.0, "USD"),
    ],
)
def test_pre_call_token_and_cost_reservations_prevent_submission(estimate):
    agent, model, _ = setup_agent([response(native_action())], estimate=estimate)
    assert agent.step().status == "budget_exceeded"
    assert model.invocations == []
    assert agent.calls == 0


@pytest.mark.parametrize(
    "estimate",
    [
        CallEstimate(True, 3, 0.2, "USD"),
        CallEstimate(5, 3, float("nan"), "USD"),
        CallEstimate(5, 3, 0.2, "EUR"),
    ],
)
def test_invalid_provider_reservation_prevents_submission(estimate):
    agent, model, _ = setup_agent([response(native_action())], estimate=estimate)
    assert agent.step().status == "error"
    assert model.invocations == []


@pytest.mark.parametrize("limit", ["max_calls", "max_steps"])
def test_loop_stops_at_call_and_action_bounds(limit):
    agent, model, _ = setup_agent([response(native_action()), response(native_action())])
    agent.config["limits"][limit] = 1
    assert agent.step().status == "proposed"
    assert agent.step(committed()).status == "budget_exceeded"
    assert len(model.invocations) == (1 if limit == "max_calls" else 2)


def test_exact_action_bound_still_allows_finish_without_another_effect():
    agent, _, _ = setup_agent([response(native_action()), response('{"finish":"completed"}')])
    agent.config["limits"]["max_steps"] = 1
    assert agent.step().status == "proposed"
    assert agent.step(committed()).status == "completed"
    assert agent.steps == 1


@pytest.mark.parametrize(
    "messages",
    [None, {}, [{"role": [], "content": "bad"}], [{"role": "tool", "content": "x" * 900_001}]],
)
def test_malformed_visible_messages_cannot_erase_returned_usage(messages):
    agent, _, _ = setup_agent([response(native_action(), messages=messages)])
    step = agent.step()
    assert step.status == "invalid_response"
    assert agent.usage["calls"] == 1
    assert agent.usage["cost"] == 0.1
    assert agent.usage["input_tokens"] == 4


def test_foreign_currency_never_acquires_the_configured_currency_label():
    agent, _, _ = setup_agent([response(native_action(), currency="EUR")])
    assert agent.step().status == "error"
    assert agent.usage["currency"] == "USD"
    assert agent.usage["cost"] == 0.0
    assert agent.usage["input_tokens"] == 4
    assert agent.usage["accounting_complete"] is False


def test_reservation_violation_retains_actual_usage_and_stops_before_execution():
    agent, _, _ = setup_agent([response(native_action(), input_tokens=6, cost=0.3)])
    step = agent.step()
    assert step.status == "budget_exceeded"
    assert step.action is None
    assert agent.usage["input_tokens"] == 6
    assert agent.usage["cost"] == 0.3


def test_failed_call_keeps_known_subtotals_and_marks_incomplete_accounting():
    agent, _, _ = setup_agent(
        [response(native_action()), RuntimeError("synthetic interrupted submission")]
    )
    assert agent.step().status == "proposed"
    step = agent.step(committed())
    assert step.status == "error"
    assert agent.usage["calls"] == 2
    assert agent.usage["input_tokens"] == 4
    assert agent.usage["cost"] == 0.1
    assert agent.usage["accounting_complete"] is False
    assert agent.usage["cost_status"] == "unavailable"


def test_unknown_billing_is_not_reported_as_an_actual_zero():
    agent, _, _ = setup_agent([response(native_action(), cost=None, cost_status="unavailable")])
    assert agent.step().status == "error"
    assert agent.usage["accounting_complete"] is False
    assert agent.usage["cost_status"] == "unavailable"


def test_zero_live_budget_does_not_call_provider_preflight_or_generate():
    agent, model, _ = setup_agent([response(native_action())])
    agent.config["limits"]["max_cost"] = 0
    assert agent.step().status == "budget_exceeded"
    assert not hasattr(model, "estimated_messages")
    assert model.invocations == []


def test_failure_before_submission_records_no_provider_call():
    agent, _, _ = setup_agent(
        [
            response(
                "",
                input_tokens=0,
                output_tokens=0,
                cost=0.0,
                stop_status="error",
                error="No credential configured",
                submitted=False,
            )
        ]
    )
    assert agent.step().status == "error"
    assert agent.usage["calls"] == 0
    assert agent.usage["accounting_complete"] is True
    assert agent.calls == 1


def test_provider_messages_and_known_usage_survive_incomplete_response():
    request_body = {"model": TestModel.model_version, "input": "synthetic visible request"}
    agent, _, _ = setup_agent(
        [
            response(
                "partial",
                messages=[{"role": "tool", "content": request_body}],
                stop_status="error",
                error="Provider response incomplete",
            )
        ]
    )
    step = agent.step()
    assert step.status == "error"
    assert step.messages[-1] == {"role": "tool", "content": request_body}
    assert agent.usage["calls"] == 1
    assert agent.usage["cost"] == 0.1


def test_unreviewed_live_provenance_is_rejected_before_model_use():
    agent, model, case = setup_agent([])
    config = deepcopy(agent.config)
    config["model"]["version"] = "different-version"
    with pytest.raises(ValueError, match="provenance"):
        BoundedAgent(case["request"], case["observations"], config, model)
    assert model.invocations == []
