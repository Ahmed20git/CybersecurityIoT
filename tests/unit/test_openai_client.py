"""OpenAI wire-contract tests: fake transport and synthetic key, never provider I/O."""

import json
from copy import deepcopy
from unittest.mock import patch

import pytest

from effectshield.agent.baseline import BoundedAgent, CallEstimate
from effectshield.agent.openai_client import (
    API_HOST,
    COUNT_PATH,
    GENERATE_PATH,
    MODEL_DATE,
    MODEL_VERSION,
    HTTPResult,
    OpenAIClientError,
    OpenAIResponsesClient,
    _post,
)
from effectshield.experiments.openai_baseline import create_backend

TEST_KEY = "synthetic-test-credential"
MESSAGES = [
    {"role": "system", "content": {"instruction": "Return one native action JSON object."}},
    {"role": "user", "content": {"request_text": "Turn on the light"}},
    {"role": "tool", "content": {"power": "off", "message": "untrusted sensor text"}},
]
CONFIG = {
    "provider": "openai",
    "version": MODEL_VERSION,
    "date": MODEL_DATE,
    "settings": {"temperature": 0},
    "seed": None,
    "seed_status": "unsupported",
}
ACTION = '{"schema_version":"1.0","device":"light","operation":"turn_on","parameters":{}}'


def generation(**changes):
    value = {
        "id": "resp-test",
        "object": "response",
        "model": MODEL_VERSION,
        "status": "completed",
        "error": None,
        "incomplete_details": None,
        "output": [
            {
                "type": "message",
                "role": "assistant",
                "content": [{"type": "output_text", "text": ACTION}],
            }
        ],
        "usage": {
            "input_tokens": 100,
            "output_tokens": 30,
            "total_tokens": 130,
            "input_tokens_details": {"cached_tokens": 20},
            "output_tokens_details": {"reasoning_tokens": 0},
        },
    }
    value.update(changes)
    return value


class FakeTransport:
    def __init__(self, responses=None):
        self.responses = (
            responses
            if responses is not None
            else [
                {"object": "response.input_tokens", "input_tokens": 100},
                generation(),
            ]
        )
        self.requests = []

    def __call__(self, path, body, api_key, timeout_s):
        assert api_key == TEST_KEY
        self.requests.append((path, json.loads(body), timeout_s))
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        if isinstance(response, HTTPResult):
            return response
        return HTTPResult(200, json.dumps(response).encode())


def client_for(response=None):
    responses = (
        None
        if response is None
        else [
            {"object": "response.input_tokens", "input_tokens": 100},
            response,
        ]
    )
    transport = FakeTransport(responses)
    client = OpenAIResponsesClient(transport=transport, key_getter=lambda: TEST_KEY)
    client.configure(CONFIG)
    return client, transport


def generated(client):
    reservation = client.estimate(MESSAGES, 2000)
    client.drain_messages()
    return client.generate(MESSAGES, reservation, CONFIG)


def test_exact_count_body_is_bound_to_generation_and_caps():
    client, transport = client_for()
    reservation = client.estimate(MESSAGES, 2000)
    preflight = client.drain_messages()
    result = client.generate(MESSAGES, reservation, CONFIG)
    assert result.stop_status is None
    assert result.text == ACTION
    count, generate = transport.requests
    assert count[0] == COUNT_PATH and generate[0] == GENERATE_PATH
    assert all(generate[1][key] == value for key, value in count[1].items())
    assert generate[1]["store"] is False
    assert generate[1]["stream"] is False
    assert generate[1]["max_output_tokens"] == 512
    assert generate[1]["service_tier"] == "default"
    assert generate[1]["truncation"] == "disabled"
    assert "seed" not in generate[1] and "tools" not in generate[1]
    assert count[2] == generate[2] == 20
    assert preflight[0]["content"]["body"] == count[1]
    assert result.messages[0]["content"]["body"] == generate[1]
    assert preflight[1]["content"]["provider_operation"] == "input_token_count"
    assert client.drain_messages() == []


def test_tool_payload_remains_user_evidence_and_is_never_promoted():
    client, transport = client_for()
    generated(client)
    wire = transport.requests[0][1]["input"]
    assert [message["role"] for message in wire] == ["system", "user", "user"]
    assert json.loads(wire[2]["content"])["type"] == "simulator_tool_result"
    assert json.loads(wire[2]["content"])["content"] == MESSAGES[2]["content"]


def test_published_tariff_cost_is_estimated_and_cache_aware():
    client, _ = client_for()
    result = generated(client)
    assert result.input_tokens == 100 and result.output_tokens == 30
    assert result.cost == pytest.approx((80 * 0.40 + 20 * 0.10 + 30 * 1.60) / 1_000_000)
    assert result.cost_status == "estimated"
    assert result.messages[-1]["content"]["cached_input_tokens"] == 20


def test_reservation_uses_uncached_price_and_capped_output():
    client, _ = client_for()
    reservation = client.estimate(MESSAGES, 300)
    assert reservation.input_tokens == 100 and reservation.output_tokens == 200
    assert reservation.cost >= (100 * 0.40 + 200 * 1.60) / 1_000_000
    assert reservation.currency == "USD"


@pytest.mark.parametrize("mutation", ["messages", "reservation", "settings", "reset"])
def test_changed_or_reused_preflight_cannot_generate(mutation):
    client, transport = client_for()
    reservation = client.estimate(MESSAGES, 2000)
    messages, config = deepcopy(MESSAGES), deepcopy(CONFIG)
    if mutation == "messages":
        messages[1]["content"] = "changed request"
    elif mutation == "reservation":
        reservation = CallEstimate(200, 512, 1, "USD")
    elif mutation == "settings":
        config["settings"]["temperature"] = 1
    else:
        client.reset()
    result = client.generate(messages, reservation, config)
    assert result.stop_status == "error" and result.submitted is False
    assert len(transport.requests) == 1


def test_reservation_is_single_use_even_after_error():
    client, transport = client_for(TimeoutError(TEST_KEY))
    reservation = client.estimate(MESSAGES, 2000)
    first = client.generate(MESSAGES, reservation, CONFIG)
    second = client.generate(MESSAGES, reservation, CONFIG)
    assert first.submitted is True and first.cost is None
    assert second.submitted is False
    assert len(transport.requests) == 2
    assert TEST_KEY not in str(first)


@pytest.mark.parametrize(
    "field,value",
    [
        ("provider", "other"),
        ("version", "gpt-4.1-mini"),
        ("date", "2026-01-01"),
        ("seed", 1),
        ("seed_status", "supported"),
        ("settings", {"api_key": TEST_KEY}),
        ("settings", {"max_output_tokens": 513}),
        ("settings", {"timeout_s": 0}),
        ("settings", {"temperature": float("nan")}),
    ],
)
def test_unsupported_config_rejected_before_transport(field, value):
    client, transport = client_for()
    config = deepcopy(CONFIG)
    config[field] = value
    with pytest.raises(OpenAIClientError):
        client.configure(config)
    assert transport.requests == []


def test_client_metadata_is_read_only_and_factory_does_not_read_key():
    with patch(
        "effectshield.agent.openai_client._key_from_environment",
        side_effect=AssertionError("read key"),
    ):
        backend = create_backend()
        backend.model.reset()
    assert backend.kind == "live"
    for attribute in ("model_version", "model_date", "seed_status", "kind"):
        with pytest.raises(AttributeError):
            setattr(backend.model, attribute, "changed")


@pytest.mark.parametrize("count", [None, True, -1, "100", 10000001])
def test_invalid_provider_token_count_stops_before_generation(count):
    transport = FakeTransport([{"object": "response.input_tokens", "input_tokens": count}])
    client = OpenAIResponsesClient(transport=transport, key_getter=lambda: TEST_KEY)
    with pytest.raises(OpenAIClientError):
        client.estimate(MESSAGES, 2000)
    assert len(transport.requests) == 1
    assert client.drain_messages()[0]["content"]["provider_operation"] == "input_token_count"


def test_preflight_error_retains_request_without_secrets():
    transport = FakeTransport([TimeoutError(TEST_KEY)])
    client = OpenAIResponsesClient(transport=transport, key_getter=lambda: TEST_KEY)
    with pytest.raises(OpenAIClientError) as error:
        client.estimate(MESSAGES, 2000)
    assert TEST_KEY not in str(error.value)
    evidence = client.drain_messages()
    assert len(evidence) == 2 and evidence[-1]["content"]["direction"] == "error"
    assert TEST_KEY not in str(evidence)


@pytest.mark.parametrize(
    "response",
    [
        TimeoutError(TEST_KEY),
        OSError(TEST_KEY),
        HTTPResult(429, TEST_KEY.encode()),
        HTTPResult(302, b"redirect"),
        HTTPResult(200, b"not JSON"),
        HTTPResult(200, b'{"object":"response","object":"response"}'),
        HTTPResult(200, b'{"usage":NaN}'),
        HTTPResult(200, b"x" * 1_000_001),
    ],
)
def test_transport_and_malformed_responses_stop_without_retries(response):
    client, transport = client_for(response)
    result = generated(client)
    assert result.stop_status == "error"
    assert result.submitted is True
    assert result.cost is None and result.cost_status == "unavailable"
    assert len(transport.requests) == 2
    assert TEST_KEY not in str(result)


@pytest.mark.parametrize(
    "usage",
    [
        None,
        {},
        {"input_tokens": True, "output_tokens": 30},
        {"input_tokens": 100, "output_tokens": 30, "total_tokens": 130},
        {
            "input_tokens": 100,
            "output_tokens": 30,
            "total_tokens": 130,
            "input_tokens_details": {"cached_tokens": 101},
        },
        {
            "input_tokens": 100,
            "output_tokens": 30,
            "total_tokens": 999,
            "input_tokens_details": {"cached_tokens": 0},
        },
    ],
)
def test_unknown_usage_cannot_become_free_success(usage):
    client, _ = client_for(generation(usage=usage))
    result = generated(client)
    assert result.stop_status == "error"
    assert result.cost is None and result.cost_status == "unavailable"


@pytest.mark.parametrize(
    "changes,status",
    [
        ({"model": "gpt-4.1-mini"}, "invalid_response"),
        (
            {"status": "incomplete", "incomplete_details": {"reason": "max_output_tokens"}},
            "invalid_response",
        ),
        ({"status": "failed", "error": {"message": TEST_KEY}}, "error"),
        (
            {"output": [{"type": "reasoning", "summary": [{"text": "PRIVATE REASONING"}]}]},
            "invalid_response",
        ),
        (
            {
                "output": [
                    {
                        "type": "message",
                        "role": "assistant",
                        "content": [{"type": "refusal", "refusal": "declined"}],
                    }
                ]
            },
            "abstained",
        ),
    ],
)
def test_refusal_incomplete_version_and_hidden_reasoning_never_execute(changes, status):
    client, _ = client_for(generation(**changes))
    result = generated(client)
    assert result.stop_status == status
    assert result.input_tokens == 100 and result.output_tokens == 30 and result.cost is not None
    assert TEST_KEY not in str(result)
    assert "PRIVATE REASONING" not in str(result)


@pytest.mark.parametrize(
    "text", ["not json", "[]", '{"a":1,"a":2}', '{"a":NaN}', "```json\n{}\n```"]
)
def test_only_strict_json_object_text_is_accepted(text):
    response = generation()
    response["output"][0]["content"][0]["text"] = text
    client, _ = client_for(response)
    result = generated(client)
    assert result.stop_status == "invalid_response" and result.cost is not None


def test_echoed_key_is_redacted_and_not_executable():
    response = generation()
    response["output"][0]["content"][0]["text"] = json.dumps({"key": TEST_KEY})
    client, _ = client_for(response)
    result = generated(client)
    assert result.stop_status == "invalid_response"
    assert TEST_KEY not in str(result)
    assert "[REDACTED:" in result.text


def test_missing_key_and_accidental_key_in_input_never_reach_transport():
    transport = FakeTransport()
    client = OpenAIResponsesClient(transport=transport, key_getter=lambda: "")
    with pytest.raises(OpenAIClientError):
        client.estimate(MESSAGES, 2000)
    client = OpenAIResponsesClient(transport=transport, key_getter=lambda: TEST_KEY)
    with pytest.raises(OpenAIClientError):
        client.estimate([{"role": "user", "content": TEST_KEY}], 2000)
    assert transport.requests == []
    assert TEST_KEY not in str(client.drain_messages())


def test_zero_budget_stops_before_authenticated_count_preflight():
    client, transport = client_for()
    config = {
        "model": CONFIG,
        "prompt_version": "baseline/v1",
        "limits": {
            "max_steps": 8,
            "max_calls": 4,
            "max_tokens": 10240,
            "max_cost": 0,
            "currency": "USD",
        },
    }
    agent = BoundedAgent({"request_text": "light on"}, [], config, client)
    step = agent.step()
    assert step.status == "budget_exceeded"
    assert transport.requests == [] and agent.usage["calls"] == 0


def test_counted_reservation_over_budget_stops_generation_and_retains_preflight():
    client, transport = client_for()
    config = {
        "model": CONFIG,
        "prompt_version": "baseline/v1",
        "limits": {
            "max_steps": 8,
            "max_calls": 4,
            "max_tokens": 10240,
            "max_cost": 0.000001,
            "currency": "USD",
        },
    }
    agent = BoundedAgent({"request_text": "light on"}, [], config, client)
    step = agent.step()
    assert step.status == "budget_exceeded"
    assert len(transport.requests) == 1 and agent.usage["calls"] == 0
    assert any(
        message["content"].get("provider_operation") == "input_token_count"
        for message in step.messages
    )


def test_stdlib_transport_uses_fixed_host_tls_single_post_and_response_bound():
    class Reply:
        status = 200

        def read(self, count):
            assert count == 1_000_001
            return b"{}"

    class Connection:
        def __init__(self):
            self.calls = []
            self.closed = False

        def request(self, method, path, body, headers):
            self.calls.append((method, path, body, headers))

        def getresponse(self):
            return Reply()

        def close(self):
            self.closed = True

    connection = Connection()
    with patch(
        "effectshield.agent.openai_client.http.client.HTTPSConnection", return_value=connection
    ) as factory:
        result = _post(COUNT_PATH, b"{}", TEST_KEY, 2)
    factory.assert_called_once_with(API_HOST, timeout=2)
    assert result == HTTPResult(200, b"{}") and connection.closed
    assert len(connection.calls) == 1 and connection.calls[0][0] == "POST"
    assert connection.calls[0][3]["Authorization"] == f"Bearer {TEST_KEY}"


def test_durable_sink_acknowledges_exact_requests_before_transport_without_duplicates():
    events = []
    transport = FakeTransport()

    def sink(event):
        assert event["type"] == "message"
        events.append(event)

    def checked_transport(path, body, api_key, timeout_s):
        assert events[-1]["content"]["direction"] == "request"
        assert events[-1]["content"]["body"] == json.loads(body)
        return transport(path, body, api_key, timeout_s)

    client = OpenAIResponsesClient(transport=checked_transport, key_getter=lambda: TEST_KEY)
    client.configure(CONFIG)
    client.set_event_sink(sink)
    reservation = client.estimate(MESSAGES, 2000)
    assert client.drain_messages() == []
    result = client.generate(MESSAGES, reservation, CONFIG)
    assert result.stop_status is None and result.messages == []
    assert [event["content"]["direction"] for event in events] == [
        "request",
        "response",
        "request",
        "response",
    ]
    assert TEST_KEY not in str(events)


def test_failure_to_persist_request_prevents_provider_submission():
    client, transport = client_for()
    reservation = client.estimate(MESSAGES, 2000)

    def failed_sink(event):
        raise OSError("disk failed: " + TEST_KEY)

    client.set_event_sink(failed_sink)
    result = client.generate(MESSAGES, reservation, CONFIG)
    assert result.stop_status == "error" and result.submitted is False
    assert result.cost == 0 and len(transport.requests) == 1
    assert TEST_KEY not in str(result)
