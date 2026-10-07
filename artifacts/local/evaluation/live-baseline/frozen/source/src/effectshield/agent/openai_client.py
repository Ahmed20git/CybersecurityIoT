"""Auditable OpenAI Responses client for a fixed non-reasoning model snapshot.

Official references reviewed 2026-09-28:
https://developers.openai.com/api/docs/models/gpt-4.1-mini
https://developers.openai.com/api/reference/cli/resources/responses/methods/create
https://developers.openai.com/api/reference/resources/responses/subresources/input_tokens/methods/count

Input-token counting is a separately recorded provider preflight. Generation
reserves uncached input plus capped output at the published standard tariff.
Reported token use produces an *estimated* monetary cost, never an invoice.
No retries, alternate endpoints, tools, hidden reasoning, or persisted Responses
conversation state are enabled. Keys are read lazily only for an approved live
preflight/generation; unit tests inject a transport and a synthetic key getter.
"""

from __future__ import annotations

import http.client
import json
import math
import os
from collections.abc import Callable
from copy import deepcopy
from dataclasses import dataclass
from decimal import Decimal
from typing import Any, Protocol, TypeGuard

from .baseline import CallEstimate, ModelResponse

MODEL_VERSION = "gpt-4.1-mini-2025-04-14"
MODEL_DATE = "2025-04-14"
COUNT_PATH = "/v1/responses/input_tokens"
GENERATE_PATH = "/v1/responses"
API_HOST = "api.openai.com"
MAX_RESPONSE_BYTES = 1_000_000
MAX_REQUEST_BYTES = 250_000
MAX_OUTPUT_TOKENS = 512
MAX_TIMEOUT_S = 20.0
CONTEXT_TOKENS = 1_047_576
PRICE_VERSION = "openai-standard-gpt-4.1-mini-2026-09-28"
INPUT_USD_PER_MILLION = Decimal("0.40")
CACHED_INPUT_USD_PER_MILLION = Decimal("0.10")
OUTPUT_USD_PER_MILLION = Decimal("1.60")


@dataclass(frozen=True)
class HTTPResult:
    status: int
    body: bytes


class Transport(Protocol):
    def __call__(self, path: str, body: bytes, api_key: str, timeout_s: float) -> HTTPResult: ...


class OpenAIClientError(ValueError):
    """Sanitized provider/validation failure; never include raw headers or bodies."""


def _key_from_environment() -> str:
    return os.environ.get("OPENAI_API_KEY", "")


def _post(path: str, body: bytes, api_key: str, timeout_s: float) -> HTTPResult:
    """One verified HTTPS request to the official host; redirects are not followed."""
    if path not in {COUNT_PATH, GENERATE_PATH}:
        raise OpenAIClientError("Unsupported OpenAI endpoint")
    connection = http.client.HTTPSConnection(API_HOST, timeout=timeout_s)
    try:
        connection.request(
            "POST",
            path,
            body=body,
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        )
        response = connection.getresponse()
        return HTTPResult(response.status, response.read(MAX_RESPONSE_BYTES + 1))
    finally:
        connection.close()


def _json(value: Any) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )


def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise OpenAIClientError("Provider returned duplicate JSON fields")
        result[key] = value
    return result


def _nonfinite(_: str) -> None:
    raise OpenAIClientError("Provider returned a nonfinite JSON value")


def _decode(raw: bytes) -> dict[str, Any]:
    if not isinstance(raw, bytes) or len(raw) > MAX_RESPONSE_BYTES:
        raise OpenAIClientError("Provider response exceeds the bounded JSON size")
    try:
        value: Any = json.loads(raw, object_pairs_hook=_pairs, parse_constant=_nonfinite)
    except (ValueError, UnicodeError, RecursionError):
        raise OpenAIClientError("Provider returned malformed JSON") from None
    if not isinstance(value, dict):
        raise OpenAIClientError("Provider response must be a JSON object")
    return value


def _counter(value: Any) -> TypeGuard[int]:
    return type(value) is int and 0 <= value <= 10_000_000


def _cost(input_tokens: int, output_tokens: int, cached_tokens: int = 0) -> float:
    dollars = (
        Decimal(input_tokens - cached_tokens) * INPUT_USD_PER_MILLION
        + Decimal(cached_tokens) * CACHED_INPUT_USD_PER_MILLION
        + Decimal(output_tokens) * OUTPUT_USD_PER_MILLION
    ) / Decimal(1_000_000)
    return float(dollars)


def _scrub(value: Any, key: str) -> Any:
    """Do not let an echoed credential enter caller-visible evidence."""
    if isinstance(value, str):
        return value.replace(key, "[REDACTED: provider credential]") if key else value
    if isinstance(value, list):
        return [_scrub(item, key) for item in value]
    if isinstance(value, dict):
        return {name: _scrub(item, key) for name, item in value.items()}
    return value


def _input(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not isinstance(messages, list) or not messages:
        raise OpenAIClientError("Visible message history must be a nonempty list")
    converted = []
    for message in messages:
        if not isinstance(message, dict) or set(message) != {"role", "content"}:
            raise OpenAIClientError("Visible messages require exact role and content fields")
        role, content = message["role"], message["content"]
        if role not in ("system", "developer", "user", "assistant", "tool"):
            raise OpenAIClientError("Unsupported visible message role")
        if role == "tool":
            # Easy input messages have no tool role/call ID. Preserve explicit
            # provenance in a user-role JSON envelope, never promote it to system.
            role = "user"
            content = _json({"type": "simulator_tool_result", "content": content})
        elif not isinstance(content, str):
            content = _json(content)
        converted.append({"role": role, "content": content})
    return converted


class OpenAIResponsesClient:
    """The live ModelClient boundary; construction/reset never touch credentials."""

    def __init__(
        self, *, transport: Transport | None = None, key_getter: Callable[[], str] | None = None
    ) -> None:
        self._transport = transport or _post
        self._key_getter = key_getter or _key_from_environment
        self._settings: dict[str, Any] = {
            "temperature": 0.0,
            "max_output_tokens": MAX_OUTPUT_TOKENS,
            "timeout_s": MAX_TIMEOUT_S,
        }
        self._preflight_messages: list[dict[str, Any]] = []
        self._pending: tuple[str, CallEstimate] | None = None
        self._event_sink: Callable[[dict[str, Any]], None] | None = None
        self._generation_submitted = False

    @property
    def kind(self) -> str:
        return "live"

    @property
    def model_version(self) -> str:
        return MODEL_VERSION

    @property
    def model_date(self) -> str:
        return MODEL_DATE

    @property
    def seed_status(self) -> str:
        return "unsupported"

    def set_event_sink(self, sink: Callable[[dict[str, Any]], None]) -> None:
        """Bind the runner's durable, synchronous evidence acknowledgement path."""
        self._event_sink = sink

    def _record(self, evidence: list[dict[str, Any]], message: dict[str, Any]) -> None:
        if self._event_sink is None:
            evidence.append(message)
        else:
            try:
                self._event_sink({"type": "message", **deepcopy(message)})
            except Exception:
                raise OpenAIClientError(
                    "Cannot persist provider evidence; request processing stopped"
                ) from None

    def reset(self) -> None:
        self._preflight_messages = []
        self._pending = None

    def configure(self, config: dict[str, Any]) -> None:
        """Validate the reviewed provider config before authenticated preflight."""
        expected = {
            "provider": "openai",
            "version": MODEL_VERSION,
            "date": MODEL_DATE,
            "seed_status": "unsupported",
            "seed": None,
        }
        if any(config.get(key) != value for key, value in expected.items()):
            raise OpenAIClientError(
                "OpenAI client requires its exact snapshot and unsupported seed"
            )
        settings = config.get("settings")
        if not isinstance(settings, dict) or set(settings) - {
            "temperature",
            "max_output_tokens",
            "timeout_s",
        }:
            raise OpenAIClientError("Unsupported OpenAI model settings")
        values = {
            "temperature": 0.0,
            "max_output_tokens": MAX_OUTPUT_TOKENS,
            "timeout_s": MAX_TIMEOUT_S,
            **settings,
        }
        temperature, timeout = values["temperature"], values["timeout_s"]
        if (
            type(temperature) not in (int, float)
            or not math.isfinite(temperature)
            or not 0 <= temperature <= 2
        ):
            raise OpenAIClientError("Temperature must be finite and between zero and two")
        if (
            type(timeout) not in (int, float)
            or not math.isfinite(timeout)
            or not 0 < timeout <= MAX_TIMEOUT_S
        ):
            raise OpenAIClientError("Request timeout must be positive and at most twenty seconds")
        if (
            type(values["max_output_tokens"]) is not int
            or not 16 <= values["max_output_tokens"] <= MAX_OUTPUT_TOKENS
        ):
            raise OpenAIClientError("Output cap must be between sixteen and 512 tokens")
        if self._pending is not None and values != self._settings:
            raise OpenAIClientError("Settings changed after input-token preflight")
        self._settings = values

    def drain_messages(self) -> list[dict[str, Any]]:
        messages, self._preflight_messages = self._preflight_messages, []
        return messages

    def _credential(self) -> str:
        key = self._key_getter()
        if (
            not isinstance(key, str)
            or not key.strip()
            or any(character.isspace() for character in key)
        ):
            raise OpenAIClientError(
                "OPENAI_API_KEY is missing or invalid; supply it through the environment"
            )
        return key

    def _request(
        self, path: str, body: dict[str, Any], key: str, evidence: list[dict[str, Any]]
    ) -> dict[str, Any]:
        wire = _json(body).encode("utf-8")
        if len(wire) > MAX_REQUEST_BYTES:
            raise OpenAIClientError("Provider request exceeds the bounded JSON size")
        if key in wire.decode("utf-8"):
            raise OpenAIClientError(
                "Provider credential appeared in visible input; request refused"
            )
        operation = "input_token_count" if path == COUNT_PATH else "generation"
        self._record(
            evidence,
            {
                "role": "tool",
                "content": {
                    "provider_operation": operation,
                    "direction": "request",
                    "endpoint": f"https://{API_HOST}{path}",
                    "body": deepcopy(body),
                },
            },
        )
        try:
            if path == GENERATE_PATH:
                self._generation_submitted = True
            response = self._transport(path, wire, key, float(self._settings["timeout_s"]))
        except TimeoutError:
            self._record(
                evidence,
                {
                    "role": "tool",
                    "content": {
                        "provider_operation": operation,
                        "direction": "error",
                        "error": "Provider request timed out",
                    },
                },
            )
            raise OpenAIClientError("Provider request timed out; no automatic retry") from None
        except Exception:
            self._record(
                evidence,
                {
                    "role": "tool",
                    "content": {
                        "provider_operation": operation,
                        "direction": "error",
                        "error": "Provider transport failed",
                    },
                },
            )
            raise OpenAIClientError("Provider transport failed; no automatic retry") from None
        if not isinstance(response, HTTPResult) or type(response.status) is not int:
            raise OpenAIClientError("Transport returned an invalid HTTP result")
        if response.status != 200:
            self._record(
                evidence,
                {
                    "role": "tool",
                    "content": {
                        "provider_operation": operation,
                        "direction": "error",
                        "http_status": response.status,
                    },
                },
            )
            raise OpenAIClientError(f"OpenAI HTTP {response.status}; no automatic retry")
        return _decode(response.body)

    def _count_body(self, messages: list[dict[str, Any]]) -> dict[str, Any]:
        return {
            "model": MODEL_VERSION,
            "input": _input(messages),
            "text": {"format": {"type": "json_object"}},
            "truncation": "disabled",
        }

    def estimate(self, messages: list[dict[str, Any]], remaining_tokens: int) -> CallEstimate:
        """Count the exact token-relevant request, then reserve capped generation."""
        self._pending = None
        if type(remaining_tokens) is not int or remaining_tokens <= 0:
            raise OpenAIClientError("Positive remaining token budget required before preflight")
        body = self._count_body(messages)
        key = self._credential()
        response = self._request(COUNT_PATH, body, key, self._preflight_messages)
        count = response.get("input_tokens")
        if response.get("object") != "response.input_tokens" or not _counter(count):
            raise OpenAIClientError("Provider returned an invalid input-token count")
        self._record(
            self._preflight_messages,
            {
                "role": "tool",
                "content": {
                    "provider_operation": "input_token_count",
                    "direction": "response",
                    "body": {"object": "response.input_tokens", "input_tokens": count},
                },
            },
        )
        output = min(self._settings["max_output_tokens"], max(16, remaining_tokens - count))
        reservation = CallEstimate(
            count, output, math.nextafter(_cost(count, output), math.inf), "USD"
        )
        if count + output > CONTEXT_TOKENS:
            raise OpenAIClientError("Counted request exceeds the fixed model context window")
        self._pending = (_json(body), reservation)
        return reservation

    def generate(
        self, messages: list[dict[str, Any]], reservation: CallEstimate, config: dict[str, Any]
    ) -> ModelResponse:
        evidence: list[dict[str, Any]] = []
        self._generation_submitted = False
        try:
            self.configure(config)
            body = self._count_body(messages)
            if self._pending is None or self._pending != (_json(body), reservation):
                raise OpenAIClientError(
                    "Generation requires an unchanged fresh token-count reservation"
                )
            if (
                reservation.currency != "USD"
                or reservation.output_tokens > self._settings["max_output_tokens"]
            ):
                raise OpenAIClientError("Generation exceeds the counted reservation")
            key = self._credential()
            self._pending = None  # Single use, including network failures.
            body.update(
                store=False,
                stream=False,
                max_output_tokens=reservation.output_tokens,
                temperature=self._settings["temperature"],
                service_tier="default",
            )
            # Check local errors before treating a model request as submitted.
            wire = _json(body)
            if key in wire or len(wire.encode("utf-8")) > MAX_REQUEST_BYTES:
                raise OpenAIClientError("Generation input failed credential or size checks")
        except (OpenAIClientError, ValueError, TypeError) as error:
            return ModelResponse(
                "",
                0,
                0,
                0.0,
                "estimated",
                "USD",
                messages=evidence,
                error=str(error),
                stop_status="error",
                submitted=False,
            )
        try:
            response = self._request(GENERATE_PATH, body, key, evidence)
        except OpenAIClientError as error:
            return ModelResponse(
                "",
                None if self._generation_submitted else 0,
                None if self._generation_submitted else 0,
                None if self._generation_submitted else 0.0,
                "unavailable" if self._generation_submitted else "estimated",
                "USD",
                messages=evidence,
                error=str(error),
                stop_status="error",
                submitted=self._generation_submitted,
            )
        return self._response(response, reservation, key, evidence)

    def _response(
        self,
        response: dict[str, Any],
        reservation: CallEstimate,
        key: str,
        evidence: list[dict[str, Any]],
    ) -> ModelResponse:
        input_tokens: int | None = None
        output_tokens: int | None = None
        cost: float | None = None
        cached_tokens: int | None = None
        usage = response.get("usage")
        if isinstance(usage, dict):
            if _counter(usage.get("input_tokens")):
                input_tokens = usage["input_tokens"]
            if _counter(usage.get("output_tokens")):
                output_tokens = usage["output_tokens"]
            details = usage.get("input_tokens_details")
            if isinstance(details, dict) and _counter(details.get("cached_tokens")):
                cached_tokens = details["cached_tokens"]
            if (
                input_tokens is not None
                and output_tokens is not None
                and cached_tokens is not None
                and cached_tokens <= input_tokens
                and type(usage.get("total_tokens")) is int
                and usage["total_tokens"] == input_tokens + output_tokens
            ):
                cost = _cost(input_tokens, output_tokens, cached_tokens)
        visible_output: list[dict[str, Any]] = []
        text_parts: list[str] = []
        refusal = False
        malformed = False
        output = response.get("output")
        if not isinstance(output, list) or not output:
            malformed = True
        else:
            for item in output:
                if (
                    not isinstance(item, dict)
                    or item.get("type") != "message"
                    or item.get("role") != "assistant"
                    or not isinstance(item.get("content"), list)
                ):
                    # Never copy reasoning/tool output into retained visible records.
                    malformed = True
                    continue
                for part in item["content"]:
                    if (
                        isinstance(part, dict)
                        and part.get("type") == "output_text"
                        and isinstance(part.get("text"), str)
                    ):
                        text_parts.append(part["text"])
                        visible_output.append(
                            {"type": "output_text", "text": _scrub(part["text"], key)}
                        )
                    elif (
                        isinstance(part, dict)
                        and part.get("type") == "refusal"
                        and isinstance(part.get("refusal"), str)
                    ):
                        refusal = True
                        visible_output.append(
                            {"type": "refusal", "refusal": _scrub(part["refusal"], key)}
                        )
                    else:
                        malformed = True
        text = "".join(text_parts)
        error, stop_status = None, None
        if response.get("model") != MODEL_VERSION:
            error, stop_status = "Provider returned a different model snapshot", "invalid_response"
        elif response.get("object") != "response":
            error, stop_status = (
                "Provider returned an unsupported response object",
                "invalid_response",
            )
        elif cost is None:
            error, stop_status = (
                "Provider usage is missing or inconsistent; further calls are stopped",
                "error",
            )
        elif response.get("error") is not None or response.get("status") == "failed":
            error, stop_status = "Provider reported a failed response", "error"
        elif (
            response.get("status") != "completed" or response.get("incomplete_details") is not None
        ):
            error, stop_status = (
                "Provider response was incomplete; partial output is not executable",
                "invalid_response",
            )
        elif malformed:
            error, stop_status = (
                "Provider returned unsupported or malformed visible output",
                "invalid_response",
            )
        elif refusal:
            error, stop_status = "Provider refused the request", "abstained"
        elif key in text:
            error, stop_status = (
                "Provider echoed a credential; output is not executable",
                "invalid_response",
            )
        elif (
            input_tokens is not None
            and input_tokens > reservation.input_tokens
            or output_tokens is not None
            and output_tokens > reservation.output_tokens
            or cost is not None
            and cost > reservation.cost
        ):
            error, stop_status = "Provider exceeded the reserved usage bounds", "budget_exceeded"
        else:
            try:
                value = json.loads(text, object_pairs_hook=_pairs, parse_constant=_nonfinite)
                if not isinstance(value, dict):
                    raise ValueError("nonobject")
            except (ValueError, UnicodeError, RecursionError):
                error, stop_status = (
                    "Provider output is not a strict JSON object",
                    "invalid_response",
                )
        self._record(
            evidence,
            {
                "role": "tool",
                "content": {
                    "provider_operation": "generation",
                    "direction": "response",
                    "response_id": _scrub(response.get("id"), key),
                    "model": _scrub(response.get("model"), key),
                    "status": _scrub(response.get("status"), key),
                    "visible_output": visible_output,
                    "input_tokens": input_tokens,
                    "output_tokens": output_tokens,
                    "cached_input_tokens": cached_tokens,
                    "estimated_cost_usd": cost,
                    "tariff_version": PRICE_VERSION,
                },
            },
        )
        return ModelResponse(
            _scrub(text, key),
            input_tokens,
            output_tokens,
            cost,
            "estimated" if cost is not None else "unavailable",
            "USD",
            messages=evidence,
            error=error,
            stop_status=stop_status,
        )
