"""Small provider adapters; no fallback, redirects, proxy inheritance or automatic retries."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
import time
from urllib.parse import quote

import httpx

from .config import Config
from .errors import AssistantError


@dataclass(frozen=True)
class ModelResult:
    text: str
    input_tokens: int | None = None
    output_tokens: int | None = None


def _usage(value) -> int | None:
    return value if type(value) is int and 0 < value <= 2_000_000 else None


def request_shape(config: Config, system: str, packet: dict, schema: dict) -> tuple[str, dict, dict]:
    content = json.dumps(packet, sort_keys=True, allow_nan=False)
    model = config.model
    headers = {"Content-Type": "application/json"}
    key = os.environ.get(config.key_name, "") if config.key_name else ""
    if config.key_name and not key:
        raise AssistantError("provider_key_missing")
    if "\r" in key or "\n" in key:
        raise AssistantError("invalid_provider_key")
    url = config.resolved_endpoint
    if config.provider == "openai":
        headers["Authorization"] = "Bearer " + key
        payload = {
            "model": model,
            "instructions": system,
            "input": content,
            "max_output_tokens": config.max_output_tokens,
            "store": False,
            "text": {
                "format": {
                    "type": "json_schema",
                    "name": "developer_review",
                    "strict": True,
                    "schema": schema,
                }
            },
        }
    elif config.provider == "anthropic":
        headers.update({"x-api-key": key, "anthropic-version": "2023-06-01"})
        payload = {
            "model": model,
            "system": system + "\nOutput JSON matching: " + json.dumps(schema),
            "messages": [{"role": "user", "content": content}],
            "max_tokens": config.max_output_tokens,
        }
    elif config.provider == "google":
        headers["x-goog-api-key"] = key
        url += "/models/" + quote(model, safe="") + ":generateContent"
        payload = {
            "systemInstruction": {"parts": [{"text": system}]},
            "contents": [{"role": "user", "parts": [{"text": content}]}],
            "generationConfig": {
                "maxOutputTokens": config.max_output_tokens,
                "responseMimeType": "application/json",
            },
        }
        payload["systemInstruction"]["parts"][0]["text"] += "\nJSON schema: " + json.dumps(schema)
    elif config.provider in {"compatible", "ollama"}:
        if key:
            headers["Authorization"] = "Bearer " + key
        payload = {
            "model": model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": content}],
            "stream": False,
        }
        if config.provider == "ollama":
            payload.update({"format": schema, "options": {"num_predict": config.max_output_tokens}})
        else:
            payload.update(
                {"max_tokens": config.max_output_tokens, "response_format": {"type": "json_object"}}
            )
            payload["messages"][0]["content"] += "\nJSON schema: " + json.dumps(schema)
    else:
        raise AssistantError("provider_not_remote")
    if key and config.provider in {"openai", "compatible"} and config.auth_header != "Authorization":
        headers.pop("Authorization", None)
        headers[config.auth_header] = key
    return url, headers, payload


def parse_response(provider: str, data: dict) -> ModelResult:
    if not isinstance(data, dict):
        raise AssistantError("invalid_provider_response")
    try:
        if provider == "openai":
            if data.get("status") != "completed":
                raise AssistantError("provider_incomplete")
            text = "".join(
                part["text"]
                for item in data["output"]
                if item.get("type") == "message"
                for part in item.get("content", [])
                if part.get("type") == "output_text"
            )
            usage = data.get("usage") or {}
            return ModelResult(text, _usage(usage.get("input_tokens")), _usage(usage.get("output_tokens")))
        if provider == "anthropic":
            if data.get("stop_reason") != "end_turn":
                raise AssistantError("provider_incomplete")
            text = "".join(item["text"] for item in data["content"] if item.get("type") == "text")
            usage = data.get("usage") or {}
            return ModelResult(text, _usage(usage.get("input_tokens")), _usage(usage.get("output_tokens")))
        if provider == "google":
            candidate = data["candidates"][0]
            if candidate.get("finishReason") != "STOP":
                raise AssistantError("provider_incomplete")
            text = "".join(p["text"] for p in candidate["content"]["parts"] if not p.get("thought"))
            usage = data.get("usageMetadata") or {}
            # Include thought tokens when supplied; missing usage remains unreconciled.
            output = _usage(usage.get("candidatesTokenCount"))
            thoughts_raw = usage.get("thoughtsTokenCount", 0)
            thoughts = 0 if thoughts_raw == 0 and type(thoughts_raw) is int else _usage(thoughts_raw)
            return ModelResult(
                text,
                _usage(usage.get("promptTokenCount")),
                output + thoughts if output is not None and thoughts is not None else None,
            )
        if provider == "ollama":
            if data.get("done") is not True:
                raise AssistantError("provider_incomplete")
            return ModelResult(
                data["message"]["content"],
                _usage(data.get("prompt_eval_count")),
                _usage(data.get("eval_count")),
            )
        choice = data["choices"][0]
        if choice.get("finish_reason") != "stop":
            raise AssistantError("provider_incomplete")
        usage = data.get("usage") or {}
        return ModelResult(
            choice["message"]["content"],
            _usage(usage.get("prompt_tokens")),
            _usage(usage.get("completion_tokens")),
        )
    except (KeyError, IndexError, TypeError, AttributeError) as exc:
        raise AssistantError("invalid_provider_response") from exc


def invoke(
    config: Config,
    system: str,
    packet: dict,
    schema: dict,
    *,
    network_approved: bool,
    transport: httpx.BaseTransport | None = None,
) -> ModelResult:
    config.validate()
    if not config.allow_network or not network_approved:
        raise AssistantError("network_not_approved")
    url, headers, payload = request_shape(config, system, packet, schema)
    started = time.monotonic()
    try:
        with httpx.Client(
            timeout=config.timeout_seconds, trust_env=False, follow_redirects=False, transport=transport
        ) as client:
            with client.stream("POST", url, headers=headers, json=payload) as response:
                if response.status_code != 200:
                    # Never print a provider response body: it may echo credentials or input.
                    raise AssistantError("provider_http_error")
                chunks, length = [], 0
                for block in response.iter_bytes():
                    if time.monotonic() - started > config.timeout_seconds:
                        raise AssistantError("provider_deadline_exceeded")
                    length += len(block)
                    if length > 2_000_000:
                        raise AssistantError("provider_response_limit")
                    chunks.append(block)
        data = json.loads(b"".join(chunks))
        result = parse_response(config.provider, data)
        if not isinstance(result.text, str) or not result.text.strip():
            raise AssistantError("provider_empty_output")
        return result
    except (httpx.HTTPError, ValueError) as exc:
        raise AssistantError("provider_transport_failed") from exc
