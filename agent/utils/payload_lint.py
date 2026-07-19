"""Pure validation of an outgoing LLM chat-completions payload — no network calls. Catches shape
issues that would otherwise surface as a confusing 400 from the provider, before the request
ever goes out.
"""
from __future__ import annotations

_TEMPERATURE_RANGE = (0.0, 2.0)


def analyze_payload(payload: dict) -> list[str]:
    """Returns human-readable problems found in payload; an empty list means it's clean."""
    messages = payload.get("messages", [])
    return [
        *_check_consecutive_system_messages(messages),
        *_check_tool_messages_have_call_id(messages),
        *_check_temperature_range(payload),
    ]


def _check_consecutive_system_messages(messages: list[dict]) -> list[str]:
    for i in range(1, len(messages)):
        if messages[i].get("role") == "system" and messages[i - 1].get("role") == "system":
            return [f"consecutive system messages at index {i - 1}/{i} — some providers 400 on this"]
    return []


def _check_tool_messages_have_call_id(messages: list[dict]) -> list[str]:
    return [
        f"tool message at index {i} is missing tool_call_id"
        for i, message in enumerate(messages)
        if message.get("role") == "tool" and not message.get("tool_call_id")
    ]


def _check_temperature_range(payload: dict) -> list[str]:
    if "temperature" not in payload:
        return []
    temperature = payload["temperature"]
    low, high = _TEMPERATURE_RANGE
    if not (low <= temperature <= high):
        return [f"temperature {temperature} is outside the valid range [{low}, {high}]"]
    return []
