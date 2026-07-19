"""Table-driven tests for the pure, network-free payload linter (4.4.2)."""
import pytest

from agent.utils.payload_lint import analyze_payload

_CASES = [
    pytest.param(
        {"messages": [{"role": "system", "content": "a"}, {"role": "user", "content": "b"}]},
        [],
        id="clean-payload",
    ),
    pytest.param(
        {
            "messages": [
                {"role": "system", "content": "a"},
                {"role": "system", "content": "b"},
                {"role": "user", "content": "c"},
            ]
        },
        ["consecutive system messages at index 0/1 — some providers 400 on this"],
        id="consecutive-system-messages",
    ),
    pytest.param(
        {"messages": [{"role": "tool", "content": "result"}]},
        ["tool message at index 0 is missing tool_call_id"],
        id="tool-message-missing-call-id",
    ),
    pytest.param(
        {"messages": [{"role": "tool", "content": "result", "tool_call_id": "call_1"}]},
        [],
        id="tool-message-with-call-id-is-clean",
    ),
    pytest.param(
        {"messages": [], "temperature": 3.5},
        ["temperature 3.5 is outside the valid range [0.0, 2.0]"],
        id="temperature-too-high",
    ),
    pytest.param(
        {"messages": [], "temperature": -0.1},
        ["temperature -0.1 is outside the valid range [0.0, 2.0]"],
        id="temperature-too-low",
    ),
    pytest.param(
        {"messages": [], "temperature": 0.7},
        [],
        id="temperature-in-range-is-clean",
    ),
    pytest.param(
        {"messages": []},
        [],
        id="no-temperature-key-is-clean",
    ),
    pytest.param(
        {
            "messages": [
                {"role": "system", "content": "a"},
                {"role": "system", "content": "b"},
                {"role": "tool", "content": "c"},
            ],
            "temperature": 5,
        },
        [
            "consecutive system messages at index 0/1 — some providers 400 on this",
            "tool message at index 2 is missing tool_call_id",
            "temperature 5 is outside the valid range [0.0, 2.0]",
        ],
        id="multiple-issues-all-reported",
    ),
]


@pytest.mark.parametrize("payload, expected_issues", _CASES)
def test_analyze_payload(payload, expected_issues):
    assert analyze_payload(payload) == expected_issues
