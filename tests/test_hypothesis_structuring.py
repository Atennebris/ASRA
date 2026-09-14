"""_structure_hypothesis_text: splits an operator's single free-text hypothesis submission (the
Hypotheses tab's own one-box form) into a clean {text, evidence} pair via one quick, tool-less LLM
call. Real requirement this exists for: an operator wants to paste a whole write-up copied from a
different scan (a finding's own title/evidence/severity, whatever they had) and have the agent pull
out the actual claim and the supporting evidence, instead of pre-splitting it into two fields
themselves.
"""
import asyncio
import json

from agent.core import RunContext, _structure_hypothesis_text
from agent.llm_client import LLMResponse


def _run(coro):
    return asyncio.run(coro)


def _ctx(llm):
    session = {"session_id": "usr_hyp_structure_test", "target": "example.com", "status": "processing", "logs": [], "findings": [], "hypotheses": []}
    return RunContext(llm=llm, session=session, session_id=session["session_id"])


class _JSONReplyLLM:
    provider_id = "test-provider"
    model = "test-model"
    def __init__(self, content):
        self._content = content

    def complete(self, messages, tools=None, stop_check=None):
        return LLMResponse(content=self._content, tool_calls=[])


class _RaisingLLM:
    provider_id = "test-provider"
    model = "test-model"
    def complete(self, messages, tools=None, stop_check=None):
        raise RuntimeError("provider unavailable")


def test_structures_a_raw_paste_into_clean_text_and_evidence():
    llm = _JSONReplyLLM(json.dumps({
        "text": "The /api/v1 legacy endpoints might still be reachable and unauthenticated",
        "evidence": "Confirmed on a prior scan of the same target: GET /api/v1/users returned 200 with no auth header.",
    }))
    ctx = _ctx(llm)

    result = _run(_structure_hypothesis_text(ctx, "found this on an old scan of the same site: /api/v1/users returns 200 with no auth, probably still there"))

    assert result["text"] == "The /api/v1 legacy endpoints might still be reachable and unauthenticated"
    assert "GET /api/v1/users" in result["evidence"]


def test_short_clean_input_can_come_back_with_empty_evidence():
    llm = _JSONReplyLLM(json.dumps({"text": "staging.example.com probably still has debug mode on", "evidence": ""}))
    ctx = _ctx(llm)

    result = _run(_structure_hypothesis_text(ctx, "staging.example.com probably still has debug mode on"))

    assert result["text"] == "staging.example.com probably still has debug mode on"
    assert result["evidence"] == ""


def test_empty_raw_text_short_circuits_without_calling_the_llm():
    llm = _RaisingLLM()
    ctx = _ctx(llm)

    result = _run(_structure_hypothesis_text(ctx, "   "))

    assert result == {"text": "", "evidence": ""}


def test_falls_back_to_raw_text_when_the_llm_reply_is_not_valid_json():
    llm = _JSONReplyLLM("sure, here's the hypothesis you asked about")
    ctx = _ctx(llm)

    result = _run(_structure_hypothesis_text(ctx, "check for exposed .git"))

    assert result == {"text": "check for exposed .git", "evidence": ""}


def test_falls_back_to_raw_text_when_the_llm_reply_has_no_text_field():
    llm = _JSONReplyLLM(json.dumps({"evidence": "something"}))
    ctx = _ctx(llm)

    result = _run(_structure_hypothesis_text(ctx, "check for exposed .git"))

    assert result == {"text": "check for exposed .git", "evidence": ""}


def test_falls_back_to_raw_text_when_the_llm_call_itself_fails():
    """Never lose the operator's own real input just because a provider hiccup killed the
    structuring call -- same discipline every other 'don't discard real user input over a
    transient failure' path in this project already follows."""
    ctx = _ctx(_RaisingLLM())

    result = _run(_structure_hypothesis_text(ctx, "check for exposed .git"))

    assert result == {"text": "check for exposed .git", "evidence": ""}
