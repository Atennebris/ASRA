"""Prompt-as-contract tests: structure checks on the four system prompts, not behavior.

Mirrors the pattern used for llm_client — no network calls, just static checks that each
prompt is non-empty, English, within a sane token budget for the configured Qwen model, and
carries the JSON output contract agent/core.py's parser expects.
"""
import re

import pytest

from agent.prompts import (
    ANALYZE_PROMPT,
    CHAT_COMPACTION_PROMPT,
    CHAT_PROMPT,
    CONFIRM_EXPLOIT_PROMPT,
    EXPLOIT_PROMPT,
    RECON_PROMPT,
    VALIDATE_PROMPT,
)

# len // 4 is the same rough chars-per-token estimate used elsewhere in this codebase
# (agent/utils/debug.py). qwen-plus's real context window is 1,000,000 tokens (see
# agent/providers/models_dev.py) — this budget is a sanity ceiling against prompt bloat, not a
# reflection of how much room is actually available.
_MAX_TOKENS_PER_PROMPT = 2000
_MIN_PROMPT_CHARS = 200

_CYRILLIC_PATTERN = re.compile(r"[Ѐ-ӿ]")

_ALL_PROMPTS = {
    "RECON_PROMPT": RECON_PROMPT,
    "ANALYZE_PROMPT": ANALYZE_PROMPT,
    "EXPLOIT_PROMPT": EXPLOIT_PROMPT,
    "CONFIRM_EXPLOIT_PROMPT": CONFIRM_EXPLOIT_PROMPT,
    "VALIDATE_PROMPT": VALIDATE_PROMPT,
}

# Chat prompts are structurally different — CHAT_PROMPT's contract is tool-calling or
# plain text, never a JSON blob; CHAT_COMPACTION_PROMPT explicitly forbids JSON output. Same
# general sanity checks apply (substantial/English/token budget), but not the JSON-contract one.
_FREE_TEXT_PROMPTS = {
    "CHAT_PROMPT": CHAT_PROMPT,
    "CHAT_COMPACTION_PROMPT": CHAT_COMPACTION_PROMPT,
}

_ALL_SYSTEM_PROMPTS = {**_ALL_PROMPTS, **_FREE_TEXT_PROMPTS}


@pytest.mark.parametrize("name,text", _ALL_SYSTEM_PROMPTS.items())
def test_prompt_is_substantial(name, text):
    assert isinstance(text, str)
    assert len(text) >= _MIN_PROMPT_CHARS, f"{name} looks too short to be a real system prompt ({len(text)} chars)"


@pytest.mark.parametrize("name,text", _ALL_SYSTEM_PROMPTS.items())
def test_prompt_is_english(name, text):
    assert not _CYRILLIC_PATTERN.search(text), f"{name} contains Cyrillic characters — prompts must be English"


@pytest.mark.parametrize("name,text", _ALL_SYSTEM_PROMPTS.items())
def test_prompt_within_token_budget(name, text):
    estimated_tokens = len(text) // 4
    assert estimated_tokens <= _MAX_TOKENS_PER_PROMPT, f"{name} is ~{estimated_tokens} tokens, over the {_MAX_TOKENS_PER_PROMPT} budget"


@pytest.mark.parametrize("name,text", _ALL_PROMPTS.items())
def test_prompt_declares_json_output_contract(name, text):
    assert "JSON" in text, f"{name} must instruct the model to answer with a specific JSON shape"
    assert "{" in text and "}" in text, f"{name} must show the expected JSON shape inline"


def test_chat_compaction_prompt_forbids_json():
    assert "not JSON" in CHAT_COMPACTION_PROMPT


def test_prompts_never_name_a_fixed_exploit_tool_set():
    """Regression guard for the fix made after initial review: EXPLOIT_PROMPT must select tools
    by category/fit, never lock the model into exactly "exploit" or "sqlmap" as an exhaustive
    enum — the tool registry is extensible (autodiscovered/custom tools included).
    """
    assert '"exploit" | "sqlmap"' not in EXPLOIT_PROMPT
    assert '"tool": "exploit" | "sqlmap"' not in EXPLOIT_PROMPT


def test_analyze_and_validate_prompts_define_verification_states():
    for name, text in (("ANALYZE_PROMPT", ANALYZE_PROMPT), ("VALIDATE_PROMPT", VALIDATE_PROMPT)):
        for state in ("verified", "inferred", "needs_verification"):
            assert state in text, f"{name} must define the {state!r} verification state"
