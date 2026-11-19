"""Prompt-side guards for two operator-reported chat behaviors.

Both the always-applied interactive base (CHAT_PROMPT) and the RE chat CORE
(reached via build_re_chat_prompt for every shape) must carry two rules:
a menu of next steps goes through suggest_next_steps as clickable cards, never
a prose numbered/bulleted list; and the agent must not announce an action it
does not actually perform in the same turn. These are intent/substring checks
so the wording can't be silently dropped in a later edit without going red."""

from agent.prompts import CHAT_PROMPT, build_re_chat_prompt


def _has_suggest_next_steps_rule(text: str) -> bool:
    low = text.lower()
    return "suggest_next_steps" in low and "numbered" in low and "bulleted" in low


def _has_no_unperformed_action_rule(text: str) -> bool:
    low = text.lower()
    return "announce an action" in low and "same turn" in low


def test_chat_prompt_has_both_rules():
    assert _has_suggest_next_steps_rule(CHAT_PROMPT)
    assert _has_no_unperformed_action_rule(CHAT_PROMPT)


def test_re_chat_core_has_both_rules():
    prompt = build_re_chat_prompt(None)
    assert _has_suggest_next_steps_rule(prompt)
    assert _has_no_unperformed_action_rule(prompt)
