"""record_reverification_result: a rescanned project's final answer for one carried-over finding
(agent/core.py's _run_reverify, terminal_tool mechanism) -- validation mirrors record_exploit_
decision's exact style, including the "reason"/"reasoning" alias fixed earlier this project for
the same underlying tool-calling-model slip. verification_outcome is a real three-way answer (not
a boolean) so a model that genuinely can't confirm or refute a finding has somewhere honest to put
that instead of being forced to guess confirmed_fixed.
"""
from agent.tools.native import record_reverification_result


def test_requires_verification_outcome_to_be_set():
    result = record_reverification_result({"reasoning": "checked, gone now"})
    assert result["status"] == "error"
    assert "verification_outcome" in result["error"]


def test_rejects_an_invalid_verification_outcome():
    result = record_reverification_result({"verification_outcome": "maybe", "reasoning": "x"})
    assert result["status"] == "error"
    assert "verification_outcome" in result["error"]


def test_requires_reasoning():
    result = record_reverification_result({"verification_outcome": "confirmed_fixed"})
    assert result["status"] == "error"
    assert "reasoning" in result["error"]


def test_accepts_reason_as_an_alias_for_reasoning():
    result = record_reverification_result({"verification_outcome": "confirmed_fixed", "reason": "the page 404s now"})
    assert result["status"] == "ok"
    assert result["reasoning"] == "the page 404s now"


def test_confirmed_present_requires_evidence_ref():
    result = record_reverification_result({"verification_outcome": "confirmed_present", "reasoning": "looks the same"})
    assert result["status"] == "error"
    assert "evidence_ref" in result["error"]


def test_confirmed_fixed_does_not_require_evidence_ref():
    result = record_reverification_result({"verification_outcome": "confirmed_fixed", "reasoning": "confirmed patched"})
    assert result["status"] == "ok"
    assert result["evidence_ref"] is None


def test_inconclusive_does_not_require_evidence_ref():
    """The whole point of this outcome: a model that hit a WAF/challenge wall every attempt still
    needs a legal way to end its turn honestly, without evidence it never actually gathered."""
    result = record_reverification_result({
        "verification_outcome": "inconclusive",
        "reasoning": "every attempt hit the same Cloudflare challenge, could not verify either way",
    })
    assert result["status"] == "ok"
    assert result["evidence_ref"] is None


def test_accepts_a_well_formed_confirmed_present_call():
    result = record_reverification_result({
        "verification_outcome": "confirmed_present", "reasoning": "re-ran the same request, same reflected payload fires",
        "evidence_ref": "curl response body still contains the unescaped payload",
    })
    assert result["status"] == "ok"
    assert result["verification_outcome"] == "confirmed_present"
    assert result["evidence_ref"] == "curl response body still contains the unescaped payload"


def test_is_registered_in_the_post_exploit_category_and_nowhere_else():
    """post_exploit is deliberate: the one Category value no phase's get_tools_by_category(...)
    call actually queries today, so this tool can't leak into Analyze's or the exploit phase's
    toolsets by category membership alone."""
    import agent.tools  # noqa: F401 (side effect: populates TOOL_REGISTRY)
    from agent.tools.registry import get_tool, get_tools_by_category

    spec = get_tool("record_reverification_result")
    assert spec.category == "post_exploit"
    for category in ("recon", "scan", "exploit"):
        assert "record_reverification_result" not in {s.name for s in get_tools_by_category(category)}
