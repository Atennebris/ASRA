"""record_skeptical_verification_result: the Skeptical Verifier's final answer (agent/core.py's
_run_skeptical_verification, terminal_tool mechanism) -- same three-way-verdict shape as
record_reverification_result, for the identical reason: a model that genuinely can't confirm or
refute a claim needs somewhere honest to put that instead of being forced to guess.
"""
from agent.tools.native import record_skeptical_verification_result


def test_requires_verdict_to_be_set():
    result = record_skeptical_verification_result({"reasoning": "re-ran the check"})
    assert result["status"] == "error"
    assert "verdict" in result["error"]


def test_rejects_an_invalid_verdict():
    result = record_skeptical_verification_result({"verdict": "maybe", "reasoning": "x"})
    assert result["status"] == "error"
    assert "verdict" in result["error"]


def test_requires_reasoning():
    result = record_skeptical_verification_result({"verdict": "confirmed"})
    assert result["status"] == "error"
    assert "reasoning" in result["error"]


def test_accepts_reason_as_an_alias_for_reasoning():
    result = record_skeptical_verification_result({"verdict": "inconclusive", "reason": "target blocked every attempt"})
    assert result["status"] == "ok"
    assert result["reasoning"] == "target blocked every attempt"


def test_confirmed_requires_evidence_ref():
    result = record_skeptical_verification_result({"verdict": "confirmed", "reasoning": "looks right"})
    assert result["status"] == "error"
    assert "evidence_ref" in result["error"]


def test_refuted_requires_evidence_ref():
    result = record_skeptical_verification_result({"verdict": "refuted", "reasoning": "did not reproduce"})
    assert result["status"] == "error"
    assert "evidence_ref" in result["error"]


def test_inconclusive_does_not_require_evidence_ref():
    result = record_skeptical_verification_result({
        "verdict": "inconclusive",
        "reasoning": "every attempt hit the same Cloudflare challenge, could not verify either way",
    })
    assert result["status"] == "ok"
    assert result["evidence_ref"] is None


def test_accepts_a_well_formed_confirmed_call():
    result = record_skeptical_verification_result({
        "verdict": "confirmed", "reasoning": "re-ran the same payload, same reflected script fires",
        "evidence_ref": "response body still contains the unescaped payload",
    })
    assert result["status"] == "ok"
    assert result["verdict"] == "confirmed"
    assert result["evidence_ref"] == "response body still contains the unescaped payload"


def test_accepts_a_well_formed_refuted_call():
    result = record_skeptical_verification_result({
        "verdict": "refuted", "reasoning": "re-ran the exact same login attempt, it failed with 401",
        "evidence_ref": "authenticated_request returned status_code=401, not the claimed 200",
    })
    assert result["status"] == "ok"
    assert result["verdict"] == "refuted"


def test_is_registered_in_the_post_exploit_category_and_nowhere_else():
    """post_exploit is deliberate: the one Category value no phase's get_tools_by_category(...)
    call actually queries today, so this tool can't leak into Analyze's or the exploit phase's
    toolsets by category membership alone."""
    import agent.tools  # noqa: F401 (side effect: populates TOOL_REGISTRY)
    from agent.tools.registry import get_tool, get_tools_by_category

    spec = get_tool("record_skeptical_verification_result")
    assert spec.category == "post_exploit"
    for category in ("recon", "scan", "exploit"):
        assert "record_skeptical_verification_result" not in {s.name for s in get_tools_by_category(category)}
