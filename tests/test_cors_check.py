"""cors_check: a real, observed incident — a model tested CORS reflection only via nuclei's
cors-misconfig template (which only ever generates a random label under the TARGET'S OWN domain),
then wrote up "reflects any arbitrary origin" and marked it qualifying, on evidence that only ever
proved the narrower "trusts its own subdomains" pattern. cors_check (native.py) is the real,
deterministic fix: it fires one request with a same-suffix Origin and one with a genuinely
unrelated Origin, and agent/core.py's _cors_qualifying_conflict is the enforced gate — a
"qualifying" claim for a host it already showed only reflects same-suffix is REJECTED (not
silently rewritten) so the model has to reconcile its own next record_finding call with the real
evidence, the same mechanism record_finding already uses for an invalid severity/verification enum.
"""
import asyncio
import dataclasses

import httpx
import pytest

import agent.tools  # noqa: F401  (side effect: populates TOOL_REGISTRY)
from agent.core import RunContext, _cors_qualifying_conflict, _run_analyze, _run_exploit_for_finding
from agent.llm_client import LLMResponse, ToolCallRequest
from agent.tools import native
from agent.tools.registry import TOOL_REGISTRY
from sessions import store

_RealHTTPXClient = httpx.Client


def _mock_httpx_client(handler):
    def factory(**kwargs):
        kwargs.pop("transport", None)
        return _RealHTTPXClient(transport=httpx.MockTransport(handler), **kwargs)
    return factory


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture(autouse=True)
def _isolated_session_storage(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")


# --- pure unit tests: cors_check itself, against a mocked HTTP server ---


def test_cors_check_verdict_reflects_any_origin_when_the_unrelated_origin_is_reflected(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        origin = request.headers.get("origin")
        return httpx.Response(200, headers={"access-control-allow-origin": origin} if origin else {})

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    result = native.cors_check({"target": "https://api.example.com"})

    assert result["status"] == "ok"
    assert result["hostname"] == "api.example.com"
    assert result["same_suffix_reflected"] is True
    assert result["unrelated_reflected"] is True
    assert result["verdict"] == "reflects_any_origin"


def test_cors_check_verdict_reflects_any_origin_for_a_static_wildcard_acao(monkeypatch):
    """Real incident this fixes: a server sending a literal "Access-Control-Allow-Origin: *" on
    every response (never echoing back the actual Origin header) used to come back
    "no_origin_reflection_detected" -- neither the same-suffix nor the unrelated test origin
    string ever equals the literal "*", so the old exact-match check silently missed the single
    most permissive CORS answer possible (confirmed live: a real GraphQL API's static wildcard
    ACAO on a real scan)."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"access-control-allow-origin": "*"})

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    result = native.cors_check({"target": "https://api.example.com"})

    assert result["same_suffix_reflected"] is True
    assert result["unrelated_reflected"] is True
    assert result["verdict"] == "reflects_any_origin"


def test_cors_check_verdict_reflects_own_subdomains_only_when_unrelated_origin_is_rejected(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        origin = request.headers.get("origin", "")
        if origin.endswith(".api.example.com") or origin == "https://api.example.com":
            return httpx.Response(200, headers={"access-control-allow-origin": origin})
        return httpx.Response(200)

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    result = native.cors_check({"target": "https://api.example.com"})

    assert result["same_suffix_reflected"] is True
    assert result["unrelated_reflected"] is False
    assert result["verdict"] == "reflects_own_subdomains_only"


def test_cors_check_verdict_no_reflection_detected_when_neither_origin_is_reflected(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200)

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    result = native.cors_check({"target": "https://api.example.com"})

    assert result["same_suffix_reflected"] is False
    assert result["unrelated_reflected"] is False
    assert result["verdict"] == "no_origin_reflection_detected"


def test_cors_check_verdict_inconclusive_when_a_probe_fails_outright_not_treated_as_a_no(monkeypatch):
    """The core false-negative risk: a network error must never read as a confirmed narrow/
    negative result — that would silently hide a real wildcard CORS bug just because one
    request happened to not go through."""
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("simulated network failure", request=request)

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    result = native.cors_check({"target": "https://api.example.com"})

    assert result["same_suffix_reflected"] is None
    assert result["unrelated_reflected"] is None
    assert result["verdict"] == "inconclusive"


def test_cors_check_reflected_via_options_preflight_counts_even_when_plain_get_does_not(monkeypatch):
    """Some servers only attach CORS headers to the OPTIONS preflight response, not a plain GET
    — testing only one shape would silently miss a real reflection on the other."""
    def handler(request: httpx.Request) -> httpx.Response:
        origin = request.headers.get("origin", "")
        if request.method == "OPTIONS":
            return httpx.Response(204, headers={"access-control-allow-origin": origin})
        return httpx.Response(200)  # plain GET never reflects anything

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    result = native.cors_check({"target": "https://api.example.com"})

    assert result["unrelated_reflected"] is True
    assert result["verdict"] == "reflects_any_origin"


# --- allows_credentials: the second, separate browser gate CORS misconfiguration alone doesn't
# grant -- reflecting an origin only exposes credentialed (cookie/session) data when the SAME
# response also sends Access-Control-Allow-Credentials: true. ---


def test_cors_check_allows_credentials_true_when_both_headers_are_present(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        origin = request.headers.get("origin")
        return httpx.Response(200, headers={
            "access-control-allow-origin": origin, "access-control-allow-credentials": "true",
        } if origin else {})

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    result = native.cors_check({"target": "https://api.example.com"})

    assert result["verdict"] == "reflects_any_origin"
    assert result["allows_credentials"] is True


def test_cors_check_allows_credentials_false_when_the_header_is_absent(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        origin = request.headers.get("origin")
        return httpx.Response(200, headers={"access-control-allow-origin": origin} if origin else {})

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    result = native.cors_check({"target": "https://api.example.com"})

    assert result["verdict"] == "reflects_any_origin"
    assert result["allows_credentials"] is False


def test_cors_check_allows_credentials_is_none_when_the_origin_isnt_reflected_at_all(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200)  # no reflection, no CORS headers at all

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    result = native.cors_check({"target": "https://api.example.com"})

    assert result["verdict"] == "no_origin_reflection_detected"
    assert result["allows_credentials"] is None


def test_cors_check_allows_credentials_false_for_a_static_wildcard_acao_even_with_credentials_header(monkeypatch):
    """The critical browser-spec nuance: Access-Control-Allow-Origin: * NEVER grants a credentialed
    cross-origin read, no matter what Access-Control-Allow-Credentials says -- a real browser
    requires an EXACT origin echo before it will honor credentials at all. A server sending both
    headers together is sending a contradictory combination; reporting allows_credentials=True
    here would overstate what a real attacker could actually do with it."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={
            "access-control-allow-origin": "*", "access-control-allow-credentials": "true",
        })

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    result = native.cors_check({"target": "https://api.example.com"})

    assert result["verdict"] == "reflects_any_origin"  # still a real, reportable misconfiguration
    assert result["allows_credentials"] is False  # but never exploitable for credentialed data


def test_cors_check_uses_a_fixed_unrelated_origin_sharing_nothing_with_the_target(monkeypatch):
    seen_origins = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_origins.append(request.headers.get("origin"))
        return httpx.Response(200)

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    native.cors_check({"target": "https://vimla.se"})

    assert native._CORS_UNRELATED_TEST_ORIGIN in seen_origins
    assert "vimla.se" not in native._CORS_UNRELATED_TEST_ORIGIN


# --- _cors_qualifying_conflict: the pure gate function ---


def test_cors_qualifying_conflict_none_when_qualifies_for_bounty_is_not_qualifying():
    session = {"cors_check_verdicts": {"api.example.com": "reflects_own_subdomains_only"}}
    finding = {"title": "CORS on api.example.com", "qualifies_for_bounty": "unclear"}
    assert _cors_qualifying_conflict(session, finding) is None


def test_cors_qualifying_conflict_fires_when_cors_check_was_never_run_at_all():
    """Whitelist, not blacklist: a model can simply skip calling cors_check entirely (nothing
    forces the call) and go straight from nuclei's own same-suffix-only test to "qualifying" —
    "nothing on record contradicts it" is not the same as "proven". No verdict at all must be
    treated the same as a narrow one, not silently allowed through."""
    session = {"cors_check_verdicts": {}}
    finding = {"title": "CORS on api.example.com", "qualifies_for_bounty": "qualifying"}
    conflict = _cors_qualifying_conflict(session, finding)
    assert conflict is not None
    assert "cors_check" in conflict


def test_cors_qualifying_conflict_none_when_verdict_is_reflects_any_origin():
    session = {"cors_check_verdicts": {"api.example.com": "reflects_any_origin"}}
    finding = {"title": "CORS Misconfiguration on api.example.com", "qualifies_for_bounty": "qualifying"}
    assert _cors_qualifying_conflict(session, finding) is None


def test_cors_qualifying_conflict_fires_when_qualifying_meets_a_same_suffix_only_verdict():
    session = {"cors_check_verdicts": {"api.example.com": "reflects_own_subdomains_only"}}
    finding = {"title": "CORS Misconfiguration on api.example.com", "qualifies_for_bounty": "qualifying"}
    conflict = _cors_qualifying_conflict(session, finding)
    assert conflict is not None
    assert "api.example.com" in conflict


def test_cors_qualifying_conflict_fires_when_verdict_is_inconclusive():
    """Inconclusive means "no answer either way" — it is not proof of a wildcard bug any more
    than same-suffix-only is, so it does not earn "qualifying" either. (It's still never read as
    a confirmed *negative* — see cors_check itself and the false_positive_reason path, which this
    function has no part in.)"""
    session = {"cors_check_verdicts": {"api.example.com": "inconclusive"}}
    finding = {"title": "CORS Misconfiguration on api.example.com", "qualifies_for_bounty": "qualifying"}
    assert _cors_qualifying_conflict(session, finding) is not None


def test_cors_qualifying_conflict_none_for_an_unrelated_finding_that_merely_mentions_the_same_host():
    """The over-blocking risk: a finding about something else entirely (SQLi here) on a host
    cors_check happened to run against must never get caught by this gate — only a finding that's
    actually about CORS."""
    session = {"cors_check_verdicts": {"api.example.com": "reflects_own_subdomains_only"}}
    finding = {
        "title": "SQL Injection in search parameter on api.example.com",
        "description": "The search endpoint is vulnerable to blind SQL injection.",
        "qualifies_for_bounty": "qualifying",
    }
    assert _cors_qualifying_conflict(session, finding) is None


def test_cors_qualifying_conflict_none_when_evidence_documents_a_real_subdomain_takeover():
    """The escape hatch promised in the rejection message must actually work, not just be words
    the gate can never honor — a finding that documents real takeover evidence stays qualifying
    even though the raw CORS reflection itself is only same-suffix."""
    session = {"cors_check_verdicts": {"api.example.com": "reflects_own_subdomains_only"}}
    finding = {
        "title": "CORS Misconfiguration on api.example.com chained with subdomain takeover",
        "description": "Reflects same-suffix origins with credentials.",
        "evidence_ref": "old.api.example.com CNAMEs to a decommissioned Heroku app — dangling, unclaimed, takeover confirmed.",
        "qualifies_for_bounty": "qualifying",
    }
    assert _cors_qualifying_conflict(session, finding) is None


# --- integration: _run_analyze wires the verdict tracking + the record_finding gate together ---


class _ScriptedLLM:
    provider_id = "test-provider"
    model = "test-model"
    def __init__(self, tool_calls_per_turn):
        self._script = list(tool_calls_per_turn)
        self.calls_made = 0

    def complete(self, messages, tools=None, stop_check=None):
        self.calls_made += 1
        if self._script:
            name, arguments = self._script.pop(0)
            return LLMResponse(content=None, tool_calls=[ToolCallRequest(id=f"call_{self.calls_made}", name=name, arguments=arguments)])
        return LLMResponse(content="done", tool_calls=[])


def _swap_native_tool(name, fake_result):
    index = next(i for i, s in enumerate(TOOL_REGISTRY) if s.name == name)
    original_spec = TOOL_REGISTRY[index]
    TOOL_REGISTRY[index] = dataclasses.replace(original_spec, native_function=lambda params: fake_result)
    return index, original_spec


def _make_session(session_id):
    return {
        "session_id": session_id, "target": "example.com", "status": "processing",
        "logs": [], "findings": [], "approvals": [], "chat": {"summary": "", "messages": []},
        "recon_result": {"targets": [], "cves": []},
        # Non-blank on purpose: these tests exercise the CORS-conflict gate specifically, not
        # agent/core.py's separate "no scope rules configured -> strip qualifies_for_bounty"
        # guardrail (_persist_new_finding) -- blank scope_rules would strip the very field these
        # assertions check, for an unrelated reason.
        "scope_rules": {"qualifying": "CORS misconfigurations", "non_qualifying": ""},
    }


_SAME_SUFFIX_ONLY_RESULT = {
    "status": "ok", "hostname": "api.example.com", "verdict": "reflects_own_subdomains_only",
    "same_suffix_origin_tested": "https://abc123.api.example.com", "same_suffix_reflected": True,
    "unrelated_origin_tested": "https://asra-unrelated-origin-check.invalid", "unrelated_reflected": False,
}
_ANY_ORIGIN_RESULT = {
    "status": "ok", "hostname": "api.example.com", "verdict": "reflects_any_origin",
    "same_suffix_origin_tested": "https://abc123.api.example.com", "same_suffix_reflected": True,
    "unrelated_origin_tested": "https://asra-unrelated-origin-check.invalid", "unrelated_reflected": True,
}

_CORS_FINDING_ARGS_QUALIFYING = {
    "title": "CORS Misconfiguration on api.example.com", "severity": "High",
    "description": "Reflects arbitrary origins with credentials.", "verification": "verified",
    "exploitation_scenario": "victim_interaction", "qualifies_for_bounty": "qualifying",
}
_CORS_FINDING_ARGS_UNCLEAR = {**_CORS_FINDING_ARGS_QUALIFYING, "qualifies_for_bounty": "unclear"}


def test_analyze_rejects_qualifying_and_persists_only_the_corrected_retry(tmp_path):
    index, original = _swap_native_tool("cors_check", _SAME_SUFFIX_ONLY_RESULT)
    try:
        session = _make_session("usr_cors_gate_reject")
        llm = _ScriptedLLM([
            ("cors_check", {"target": "https://api.example.com"}),
            ("record_finding", _CORS_FINDING_ARGS_QUALIFYING),
            ("record_finding", _CORS_FINDING_ARGS_UNCLEAR),
        ])
        ctx = RunContext(llm=llm, session=session, session_id=session["session_id"])

        _run(_run_analyze(ctx, "example.com", session["recon_result"]))

        assert session["cors_check_verdicts"] == {"api.example.com": "reflects_own_subdomains_only"}
        # Only the corrected retry made it in — the first, conflicting "qualifying" call was
        # rejected as a tool error and never appended to session["findings"] at all.
        assert len(session["findings"]) == 1
        assert session["findings"][0]["qualifies_for_bounty"] == "unclear"
    finally:
        TOOL_REGISTRY[index] = original


def test_analyze_rejects_qualifying_when_cors_check_was_never_called_but_the_downgrade_retry_still_succeeds_cleanly(tmp_path):
    """The gap the whitelist redesign closes: a model that skips cors_check entirely and goes
    straight from a scanner's same-suffix-only signal to "qualifying" gets rejected too — and,
    just as importantly, the corrected retry succeeds immediately with no loop, and nothing else
    in the session (there's nothing else here) is disturbed by the rejection."""
    session = _make_session("usr_cors_never_checked")
    llm = _ScriptedLLM([
        ("record_finding", _CORS_FINDING_ARGS_QUALIFYING),
        ("record_finding", _CORS_FINDING_ARGS_UNCLEAR),
    ])
    ctx = RunContext(llm=llm, session=session, session_id=session["session_id"])

    _run(_run_analyze(ctx, "example.com", session["recon_result"]))

    assert session.get("cors_check_verdicts", {}) == {}
    assert len(session["findings"]) == 1
    assert session["findings"][0]["qualifies_for_bounty"] == "unclear"


def test_analyze_allows_qualifying_when_cors_check_confirmed_a_genuinely_unrelated_origin(tmp_path):
    index, original = _swap_native_tool("cors_check", _ANY_ORIGIN_RESULT)
    try:
        session = _make_session("usr_cors_gate_allow")
        llm = _ScriptedLLM([
            ("cors_check", {"target": "https://api.example.com"}),
            ("record_finding", _CORS_FINDING_ARGS_QUALIFYING),
        ])
        ctx = RunContext(llm=llm, session=session, session_id=session["session_id"])

        _run(_run_analyze(ctx, "example.com", session["recon_result"]))

        assert session["cors_check_verdicts"] == {"api.example.com": "reflects_any_origin"}
        assert len(session["findings"]) == 1
        assert session["findings"][0]["qualifies_for_bounty"] == "qualifying"
    finally:
        TOOL_REGISTRY[index] = original


def test_deep_dive_gate_rejects_a_repeat_qualifying_claim_for_an_already_narrowed_host(tmp_path):
    """The exact real incident: a deep dive re-runs the same-shaped test and tries to record
    another "qualifying" restatement — the gate must catch it here too, not just in Analyze."""
    index, original = _swap_native_tool("cors_check", _SAME_SUFFIX_ONLY_RESULT)
    try:
        session = _make_session("usr_cors_gate_deepdive")
        session["cors_check_verdicts"] = {"api.example.com": "reflects_own_subdomains_only"}
        finding = {
            "title": "CORS Misconfiguration on api.example.com", "severity": "High",
            "verification": "verified", "qualifies_for_bounty": "qualifying",
        }
        session["findings"] = [finding]
        llm = _ScriptedLLM([("record_finding", _CORS_FINDING_ARGS_QUALIFYING)])
        ctx = RunContext(llm=llm, session=session, session_id=session["session_id"])
        from agent.tools.registry import get_tools_by_category

        _run(_run_exploit_for_finding(ctx, "example.com", finding, get_tools_by_category("exploit"), deep_dive=True))

        # The pre-existing finding is untouched, and the repeat "qualifying" restatement the
        # deep-dive's model tried to record was rejected — never appended as a second entry.
        assert len(session["findings"]) == 1
    finally:
        TOOL_REGISTRY[index] = original
