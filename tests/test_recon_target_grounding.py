"""Recon's nmap gate: a hostname must have a real basis (the literal scope, a wildcard-covered
subdomain, or something a real discovery tool actually resolved this run) before nmap is allowed
to touch it. Real incident this fixes: a scan authorized only for "example.ru" had the model
directly nmap "example.com" and "forum.example.com" -- a different registrable domain entirely
-- purely from its own guess about the target's likely other domains, with zero recon tool ever
having mentioned either. Both happened to resolve to something real (Cloudflare), which is exactly
what let the guess pass as an equally-trustworthy finding for the rest of that scan.
"""
import asyncio
import dataclasses

import agent.tools  # noqa: F401  (side effect: populates TOOL_REGISTRY)
from agent.core import RunContext, _is_recon_target_grounded, _run_recon
from agent.llm_client import LLMResponse, ToolCallRequest
from agent.tools.registry import TOOL_REGISTRY
from sessions import store


def _run(coro):
    return asyncio.run(coro)


# --- _is_recon_target_grounded: the pure grounding check ---


def test_grounded_when_target_is_the_literal_scope():
    assert _is_recon_target_grounded({}, "example.com", "example.com") is True


def test_grounded_when_scope_entry_has_a_scheme_and_path():
    # The literal scope entry carries a scheme+path (a real New Project form shape,
    # "https://example.com/game.php") -- extract_hostname must still match it against the bare
    # hostname the model passes to nmap.
    assert _is_recon_target_grounded({}, "example.com", "https://example.com/game.php, *.example.com") is True


def test_not_grounded_for_a_bare_ip_never_actually_resolved_this_run():
    # A raw IP is only grounded once a real dns_lookup/subdomain_enum call actually resolved it
    # for an in-scope host (recon_result["dns_map"]) -- matching it against the scope string
    # itself is meaningless, an IP has no hostname to compare.
    assert _is_recon_target_grounded({}, "185.132.176.192", "https://example.com/game.php, *.example.com") is False


def test_grounded_when_target_is_a_subdomain_of_a_wildcard_scope_entry():
    assert _is_recon_target_grounded({}, "portal.example.com", "*.example.com") is True


def test_grounded_when_target_matches_a_wildcard_filling_out_part_of_one_label():
    """Real incident this covers: a "prod-*.example.com.br" scope entry now passes
    validate_scope_entry()'s shape check and is_target_allowed() matches it for real -- without
    this same generalization here, a legitimately in-scope host like prod-us1.example.com.br would
    still get silently refused active nmap scanning during Recon, an accepted-but-doesn't-
    actually-work gap for exactly the entries this was just made to accept."""
    assert _is_recon_target_grounded({}, "prod-us1.example.com.br", "prod-*.example.com.br") is True
    assert _is_recon_target_grounded({}, "staging-us1.example.com.br", "prod-*.example.com.br") is False


def test_grounded_when_target_matches_a_wildcard_as_a_labels_own_prefix():
    assert _is_recon_target_grounded({}, "api-noneu.example.com", "*-noneu.example.com") is True
    assert _is_recon_target_grounded({}, "api-eu.example.com", "*-noneu.example.com") is False


def test_grounded_when_target_is_a_hostname_already_in_dns_map():
    session = {"recon_result": {"dns_map": {"portal.example.com": ["150.251.138.237"]}}}
    assert _is_recon_target_grounded(session, "portal.example.com", "example.com") is True


def test_grounded_when_target_is_an_ip_resolved_for_an_already_known_host():
    session = {"recon_result": {"dns_map": {"example.com": ["185.132.176.192"]}}}
    assert _is_recon_target_grounded(session, "185.132.176.192", "example.com") is True


def test_not_grounded_for_a_completely_unrelated_domain():
    assert _is_recon_target_grounded({}, "totally-unrelated-site.example", "example.com") is False


def test_not_grounded_for_a_different_tld_lookalike_domain():
    """The exact real incident: example.com is NOT a subdomain of example.ru, and no discovery
    tool ever surfaced it -- it must not pass just because the name looks related."""
    session = {"recon_result": {"dns_map": {"example.ru": ["185.132.176.192"]}}}
    assert _is_recon_target_grounded(session, "example.com", "example.ru") is False
    assert _is_recon_target_grounded(session, "forum.example.com", "example.ru") is False


def test_not_grounded_when_no_wildcard_scope_and_never_discovered():
    """A bare (non-wildcard) target authorizes only that one literal host -- a plausible-sounding
    subdomain the model invented, never resolved by a real tool, must not pass."""
    assert _is_recon_target_grounded({}, "forumadm.example.com", "example.com") is False


# --- integration: the gate actually blocks nmap in _run_recon, and never touches the real tool ---


def _swap_nmap(fake_result):
    index = next(i for i, s in enumerate(TOOL_REGISTRY) if s.name == "nmap")
    original_spec = TOOL_REGISTRY[index]
    calls = []

    def fake_native(params):
        calls.append(params)
        return dict(fake_result)

    TOOL_REGISTRY[index] = dataclasses.replace(original_spec, tool_tier=1, native_function=fake_native)
    return index, original_spec, calls


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


def test_run_recon_rejects_nmap_against_an_ungrounded_target_and_never_calls_the_real_tool(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    index, original_spec, calls = _swap_nmap({"status": "ok", "stdout": "PORT 80/tcp open http"})
    try:
        session = {
            "session_id": "usr_grounding_reject", "target": "example.com", "status": "processing",
            "logs": [], "findings": [], "approvals": [], "chat": {"summary": "", "messages": []},
        }
        llm = _ScriptedLLM([("nmap", {"target": "forum.example.com"})])
        ctx = RunContext(llm=llm, session=session, session_id=session["session_id"])

        _run(_run_recon(ctx, "example.com"))

        assert calls == []  # the real nmap function never ran at all
        assert session["logs"][0]["status"] == "error"
        assert "no real basis" in session["logs"][0]["error"]
        assert session["recon_result"]["targets"] == []
    finally:
        TOOL_REGISTRY[index] = original_spec


def test_run_recon_allows_nmap_against_the_literal_target(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    index, original_spec, calls = _swap_nmap({"status": "ok", "stdout": "PORT 80/tcp open http"})
    try:
        session = {
            "session_id": "usr_grounding_literal", "target": "example.com", "status": "processing",
            "logs": [], "findings": [], "approvals": [], "chat": {"summary": "", "messages": []},
        }
        llm = _ScriptedLLM([("nmap", {"target": "example.com"})])
        ctx = RunContext(llm=llm, session=session, session_id=session["session_id"])

        _run(_run_recon(ctx, "example.com"))

        assert len(calls) == 1  # the real nmap function actually ran
    finally:
        TOOL_REGISTRY[index] = original_spec


def test_run_recon_allows_nmap_against_a_host_discovered_earlier_this_same_run(tmp_path, monkeypatch):
    """dns_lookup resolves portal.example.com mid-phase -> a later nmap on it is grounded, no
    separate scan needed to "pre-register" it."""
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    dns_index = next(i for i, s in enumerate(TOOL_REGISTRY) if s.name == "dns_lookup")
    dns_original = TOOL_REGISTRY[dns_index]
    TOOL_REGISTRY[dns_index] = dataclasses.replace(
        dns_original, tool_tier=1,
        native_function=lambda params: {"status": "ok", "ips": ["150.251.138.237"]},
    )
    nmap_index, nmap_original, calls = _swap_nmap({"status": "ok", "stdout": "PORT 22/tcp open ssh"})
    try:
        session = {
            "session_id": "usr_grounding_dynamic", "target": "example.com", "status": "processing",
            "logs": [], "findings": [], "approvals": [], "chat": {"summary": "", "messages": []},
        }
        llm = _ScriptedLLM([
            ("dns_lookup", {"domain": "portal.example.com"}),
            ("nmap", {"target": "portal.example.com"}),
        ])
        ctx = RunContext(llm=llm, session=session, session_id=session["session_id"])

        _run(_run_recon(ctx, "example.com"))

        assert len(calls) == 1
    finally:
        TOOL_REGISTRY[dns_index] = dns_original
        TOOL_REGISTRY[nmap_index] = nmap_original
