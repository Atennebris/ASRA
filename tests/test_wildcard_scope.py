"""Wildcard scope support ("*.example.com" in the New Project target field): validate_scope_entry()
accepting the marker, is_target_allowed() matching any subdomain under an allowlisted wildcard, and
subdomain_enum() actually trying its wordlist -- without a real network call in the test.
"""
import asyncio
import socket

from fastapi.testclient import TestClient

import agent.tools  # noqa: F401  (side effect: populates TOOL_REGISTRY)
import main
from agent.core import RunContext, _has_wildcard_scope, _run_recon
from agent.llm_client import LLMResponse
from agent.tools import allowed_targets
from agent.tools.allowed_targets import is_target_allowed
from agent.tools.builders.validators import validate_scope_entry
from agent.tools.native import subdomain_enum
from projects import paths as project_paths
from sessions import store


def test_has_wildcard_scope_true_for_a_wildcard_entry():
    assert _has_wildcard_scope("*.example.com") is True


def test_has_wildcard_scope_true_when_mixed_with_a_plain_entry():
    assert _has_wildcard_scope("example.com, *.other.com") is True


def test_has_wildcard_scope_false_for_a_plain_target():
    assert _has_wildcard_scope("example.com") is False


class _ToolListRecordingLLM:
    """Captures the tool names offered on the first call, then ends the phase immediately --
    enough to see whether subdomain_enum was actually in Recon's tool list without needing a
    full scripted multi-turn conversation.
    """
    provider_id = "test-provider"
    model = "test-model"

    def __init__(self):
        self.offered_tool_names: list[str] | None = None
        self.last_messages = None

    def complete(self, messages, tools=None, stop_check=None):
        if self.offered_tool_names is None:
            self.offered_tool_names = [t["function"]["name"] for t in (tools or [])]
        self.last_messages = messages
        return LLMResponse(content="done", tool_calls=[])


def test_recon_does_not_offer_any_subdomain_discovery_tool_for_a_plain_target():
    """Real incident this fixes: only subdomain_enum was ever actually excluded here -- subfinder
    (its own description literally says "use this first for a wildcard-scope target") and
    crt_sh_lookup (whose sole purpose is finding subdomains via certificate transparency) both
    stayed offered unconditionally, on the theory that a "passive" lookup was harmless. It isn't:
    a subdomain crt_sh_lookup/subfinder discovers, once resolved via the always-available
    dns_lookup, is enough to ground an active nmap scan against it (_is_recon_target_grounded) --
    a plain "example.com" target with the checkbox off (no wildcard entry) means exactly that one
    host is authorized, not "and whatever crt.sh/subfinder can dig up about it too"."""
    llm = _ToolListRecordingLLM()
    session = {"session_id": "usr_recon_plain", "logs": [], "findings": []}
    ctx = RunContext(llm=llm, session=session, session_id=session["session_id"])

    asyncio.run(_run_recon(ctx, "example.com"))

    assert "subdomain_enum" not in llm.offered_tool_names
    assert "subfinder" not in llm.offered_tool_names
    assert "crt_sh_lookup" not in llm.offered_tool_names


def test_recon_offers_all_subdomain_discovery_tools_for_a_wildcard_target():
    llm = _ToolListRecordingLLM()
    session = {"session_id": "usr_recon_wildcard", "logs": [], "findings": []}
    ctx = RunContext(llm=llm, session=session, session_id=session["session_id"])

    asyncio.run(_run_recon(ctx, "*.example.com"))

    assert "subdomain_enum" in llm.offered_tool_names
    assert "subfinder" in llm.offered_tool_names
    assert "crt_sh_lookup" in llm.offered_tool_names


def test_recon_offers_subdomain_enum_when_the_project_checkbox_is_on_even_without_wildcard_syntax():
    """The New Project form's "Enumerate subdomains" checkbox (off by default,
    sessions/store.py's create_session()) is a second, independent way to turn this on — the
    operator shouldn't have to type "*." on every scope entry if they just check the box.
    """
    llm = _ToolListRecordingLLM()
    session = {"session_id": "usr_recon_checkbox", "logs": [], "findings": [], "enumerate_subdomains": True}
    ctx = RunContext(llm=llm, session=session, session_id=session["session_id"])

    asyncio.run(_run_recon(ctx, "example.com"))

    assert "subdomain_enum" in llm.offered_tool_names
    assert "subfinder" in llm.offered_tool_names
    assert "crt_sh_lookup" in llm.offered_tool_names
    # The model needs to be told explicitly why it has this tool when nothing in the target
    # string itself hints at it (unlike a "*." entry, which RECON_PROMPT already explains).
    task_text = llm.last_messages[1]["content"]
    assert "Subdomain enumeration is enabled for this project" in task_text


def test_recon_still_excludes_subdomain_enum_when_checkbox_is_off_and_no_wildcard():
    llm = _ToolListRecordingLLM()
    session = {"session_id": "usr_recon_checkbox_off", "logs": [], "findings": [], "enumerate_subdomains": False}
    ctx = RunContext(llm=llm, session=session, session_id=session["session_id"])

    asyncio.run(_run_recon(ctx, "example.com"))

    assert "subdomain_enum" not in llm.offered_tool_names


def test_validate_scope_entry_accepts_wildcard_and_keeps_the_marker():
    assert validate_scope_entry("*.example.com") == "*.example.com"


def test_validate_scope_entry_normalizes_a_scheme_prefixed_wildcard():
    """A real variant scope tables use ("https://*.example.com"), not just the bare form —
    normalizes to the same canonical "*.example.com" every downstream consumer (allowed_targets.py's
    is_target_allowed, agent/core.py's _has_wildcard_scope, RECON_PROMPT) already expects."""
    assert validate_scope_entry("https://*.example.com") == "*.example.com"
    assert validate_scope_entry("http://*.example.com") == "*.example.com"


def test_validate_scope_entry_normalizes_a_scheme_prefixed_wildcard_case_insensitively():
    assert validate_scope_entry("HTTPS://*.example.com") == "*.example.com"


def test_validate_scope_entry_still_rejects_an_invalid_domain_under_a_schemed_wildcard():
    try:
        validate_scope_entry("https://*. not a domain")
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_validate_scope_entry_rejects_wildcard_over_an_invalid_domain():
    try:
        validate_scope_entry("*. not a domain")
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_validate_scope_entry_accepts_a_wildcard_filling_out_part_of_one_label():
    """Real, commonly-seen scope-table shape (confirmed live): "prod-*.example.com" -- a wildcard
    for part of one specific label, matching prod-us1.example.com/prod-eu2.example.com/... -- used
    to be rejected outright ("Target does not look like a hostname/IP/URL") because only a leading
    whole-label "*." was ever recognized."""
    assert validate_scope_entry("prod-*.example.com.br") == "prod-*.example.com.br"


def test_validate_scope_entry_accepts_a_wildcard_as_a_labels_own_prefix():
    """Real, commonly-seen scope-table shape (confirmed live): "*-eu.example.com" -- a wildcard as
    a label's own prefix, matching api-eu.example.com/web-eu.example.com/... -- same gap as the
    prod-*.example.com case above, just the wildcard on the other side of the label."""
    assert validate_scope_entry("*-noneu.example.com") == "*-noneu.example.com"
    assert validate_scope_entry("*-eu.example.com") == "*-eu.example.com"
    assert validate_scope_entry("*-asia-south1.example.com") == "*-asia-south1.example.com"


def test_validate_scope_entry_still_validates_a_plain_target_like_before():
    assert validate_scope_entry("example.com") == "example.com"
    try:
        validate_scope_entry("")
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_is_target_allowed_wildcard_covers_a_subdomain(tmp_path, monkeypatch):
    from agent.tools import allowed_targets

    monkeypatch.setattr(allowed_targets, "ALLOWED_TARGETS_PATH", tmp_path / "allowed.json")
    allowed_targets.add_allowed_target("*.example.com")

    assert is_target_allowed("library.example.com") is True
    assert is_target_allowed("https://portal.example.com/login") is True


def test_is_target_allowed_wildcard_also_covers_the_bare_apex_domain(tmp_path, monkeypatch):
    from agent.tools import allowed_targets

    monkeypatch.setattr(allowed_targets, "ALLOWED_TARGETS_PATH", tmp_path / "allowed.json")
    allowed_targets.add_allowed_target("*.example.com")

    assert is_target_allowed("example.com") is True


def test_is_target_allowed_wildcard_does_not_cover_an_unrelated_domain(tmp_path, monkeypatch):
    from agent.tools import allowed_targets

    monkeypatch.setattr(allowed_targets, "ALLOWED_TARGETS_PATH", tmp_path / "allowed.json")
    allowed_targets.add_allowed_target("*.example.com")

    assert is_target_allowed("other-site.com") is False


def test_is_target_allowed_matches_a_wildcard_filling_out_part_of_one_label(tmp_path, monkeypatch):
    """Real incident this covers: "prod-*.example.com.br" used to be accepted as a shape by
    validate_scope_entry() (once that was fixed) but never actually matched anything here — the
    matcher only ever recognized a whole leading "*." label, an accepted-but-doesn't-actually-work
    gap worse than an outright rejection."""
    from agent.tools import allowed_targets

    monkeypatch.setattr(allowed_targets, "ALLOWED_TARGETS_PATH", tmp_path / "allowed.json")
    allowed_targets.add_allowed_target("prod-*.example.com.br")

    assert is_target_allowed("prod-us1.example.com.br") is True
    assert is_target_allowed("staging-us1.example.com.br") is False


def test_is_target_allowed_matches_a_wildcard_as_a_labels_own_prefix(tmp_path, monkeypatch):
    from agent.tools import allowed_targets

    monkeypatch.setattr(allowed_targets, "ALLOWED_TARGETS_PATH", tmp_path / "allowed.json")
    allowed_targets.add_allowed_target("*-noneu.example.com")

    assert is_target_allowed("api-noneu.example.com") is True
    assert is_target_allowed("api-eu.example.com") is False


def test_is_target_allowed_wildcard_matching_is_case_insensitive(tmp_path, monkeypatch):
    from agent.tools import allowed_targets

    monkeypatch.setattr(allowed_targets, "ALLOWED_TARGETS_PATH", tmp_path / "allowed.json")
    allowed_targets.add_allowed_target("prod-*.Example.com")

    assert is_target_allowed("PROD-US1.example.com") is True


# --- /api/scan: the "Enumerate subdomains" checkbox's own documented promise ("same effect as
# writing each one as *.example.com") has to actually reach the exploitation allowlist, not just
# recon's tool list -- real incident this fixes: a real scan with the box checked found a real,
# verified finding on a legitimately-discovered subdomain, and default_creds_check still refused
# to run against it because only the literal typed host had ever been authorized. ---


async def _fake_run_session(session_id, provider_id=None, entry_point="recon"):
    return None


def _post_scan(tmp_path, monkeypatch, **form_overrides):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path / "legacy")
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    monkeypatch.setattr(allowed_targets, "ALLOWED_TARGETS_PATH", tmp_path / "allowed.json")
    monkeypatch.setenv("PROJECTS_DIR", str(tmp_path / "projects"))
    project_paths.resolve_projects_base_dir.cache_clear()
    monkeypatch.setattr(main, "run_session", _fake_run_session)
    form = {"name": "Wildcard Scope Project", "target": "example.com", "authorize_exploit": "on"}
    form.update(form_overrides)
    client = TestClient(main.app)
    try:
        return client.post("/api/scan", data=form, follow_redirects=False)
    finally:
        project_paths.resolve_projects_base_dir.cache_clear()


def test_scan_form_with_enumerate_subdomains_authorizes_the_whole_subdomain_tree(tmp_path, monkeypatch):
    resp = _post_scan(tmp_path, monkeypatch, enumerate_subdomains="on")
    assert resp.status_code == 303, resp.text
    assert is_target_allowed("forum.example.com") is True
    assert is_target_allowed("example.com") is True


def test_scan_form_without_enumerate_subdomains_only_authorizes_the_literal_host(tmp_path, monkeypatch):
    resp = _post_scan(tmp_path, monkeypatch)
    assert resp.status_code == 303, resp.text
    assert is_target_allowed("example.com") is True
    assert is_target_allowed("forum.example.com") is False


def test_scan_form_enumerate_subdomains_does_not_cover_an_unrelated_domain(tmp_path, monkeypatch):
    """*.example.com must never cover example.org -- a different registrable domain, not a
    subdomain, regardless of how related the two sites are in practice."""
    resp = _post_scan(tmp_path, monkeypatch, enumerate_subdomains="on")
    assert resp.status_code == 303, resp.text
    assert is_target_allowed("forum.example.org") is False


def test_scan_form_enumerate_subdomains_does_not_double_wrap_an_already_wildcard_target(tmp_path, monkeypatch):
    resp = _post_scan(tmp_path, monkeypatch, target="*.example.com", enumerate_subdomains="on")
    assert resp.status_code == 303, resp.text
    assert allowed_targets.load_allowed_targets() == ["*.example.com"]


def test_scan_form_enumerate_subdomains_uses_the_apex_domain_when_the_target_is_itself_a_subdomain(tmp_path, monkeypatch):
    """Real, confirmed incident this fixes (test-2-again2-usr_2f4db1): a project targeting
    "crossfire.z8games.com" (itself already a subdomain, not the apex) with "Enumerate subdomains"
    checked used to authorize only "*.crossfire.z8games.com" — recon legitimately discovered and
    reported real, verified findings on sibling hosts under the actual apex ("support.z8games.com"),
    and Exploit could never act on them for the rest of the session because the allowlist never
    covered anything outside crossfire.z8games.com's own subtree. The wildcard base must be the
    target's APEX/registrable domain (via tldextract), matching what recon's own grounding logic
    (_is_recon_target_grounded) is already allowed to range across.
    """
    resp = _post_scan(tmp_path, monkeypatch, target="crossfire.z8games.com", enumerate_subdomains="on")
    assert resp.status_code == 303, resp.text
    assert allowed_targets.load_allowed_targets() == ["*.z8games.com"]
    assert is_target_allowed("support.z8games.com") is True
    assert is_target_allowed("crossfire.z8games.com") is True
    assert is_target_allowed("z8games.com") is True


def test_authorize_exploit_targets_apex_domain_handles_multi_label_tld(tmp_path, monkeypatch):
    """A naive "last two labels" split would wrongly turn "shop.example.co.uk" into "*.co.uk" (a
    real public suffix, not a registrable domain) -- tldextract's Public-Suffix-List awareness is
    what keeps this correct for multi-label TLDs like .co.uk/.com.au."""
    monkeypatch.setattr(allowed_targets, "ALLOWED_TARGETS_PATH", tmp_path / "allowed.json")

    allowed_targets.authorize_exploit_targets(["shop.example.co.uk"], True)

    assert allowed_targets.load_allowed_targets() == ["*.example.co.uk"]
    assert is_target_allowed("other.example.co.uk") is True
    assert is_target_allowed("unrelated.co.uk") is False


def test_subdomain_enum_tries_every_prefix_and_reports_only_the_ones_that_resolved(monkeypatch):
    def fake_getaddrinfo(host, port):
        if host == "www.example.com":
            return [(None, None, None, None, ("203.0.113.5", 0))]
        raise socket.gaierror("not found")

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    result = subdomain_enum({"domain": "example.com"})

    assert result["status"] == "ok"
    assert result["found"] == [{"host": "www.example.com", "ips": ["203.0.113.5"]}]
    assert result["tried"] > 1
