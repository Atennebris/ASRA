"""_update_asset_graph (agent/core.py): deterministic (no LLM) credential-reuse tracking -- a
credential default_creds_check/hydra_start/web_login_bruteforce_start actually finds gets checked
against every OTHER host this session discovered, auto-generating a hypothesis (via the existing
_persist_new_hypothesis) for any host it hasn't been suggested against yet. Real motivation: a
single end-of-scan LLM pass (_run_chain) has no reliable notion of "have I tried this exact
credential everywhere" -- this makes it a structural, not a memory-dependent, check.
"""
import asyncio
import dataclasses

import agent.tools  # noqa: F401  (side effect: populates TOOL_REGISTRY)
from agent.core import RunContext, _run_tool_with_retry, _update_asset_graph
from agent.tools import allowed_targets
from agent.tools.allowed_targets import add_allowed_target
from agent.tools.registry import TOOL_REGISTRY, get_tool
from sessions import store


def _run(coro):
    return asyncio.run(coro)


def _swap_tool(name, fake_result):
    """Same fake-native-function-swap pattern as tests/test_host_health.py -- exercises the real
    _run_tool_with_retry call path (not just the unit-level _update_asset_graph calls above)."""
    index = next(i for i, s in enumerate(TOOL_REGISTRY) if s.name == name)
    original_spec = TOOL_REGISTRY[index]
    TOOL_REGISTRY[index] = dataclasses.replace(original_spec, tool_tier=1, native_function=lambda params: dict(fake_result))
    return index, original_spec


def _make_session(recon_targets=None):
    return {
        "session_id": "usr_asset_graph_test", "target": "example.com", "status": "processing",
        "logs": [], "findings": [], "hypotheses": [], "approvals": [], "chat": {"summary": "", "messages": []},
        "recon_result": {"targets": recon_targets or []},
    }


def _ctx(session):
    return RunContext(llm=object(), session=session, session_id=session["session_id"])


def _default_creds_check_spec():
    return get_tool("default_creds_check")


def _background_job_check_spec():
    return get_tool("background_job_check")


def _web_self_register_spec():
    return get_tool("web_self_register")


def test_default_creds_check_success_registers_credential_and_suggests_other_hosts(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    monkeypatch.setattr(allowed_targets, "ALLOWED_TARGETS_PATH", tmp_path / "allowed.json")
    from agent.tools import native
    monkeypatch.setattr(native, "_CREDENTIALS_DIR", tmp_path / "credentials")
    add_allowed_target("host-b.example.com")

    session = _make_session(recon_targets=[
        {"host": "host-a.example.com", "port": 443, "service": "https"},
        {"host": "host-b.example.com", "port": 443, "service": "https"},
    ])
    ctx = _ctx(session)
    arguments = {"target": "https://host-a.example.com/login"}
    result = {"status": "ok", "successful_credentials": [{"username": "admin", "password": "admin123"}]}

    _update_asset_graph(ctx, _default_creds_check_spec(), arguments, result)

    creds = ctx.session["asset_graph"]["credentials"]
    assert len(creds) == 1
    cred = creds[0]
    assert cred["username"] == "admin" and cred["password"] == "admin123"
    assert cred["found_on_host"] == "host-a.example.com"
    assert cred["identity_name"] == "discovered_1"
    assert cred["suggested_hosts"] == ["host-b.example.com"]

    stored_identity = native._load_credentials(ctx.session_id)["discovered_1"]
    assert stored_identity == {"username": "admin", "password": "admin123", "login_url": "https://host-a.example.com/login"}

    # The model has no other way to learn the identity_name register_discovered_credential just
    # assigned -- that happens AFTER this tool's own native_function already returned its result.
    assert result["credential_identity_names"]["admin:admin123"] == "discovered_1"

    hyp_texts = [h["text"] for h in ctx.session["hypotheses"]]
    assert any("host-b.example.com" in t and "discovered_1" in t for t in hyp_texts)
    assert ctx.session["hypotheses"][0]["source_phase"] == "asset_graph"


def test_default_creds_check_with_no_successes_is_a_noop(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    session = _make_session()
    ctx = _ctx(session)
    result = {"status": "ok", "successful_credentials": []}

    _update_asset_graph(ctx, _default_creds_check_spec(), {"target": "https://x.example.com"}, result)

    assert ctx.session.get("asset_graph", {}).get("credentials", []) == []
    assert ctx.session["hypotheses"] == []


def test_background_job_check_hydra_result_uses_the_credentials_own_host_field(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    monkeypatch.setattr(allowed_targets, "ALLOWED_TARGETS_PATH", tmp_path / "allowed.json")
    add_allowed_target("db2.example.com")

    session = _make_session(recon_targets=[
        {"host": "db1.example.com", "port": 22, "service": "ssh"},
        {"host": "db2.example.com", "port": 22, "service": "ssh"},
    ])
    session["background_jobs"] = {"job1": {"tool": "hydra", "status": "ok"}}
    ctx = _ctx(session)
    result = {"status": "ok", "result": {"credentials": [{"host": "db1.example.com", "login": "root", "password": "toor", "port": 22}]}}

    _update_asset_graph(ctx, _background_job_check_spec(), {"job_id": "job1"}, result)

    creds = ctx.session["asset_graph"]["credentials"]
    assert len(creds) == 1
    assert creds[0]["username"] == "root" and creds[0]["password"] == "toor"
    assert creds[0]["found_on_host"] == "db1.example.com"
    assert creds[0]["identity_name"] is None  # never registered as a web identity -- protocol-ambiguous
    assert creds[0]["suggested_hosts"] == ["db2.example.com"]
    hyp_texts = [h["text"] for h in ctx.session["hypotheses"]]
    assert any("root:toor" in t and "db2.example.com" in t for t in hyp_texts)


def test_background_job_check_web_login_bruteforce_recovers_host_from_stashed_job_target(tmp_path, monkeypatch):
    """web_login_bruteforce's own parsed credentials carry no host field at all (unlike hydra's) --
    the host must be recovered from the job's own stashed "target" metadata (Part 1's
    extra_metadata plumbing in agent/tools/background_jobs.py)."""
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    monkeypatch.setattr(allowed_targets, "ALLOWED_TARGETS_PATH", tmp_path / "allowed.json")
    add_allowed_target("app2.example.com")

    session = _make_session(recon_targets=[
        {"host": "app1.example.com", "port": 443, "service": "https"},
        {"host": "app2.example.com", "port": 443, "service": "https"},
    ])
    session["background_jobs"] = {"job2": {"tool": "web_login_bruteforce", "status": "ok", "target": "https://app1.example.com/login"}}
    ctx = _ctx(session)
    result = {"status": "ok", "result": {"credentials": [{"username": "bob", "password": "hunter2"}]}}

    _update_asset_graph(ctx, _background_job_check_spec(), {"job_id": "job2"}, result)

    creds = ctx.session["asset_graph"]["credentials"]
    assert len(creds) == 1
    assert creds[0]["found_on_host"] == "app1.example.com"
    assert creds[0]["suggested_hosts"] == ["app2.example.com"]


def test_background_job_check_ignores_a_job_that_is_not_a_credential_cracking_tool(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    session = _make_session()
    session["background_jobs"] = {"job3": {"tool": "some_other_tool", "status": "ok"}}
    ctx = _ctx(session)
    result = {"status": "ok", "result": {"credentials": [{"username": "x", "password": "y", "host": "z.example.com"}]}}

    _update_asset_graph(ctx, _background_job_check_spec(), {"job_id": "job3"}, result)

    assert ctx.session.get("asset_graph", {}).get("credentials", []) == []


def test_calling_twice_with_the_identical_result_is_idempotent(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    monkeypatch.setattr(allowed_targets, "ALLOWED_TARGETS_PATH", tmp_path / "allowed.json")
    from agent.tools import native
    monkeypatch.setattr(native, "_CREDENTIALS_DIR", tmp_path / "credentials")
    add_allowed_target("host-b.example.com")

    session = _make_session(recon_targets=[
        {"host": "host-a.example.com", "port": 443, "service": "https"},
        {"host": "host-b.example.com", "port": 443, "service": "https"},
    ])
    ctx = _ctx(session)
    arguments = {"target": "https://host-a.example.com/login"}
    result = {"status": "ok", "successful_credentials": [{"username": "admin", "password": "admin123"}]}

    _update_asset_graph(ctx, _default_creds_check_spec(), arguments, result)
    _update_asset_graph(ctx, _default_creds_check_spec(), arguments, result)  # background_job_check on an already-finished job returns the same cached result every time it's re-checked

    assert len(ctx.session["asset_graph"]["credentials"]) == 1
    assert len(ctx.session["hypotheses"]) == 1


def test_a_host_not_on_the_exploitation_allowlist_is_never_suggested(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    monkeypatch.setattr(allowed_targets, "ALLOWED_TARGETS_PATH", tmp_path / "allowed.json")
    from agent.tools import native
    monkeypatch.setattr(native, "_CREDENTIALS_DIR", tmp_path / "credentials")
    # Deliberately never add_allowed_target("host-b.example.com") -- it's discovered, but never
    # authorized for exploitation, so it must never get suggested.

    session = _make_session(recon_targets=[
        {"host": "host-a.example.com", "port": 443, "service": "https"},
        {"host": "host-b.example.com", "port": 443, "service": "https"},
    ])
    ctx = _ctx(session)
    arguments = {"target": "https://host-a.example.com/login"}
    result = {"status": "ok", "successful_credentials": [{"username": "admin", "password": "admin123"}]}

    _update_asset_graph(ctx, _default_creds_check_spec(), arguments, result)

    assert ctx.session["asset_graph"]["credentials"][0]["suggested_hosts"] == []
    assert ctx.session["hypotheses"] == []


def test_web_self_register_success_registers_identity_and_carries_its_own_cookie(tmp_path, monkeypatch):
    """web_self_register hands back its OWN login_url/cookie (unlike default_creds_check, which
    reuses the endpoint it tested) -- both must flow through into the credential store as-is."""
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    monkeypatch.setattr(allowed_targets, "ALLOWED_TARGETS_PATH", tmp_path / "allowed.json")
    from agent.tools import native
    monkeypatch.setattr(native, "_CREDENTIALS_DIR", tmp_path / "credentials")
    add_allowed_target("host-b.example.com")

    session = _make_session(recon_targets=[
        {"host": "host-a.example.com", "port": 443, "service": "https"},
        {"host": "host-b.example.com", "port": 443, "service": "https"},
    ])
    ctx = _ctx(session)
    arguments = {"target": "https://host-a.example.com"}
    result = {
        "status": "ok",
        "successful_credentials": [{"username": "asra_deadbeef", "password": "Asra!xyz9"}],
        "registration_url": "https://host-a.example.com/register",
        "login_url": None,
        "cookie": "sessionid=abc123",
    }

    _update_asset_graph(ctx, _web_self_register_spec(), arguments, result)

    creds = ctx.session["asset_graph"]["credentials"]
    assert len(creds) == 1
    cred = creds[0]
    assert cred["username"] == "asra_deadbeef" and cred["source_tool"] == "web_self_register"
    assert cred["found_on_host"] == "host-a.example.com"
    assert cred["identity_name"] == "self_registered_1"

    stored_identity = native._load_credentials(ctx.session_id)["self_registered_1"]
    assert stored_identity["cookie"] == "sessionid=abc123"
    assert stored_identity["login_url"] is None

    # The identity_name assigned above must also flow back into the tool's OWN result dict -- the
    # model has no other way to learn it (it's assigned here, AFTER the tool's native_function
    # already returned), and without it a self-registered account would be structurally unusable
    # via authenticated_request/idor_probe's own identity= lookup for the rest of the run.
    assert result["credential_identity_names"]["asra_deadbeef:Asra!xyz9"] == "self_registered_1"

    hyp_texts = [h["text"] for h in ctx.session["hypotheses"]]
    assert any("host-b.example.com" in t and "self_registered_1" in t for t in hyp_texts)


def test_other_tool_names_are_untouched():
    session = _make_session()
    ctx = _ctx(session)
    http_request_spec = get_tool("http_request")

    _update_asset_graph(ctx, http_request_spec, {"target": "https://x.example.com"}, {"status": "ok", "status_code": 200})

    assert "asset_graph" not in ctx.session


def test_run_tool_with_retry_actually_wires_the_hook_end_to_end(tmp_path, monkeypatch):
    """Confirms the real call path (_run_tool_with_retry itself), not just the unit-level
    _update_asset_graph calls above -- a fake default_creds_check native_function swapped into the
    real registry, dispatched through the real function."""
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    monkeypatch.setattr(allowed_targets, "ALLOWED_TARGETS_PATH", tmp_path / "allowed.json")
    from agent.tools import native
    monkeypatch.setattr(native, "_CREDENTIALS_DIR", tmp_path / "credentials")
    add_allowed_target("host-a.example.com")  # the dispatch target itself must be authorized too
    add_allowed_target("host-b.example.com")

    index, original_spec = _swap_tool("default_creds_check", {
        "status": "ok", "successful_credentials": [{"username": "admin", "password": "admin123"}], "attempted": 5,
    })
    try:
        session = _make_session(recon_targets=[
            {"host": "host-a.example.com", "port": 443, "service": "https"},
            {"host": "host-b.example.com", "port": 443, "service": "https"},
        ])
        ctx = _ctx(session)
        spec = TOOL_REGISTRY[index]

        result = _run(_run_tool_with_retry(ctx, spec, {"target": "https://host-a.example.com/login"}))

        assert result["status"] == "ok"
        creds = ctx.session["asset_graph"]["credentials"]
        assert len(creds) == 1
        assert creds[0]["suggested_hosts"] == ["host-b.example.com"]
    finally:
        TOOL_REGISTRY[index] = original_spec
