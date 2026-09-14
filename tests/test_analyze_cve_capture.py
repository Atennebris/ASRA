"""cve_lookup results get captured into session.recon_result.cves during Analyze — regression
test for a real bug: the tool is registered category="scan" (only Analyze's tool set includes
it, matching ANALYZE_PROMPT's own instruction to use it there), but the capture hook used to sit
in _run_recon's execute() instead, where the model never had cve_lookup in its schema at all and
so could never trigger it. Moved to _run_analyze; this pins the fix down directly.
"""
import asyncio
import dataclasses

import agent.core as core
import agent.tools  # noqa: F401  (side effect: populates TOOL_REGISTRY)
from agent.core import RunContext, _run_analyze
from agent.llm_client import LLMResponse, ToolCallRequest
from agent.tools.registry import TOOL_REGISTRY
from sessions import store


def _run(coro):
    return asyncio.run(coro)


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


def test_cve_lookup_is_available_during_analyze_not_recon():
    """The actual bug: which phase's tool set includes cve_lookup at all."""
    from agent.tools.registry import get_tools_by_category

    recon_names = {spec.name for spec in get_tools_by_category("recon")}
    scan_names = {spec.name for spec in get_tools_by_category("scan")}
    assert "cve_lookup" in scan_names
    assert "cve_lookup" not in recon_names


def test_cve_lookup_result_lands_in_recon_result_cves(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")

    # ToolSpec is a frozen dataclass — can't monkeypatch an attribute on the instance itself,
    # swap the whole registry entry for one with a fake native_function instead (TOOL_REGISTRY
    # is a plain list, not a Mapping, so this is a manual save/restore, not monkeypatch.setitem).
    index = next(i for i, s in enumerate(TOOL_REGISTRY) if s.name == "cve_lookup")
    original_spec = TOOL_REGISTRY[index]
    TOOL_REGISTRY[index] = dataclasses.replace(
        original_spec,
        native_function=lambda params: {"status": "ok", "cve_ids": ["CVE-2019-10758", "CVE-2018-16487"]},
    )
    try:
        # A confirmed host running the product -- the chip only gets populated once there's
        # ground truth behind it (see the no-confirmed-host test below for the opposite case).
        recon_result = {"targets": [{"host": "iot.example.com", "port": 80, "service": "http", "version": "mongoose-os 2.0"}]}
        session = {
            "session_id": "usr_cve_test", "target": "example.com", "status": "processing",
            "logs": [], "findings": [], "approvals": [], "chat": {"summary": "", "messages": []},
            "recon_result": recon_result,
        }
        llm = _ScriptedLLM([("cve_lookup", {"product": "mongoose-os"})])
        ctx = RunContext(llm=llm, session=session, session_id=session["session_id"])

        _run(_run_analyze(ctx, "example.com", recon_result))

        assert session["recon_result"]["cves"] == ["CVE-2018-16487", "CVE-2019-10758"]
    finally:
        TOOL_REGISTRY[index] = original_spec


def test_cve_lookup_auto_records_a_finding_for_an_uncovered_cve(tmp_path, monkeypatch):
    """A CVE chip with no backing finding card was a real, reported bug — whether the model also
    calls record_finding isn't reliable enough to promise a card always exists, so _run_analyze
    must record one itself from cve_lookup's own description/severity data. Only reachable when
    Recon actually confirmed a host running the product — see the no-confirmed-host test below for
    the (now default) opposite case.
    """
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")

    index = next(i for i, s in enumerate(TOOL_REGISTRY) if s.name == "cve_lookup")
    original_spec = TOOL_REGISTRY[index]
    TOOL_REGISTRY[index] = dataclasses.replace(
        original_spec,
        native_function=lambda params: {
            "status": "ok",
            "cve_ids": ["CVE-2023-48795"],
            "details": {"CVE-2023-48795": {"description": "Terrapin attack.", "severity": "High"}},
        },
    )
    try:
        recon_result = {"targets": [{"host": "ssh.example.com", "port": 22, "service": "ssh", "version": "OpenSSH 8.9"}]}
        session = {
            "session_id": "usr_cve_autofind", "target": "example.com", "status": "processing",
            "logs": [], "findings": [], "approvals": [], "chat": {"summary": "", "messages": []},
            "recon_result": recon_result,
        }
        llm = _ScriptedLLM([("cve_lookup", {"product": "OpenSSH"})])
        ctx = RunContext(llm=llm, session=session, session_id=session["session_id"])

        _run(_run_analyze(ctx, "example.com", recon_result))

        titles = [f["title"] for f in session["findings"]]
        assert titles == ["OpenSSH — CVE-2023-48795"]
        assert session["findings"][0]["severity"] == "High"
        assert session["findings"][0]["verification"] == "inferred"
    finally:
        TOOL_REGISTRY[index] = original_spec


def test_cve_lookup_auto_record_notifies_on_a_high_or_critical_severity(tmp_path, monkeypatch):
    """This deterministic auto-recording path appends directly to session["findings"], a SEPARATE
    append site from _persist_new_finding's own (model-driven record_finding) one -- needs its own
    notification call, not covered by that one."""
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    notified = []
    monkeypatch.setattr(core, "notify_high_severity_finding", lambda *a: notified.append(a))

    index = next(i for i, s in enumerate(TOOL_REGISTRY) if s.name == "cve_lookup")
    original_spec = TOOL_REGISTRY[index]
    TOOL_REGISTRY[index] = dataclasses.replace(
        original_spec,
        native_function=lambda params: {
            "status": "ok",
            "cve_ids": ["CVE-2023-48795"],
            "details": {"CVE-2023-48795": {"description": "Terrapin attack.", "severity": "High"}},
        },
    )
    try:
        recon_result = {"targets": [{"host": "ssh.example.com", "port": 22, "service": "ssh", "version": "OpenSSH 8.9"}]}
        session = {
            "session_id": "usr_cve_notify", "name": "CVE Notify Test", "target": "example.com", "status": "processing",
            "logs": [], "findings": [], "approvals": [], "chat": {"summary": "", "messages": []},
            "recon_result": recon_result,
        }
        llm = _ScriptedLLM([("cve_lookup", {"product": "OpenSSH"})])
        ctx = RunContext(llm=llm, session=session, session_id=session["session_id"])

        _run(_run_analyze(ctx, "example.com", recon_result))

        assert notified == [("CVE Notify Test", "example.com", "OpenSSH — CVE-2023-48795", "High")]
    finally:
        TOOL_REGISTRY[index] = original_spec


def test_cve_lookup_records_nothing_when_no_host_confirmed_running_the_product(tmp_path, monkeypatch):
    """The default case, and the one this whole gate exists for: a bare product-name match with
    zero evidence any in-scope host runs it must not become a Findings card OR a CVE chip — a real
    incident where 18 such speculative Jenkins/Grafana/Confluence "findings" looked identical to
    real, verified ones on sight, with no target behind any of them.
    """
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")

    index = next(i for i, s in enumerate(TOOL_REGISTRY) if s.name == "cve_lookup")
    original_spec = TOOL_REGISTRY[index]
    TOOL_REGISTRY[index] = dataclasses.replace(
        original_spec,
        native_function=lambda params: {
            "status": "ok",
            "cve_ids": ["CVE-2026-53435"],
            "details": {"CVE-2026-53435": {"description": "Jenkins deserialization.", "severity": "High"}},
        },
    )
    try:
        session = {
            "session_id": "usr_cve_ungrounded", "target": "example.com", "status": "processing",
            "logs": [], "findings": [], "approvals": [], "chat": {"summary": "", "messages": []},
        }
        llm = _ScriptedLLM([("cve_lookup", {"product": "Jenkins"})])
        ctx = RunContext(llm=llm, session=session, session_id=session["session_id"])

        _run(_run_analyze(ctx, "example.com", {"targets": []}))

        assert session["findings"] == []
        assert session["recon_result"]["cves"] == []
    finally:
        TOOL_REGISTRY[index] = original_spec


def test_cve_lookup_auto_record_includes_affected_versions_and_references_when_available(tmp_path, monkeypatch):
    """technology must name the real confirmed host+version (stronger than a generic affected-range
    pointer), and reproduction_steps must both state the affected range to compare against and
    point at real reference links, not just a generic NVD URL.
    """
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")

    index = next(i for i, s in enumerate(TOOL_REGISTRY) if s.name == "cve_lookup")
    original_spec = TOOL_REGISTRY[index]
    TOOL_REGISTRY[index] = dataclasses.replace(
        original_spec,
        native_function=lambda params: {
            "status": "ok",
            "cve_ids": ["CVE-2026-27851"],
            "details": {
                "CVE-2026-27851": {
                    "description": "Safe filter variable expansion bug.",
                    "severity": "High",
                    "affected_versions": "2.3.0 – 2.3.21",
                    "references": ["https://dovecot.org/security/CVE-2026-27851.html"],
                },
            },
        },
    )
    try:
        recon_result = {"targets": [{"host": "mail.example.com", "port": 993, "service": "imaps", "version": "Dovecot 2.3.15"}]}
        session = {
            "session_id": "usr_cve_enriched", "target": "example.com", "status": "processing",
            "logs": [], "findings": [], "approvals": [], "chat": {"summary": "", "messages": []},
            "recon_result": recon_result,
        }
        llm = _ScriptedLLM([("cve_lookup", {"product": "Dovecot"})])
        ctx = RunContext(llm=llm, session=session, session_id=session["session_id"])

        _run(_run_analyze(ctx, "example.com", recon_result))

        finding = session["findings"][0]
        assert "mail.example.com" in finding["technology"] and "2.3.15" in finding["technology"]
        assert "2.3.0" in finding["reproduction_steps"] and "2.3.21" in finding["reproduction_steps"]
        assert "dovecot.org/security/CVE-2026-27851.html" in finding["reproduction_steps"]
    finally:
        TOOL_REGISTRY[index] = original_spec


def test_cve_lookup_auto_record_falls_back_gracefully_when_cve_record_has_no_affected_versions(tmp_path, monkeypatch):
    """A confirmed host still gets a real finding even when the CVE record itself is thin (no
    affected_versions) — reproduction_steps must say plainly that range isn't known rather than
    silently rendering "None" or omitting the comparison step.
    """
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")

    index = next(i for i, s in enumerate(TOOL_REGISTRY) if s.name == "cve_lookup")
    original_spec = TOOL_REGISTRY[index]
    TOOL_REGISTRY[index] = dataclasses.replace(
        original_spec,
        native_function=lambda params: {
            "status": "ok",
            "cve_ids": ["CVE-2011-2523"],
            "details": {"CVE-2011-2523": {"description": "Backdoor.", "severity": None}},
        },
    )
    try:
        recon_result = {"targets": [{"host": "ftp.example.com", "port": 21, "service": "ftp", "version": "vsftpd 2.3.4"}]}
        session = {
            "session_id": "usr_cve_no_version", "target": "example.com", "status": "processing",
            "logs": [], "findings": [], "approvals": [], "chat": {"summary": "", "messages": []},
            "recon_result": recon_result,
        }
        llm = _ScriptedLLM([("cve_lookup", {"product": "vsftpd"})])
        ctx = RunContext(llm=llm, session=session, session_id=session["session_id"])

        _run(_run_analyze(ctx, "example.com", recon_result))

        finding = session["findings"][0]
        assert "ftp.example.com" in finding["technology"] and "vsftpd" in finding["technology"]
        assert "see structured version data" in finding["reproduction_steps"]
    finally:
        TOOL_REGISTRY[index] = original_spec


def test_cve_lookup_auto_record_carries_over_a_real_cvss_vector_when_present(tmp_path, monkeypatch):
    """A CVE record that carries a real NVD/CIRCL CVSS vector should land on the auto-recorded
    finding as-is -- never fabricated by the model, never dropped just because this path is
    deterministic rather than a model-driven record_finding call.
    """
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")

    index = next(i for i, s in enumerate(TOOL_REGISTRY) if s.name == "cve_lookup")
    original_spec = TOOL_REGISTRY[index]
    TOOL_REGISTRY[index] = dataclasses.replace(
        original_spec,
        native_function=lambda params: {
            "status": "ok",
            "cve_ids": ["CVE-2023-48795"],
            "details": {
                "CVE-2023-48795": {
                    "description": "Terrapin attack.", "severity": "High",
                    "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
                },
            },
        },
    )
    try:
        recon_result = {"targets": [{"host": "ssh.example.com", "port": 22, "service": "ssh", "version": "OpenSSH 8.9"}]}
        session = {
            "session_id": "usr_cve_vector", "target": "example.com", "status": "processing",
            "logs": [], "findings": [], "approvals": [], "chat": {"summary": "", "messages": []},
            "recon_result": recon_result,
        }
        llm = _ScriptedLLM([("cve_lookup", {"product": "OpenSSH"})])
        ctx = RunContext(llm=llm, session=session, session_id=session["session_id"])

        _run(_run_analyze(ctx, "example.com", recon_result))

        assert session["findings"][0]["cvss_vector"] == "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N"
    finally:
        TOOL_REGISTRY[index] = original_spec


def test_cve_lookup_does_not_duplicate_a_finding_the_model_already_recorded(tmp_path, monkeypatch):
    """If the model already wrote a real, more specific finding mentioning this CVE, auto-record
    must not pile a redundant generic entry on top of it.
    """
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")

    index = next(i for i, s in enumerate(TOOL_REGISTRY) if s.name == "cve_lookup")
    original_spec = TOOL_REGISTRY[index]
    TOOL_REGISTRY[index] = dataclasses.replace(
        original_spec,
        native_function=lambda params: {
            "status": "ok",
            "cve_ids": ["CVE-2023-48795"],
            "details": {"CVE-2023-48795": {"description": "Terrapin attack.", "severity": "High"}},
        },
    )
    try:
        # A confirmed host, so this actually exercises the dedup check (covered_cve_ids) rather
        # than short-circuiting on the no-confirmed-host early return before ever reaching it.
        recon_result = {"targets": [{"host": "ssh.example.com", "port": 22, "service": "ssh", "version": "OpenSSH 8.9"}]}
        session = {
            "session_id": "usr_cve_nodupe", "target": "example.com", "status": "processing",
            "logs": [],
            "findings": [
                {"title": "OpenSSH Terrapin Attack (CVE-2023-48795)", "severity": "Medium", "description": "manually written finding"},
            ],
            "approvals": [], "chat": {"summary": "", "messages": []},
            "recon_result": recon_result,
        }
        llm = _ScriptedLLM([("cve_lookup", {"product": "OpenSSH"})])
        ctx = RunContext(llm=llm, session=session, session_id=session["session_id"])

        _run(_run_analyze(ctx, "example.com", recon_result))

        assert len(session["findings"]) == 1
    finally:
        TOOL_REGISTRY[index] = original_spec
