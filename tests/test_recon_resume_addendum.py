"""A resumed recon phase must tell the model what an earlier, interrupted attempt already found --
otherwise it blindly redoes every crt_sh_lookup/subfinder/subdomain_enum/dns_lookup call the
interrupted attempt already paid for. Real, confirmed incident (midnight-usr_24ba7e): a session was
interrupted before the model ever called record_target (recon can run many steps -- CT/subfinder/
DNS/whois/wayback/shodan -- before the model explicitly "commits" a target), so
recon_result["targets"] was still empty on resume. The old addendum condition only checked that
list, never recon_result["dns_map"] (filled in deterministically by dns_lookup/subdomain_enum
regardless of record_target), so it never fired even though dns_map already held 5+ resolved hosts
-- the resumed run redid every discovery tool call from scratch.
"""
import asyncio

import agent.tools  # noqa: F401  (side effect: populates TOOL_REGISTRY)
from agent.core import RunContext, _run_recon
from agent.llm_client import LLMResponse


def _run(coro):
    return asyncio.run(coro)


class _CapturingLLM:
    """Records every messages list it's called with, then ends the phase immediately -- this test
    only cares what the model was TOLD, not what it does with it."""
    provider_id = "test-provider"
    model = "test-model"

    def __init__(self):
        self.calls: list[list[dict]] = []

    def complete(self, messages, tools=None, stop_check=None):
        self.calls.append(messages)
        return LLMResponse(content="done", tool_calls=[])


def _base_session(**recon_result_extra) -> dict:
    return {
        "session_id": "usr_resume_test", "target": "midnight.im", "status": "processing",
        "logs": [], "findings": [], "approvals": [], "chat": {"summary": "", "messages": []},
        "recon_result": {"targets": [], "cves": [], "dns_map": {}, **recon_result_extra},
    }


def test_resume_addendum_fires_from_dns_map_even_with_no_recorded_targets():
    """The exact real-incident shape: record_target was never called, but dns_lookup/subdomain_enum
    already resolved real hosts this session."""
    session = _base_session(dns_map={"midnight.im": ["5.252.32.97"], "www.midnight.im": ["5.252.32.97"]})
    llm = _CapturingLLM()
    ctx = RunContext(llm=llm, session=session, session_id=session["session_id"])

    _run(_run_recon(ctx, "midnight.im"))

    task_message = llm.calls[0][1]["content"]
    assert "resumed recon phase" in task_message
    assert "midnight.im -> 5.252.32.97" in task_message
    assert "don't repeat crt_sh_lookup/subfinder/subdomain_enum/dns_lookup" in task_message


def test_resume_addendum_still_fires_from_recorded_targets_alone():
    """Regression guard: the pre-existing path (targets recorded via record_target) must keep
    working exactly as before -- this fix only ADDS a second trigger, never removes the first."""
    session = _base_session()
    session["recon_result"]["targets"] = [{"host": "midnight.im", "port": 443}]
    llm = _CapturingLLM()
    ctx = RunContext(llm=llm, session=session, session_id=session["session_id"])

    _run(_run_recon(ctx, "midnight.im"))

    task_message = llm.calls[0][1]["content"]
    assert "resumed recon phase" in task_message
    assert "Recorded targets: midnight.im:443" in task_message


def test_no_resume_addendum_on_a_fresh_recon_phase():
    """Neither targets nor dns_map has anything yet -- a brand-new phase must not be told it's
    "resumed", which would be actively confusing on a first run."""
    session = _base_session()
    llm = _CapturingLLM()
    ctx = RunContext(llm=llm, session=session, session_id=session["session_id"])

    _run(_run_recon(ctx, "midnight.im"))

    task_message = llm.calls[0][1]["content"]
    assert "resumed recon phase" not in task_message
