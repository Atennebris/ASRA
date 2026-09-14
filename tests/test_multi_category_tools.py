"""ToolSpec.category can be a tuple, not just a single Category -- for a read-only verification
tool genuinely useful in more than one phase's toolset (agent/tools/registry.py's categories_of).
Real incident this exists because of: exploit-phase turns that stalled on "I have no HTTP request
tool to verify X" when the identical tool already existed one phase over (agent/tools/__init__.py's
_ALSO_EXPLOIT_CATEGORY).
"""
import agent.tools  # noqa: F401  (side effect: populates TOOL_REGISTRY)
from agent.tools.registry import categories_of, get_tool, get_tools_by_category
from agent.tools.runner import _timeout_for


def test_http_request_is_registered_in_both_scan_and_exploit():
    spec = get_tool("http_request")
    assert categories_of(spec) == ("scan", "exploit")


def test_get_tools_by_category_finds_a_multi_category_tool_from_either_category():
    scan_names = {s.name for s in get_tools_by_category("scan")}
    exploit_names = {s.name for s in get_tools_by_category("exploit")}
    for name in ("http_request", "oob_generate", "oob_poll", "tcp_port_check"):
        assert name in scan_names, f"{name} must still be reachable from Analyze"
        assert name in exploit_names, f"{name} must now also be reachable from Exploit"


def test_a_single_category_tool_is_unaffected_by_the_tuple_support():
    """Regression guard: nmap (a plain, single-category tool) must not accidentally start
    matching every category just because categories_of() now normalizes to a tuple internally.
    """
    spec = get_tool("nmap")
    assert categories_of(spec) == ("recon",)
    assert spec.name in {s.name for s in get_tools_by_category("recon")}
    assert spec.name not in {s.name for s in get_tools_by_category("exploit")}


def test_multi_category_tool_still_gets_the_exploit_timeout_when_used_from_exploit(monkeypatch):
    """A tool shared with Analyze must not silently fall back to the shorter general-purpose
    timeout just because its "home" category (the first one, "scan") isn't exploit-class."""
    monkeypatch.setenv("EXPLOIT_TIMEOUT_SECONDS", "999")
    spec = get_tool("http_request")
    assert _timeout_for(spec) == 999
