"""agent/tools/tool_inventory.py: the one real "list every registered tool + is it actually
installed right now" function -- feeds both the Tools settings tab and the Subagents tab's tool
checklist. Reuses agent/tools/runner.py's tool_is_installed (the SAME live check _run_subprocess
itself consults), not a hardcoded list or a second, separately-drifting guess.
"""
from agent.tools.registry import ToolSpec
from agent.tools.tool_inventory import list_installed_tool_names, list_tool_availability


def test_list_tool_availability_covers_the_real_registry():
    import agent.tools  # noqa: F401  (side effect: populates TOOL_REGISTRY)
    from agent.tools.registry import TOOL_REGISTRY

    entries = list_tool_availability()
    assert len(entries) == len(TOOL_REGISTRY)
    assert {e["name"] for e in entries} == {spec.name for spec in TOOL_REGISTRY}


def test_list_tool_availability_is_sorted_by_name():
    entries = list_tool_availability()
    assert [e["name"] for e in entries] == sorted(e["name"] for e in entries)


def test_a_tier1_native_tool_is_always_reported_installed(monkeypatch):
    import agent.tools.tool_inventory as inv

    fake_spec = ToolSpec(
        name="fake_native_tool", category="scan", tool_tier=1, executable="",
        build_command=None, requires_allowed_target=False, installed_by_default=True,
        native_function=lambda params: {"status": "ok"},
    )
    monkeypatch.setattr(inv, "TOOL_REGISTRY", [fake_spec])

    entries = list_tool_availability()
    assert entries == [{"name": "fake_native_tool", "categories": ("scan",), "tier": 1, "installed": True, "description": "", "checks_dependency": False}]


def test_a_tier2_tool_reports_installed_false_when_its_real_binary_is_missing(monkeypatch):
    import agent.tools.tool_inventory as inv

    fake_spec = ToolSpec(
        name="definitely_not_a_real_binary_xyz", category="scan", tool_tier=2,
        executable="definitely_not_a_real_binary_xyz", build_command=lambda p: [],
        requires_allowed_target=False, installed_by_default=True,
    )
    monkeypatch.setattr(inv, "TOOL_REGISTRY", [fake_spec])

    entries = list_tool_availability()
    assert entries[0]["installed"] is False


def test_a_tier2_tool_reports_installed_true_when_its_real_binary_is_on_path(monkeypatch):
    import agent.tools.tool_inventory as inv

    fake_spec = ToolSpec(
        name="python3_as_a_fake_tool", category="scan", tool_tier=2,
        executable="python3", build_command=lambda p: [],
        requires_allowed_target=False, installed_by_default=True,
    )
    monkeypatch.setattr(inv, "TOOL_REGISTRY", [fake_spec])

    entries = list_tool_availability()
    assert entries[0]["installed"] is True


def test_list_installed_tool_names_only_returns_installed_ones(monkeypatch):
    import agent.tools.tool_inventory as inv

    installed_spec = ToolSpec(
        name="python3_as_a_fake_tool", category="scan", tool_tier=2,
        executable="python3", build_command=lambda p: [], requires_allowed_target=False, installed_by_default=True,
    )
    missing_spec = ToolSpec(
        name="definitely_not_a_real_binary_xyz", category="scan", tool_tier=2,
        executable="definitely_not_a_real_binary_xyz", build_command=lambda p: [],
        requires_allowed_target=False, installed_by_default=True,
    )
    monkeypatch.setattr(inv, "TOOL_REGISTRY", [installed_spec, missing_spec])

    assert list_installed_tool_names() == ["python3_as_a_fake_tool"]


def test_tool_categories_are_always_a_tuple_even_for_a_single_category_spec():
    entries = list_tool_availability()
    assert all(isinstance(e["categories"], tuple) for e in entries)


def test_a_hardcoded_tool_surfaces_its_real_llm_facing_description():
    """Every hardcoded tool in agent/tools/__init__.py sets ToolSpec.description to a real
    one-liner -- the Subagents tab's tool checklist (subagents.html) surfaces this as a hover
    tooltip, so it must actually come through list_tool_availability(), not just live unused on
    the spec."""
    import agent.tools  # noqa: F401  (side effect: populates TOOL_REGISTRY)

    entries = {e["name"]: e for e in list_tool_availability()}
    assert entries["nmap"]["description"]
    assert "port scan" in entries["nmap"]["description"].lower()


def test_availability_check_overrides_the_tier1_always_installed_default(monkeypatch):
    """A tier_tier=1 (native) tool is normally always reported installed -- true for ordinary
    native tools, but the browser_* tools' real dependency (a Playwright-managed Chromium
    download) can genuinely be missing even though the Python code always imports fine.
    ToolSpec.availability_check exists precisely to make that difference visible instead of a
    guaranteed false-positive."""
    import agent.tools.tool_inventory as inv

    not_installed_spec = ToolSpec(
        name="fake_browser_tool", category="scan", tool_tier=1, executable="",
        build_command=None, requires_allowed_target=False, installed_by_default=True,
        native_function=lambda params: {"status": "ok"}, availability_check=lambda: False,
    )
    monkeypatch.setattr(inv, "TOOL_REGISTRY", [not_installed_spec])

    entries = list_tool_availability()
    assert entries[0]["installed"] is False


def test_availability_check_true_also_overrides_correctly(monkeypatch):
    import agent.tools.tool_inventory as inv

    installed_spec = ToolSpec(
        name="fake_browser_tool", category="scan", tool_tier=1, executable="",
        build_command=None, requires_allowed_target=False, installed_by_default=True,
        native_function=lambda params: {"status": "ok"}, availability_check=lambda: True,
    )
    monkeypatch.setattr(inv, "TOOL_REGISTRY", [installed_spec])

    entries = list_tool_availability()
    assert entries[0]["installed"] is True


def test_availability_check_none_keeps_the_old_tier1_always_installed_behavior(monkeypatch):
    """Regression guard on the other ~40 existing tier_tier=1 registrations, none of which set
    availability_check -- they must keep reporting installed=True unconditionally, unchanged."""
    import agent.tools.tool_inventory as inv

    ordinary_native_spec = ToolSpec(
        name="ordinary_native_tool", category="scan", tool_tier=1, executable="",
        build_command=None, requires_allowed_target=False, installed_by_default=True,
        native_function=lambda params: {"status": "ok"},
    )
    monkeypatch.setattr(inv, "TOOL_REGISTRY", [ordinary_native_spec])

    entries = list_tool_availability()
    assert entries[0]["installed"] is True


def test_description_falls_back_to_full_description_for_a_discovered_tool(monkeypatch):
    import agent.tools.tool_inventory as inv

    fake_spec = ToolSpec(
        name="discovered_custom_tool", category="scan", tool_tier=2,
        executable="python3", build_command=lambda p: [], requires_allowed_target=False,
        installed_by_default=True, full_description="Hand-written summary for a tool with no --help.",
    )
    monkeypatch.setattr(inv, "TOOL_REGISTRY", [fake_spec])

    entries = list_tool_availability()
    assert entries[0]["description"] == "Hand-written summary for a tool with no --help."
