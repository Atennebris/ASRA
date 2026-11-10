"""agent/tools/custom_tools_store.py: the operator-registered "(custom)" tool registry backing
Settings -> Tools -> Custom tools."""
from agent.tools import custom_tools_store as cts


def _isolate(tmp_path, monkeypatch):
    monkeypatch.setattr(cts, "CUSTOM_TOOLS_STORE_PATH", tmp_path / "custom_tools.json")


def test_load_returns_empty_list_when_file_is_missing(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    assert cts.load_custom_tools() == []


def test_load_treats_corrupt_json_as_empty(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    cts.CUSTOM_TOOLS_STORE_PATH.write_text("{not valid json")
    assert cts.load_custom_tools() == []


def test_load_treats_a_non_list_json_as_empty(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    cts.CUSTOM_TOOLS_STORE_PATH.write_text("{}")
    assert cts.load_custom_tools() == []


def test_add_custom_tool_persists_a_real_record(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    record = cts.add_custom_tool(name="mytool", path="/opt/tools/mytool", description="does a thing", requires_target=True, category="recon")

    assert record["name"] == "mytool"
    assert record["enabled"] is True  # the Add click itself is the explicit confirmation
    loaded = cts.load_custom_tools()
    assert len(loaded) == 1
    assert loaded[0]["id"] == record["id"]


def test_add_custom_tool_rejects_a_duplicate_name(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    cts.add_custom_tool(name="mytool", path="/opt/a/mytool", description="", requires_target=True, category="recon")

    try:
        cts.add_custom_tool(name="mytool", path="/opt/b/mytool", description="", requires_target=True, category="scan")
        assert False, "expected a ValueError for the duplicate name"
    except ValueError as exc:
        assert "already registered" in str(exc)
    assert len(cts.load_custom_tools()) == 1


def test_add_custom_tool_rejects_an_unknown_category(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    try:
        cts.add_custom_tool(name="mytool", path="/opt/a/mytool", description="", requires_target=True, category="not-a-real-category")
        assert False, "expected a ValueError"
    except ValueError as exc:
        assert "category" in str(exc)


def test_post_exploit_is_not_a_choosable_category():
    """Real, confirmed gap this guards against: nothing in agent/core.py/agent/chat.py ever
    queries get_tools_by_category("post_exploit") directly -- a custom tool registered under that
    bare category would be silently unreachable from every phase/subagent forever."""
    assert "post_exploit" not in cts.CUSTOM_TOOL_CATEGORIES


def test_set_custom_tool_enabled_toggles_and_persists(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    record = cts.add_custom_tool(name="mytool", path="/opt/a/mytool", description="", requires_target=True, category="recon")

    cts.set_custom_tool_enabled(record["id"], False)
    assert cts.get_custom_tool(record["id"])["enabled"] is False

    cts.set_custom_tool_enabled(record["id"], True)
    assert cts.get_custom_tool(record["id"])["enabled"] is True


def test_set_custom_tool_enabled_returns_none_for_an_unknown_id(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    assert cts.set_custom_tool_enabled("not-a-real-id", True) is None


def test_update_custom_tool_changes_only_the_given_fields(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    record = cts.add_custom_tool(name="mytool", path="/opt/a/mytool", description="old", requires_target=True, category="recon")

    cts.update_custom_tool(record["id"], description="new description")

    updated = cts.get_custom_tool(record["id"])
    assert updated["description"] == "new description"
    assert updated["requires_target"] is True  # untouched
    assert updated["category"] == "recon"  # untouched


def test_update_custom_tool_rejects_an_unknown_category(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    record = cts.add_custom_tool(name="mytool", path="/opt/a/mytool", description="", requires_target=True, category="recon")
    try:
        cts.update_custom_tool(record["id"], category="not-a-real-category")
        assert False, "expected a ValueError"
    except ValueError:
        pass


def test_remove_custom_tool(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    record = cts.add_custom_tool(name="mytool", path="/opt/a/mytool", description="", requires_target=True, category="recon")

    assert cts.remove_custom_tool(record["id"]) is True
    assert cts.load_custom_tools() == []
    assert cts.remove_custom_tool(record["id"]) is False  # already gone


def test_registered_custom_tool_paths_includes_disabled_entries(tmp_path, monkeypatch):
    """Discovery (custom_tools_root.py) uses this to stop re-offering an already-added path --
    must still exclude a DISABLED one too, not just enabled ones (re-offering something the
    operator deliberately turned off would be confusing, not helpful)."""
    _isolate(tmp_path, monkeypatch)
    record = cts.add_custom_tool(name="mytool", path="/opt/a/mytool", description="", requires_target=True, category="recon")
    cts.set_custom_tool_enabled(record["id"], False)

    assert "/opt/a/mytool" in cts.registered_custom_tool_paths()
