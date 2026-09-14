"""Unit tests for agent/tools/toolkit_comparer.py -- diff_lines' own line/char-level opcodes, and
diff_entries' entry-lookup + text-building + error handling. Never drives a real server/browser --
diff_entries is exercised against toolkit_store entries seeded directly, same "mocked at the
store boundary" convention already used by tests/test_toolkit_routes.py.
"""
from agent.tools import toolkit_comparer, toolkit_store


def test_diff_lines_all_equal_when_texts_are_identical():
    rows = toolkit_comparer.diff_lines("a\nb\nc", "a\nb\nc")
    assert all(row["tag"] == "equal" for row in rows)
    assert [row["left_text"] for row in rows] == ["a", "b", "c"]
    assert [row["right_text"] for row in rows] == ["a", "b", "c"]


def test_diff_lines_detects_a_pure_insertion():
    rows = toolkit_comparer.diff_lines("a\nc", "a\nb\nc")
    tags = [row["tag"] for row in rows]
    assert "insert" in tags
    inserted = next(row for row in rows if row["tag"] == "insert")
    assert inserted["left_text"] is None
    assert inserted["right_text"] == "b"


def test_diff_lines_detects_a_pure_deletion():
    rows = toolkit_comparer.diff_lines("a\nb\nc", "a\nc")
    deleted = next(row for row in rows if row["tag"] == "delete")
    assert deleted["left_text"] == "b"
    assert deleted["right_text"] is None


def test_diff_lines_replace_row_carries_char_level_spans():
    rows = toolkit_comparer.diff_lines("token=abc123", "token=abc999")
    replace_rows = [row for row in rows if row["tag"] == "replace"]
    assert len(replace_rows) == 1
    row = replace_rows[0]
    assert row["left_text"] == "token=abc123"
    assert row["right_text"] == "token=abc999"
    # The common prefix "token=abc" must be marked unchanged, and the differing digits changed.
    left_unchanged = "".join(s["text"] for s in row["left_spans"] if not s["changed"])
    right_unchanged = "".join(s["text"] for s in row["right_spans"] if not s["changed"])
    assert left_unchanged == right_unchanged == "token=abc"
    left_changed = "".join(s["text"] for s in row["left_spans"] if s["changed"])
    right_changed = "".join(s["text"] for s in row["right_spans"] if s["changed"])
    assert left_changed == "123"
    assert right_changed == "999"


def test_diff_lines_uneven_replace_falls_back_to_delete_and_insert_for_the_leftover():
    rows = toolkit_comparer.diff_lines("only-line", "line-one\nline-two\nline-three")
    tags = [row["tag"] for row in rows]
    assert tags.count("replace") == 1
    assert tags.count("insert") == 2


def _seed_entry(session_id, **overrides):
    entry = toolkit_store.build_traffic_entry(
        session_id=session_id, method="GET", url="https://example.com/",
        request_headers={"Host": "example.com"}, request_body="",
        response_status=200, response_headers={"Content-Type": "text/plain"}, response_body="hello",
    )
    entry.update(overrides)
    toolkit_store.append_traffic_entry(entry)
    return entry


def test_diff_entries_returns_error_for_unknown_scheme_part():
    result = toolkit_comparer.diff_entries(session_id="usr_x", entry_id_a="a", entry_id_b="b", part="cookies")
    assert result == {"status": "error", "error": "Unknown part: cookies"}


def test_diff_entries_returns_error_when_an_entry_is_missing(tmp_path, monkeypatch):
    import projects.paths as project_paths
    from sessions import store as session_store

    monkeypatch.setattr(session_store, "SESSIONS_DIR", tmp_path / "legacy")
    monkeypatch.setattr(session_store, "INDEX_PATH", tmp_path / "sessions_index.json")
    monkeypatch.setattr(session_store, "SUMMARY_INDEX_PATH", tmp_path / "sessions_summary.json")
    monkeypatch.setenv("PROJECTS_DIR", str(tmp_path / "projects"))
    project_paths.resolve_projects_base_dir.cache_clear()

    session_id = session_store.create_session("https://example.com")
    entry = _seed_entry(session_id)

    result = toolkit_comparer.diff_entries(session_id=session_id, entry_id_a=entry["id"], entry_id_b="missing", part="response")
    assert result["status"] == "error"
    assert "not found" in result["error"]


def test_diff_entries_diffs_two_responses_end_to_end(tmp_path, monkeypatch):
    import projects.paths as project_paths
    from sessions import store as session_store

    monkeypatch.setattr(session_store, "SESSIONS_DIR", tmp_path / "legacy")
    monkeypatch.setattr(session_store, "INDEX_PATH", tmp_path / "sessions_index.json")
    monkeypatch.setattr(session_store, "SUMMARY_INDEX_PATH", tmp_path / "sessions_summary.json")
    monkeypatch.setenv("PROJECTS_DIR", str(tmp_path / "projects"))
    project_paths.resolve_projects_base_dir.cache_clear()

    session_id = session_store.create_session("https://example.com")
    entry_a = _seed_entry(session_id, response_body="hello world")
    entry_b = _seed_entry(session_id, response_body="hello there")

    result = toolkit_comparer.diff_entries(session_id=session_id, entry_id_a=entry_a["id"], entry_id_b=entry_b["id"], part="response")
    assert result["status"] == "ok"
    body_row = next(row for row in result["rows"] if row.get("left_text") == "hello world" or row.get("right_text") == "hello there")
    assert body_row["tag"] == "replace"


def test_diff_entries_never_diffs_a_binary_body_as_raw_text(tmp_path, monkeypatch):
    import projects.paths as project_paths
    from sessions import store as session_store

    monkeypatch.setattr(session_store, "SESSIONS_DIR", tmp_path / "legacy")
    monkeypatch.setattr(session_store, "INDEX_PATH", tmp_path / "sessions_index.json")
    monkeypatch.setattr(session_store, "SUMMARY_INDEX_PATH", tmp_path / "sessions_summary.json")
    monkeypatch.setenv("PROJECTS_DIR", str(tmp_path / "projects"))
    project_paths.resolve_projects_base_dir.cache_clear()

    session_id = session_store.create_session("https://example.com")
    entry_a = _seed_entry(
        session_id, response_body="c29tZWJpbmFyeQ==", response_body_encoding="base64", response_content_length=9,
        response_headers={"Content-Type": "image/png"},
    )
    entry_b = _seed_entry(session_id)

    result = toolkit_comparer.diff_entries(session_id=session_id, entry_id_a=entry_a["id"], entry_id_b=entry_b["id"], part="response")
    assert result["status"] == "ok"
    joined_left = "\n".join(row["left_text"] for row in result["rows"] if row["left_text"] is not None)
    assert "c29tZWJpbmFyeQ==" not in joined_left
    assert "binary content" in joined_left
