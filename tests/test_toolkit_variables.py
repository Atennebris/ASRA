"""agent/tools/toolkit_variables.py -- {{name}} variables for the manual Repeater/Intruder/Racer
forms."""
import pytest

from agent.tools import toolkit_variables


@pytest.fixture(autouse=True)
def _isolated_storage(tmp_path, monkeypatch):
    monkeypatch.setattr(toolkit_variables, "get_session_folder", lambda session_id: str(tmp_path))


def test_load_variables_empty_when_nothing_saved():
    assert toolkit_variables.load_variables("sess_1") == {}


def test_set_and_load_variable_round_trip():
    toolkit_variables.set_variable("sess_1", "token", "abc123")
    assert toolkit_variables.load_variables("sess_1") == {"token": "abc123"}


def test_set_variable_overwrites_existing():
    toolkit_variables.set_variable("sess_1", "token", "first")
    toolkit_variables.set_variable("sess_1", "token", "second")
    assert toolkit_variables.load_variables("sess_1") == {"token": "second"}


def test_set_variable_trims_name_whitespace():
    toolkit_variables.set_variable("sess_1", "  token  ", "abc")
    assert toolkit_variables.load_variables("sess_1") == {"token": "abc"}


def test_set_variable_blank_name_is_a_no_op():
    result = toolkit_variables.set_variable("sess_1", "   ", "abc")
    assert result == {}
    assert toolkit_variables.load_variables("sess_1") == {}


def test_delete_variable_removes_only_the_named_one():
    toolkit_variables.set_variable("sess_1", "a", "1")
    toolkit_variables.set_variable("sess_1", "b", "2")
    toolkit_variables.delete_variable("sess_1", "a")
    assert toolkit_variables.load_variables("sess_1") == {"b": "2"}


def test_delete_variable_unknown_name_is_a_no_op():
    toolkit_variables.set_variable("sess_1", "a", "1")
    result = toolkit_variables.delete_variable("sess_1", "nonexistent")
    assert result == {"a": "1"}


def test_load_variables_no_project_folder_returns_empty(monkeypatch):
    monkeypatch.setattr(toolkit_variables, "get_session_folder", lambda session_id: None)
    assert toolkit_variables.load_variables("sess_missing") == {}


def test_load_variables_corrupt_file_treated_as_empty(tmp_path, monkeypatch):
    monkeypatch.setattr(toolkit_variables, "get_session_folder", lambda session_id: str(tmp_path))
    variables_dir = tmp_path / "toolkit"
    variables_dir.mkdir()
    (variables_dir / "variables.json").write_text("not valid json", encoding="utf-8")
    assert toolkit_variables.load_variables("sess_1") == {}


# --- substitute -----------------------------------------------------------------------------


def test_substitute_replaces_known_placeholder():
    assert toolkit_variables.substitute("Cookie: session={{token}}", {"token": "abc123"}) == "Cookie: session=abc123"


def test_substitute_leaves_unknown_placeholder_literal():
    assert toolkit_variables.substitute("Cookie: session={{missing}}", {"token": "abc"}) == "Cookie: session={{missing}}"


def test_substitute_replaces_multiple_placeholders():
    text = "{{a}}-{{b}}-{{a}}"
    assert toolkit_variables.substitute(text, {"a": "1", "b": "2"}) == "1-2-1"


def test_substitute_no_placeholders_returns_text_unchanged():
    assert toolkit_variables.substitute("plain text", {"token": "abc"}) == "plain text"


def test_substitute_empty_text():
    assert toolkit_variables.substitute("", {"token": "abc"}) == ""
