"""sessions.store._sanitize_folder_name must never produce a confusing on-disk folder name. Real
incident: a project folder ended up literally named "...r-usr_f200a6" because the project name
arrived already ellipsized ("...r") and only dashes were stripped, leaving the leading dots.
"""
from sessions import store


def test_leading_dots_are_stripped():
    assert store._sanitize_folder_name("...r") == "r"


def test_all_dots_does_not_collapse_to_dot():
    # Must never become "." / ".." / "" -- falls back to the placeholder instead.
    assert store._sanitize_folder_name("...") == "target"


def test_interior_dots_are_preserved():
    assert store._sanitize_folder_name("my.tool.v2") == "my.tool.v2"


def test_normal_target_is_unchanged():
    assert store._sanitize_folder_name("example.com") == "example.com"


def test_trailing_dots_and_spaces_stripped():
    assert store._sanitize_folder_name("crackme...  ") == "crackme"
