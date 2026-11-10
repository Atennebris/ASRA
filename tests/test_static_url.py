"""agent/utils/static_url.py -- mtime-based ?v= for the app's own css/js, replacing hand-bumped
numbers. The regression this exists for: an edited themes.css kept its old ?v=N, so the desktop
webview served its cached copy and a real fix looked like it had not been applied.
"""
import os
import re
from pathlib import Path

from agent.utils.static_url import make_static_url

TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"


def _write(path: Path, text: str, mtime: float) -> None:
    path.write_text(text)
    os.utime(path, (mtime, mtime))


def test_version_is_the_files_own_modification_time(tmp_path):
    (tmp_path / "css").mkdir()
    _write(tmp_path / "css" / "a.css", "a", mtime=1_700_000_000)
    static_url = make_static_url(tmp_path, cache_seconds=0)

    assert static_url("/static/css/a.css") == "/static/css/a.css?v=1700000000000"


def test_editing_a_file_changes_its_url(tmp_path):
    _write(tmp_path / "a.js", "1", mtime=1_700_000_000)
    static_url = make_static_url(tmp_path, cache_seconds=0)
    before = static_url("/static/a.js")

    _write(tmp_path / "a.js", "2", mtime=1_700_000_500)

    assert static_url("/static/a.js") != before


def test_result_is_remembered_within_the_window_then_refreshed(tmp_path):
    now = [100.0]
    _write(tmp_path / "a.js", "1", mtime=1_700_000_000)
    static_url = make_static_url(tmp_path, cache_seconds=10, clock=lambda: now[0])
    first = static_url("/static/a.js")

    _write(tmp_path / "a.js", "2", mtime=1_700_000_500)
    now[0] = 105.0
    assert static_url("/static/a.js") == first  # still inside the window: no stat

    now[0] = 111.0
    assert static_url("/static/a.js") != first  # window over: the edit is picked up


def test_missing_file_is_served_unversioned_instead_of_raising(tmp_path):
    static_url = make_static_url(tmp_path, cache_seconds=0)

    assert static_url("/static/js/nope.js") == "/static/js/nope.js"


def test_templates_never_hardcode_a_version_number_on_css_or_js():
    # A literal ?v=N is the bug itself: nothing forces it to be bumped when the file changes.
    offenders = []
    for template in TEMPLATES_DIR.rglob("*.html"):
        text = template.read_text(encoding="utf-8")
        for match in re.finditer(r"""(?:src|href)=["'](/static/(?:css|js|vendor)/[^"']*\?v=\d+)""", text):
            offenders.append(f"{template.name}: {match.group(1)}")

    assert not offenders, offenders
