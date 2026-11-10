"""static/css/themes.css -- elements that carry a Tailwind display class (`flex`, `block`, ...) AND
get the `hidden` attribute toggled by settings/JS never actually hide: Tailwind's author-origin
`.flex{display:flex}` beats the browser's user-agent `[hidden]{display:none}`. Each such element
needs its own `[hidden]` rule in the author origin. The sidebar clock row hit this: Settings ->
Customization's "Show clock" switch set `hidden` on it and the clock stayed on screen.
"""
import re
from pathlib import Path

THEMES_CSS = Path(__file__).resolve().parent.parent / "static" / "css" / "themes.css"
BASE_HTML = Path(__file__).resolve().parent.parent / "templates" / "base.html"


def test_sidebar_clock_row_and_time_line_hide_when_hidden_attribute_is_set():
    css = THEMES_CSS.read_text(encoding="utf-8")
    rule = re.search(r"((?:#asra-clock-[a-z]+\[hidden\],?\s*)+)\{[^}]*display:\s*none\s*!important", css)

    assert rule, "no display:none !important rule for the hidden clock elements"
    assert "#asra-clock-row[hidden]" in rule.group(1)
    assert "#asra-clock-line[hidden]" in rule.group(1)


def test_sidebar_clock_row_still_uses_a_display_class():
    # If the row ever stops carrying `flex`, the override above is merely redundant, not wrong --
    # but this documents why it exists: the two together are the bug.
    html = BASE_HTML.read_text(encoding="utf-8")
    row_tag = re.search(r'<a id="asra-clock-row"[^>]*>', html, re.S).group(0)

    assert "flex" in row_tag and "hidden" in row_tag
