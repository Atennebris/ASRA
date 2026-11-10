"""static/css/themes.css -- the header-light "children win paint order" rule.

That rule gives every plain child of a title bar position:relative + z-index:1 so the lamp can never
cover a real button. At normal specificity it ALSO overrode `.asra-mascot { position: absolute }`:
the mascot became an in-flow flex item, the bar's justify-between spread title | "live" badge |
mascot apart, and the badge jumped to the middle of the session header. A CSS cascade bug has no
runtime to unit-test, so this pins the one property that prevents it: the rule must carry zero
specificity (wrapped in :where) so an element's own explicit position always wins.
"""
import re
from pathlib import Path

THEMES_CSS = Path(__file__).resolve().parent.parent / "static" / "css" / "themes.css"
CHILD_RULE = re.compile(r"^(?P<selector>[^{}]*\.header-light-fixture\)\s*>\s*\*[^{}]*)\{(?P<body>[^}]*)\}", re.M)


def _child_rule() -> re.Match:
    matches = [m for m in CHILD_RULE.finditer(THEMES_CSS.read_text(encoding="utf-8"))
               if "position: relative" in m.group("body")]
    assert len(matches) == 1, "expected exactly one header-light children paint-order rule"
    return matches[0]


def test_header_light_child_rule_has_zero_specificity():
    # The match can begin inside the explanatory comment above the rule; only the text after it is
    # the selector.
    selector = _child_rule().group("selector").rsplit("*/", 1)[-1].strip()

    assert selector.startswith(":where(") and selector.endswith(")"), (
        "wrap the selector in :where() -- at normal specificity it overrides .asra-mascot's "
        "position:absolute and breaks the session header layout"
    )


def test_header_light_child_rule_still_lifts_plain_children():
    body = _child_rule().group("body")

    assert "position: relative" in body and "z-index: 1" in body


def test_mascot_stays_absolutely_positioned():
    css = THEMES_CSS.read_text(encoding="utf-8")

    assert re.search(r"\.asra-mascot\s*\{[^}]*position:\s*absolute", css)
