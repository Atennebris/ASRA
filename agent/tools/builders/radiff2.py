"""build_command() and output parser for radiff2 -- radare2's own binary-diffing tool (already
installed alongside radare2 itself, no separate package). Real reverse-engineering use case this
covers that nothing else in the arsenal does: n-day analysis (diff a patched binary against the
pre-patch version to find what a vendor's advisory doesn't spell out) and version/variant
comparison (is this sample a known family, just repacked?) -- neither radare2.py's own single-file
analysis commands nor any other RE tool here compares two files against each other at all.
"""
from __future__ import annotations

import json
import re

from agent.tools.builders.validators import validate_safe_value

_VALID_MODES = {"similarity", "changes"}

# radiff2's own "similarity: 0.847" / "distance: 123" plain-text output (mode="similarity", -s -V).
_SIMILARITY_RE = re.compile(r"similarity:\s*([\d.]+)")
_DISTANCE_RE = re.compile(r"distance:\s*(\d+)")


def build_radiff2_command(params: dict) -> list[str]:
    file_a = validate_safe_value(str(params["file_a"]).strip())
    file_b = validate_safe_value(str(params["file_b"]).strip())
    mode = params.get("mode", "similarity")
    if mode not in _VALID_MODES:
        raise ValueError(f"Unknown radiff2 mode={mode!r} -- must be one of {sorted(_VALID_MODES)}")
    if mode == "similarity":
        # -V (verbose) is what actually prints the similarity/distance lines -s alone computes but
        # doesn't display on its own -- confirmed against a real run, -s with no -V produces no
        # output at all.
        return ["radiff2", "-s", "-V", file_a, file_b]
    return ["radiff2", "-j", file_a, file_b]


# Same reasoning as agent/tools/builders/radare2.py's own _MAX_LIST_ENTRIES: two genuinely
# different binaries (not just a small patch) can produce thousands of byte-level "changes"
# entries -- capped at the entry level with an honest total-count note, not left to the generic
# char-limit truncation to cut it off mid-structure.
_MAX_CHANGES_ENTRIES = 50


def parse_radiff2_output(stdout: str) -> dict:
    stripped = stdout.strip()
    sim_match = _SIMILARITY_RE.search(stripped)
    if sim_match:
        dist_match = _DISTANCE_RE.search(stripped)
        return {
            "similarity": float(sim_match.group(1)),
            "distance": int(dist_match.group(1)) if dist_match else None,
        }
    try:
        parsed = json.loads(stripped)
    except (json.JSONDecodeError, ValueError):
        return {"raw_output": stripped}

    changes = parsed.get("changes") if isinstance(parsed, dict) else None
    if isinstance(changes, list) and len(changes) > _MAX_CHANGES_ENTRIES:
        parsed = {**parsed, "changes": changes[:_MAX_CHANGES_ENTRIES]}
        return {
            "result": parsed,
            "total_changes": len(changes),
            "note": f"{len(changes)} byte-level changes found, showing the first {_MAX_CHANGES_ENTRIES} -- these are two genuinely different files, not a small patch, if the count is this high.",
        }
    return {"result": parsed}
