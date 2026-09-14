"""parse_radare2_output's truncation note must never suggest a fix that doesn't exist. Real,
confirmed incident (NinthCircle-crackmes-usr_04a301): the old note said "narrow the analysis (e.g.
a more specific address) for the rest" for EVERY truncated list, but strings/symbols/imports/
exports/functions take no address parameter at all (build_radare2_command silently ignores one if
sent), so a model trying to follow that advice just reran the identical, still-truncated command --
and xrefs_to's address is already a required single target, not an optional narrowing knob, so the
advice was never actually actionable for any of the six commands that can land here.
"""
from agent.tools.builders.radare2 import _MAX_LIST_ENTRIES, parse_radare2_output


def test_truncation_note_never_suggests_narrowing_by_address():
    import json

    entries = [{"name": f"str_{i}"} for i in range(_MAX_LIST_ENTRIES + 10)]
    parsed = parse_radare2_output(json.dumps(entries))

    assert parsed["total_entries"] == len(entries)
    assert len(parsed["result"]) == _MAX_LIST_ENTRIES
    # The old wording ("narrow the analysis, e.g. a more specific address") was actively wrong --
    # none of the six commands that can land here (strings/symbols/imports/exports/functions have
    # no address parameter at all; xrefs_to's address is already a required single target, not an
    # optional narrowing knob) can actually be narrowed via address.
    assert "address" not in parsed["note"]


def test_short_list_is_returned_whole_with_no_note():
    import json

    entries = [{"name": "str_0"}]
    parsed = parse_radare2_output(json.dumps(entries))

    assert parsed == {"result": entries}
    assert "note" not in parsed


def test_non_json_output_falls_back_to_raw_text():
    parsed = parse_radare2_output("ERROR: r2ghidra not installed\n")
    assert parsed == {"raw_output": "ERROR: r2ghidra not installed"}
