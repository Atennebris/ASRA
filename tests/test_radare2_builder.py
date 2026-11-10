"""parse_radare2_output's truncation note must never suggest a fix that doesn't exist, and (Phase
9) a truncated list must be genuinely retrievable via paging, not just honestly reported as lost.

Real, confirmed incident (NinthCircle-crackmes-usr_04a301): the old note said "narrow the analysis
(e.g. a more specific address) for the rest" for EVERY truncated list, but strings/symbols/imports/
exports/functions take no address parameter at all (build_radare2_command silently ignores one if
sent), so a model trying to follow that advice just reran the identical, still-truncated command --
and xrefs_to's address is already a required single target, not an optional narrowing knob, so the
advice was never actually actionable for any of the six commands that can land here.
"""
import json
import os

from agent.tools.builders.radare2 import (
    _MAX_LIST_ENTRIES,
    _read_warm_cache,
    _warm_cache_path,
    _write_warm_cache,
    build_radare2_command,
    parse_radare2_output,
)


def test_truncation_note_never_suggests_narrowing_by_address():
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
    entries = [{"name": "str_0"}]
    parsed = parse_radare2_output(json.dumps(entries))

    assert parsed == {"result": entries}
    assert "note" not in parsed


def test_non_json_output_falls_back_to_raw_text():
    parsed = parse_radare2_output("ERROR: r2ghidra not installed\n")
    assert parsed == {"raw_output": "ERROR: r2ghidra not installed"}


def test_first_page_reports_next_offset_and_a_full_dump_path():
    entries = [{"name": f"fn_{i}"} for i in range(_MAX_LIST_ENTRIES + 10)]
    parsed = parse_radare2_output(json.dumps(entries))

    assert parsed["offset"] == 0
    assert parsed["next_offset"] == _MAX_LIST_ENTRIES
    assert parsed["result"] == entries[:_MAX_LIST_ENTRIES]
    assert parsed["full_dump_path"]
    with open(parsed["full_dump_path"], encoding="utf-8") as f:
        dumped = json.load(f)
    assert dumped == entries  # the full, untruncated list, not just the first page


def test_second_page_picks_up_where_the_first_left_off():
    entries = [{"name": f"fn_{i}"} for i in range(_MAX_LIST_ENTRIES + 10)]
    parsed = parse_radare2_output(json.dumps(entries), {"offset": _MAX_LIST_ENTRIES})

    assert parsed["offset"] == _MAX_LIST_ENTRIES
    assert parsed["next_offset"] is None  # only 10 entries left after the first 50 -- last page
    assert parsed["result"] == entries[_MAX_LIST_ENTRIES:]
    assert "full_dump_path" not in parsed  # only written once, on the first page


def test_offset_past_the_end_comes_back_empty_with_an_honest_note():
    entries = [{"name": f"fn_{i}"} for i in range(_MAX_LIST_ENTRIES + 10)]
    parsed = parse_radare2_output(json.dumps(entries), {"offset": 9999})

    assert parsed["result"] == []
    assert parsed["total_entries"] == len(entries)
    assert "past the end" in parsed["note"]


def test_malformed_offset_degrades_to_the_first_page_instead_of_raising():
    entries = [{"name": f"fn_{i}"} for i in range(_MAX_LIST_ENTRIES + 10)]

    parsed = parse_radare2_output(json.dumps(entries), {"offset": "not-a-number"})
    assert parsed["offset"] == 0

    parsed_negative = parse_radare2_output(json.dumps(entries), {"offset": -5})
    assert parsed_negative["offset"] == 0


# --- Warm cache (11.2) -------------------------------------------------------------------------
# Real, confirmed-live finding this whole design is built around: radare2's own `Ps`/`P` project
# save/reopen reproducibly SEGFAULTS the process on this project's actual installed radare2 6.2.1
# (3/3 crashes) -- so none of this caching ever touches r2's native project mechanism at all. It
# only ever substitutes a cheap single-function `af @ <address>` for the expensive whole-binary
# `aaa`, backed by our own on-disk name->address map, with a strict "never guess" fallback to the
# existing, unmodified, always-correct full-`aaa` cold path whenever that map doesn't have what's
# needed. See the long design-history comment above _ALLOWED_ANALYSIS_COMMANDS in radare2.py.

_SAMPLE_FUNCTIONS = [
    {"addr": 4494, "name": "main"},
    {"addr": 4425, "name": "dbg.helper_add"},
]


def _make_target(tmp_path, name="target.bin"):
    target = tmp_path / name
    target.write_bytes(b"\x7fELF" + b"\0" * 60)
    return target


def test_write_then_read_warm_cache_round_trips_on_an_unchanged_file(tmp_path):
    target = _make_target(tmp_path)
    _write_warm_cache(str(target), _SAMPLE_FUNCTIONS)

    cache = _read_warm_cache(str(target))
    assert cache is not None
    assert cache["names"]["main"] == hex(4494)
    assert cache["names"]["dbg.helper_add"] == hex(4425)


def test_read_warm_cache_misses_when_no_prime_ever_happened(tmp_path):
    target = _make_target(tmp_path)
    assert _read_warm_cache(str(target)) is None


def test_read_warm_cache_misses_once_the_file_is_touched_after_priming(tmp_path):
    target = _make_target(tmp_path)
    _write_warm_cache(str(target), _SAMPLE_FUNCTIONS)
    assert _read_warm_cache(str(target)) is not None

    # A real edit changes mtime -- the same staleness contract radare2_result_cache_key already
    # uses elsewhere in this file, deliberately kept consistent.
    new_mtime = os.path.getmtime(str(target)) + 5
    os.utime(str(target), (new_mtime, new_mtime))
    assert _read_warm_cache(str(target)) is None


def test_read_warm_cache_tolerates_corrupt_json_without_raising(tmp_path):
    target = _make_target(tmp_path)
    _write_warm_cache(str(target), _SAMPLE_FUNCTIONS)
    _warm_cache_path(str(target)).write_text("{not valid json", encoding="utf-8")

    assert _read_warm_cache(str(target)) is None


def test_write_warm_cache_never_persists_an_empty_or_malformed_prime(tmp_path):
    target = _make_target(tmp_path)
    _write_warm_cache(str(target), [])
    assert not _warm_cache_path(str(target)).exists()

    _write_warm_cache(str(target), [{"addr": "not-an-int", "name": "main"}])
    assert not _warm_cache_path(str(target)).exists()


def test_warm_cache_env_var_kill_switch_disables_reads_and_writes(tmp_path, monkeypatch):
    monkeypatch.setenv("RADARE2_WARM_PROJECT_CACHE", "false")
    target = _make_target(tmp_path)

    _write_warm_cache(str(target), _SAMPLE_FUNCTIONS)
    assert not _warm_cache_path(str(target)).exists()
    assert _read_warm_cache(str(target)) is None


def test_decompile_function_is_always_cold_aaa_when_no_cache_exists(tmp_path):
    target = _make_target(tmp_path)
    command = build_radare2_command({"file_path": str(target), "analysis": "decompile_function", "address": "main"})

    r2_cmd = command[command.index("-c") + 1]
    assert r2_cmd.startswith("aaa; ")
    assert "pdgj @ main" in r2_cmd
    assert "__ASRA_R2_WARM_PRIME__" in r2_cmd  # primes the cache for next time
    assert "aflj" in r2_cmd


def test_disassemble_function_resolves_a_cached_name_to_its_warm_narrow_path(tmp_path):
    target = _make_target(tmp_path)
    _write_warm_cache(str(target), _SAMPLE_FUNCTIONS)

    command = build_radare2_command({"file_path": str(target), "analysis": "disassemble_function", "address": "main"})
    r2_cmd = command[command.index("-c") + 1]

    assert "aaa" not in r2_cmd.split(";")[0]  # no whole-binary analysis at all
    assert r2_cmd.startswith(f"af @ {hex(4494)}")
    # "main" is the one address this call's own `af` actually just defined -- rename it for real.
    assert "afn main @ 0x118e" in r2_cmd  # 4494 == 0x118e
    # "dbg.helper_add" was never `af`'d this call (see the regression this fixes, in
    # build_radare2_command's own comment) -- a bare label (`f`), never `afn` (which r2 refuses
    # with "Cannot find function at <addr>" for an address nothing has analyzed yet).
    assert "f dbg.helper_add @ 0x1149" in r2_cmd  # 4425 == 0x1149
    assert "afn dbg.helper_add @ 0x1149" not in r2_cmd
    assert f"pdfj @ {hex(4494)}" in r2_cmd  # the model's own "main" translated to a real address


def test_unrecognized_name_forces_the_cold_path_even_with_a_warm_cache_present(tmp_path):
    target = _make_target(tmp_path)
    _write_warm_cache(str(target), _SAMPLE_FUNCTIONS)

    # "typo_name" is NOT one of the cached names -- never guess, never let an unresolved name reach
    # a narrow single-function analysis (the exact failure mode this design exists to avoid).
    command = build_radare2_command({"file_path": str(target), "analysis": "decompile_function", "address": "typo_name"})
    r2_cmd = command[command.index("-c") + 1]

    assert r2_cmd.startswith("aaa; ")
    assert "pdgj @ typo_name" in r2_cmd


def test_a_raw_numeric_address_uses_the_warm_narrow_path_when_a_cache_exists(tmp_path):
    target = _make_target(tmp_path)
    _write_warm_cache(str(target), _SAMPLE_FUNCTIONS)

    command = build_radare2_command({"file_path": str(target), "analysis": "disassemble_function", "address": "0x1192"})
    r2_cmd = command[command.index("-c") + 1]

    assert r2_cmd.startswith("af @ 0x1192")
    assert "pdfj @ 0x1192" in r2_cmd


def test_a_raw_numeric_address_stays_cold_without_any_cache(tmp_path):
    target = _make_target(tmp_path)
    command = build_radare2_command({"file_path": str(target), "analysis": "disassemble_function", "address": "0x1192"})
    r2_cmd = command[command.index("-c") + 1]

    assert r2_cmd.startswith("aaa; ")
    assert "pdfj @ 0x1192" in r2_cmd


def test_env_var_disabled_keeps_decompile_function_fully_cold_with_no_sentinel(tmp_path, monkeypatch):
    monkeypatch.setenv("RADARE2_WARM_PROJECT_CACHE", "false")
    target = _make_target(tmp_path)
    _write_warm_cache(str(target), _SAMPLE_FUNCTIONS)  # no-ops under the kill switch, see test above

    command = build_radare2_command({"file_path": str(target), "analysis": "decompile_function", "address": "main"})
    r2_cmd = command[command.index("-c") + 1]

    assert r2_cmd == "aaa; e r2ghidra.pdg=true; pdgj @ main"  # byte-identical to this feature not existing


def test_functions_and_xrefs_to_are_never_touched_by_the_warm_path(tmp_path):
    target = _make_target(tmp_path)
    _write_warm_cache(str(target), _SAMPLE_FUNCTIONS)

    functions_cmd = build_radare2_command({"file_path": str(target), "analysis": "functions"})[3]
    assert functions_cmd == "aaa; aflj"

    xrefs_cmd = build_radare2_command({"file_path": str(target), "analysis": "xrefs_to", "address": "main"})[3]
    assert xrefs_cmd == "aaa; axtj @ main"


def test_parser_splits_the_priming_sentinel_and_writes_the_warm_cache(tmp_path):
    target = _make_target(tmp_path)
    real_result = {"code": "int main() {}", "annotations": []}
    priming = _SAMPLE_FUNCTIONS
    stdout = f"{json.dumps(real_result)}\n__ASRA_R2_WARM_PRIME__\n{json.dumps(priming)}\n"

    parsed = parse_radare2_output(stdout, {"file_path": str(target), "analysis": "decompile_function"})

    assert parsed == {"result": real_result}  # the model sees ONLY the real answer
    cache = _read_warm_cache(str(target))
    assert cache is not None
    assert cache["names"]["main"] == hex(4494)


def test_parser_discards_a_priming_tail_that_fails_to_parse_without_caching_garbage(tmp_path):
    target = _make_target(tmp_path)
    real_result = {"code": "int main() {}", "annotations": []}
    stdout = f"{json.dumps(real_result)}\n__ASRA_R2_WARM_PRIME__\nnot valid json at all\n"

    parsed = parse_radare2_output(stdout, {"file_path": str(target), "analysis": "decompile_function"})

    assert parsed == {"result": real_result}
    assert _read_warm_cache(str(target)) is None


def test_parser_without_a_sentinel_is_completely_unaffected(tmp_path):
    target = _make_target(tmp_path)
    parsed = parse_radare2_output('{"code": "x"}', {"file_path": str(target), "analysis": "disassemble_function"})

    assert parsed == {"result": {"code": "x"}}
    assert _read_warm_cache(str(target)) is None
