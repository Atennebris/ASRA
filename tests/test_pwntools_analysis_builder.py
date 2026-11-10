"""agent/tools/builders/pwntools_analysis.py -- pwntools' own crash/exploit-primitive analysis
(cyclic pattern generation/offset-finding, core dump parsing), wrapped as a pure-Python tier-1
native tool with no subprocess/external binary at all.

cyclic_pattern/cyclic_offset are tested against the REAL pwntools functions (pure, fast,
deterministic -- no reason to mock them, same reasoning real pure-function tests elsewhere in this
project use). parse_corefile is tested against a MOCKED Corefile -- a real core dump needs a real
gcc+gdb crash-and-dump round trip, confirmed to work live during this phase's own self-check, but
too slow/environment-dependent for the committed test suite itself.
"""
from __future__ import annotations

import pytest

import agent.tools.builders.pwntools_analysis as pwntools_analysis_module
from agent.tools.builders.pwntools_analysis import run_pwntools_analysis


# --- mode validation ------------------------------------------------------------------------------


def test_unknown_mode_rejected():
    with pytest.raises(ValueError, match="Unknown pwntools_analysis mode"):
        run_pwntools_analysis({"mode": "explode"})


# --- cyclic_pattern (real pwntools, no mocking needed) ---------------------------------------------


def test_cyclic_pattern_default_length():
    result = run_pwntools_analysis({"mode": "cyclic_pattern"})
    assert result["status"] == "ok"
    assert result["length"] == 200
    assert len(result["pattern"]) == 200
    assert result["pattern"].isascii()


def test_cyclic_pattern_custom_length():
    result = run_pwntools_analysis({"mode": "cyclic_pattern", "length": 44})
    assert len(result["pattern"]) == 44


def test_cyclic_pattern_rejects_too_short():
    with pytest.raises(ValueError, match="length"):
        run_pwntools_analysis({"mode": "cyclic_pattern", "length": 1})


def test_cyclic_pattern_rejects_too_long():
    with pytest.raises(ValueError, match="length"):
        run_pwntools_analysis({"mode": "cyclic_pattern", "length": 10_000_000})


def test_cyclic_pattern_rejects_non_integer_length():
    with pytest.raises(ValueError, match="length"):
        run_pwntools_analysis({"mode": "cyclic_pattern", "length": "not-a-number"})


# --- cyclic_offset (real pwntools) -----------------------------------------------------------------


def test_cyclic_offset_finds_a_value_from_the_default_pattern():
    # Generated and independently confirmed live: the 4-byte value at offset 44 of pwntools' own
    # default-alphabet cyclic sequence is 0x6161616c ("laaa", little-endian).
    result = run_pwntools_analysis({"mode": "cyclic_offset", "value": "0x6161616c"})
    assert result["status"] == "ok"
    assert result["found"] is True
    assert result["offset"] == 44


def test_cyclic_offset_accepts_a_bare_hex_string_without_0x_prefix():
    result = run_pwntools_analysis({"mode": "cyclic_offset", "value": "6161616c"})
    assert result["offset"] == 44


def test_cyclic_offset_accepts_a_plain_decimal_value():
    result = run_pwntools_analysis({"mode": "cyclic_offset", "value": str(0x6161616c)})
    assert result["offset"] == 44


def test_cyclic_offset_not_found_is_still_status_ok_not_an_error():
    """A value that never occurs in the sequence is a real, useful negative answer -- not a tool
    failure (the call itself worked fine; it's the caller's own value that doesn't match)."""
    result = run_pwntools_analysis({"mode": "cyclic_offset", "value": "0xdeadbeef"})
    assert result["status"] == "ok"
    assert result["found"] is False
    assert "note" in result


def test_cyclic_offset_respects_explicit_n_for_8_byte_values():
    pattern = pwntools_analysis_module.cyclic(200, n=8)
    value = int.from_bytes(pattern[40:48], "little")
    result = run_pwntools_analysis({"mode": "cyclic_offset", "value": hex(value), "n": 8})
    assert result["found"] is True
    assert result["offset"] == 40


def test_cyclic_offset_rejects_an_empty_value():
    with pytest.raises(ValueError, match="value"):
        run_pwntools_analysis({"mode": "cyclic_offset", "value": ""})


# --- parse_corefile (mocked Corefile) ---------------------------------------------------------------
#
# A real file with a genuine ELF magic header must exist on disk for every one of these -- the
# early magic-byte check (added alongside the per-field hardening below) deliberately runs BEFORE
# Corefile is ever called, even a mocked one, so every test here needs a real (if otherwise fake)
# ELF-shaped file at its own file_path, not just a bare string.


def _make_elf_stub(tmp_path, name="core", content=b"\x7fELF" + b"\x00" * 60):
    path = tmp_path / name
    path.write_bytes(content)
    return str(path)


class _FakeExe:
    path = "/tmp/crashbin"


class _FakeCorefile:
    def __init__(self, path):
        self.path_arg = path
        self.pc = 0x55555555516E
        self.sp = 0x7FFFFFFFDF78
        self.fault_addr = 0x6161616C6161616B
        self.signal = 11
        self.pid = 450
        self.exe = _FakeExe()

    def read(self, addr, size):
        return b"A" * size


def test_parse_corefile_requires_file_path():
    with pytest.raises(ValueError, match="file_path"):
        run_pwntools_analysis({"mode": "parse_corefile"})


def test_parse_corefile_returns_structured_crash_facts(tmp_path, monkeypatch):
    monkeypatch.setattr(pwntools_analysis_module, "Corefile", _FakeCorefile)
    core_path = _make_elf_stub(tmp_path)

    result = run_pwntools_analysis({"mode": "parse_corefile", "file_path": core_path})

    assert result["status"] == "ok"
    assert result["observed"]["signal_name"] == "SIGSEGV"
    assert result["observed"]["pc"] == "0x55555555516e"
    assert result["observed"]["fault_address"] == "0x6161616c6161616b"
    assert result["observed"]["executable"] == "/tmp/crashbin"
    assert result["observed"]["stack_dump_hex"] == ("41" * 256)
    assert result["_evidence"]["method"] == "dynamic"
    assert result["_evidence"]["untrusted_content"] is True
    assert result["unknown"] == {}


def test_parse_corefile_rejects_a_missing_file():
    result = run_pwntools_analysis({"mode": "parse_corefile", "file_path": "/does/not/exist/core"})
    assert result["status"] == "error"
    assert "could not open" in result["error"]


def test_parse_corefile_rejects_a_file_with_no_elf_magic_before_ever_calling_corefile(tmp_path, monkeypatch):
    """The early, cheap check -- confirmed live this session that pwntools' own Corefile already
    handles this safely too, but a specific, fast message beats whatever exception type it
    happens to raise for "this isn't ELF at all"."""
    called = {"value": False}
    monkeypatch.setattr(pwntools_analysis_module, "Corefile", lambda path: called.__setitem__("value", True))
    not_a_core = _make_elf_stub(tmp_path, content=b"not an elf file at all")

    result = run_pwntools_analysis({"mode": "parse_corefile", "file_path": not_a_core})

    assert result["status"] == "error"
    assert "does not start with a valid ELF core header" in result["error"]
    assert called["value"] is False


def test_parse_corefile_rejects_an_empty_file(tmp_path, monkeypatch):
    monkeypatch.setattr(pwntools_analysis_module, "Corefile", _FakeCorefile)
    empty = _make_elf_stub(tmp_path, content=b"")

    result = run_pwntools_analysis({"mode": "parse_corefile", "file_path": empty})

    assert result["status"] == "error"
    assert "does not start with a valid ELF core header" in result["error"]


def test_parse_corefile_handles_a_file_corefile_itself_cannot_parse(tmp_path, monkeypatch):
    def _raise(path):
        raise ValueError("not a real core dump")

    monkeypatch.setattr(pwntools_analysis_module, "Corefile", _raise)
    core_path = _make_elf_stub(tmp_path)

    result = run_pwntools_analysis({"mode": "parse_corefile", "file_path": core_path})

    assert result["status"] == "error"
    assert "not a real core dump" in result["error"]


def test_parse_corefile_notes_an_unreadable_stack_instead_of_crashing(tmp_path, monkeypatch):
    class _UnreadableStackCorefile(_FakeCorefile):
        def read(self, addr, size):
            raise Exception("unmapped memory")

    monkeypatch.setattr(pwntools_analysis_module, "Corefile", _UnreadableStackCorefile)
    core_path = _make_elf_stub(tmp_path)

    result = run_pwntools_analysis({"mode": "parse_corefile", "file_path": core_path})

    assert result["status"] == "ok"
    assert "stack_dump_hex" not in result["observed"]
    assert "stack_dump_hex" in result["unknown"]


def test_parse_corefile_one_bad_field_does_not_lose_the_others(tmp_path, monkeypatch):
    """The real, confirmed-live gap this closes: a malformed-enough core can make Corefile's own
    construction succeed while some fields silently misbehave -- one bad field must degrade to
    its own `unknown` entry without losing every OTHER field that genuinely did read fine."""
    class _OnePoisonedField(_FakeCorefile):
        @property
        def fault_addr(self):
            raise RuntimeError("corrupted NT_SIGINFO descriptor")

        @fault_addr.setter
        def fault_addr(self, value):
            pass  # the inherited __init__ assigns this -- discard it, only the getter above matters

    monkeypatch.setattr(pwntools_analysis_module, "Corefile", _OnePoisonedField)
    core_path = _make_elf_stub(tmp_path)

    result = run_pwntools_analysis({"mode": "parse_corefile", "file_path": core_path})

    assert result["status"] == "ok"
    assert "fault_address" not in result["observed"]
    assert "corrupted NT_SIGINFO descriptor" in result["unknown"]["fault_address"]
    # Every OTHER field still came through fine.
    assert result["observed"]["pc"] == "0x55555555516e"
    assert result["observed"]["signal_name"] == "SIGSEGV"


def test_parse_corefile_all_fields_none_is_not_a_crash(tmp_path, monkeypatch):
    """Confirmed live this session: a forged, absurdly large program-header count was enough to
    make pwntools' own Corefile construction succeed while EVERY field came back None -- this
    must degrade to clean, absent-from-observed fields (and no stack dump attempted at all, since
    there's no real sp to read from), never an uncaught exception."""
    class _AllNoneCorefile:
        def __init__(self, path):
            self.pc = None
            self.sp = None
            self.fault_addr = None
            self.signal = None
            self.exe = None
            self.pid = None

        def read(self, addr, size):
            raise AssertionError("must never be called when sp is None")

    monkeypatch.setattr(pwntools_analysis_module, "Corefile", _AllNoneCorefile)
    core_path = _make_elf_stub(tmp_path)

    result = run_pwntools_analysis({"mode": "parse_corefile", "file_path": core_path})

    assert result["status"] == "ok"
    assert result["observed"]["pc"] is None
    assert result["observed"]["sp"] is None
    assert "stack_dump_hex" not in result["observed"]
    assert "stack_dump_hex" in result["unknown"]
