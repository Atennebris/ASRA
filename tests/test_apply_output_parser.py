"""agent/core.py's _apply_output_parser: real, confirmed gaps found during log-review audits.

1. A successfully parsed tool result kept its full, raw stdout in the dict ALONGSIDE the new
   "parsed" field -- for a tool whose raw stdout can run to hundreds of KB (ffuf against a large
   wordlist), the later json.dumps(result)[:_TOOL_RESULT_CHAR_LIMIT] truncation cut the whole
   result off inside that raw dump, so "parsed" never survived into what the model or session.json
   actually saw. Confirmed live (again-tests-usr_73fe2f): two real ffuf scans, both logged as a
   raw, truncated wordlist dump with zero status/length/path info.
2. WhatWeb can hit its own internal per-URL timeout mid-scan and still exit 0 -- confirmed live
   (test-2-again2-usr_2f4db1): stderr carried "ERROR Opening: ... - execution expired" while
   status stayed "ok", reading as a clean, information-free "nothing detected" result.
3. qiling_emulate's own wrapper subprocess always exits 0 even on a real internal failure (missing
   rootfs, a Windows PE target with no real DLLs, qiling not importable), so a run that never
   actually emulated anything came back {"status": "ok", ...} -- confirmed live
   (Supratest_RE_a-usr_ff40fb): a real crackme session's qiling_emulate call reported a plain
   successful tool call (green dot in the chat UI) for a Qiling loader failure the model only
   noticed by reading the raw JSON text itself.
"""
import json

import agent.tools  # noqa: F401  (side effect: populates TOOL_REGISTRY)
from agent.core import _TOOL_RESULT_CHAR_LIMIT, _apply_output_parser
from agent.tools.registry import get_tool


def test_apply_output_parser_caps_raw_stdout_so_parsed_survives_truncation():
    spec = get_tool("ffuf")
    huge_stdout = "candidateword\n" * 4000  # ~56KB, comfortably bigger than _TOOL_RESULT_CHAR_LIMIT
    raw_result = {"status": "ok", "stdout": huge_stdout, "stderr": ""}

    result = _apply_output_parser(spec, raw_result)

    assert "parsed" in result
    assert len(result["stdout"]) < 2100
    # The real downstream truncation point (agent/core.py's message-append/_log_output) -- "parsed"
    # must actually survive it, not just exist in the pre-truncation dict.
    assert len(json.dumps(result)) < _TOOL_RESULT_CHAR_LIMIT
    assert "parsed" in json.dumps(result)[:_TOOL_RESULT_CHAR_LIMIT]


def test_apply_output_parser_leaves_small_stdout_untouched():
    spec = get_tool("ffuf")
    raw_result = {"status": "ok", "stdout": "short output", "stderr": ""}

    result = _apply_output_parser(spec, raw_result)

    assert result["stdout"] == "short output"


def test_apply_output_parser_flags_whatweb_that_hit_its_own_internal_timeout():
    spec = get_tool("whatweb")
    raw_result = {
        "status": "ok", "exit_code": 0,
        "stdout": "", "stderr": "ERROR Opening: http://slow.example.com - execution expired",
    }

    result = _apply_output_parser(spec, raw_result)

    assert result["status"] == "ok"  # still a real completion, not downgraded
    assert "note" in result
    assert "timeout" in result["note"].lower()


def test_apply_output_parser_does_not_flag_a_clean_whatweb_result():
    spec = get_tool("whatweb")
    raw_result = {"status": "ok", "exit_code": 0, "stdout": "https://example.com [200] Apache[2.4]", "stderr": ""}

    result = _apply_output_parser(spec, raw_result)

    assert "note" not in result


def test_apply_output_parser_downgrades_a_qiling_run_that_only_failed_inside_its_own_payload():
    spec = get_tool("qiling_emulate")
    payload = json.dumps({"status": "error", "error": "Qiling failed to load the target: QlErrorFileNotFound: ..."})
    raw_result = {"status": "ok", "exit_code": 0, "stdout": f"===QILING_RESULT===\n{payload}", "stderr": ""}

    result = _apply_output_parser(spec, raw_result)

    assert result["status"] == "failed"
    assert "Qiling failed to load the target" in result["error"]
    assert result["parsed"]["status"] == "error"  # the raw payload is still there to inspect


def test_apply_output_parser_leaves_a_genuinely_successful_qiling_run_as_ok():
    spec = get_tool("qiling_emulate")
    payload = json.dumps({"status": "ok", "os": "WINDOWS", "instructions_executed": 42})
    raw_result = {"status": "ok", "exit_code": 0, "stdout": f"===QILING_RESULT===\n{payload}", "stderr": ""}

    result = _apply_output_parser(spec, raw_result)

    assert result["status"] == "ok"
    assert "error" not in result
