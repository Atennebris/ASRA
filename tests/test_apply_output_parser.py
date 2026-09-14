"""agent/core.py's _apply_output_parser: two real, confirmed gaps found during a log-review audit.

1. A successfully parsed tool result kept its full, raw stdout in the dict ALONGSIDE the new
   "parsed" field -- for a tool whose raw stdout can run to hundreds of KB (ffuf against a large
   wordlist), the later json.dumps(result)[:_TOOL_RESULT_CHAR_LIMIT] truncation cut the whole
   result off inside that raw dump, so "parsed" never survived into what the model or session.json
   actually saw. Confirmed live (again-tests-usr_73fe2f): two real ffuf scans, both logged as a
   raw, truncated wordlist dump with zero status/length/path info.
2. WhatWeb can hit its own internal per-URL timeout mid-scan and still exit 0 -- confirmed live
   (test-2-again2-usr_2f4db1): stderr carried "ERROR Opening: ... - execution expired" while
   status stayed "ok", reading as a clean, information-free "nothing detected" result.
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
