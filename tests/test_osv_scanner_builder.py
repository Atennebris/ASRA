"""build_osv_scanner_command / parse_osv_scanner_output -- SCA over a source tree's dependency
lockfiles against the OSV database. Sample JSON below mirrors osv-scanner's own documented
--format json schema (results[].source.path, results[].packages[].package{name,version,ecosystem},
packages[].vulnerabilities[]{id,summary}).
"""
import agent.tools  # noqa: F401  (side effect: populates TOOL_REGISTRY)
from agent.tools.builders.osv_scanner import build_osv_scanner_command, parse_osv_scanner_output
from agent.tools.registry import get_tool

_REAL_SHAPED_HIT_OUTPUT = """{
  "results": [
    {
      "source": {"path": "package-lock.json", "type": "lockfile"},
      "packages": [
        {
          "package": {"name": "lodash", "version": "4.17.15", "ecosystem": "npm"},
          "vulnerabilities": [
            {"id": "GHSA-p6mc-m468-83gw", "summary": "Prototype Pollution in lodash"},
            {"id": "GHSA-29mw-wpgm-hmr9", "summary": "Command Injection in lodash"}
          ]
        }
      ]
    }
  ]
}"""

_CLEAN_OUTPUT = '{"results": []}'


def test_build_command_shape():
    command = build_osv_scanner_command({"path": "/repo/checkout"})
    assert command == ["osv-scanner", "scan", "source", "--format", "json", "/repo/checkout"]


def test_build_command_strips_whitespace_from_path():
    command = build_osv_scanner_command({"path": "  /repo/checkout  "})
    assert command[-1] == "/repo/checkout"


def test_parse_real_shaped_hit_output_extracts_every_vulnerability_per_package():
    parsed = parse_osv_scanner_output(_REAL_SHAPED_HIT_OUTPUT)
    assert parsed == {
        "findings": [
            {
                "source": "package-lock.json", "package": "lodash", "version": "4.17.15",
                "ecosystem": "npm", "id": "GHSA-p6mc-m468-83gw", "summary": "Prototype Pollution in lodash",
            },
            {
                "source": "package-lock.json", "package": "lodash", "version": "4.17.15",
                "ecosystem": "npm", "id": "GHSA-29mw-wpgm-hmr9", "summary": "Command Injection in lodash",
            },
        ]
    }


def test_parse_clean_output_returns_empty_findings_not_an_error():
    assert parse_osv_scanner_output(_CLEAN_OUTPUT) == {"findings": []}


def test_parse_non_json_output_falls_back_to_raw_text():
    parsed = parse_osv_scanner_output("osv-scanner: no lockfiles found\n")
    assert parsed == {"raw_output": "osv-scanner: no lockfiles found"}


def test_the_registered_osv_scanner_tool_has_the_expected_shape():
    spec = get_tool("osv_scanner")
    assert spec.category == "re"
    assert spec.executable == "osv-scanner"
    assert spec.requires_allowed_target is False
    assert spec.build_command is build_osv_scanner_command
    # scan-with-real-findings is a normal, expected exit -- not a broken tool call.
    assert spec.ok_exit_codes == frozenset({0, 1})
