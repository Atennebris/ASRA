"""build_trufflehog_command / parse_trufflehog_output -- secrets scanning, git-history-aware when
the target has a real .git directory. Sample JSONL lines below mirror trufflehog's own documented
--json output shape (one JSON object per line: DetectorName/Verified/Raw/SourceMetadata.Data.
{Filesystem,Git}.file, SourceMetadata.Data.Git.commit).
"""
import agent.tools  # noqa: F401  (side effect: populates TOOL_REGISTRY)
from agent.tools.builders.trufflehog import build_trufflehog_command, parse_trufflehog_output
from agent.tools.registry import get_tool

_REAL_SHAPED_JSONL = (
    '{"DetectorName": "AWS", "Verified": true, "Raw": "AKIAABCDEFGHIJKLMNOP", '
    '"SourceMetadata": {"Data": {"Git": {"file": "config/settings.py", "commit": "a1b2c3d4"}}}}\n'
    '{"DetectorName": "GitHub", "Verified": false, "Raw": "ghp_0123456789abcdefghij", '
    '"SourceMetadata": {"Data": {"Filesystem": {"file": "notes.txt"}}}}\n'
)


def test_build_command_uses_git_mode_for_a_real_git_repo(tmp_path):
    (tmp_path / ".git").mkdir()
    command = build_trufflehog_command({"path": str(tmp_path)})
    assert command == ["trufflehog", "git", f"file://{tmp_path}", "--json"]


def test_build_command_uses_filesystem_mode_for_a_plain_directory(tmp_path):
    command = build_trufflehog_command({"path": str(tmp_path)})
    assert command == ["trufflehog", "filesystem", str(tmp_path), "--json"]


def test_parse_real_shaped_jsonl_extracts_every_line_independently():
    parsed = parse_trufflehog_output(_REAL_SHAPED_JSONL)
    assert parsed == {
        "findings": [
            {
                "detector": "AWS", "verified": True, "raw_secret_preview": "AKIAABCDEFGHIJKLMNOP",
                "file": "config/settings.py", "commit": "a1b2c3d4",
            },
            {
                "detector": "GitHub", "verified": False, "raw_secret_preview": "ghp_0123456789abcdefghij",
                "file": "notes.txt", "commit": None,
            },
        ]
    }


def test_parse_skips_a_malformed_line_instead_of_failing_the_whole_parse():
    stdout = '{"DetectorName": "AWS", "Verified": true, "Raw": "x", "SourceMetadata": {"Data": {}}}\nnot json at all\n'
    parsed = parse_trufflehog_output(stdout)
    assert len(parsed["findings"]) == 1
    assert parsed["findings"][0]["detector"] == "AWS"


def test_parse_empty_output_returns_empty_findings_not_an_error():
    assert parse_trufflehog_output("") == {"findings": []}


def test_parse_skips_a_line_with_no_detector_name():
    # A trufflehog progress/status line, not a real finding -- must not surface as a bogus finding.
    stdout = '{"level": "info", "msg": "finished scanning"}\n'
    assert parse_trufflehog_output(stdout) == {"findings": []}


def test_the_registered_trufflehog_tool_has_the_expected_shape():
    spec = get_tool("trufflehog")
    assert spec.category == "re"
    assert spec.executable == "trufflehog"
    assert spec.requires_allowed_target is False
    assert spec.build_command is build_trufflehog_command
