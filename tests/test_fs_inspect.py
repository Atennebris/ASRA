"""Read-only RE filesystem tools (agent/tools/builders/fs_inspect.py): list_dir / read_file / grep.
These exist because the RE chat/triage agent had no way to look at a tool's on-disk output (a
jadx-decompiled tree) and kept hallucinating `ls`/`bash`/`cat` tools that don't exist.
"""
from agent.tools.builders.fs_inspect import run_grep, run_list_dir, run_read_file
from agent.tools.registry import categories_of, get_tool


def test_list_dir_reports_entries_with_types(tmp_path):
    (tmp_path / "sub").mkdir()
    (tmp_path / "MainActivity.java").write_text("class MainActivity {}")
    (tmp_path / "app.dll").write_bytes(b"MZ\x00\x00")
    result = run_list_dir({"path": str(tmp_path)})

    assert result["status"] == "ok"
    by_name = {e["name"]: e for e in result["entries"]}
    assert by_name["sub"]["is_dir"] is True
    assert by_name["MainActivity.java"]["type"] == "source code"
    assert by_name["app.dll"]["type"] == "Windows DLL"


def test_list_dir_on_a_file_errors(tmp_path):
    f = tmp_path / "x.txt"
    f.write_text("hi")
    assert run_list_dir({"path": str(f)})["status"] == "error"


def test_read_file_returns_text_and_bounds(tmp_path):
    f = tmp_path / "Login.java"
    f.write_text("\n".join(f"line {i}" for i in range(1, 51)))
    result = run_read_file({"path": str(f), "start_line": 10, "max_lines": 5})

    assert result["status"] == "ok"
    assert result["start_line"] == 10
    assert result["end_line"] == 14
    assert result["total_lines"] == 50
    assert "line 10" in result["content"] and "line 14" in result["content"]
    assert "line 15" not in result["content"]
    assert result["truncated"] is True


def test_read_file_refuses_a_binary(tmp_path):
    f = tmp_path / "crackme.dll"
    f.write_bytes(b"MZ\x00\x00" + b"\x00" * 100)
    result = run_read_file({"path": str(f)})
    assert result["status"] == "error"
    assert "binary" in result["error"].lower()


def test_grep_finds_matches_across_a_tree(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "Check.java").write_text("if (isValidLicense(key)) {\n  grant();\n}")
    (tmp_path / "Readme.txt").write_text("nothing here")
    result = run_grep({"pattern": r"valid|licen", "path": str(tmp_path)})

    assert result["status"] == "ok"
    assert result["match_count"] == 1
    m = result["matches"][0]
    assert m["file"].endswith("Check.java")
    assert m["line_no"] == 1


def test_grep_case_sensitive_flag(tmp_path):
    (tmp_path / "f.java").write_text("VALID\nvalid")
    sensitive = run_grep({"pattern": "VALID", "path": str(tmp_path), "case_sensitive": True})
    assert sensitive["match_count"] == 1
    insensitive = run_grep({"pattern": "VALID", "path": str(tmp_path)})
    assert insensitive["match_count"] == 2


def test_grep_invalid_regex_errors(tmp_path):
    assert run_grep({"pattern": "(", "path": str(tmp_path)})["status"] == "error"


def test_the_three_tools_are_registered_for_every_mode():
    # Read-only inspection is useful far beyond RE -- it must reach the web/agentic phases too, or
    # the main pipeline has no `ls`/`grep`/read_file and flails exactly like the RE agent used to.
    for name in ("list_dir", "read_file", "grep"):
        spec = get_tool(name)
        assert spec is not None, f"{name} not registered"
        cats = set(categories_of(spec))
        assert {"re", "recon", "scan", "exploit", "post_exploit"} <= cats
        assert spec.native_function is not None
