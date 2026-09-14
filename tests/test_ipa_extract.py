"""ipa_extract: unpacks a local .ipa (a plain ZIP under the hood) and reports the embedded app's
real Info.plist metadata + main executable path -- iOS's mobile-RE preparation step, mirroring
apktool/jadx for Android. Exercised here against REAL .ipa-shaped zip fixtures built in tmp_path
(plistlib.dump for a real binary plist, zipfile for a real archive) -- nothing mocked, since
extraction/plist-parsing needs no external binary or network access at all.
"""
import plistlib
import zipfile
from pathlib import Path

import agent.tools  # noqa: F401  (side effect: populates TOOL_REGISTRY)
from agent.tools import native
from agent.tools.registry import get_tools_by_category


def _build_fake_ipa(path: Path, *, executable_name: str = "TestApp", include_executable: bool = True, plist_bytes: bytes | None = None) -> Path:
    info_plist = plist_bytes if plist_bytes is not None else plistlib.dumps({
        "CFBundleIdentifier": "com.example.testapp",
        "CFBundleName": "TestApp",
        "CFBundleShortVersionString": "1.2.3",
        "CFBundleVersion": "42",
        "CFBundleExecutable": executable_name,
    })
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(f"Payload/{executable_name}.app/Info.plist", info_plist)
        if include_executable:
            # A real Mach-O binary starts with a magic number (0xFEEDFACE/0xFEEDFACF/0xCAFEBABE) --
            # the content itself is never read by ipa_extract (only .is_file() is checked), so any
            # non-empty bytes stand in for "a real executable is here" without needing a genuine one.
            archive.writestr(f"Payload/{executable_name}.app/{executable_name}", b"\xcf\xfa\xed\xfe fake macho bytes")
    return path


def test_extracts_a_real_ipa_and_reports_metadata_and_executable_path(tmp_path):
    ipa_path = _build_fake_ipa(tmp_path / "TestApp.ipa")

    result = native.ipa_extract({"file_path": str(ipa_path)})

    assert result["status"] == "ok"
    assert result["metadata"] == {
        "bundle_id": "com.example.testapp", "bundle_name": "TestApp",
        "version": "1.2.3", "build": "42", "executable_name": "TestApp",
    }
    assert result["executable_path"] == str(Path(result["app_dir"]) / "TestApp")
    assert Path(result["executable_path"]).is_file()
    assert "radare2" in result["note"]


def test_extracts_into_a_sibling_directory_named_after_the_ipa(tmp_path):
    ipa_path = _build_fake_ipa(tmp_path / "TestApp.ipa")
    result = native.ipa_extract({"file_path": str(ipa_path)})
    assert result["app_dir"] == str(tmp_path / "TestApp_ipa" / "Payload" / "TestApp.app")


def test_missing_file_path_is_rejected():
    result = native.ipa_extract({})
    assert result["status"] == "error"
    assert "file_path" in result["error"]


def test_non_existent_file_is_rejected(tmp_path):
    result = native.ipa_extract({"file_path": str(tmp_path / "does_not_exist.ipa")})
    assert result["status"] == "error"
    assert "not found" in result["error"].lower()


def test_a_non_zip_file_is_rejected_cleanly(tmp_path):
    fake = tmp_path / "not_really_an_ipa.ipa"
    fake.write_text("this is not a zip file")
    result = native.ipa_extract({"file_path": str(fake)})
    assert result["status"] == "error"
    assert "zip" in result["error"].lower()


def test_a_zip_with_no_payload_app_directory_is_rejected(tmp_path):
    empty_zip = tmp_path / "empty.ipa"
    with zipfile.ZipFile(empty_zip, "w") as archive:
        archive.writestr("README.txt", "not an app")
    result = native.ipa_extract({"file_path": str(empty_zip)})
    assert result["status"] == "error"
    assert "Payload" in result["error"]


def test_missing_executable_is_reported_without_crashing(tmp_path):
    """CFBundleExecutable names a file that isn't actually in the archive -- a malformed/corrupt
    .ipa, not something that should ever raise."""
    ipa_path = _build_fake_ipa(tmp_path / "Broken.ipa", executable_name="Broken", include_executable=False)
    result = native.ipa_extract({"file_path": str(ipa_path)})
    assert result["status"] == "ok"
    assert result["executable_path"] is None
    assert "Could not determine the main executable" in result["note"]


def test_unparsable_info_plist_is_reported_without_crashing(tmp_path):
    ipa_path = _build_fake_ipa(tmp_path / "BadPlist.ipa", plist_bytes=b"not a real plist at all")
    result = native.ipa_extract({"file_path": str(ipa_path)})
    assert result["status"] == "ok"
    assert "parse_error" in result["metadata"]
    assert result["executable_path"] is None


def test_zip_slip_style_archive_is_rejected(tmp_path):
    """Same zip-slip protection re_target.py's own _safe_extract_zip already gives real archive
    staging -- reused here, not reimplemented, so a malicious .ipa can't write outside the extract
    directory either."""
    malicious = tmp_path / "malicious.ipa"
    with zipfile.ZipFile(malicious, "w") as archive:
        archive.writestr("../../../evil.txt", "escaped")
    result = native.ipa_extract({"file_path": str(malicious)})
    assert result["status"] == "error"


def test_the_registered_ipa_extract_tool_has_the_expected_shape():
    re_tools = {spec.name: spec for spec in get_tools_by_category("re")}
    assert "ipa_extract" in re_tools
    spec = re_tools["ipa_extract"]
    assert spec.tool_tier == 1
    assert spec.native_function is native.ipa_extract
    assert spec.requires_allowed_target is False
