"""build_command() and output parser for apktool -- decompiles an Android APK's resources and
DEX bytecode (into smali, Android's own disassembly format for the ART/Dalvik bytecode) into a
real directory tree the model can then read/grep through (via the chat's own file-reading, or a
follow-up semgrep pass over the extracted sources). A preparation/unpacking step, not a
finding-producing scanner itself -- the RE toolset's mobile-app analog of upx's own "unpack first,
analyze after" role for a packed native binary."""
from __future__ import annotations

from pathlib import Path

from agent.tools.builders.validators import validate_safe_value


def _apktool_output_dir(apk_path: str) -> str:
    p = Path(apk_path)
    return str(p.parent / f"{p.stem}_apktool")


def build_apktool_command(params: dict) -> list[str]:
    apk_path = validate_safe_value(str(params["file_path"]).strip())
    output_dir = _apktool_output_dir(apk_path)
    # -f: force overwrite -- re-running this against the same APK (a second look, a retry after an
    # earlier partial failure) must not fail just because the output directory already exists.
    return ["apktool", "d", apk_path, "-o", output_dir, "-f"]


def parse_apktool_output(stdout: str) -> dict:
    return {"raw_output": stdout.strip()}
