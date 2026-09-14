"""build_command() and output parser for jadx -- decompiles an Android APK/DEX/JAR into readable
Java source (unlike apktool's own smali disassembly, this is genuine higher-level source, much
easier to actually read/audit) into a real directory tree the model can then read through or point
semgrep at. Same "preparation step, not a finding-producing scanner itself" role as apktool.py --
the two are complementary, not redundant: apktool for resources/manifest/smali, jadx for readable
decompiled source."""
from __future__ import annotations

from pathlib import Path

from agent.tools.builders.validators import validate_safe_value


def _jadx_output_dir(apk_path: str) -> str:
    p = Path(apk_path)
    return str(p.parent / f"{p.stem}_jadx")


def build_jadx_command(params: dict) -> list[str]:
    apk_path = validate_safe_value(str(params["file_path"]).strip())
    output_dir = _jadx_output_dir(apk_path)
    return ["jadx", "-d", output_dir, apk_path]


def parse_jadx_output(stdout: str) -> dict:
    return {"raw_output": stdout.strip()}
