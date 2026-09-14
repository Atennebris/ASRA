"""build_command() and output parser for binwalk -- firmware/embedded-image analysis for RE mode:
identifies and extracts embedded filesystems/compressed data/known file signatures inside a binary
blob (a firmware dump, a bootloader, an update package). Real gap this closes: nothing else in the
arsenal looks INSIDE a file for other, smaller files packed within it -- radare2/gdb analyze one
executable's own code, this looks for what's hidden alongside/inside it.

Installed via apt (setup_tools.sh's install_binwalk), not pip -- confirmed live: PyPI's own
"binwalk" package (2.1.0) is genuinely broken (missing its own binwalk.core submodule), a known
packaging gap in the upstream project.
"""
from __future__ import annotations

import re

from agent.tools.builders.validators import validate_safe_value

_VALID_MODES = {"scan", "extract"}

# binwalk's own plain-text table: "<decimal>   <hex>   <description>", header + dashes above it,
# confirmed against a real run -- no --json/--log-to-structured-format option exists in this
# version, so this is the only way to get anything other than raw_output back to the model.
_ROW_RE = re.compile(r"^(\d+)\s+(0x[0-9A-Fa-f]+)\s+(.+)$")


def build_binwalk_command(params: dict) -> list[str]:
    file_path = validate_safe_value(str(params["file_path"]).strip())
    mode = params.get("mode", "scan")
    if mode not in _VALID_MODES:
        raise ValueError(f"Unknown binwalk mode={mode!r} -- must be one of {sorted(_VALID_MODES)}")
    if mode == "extract":
        # Extracts into <file>.extracted next to the input, same "own subdirectory, never the
        # current working directory" convention apktool.py/jadx.py's own output-dir helpers use.
        output_dir = f"{file_path}.extracted"
        return ["binwalk", "-e", "-M", "-C", output_dir, file_path]
    return ["binwalk", "-B", file_path]


_MAX_SIGNATURES = 100


def parse_binwalk_output(stdout: str) -> dict:
    signatures = []
    for line in stdout.splitlines():
        match = _ROW_RE.match(line.strip())
        if match:
            signatures.append({"offset_decimal": int(match.group(1)), "offset_hex": match.group(2), "description": match.group(3).strip()})
    if not signatures:
        return {"raw_output": stdout.strip()}
    if len(signatures) > _MAX_SIGNATURES:
        return {
            "signatures": signatures[:_MAX_SIGNATURES],
            "total_signatures": len(signatures),
            "note": f"{len(signatures)} signatures found, showing the first {_MAX_SIGNATURES}.",
        }
    return {"signatures": signatures}
