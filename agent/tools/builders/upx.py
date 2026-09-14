"""build_command() and output parser for upx -- detects whether a binary is UPX-packed (a real,
common first step in binary RE: a packed binary's own real logic is invisible to radare2/gdb until
it's unpacked, everything they'd see otherwise is just the packer's own unwrapping stub) and
unpacks it when it is. Two operations, one tool, picked via params["mode"]:
- "detect" (default): `upx -t <file>` -- tests whether the file is a valid UPX-packed binary,
  without modifying anything.
- "unpack": `upx -d <file> -o <output>` -- decompresses into a new file next to the original
  (never overwrites it), so the ORIGINAL packed binary is always still there to reference too.
"""
from __future__ import annotations

from pathlib import Path

from agent.tools.builders.validators import validate_safe_value

_VALID_MODES = {"detect", "unpack"}


def build_upx_command(params: dict) -> list[str]:
    file_path = validate_safe_value(str(params["file_path"]).strip())
    mode = params.get("mode", "detect")
    if mode not in _VALID_MODES:
        raise ValueError(f"Unknown upx mode={mode!r} -- must be one of {sorted(_VALID_MODES)}")
    if mode == "detect":
        return ["upx", "-t", file_path]
    output_path = str(Path(file_path).with_suffix(Path(file_path).suffix + ".unpacked"))
    return ["upx", "-d", file_path, "-o", output_path]


def parse_upx_output(stdout: str) -> dict:
    """upx's own exit code alone isn't a reliable "is this packed" signal across its different
    real-world failure shapes (confirmed uncertain, not verified against every upx version) --
    the text itself is: "[file]: OK" / a summary line for a genuine UPX file, or a
    "NotPackedException"/"CantPackException"-shaped message for one that isn't. Both are
    reported here as real, structured facts either way, not just a bare pass/fail."""
    lower = stdout.lower()
    looks_packed = "upx" in lower and ("ok" in lower or "unpacked" in lower or "compressed" in lower)
    looks_not_packed = "notpackedexception" in lower or "not packed" in lower or "unknown file format" in lower
    return {"raw_output": stdout.strip(), "appears_upx_packed": looks_packed and not looks_not_packed}


_NOT_PACKED_MARKERS = ("notpackedexception", "not packed", "unknown file format")


def interpret_upx_not_packed(result: dict) -> str | None:
    """upx's own "not packed" signal (the same text markers parse_upx_output already recognizes)
    is a deterministic, argument-independent fact about the FILE, not something a corrected
    retry (a different mode, a different flag) can ever change. Real, confirmed incident this
    fixes (fss-usr_d5b09a): `upx --detect` correctly determined a file wasn't UPX-packed
    (exit_code=2, outside this tool's own ok_exit_codes={0,1} — deliberately not widened further,
    see that registration's own comment on exit-code reliability), but the resulting status="error"
    still triggered a full 1-Step Retry round-trip; the model spent it switching to mode="unpack",
    which failed with the exact same "not packed" signal for the exact same reason — one wasted
    correction cycle and one wasted subprocess dispatch for a fact the first call already settled.
    Checked against BOTH stdout and stderr (upx's real "not packed" message has been observed on
    either depending on version/mode), fires for either "detect" or "unpack" mode alike.
    """
    combined = ((result.get("stdout") or "") + (result.get("stderr") or "")).lower()
    if not any(marker in combined for marker in _NOT_PACKED_MARKERS):
        return None
    return (
        "upx reports this file is not UPX-packed (NotPackedException / \"not packed\" / \"unknown "
        "file format\") — a deterministic fact about the file itself. No further upx call against "
        "this same file, in either mode, will produce a different result; treat it as confirmed "
        "unpacked and move on to the next analysis step instead of retrying."
    )
