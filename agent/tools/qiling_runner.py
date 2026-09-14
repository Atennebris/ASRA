"""Standalone subprocess runner for the `qiling_emulate` RE tool -- cross-platform binary emulation
(Qiling Framework, github.com/qilingframework/qiling, built on Unicorn) that REPLACED the old,
Windows-only `cdb` tool. Runs a target binary (Windows PE / Linux ELF / macOS Mach-O) under full
CPU emulation with a faked OS layer, so a Windows .exe can be triaged on Linux/macOS with no real
Windows and no wine -- the exact cross-platform gap cdb could never fill.

Deliberately standalone (stdlib + qiling only, NO `from agent...` imports) so agent/tools/builders/
qiling.py can launch it by ABSOLUTE FILE PATH, independent of the server's cwd or whether the
package is importable from wherever the subprocess starts. It reads one JSON blob of params as
argv[1] and prints its result as JSON after a sentinel line (qiling itself can emit stray output;
the sentinel lets the parser separate our result from anything the emulator printed).

Emulation is a CPU-level boundary: the target's own machine code executes inside Unicorn, not as
native host instructions, and its OS calls are intercepted by qiling's OS layer rather than reaching
the real host -- meaningfully safer than natively running an untrusted sample. The hard wall-clock
cap is enforced by the PARENT (subprocess timeout); an instruction-count cap here guards against a
tight infinite loop burning the whole timeout with nothing to show.
"""
from __future__ import annotations

import json
import os
import sys

_RESULT_SENTINEL = "===QILING_RESULT==="
_DEFAULT_MAX_INSTRUCTIONS = 2_000_000
# Where setup_tools.sh clones the Qiling rootfs collection -- used as the fallback base when neither
# a rootfs param nor QILING_ROOTFS is given, so the button-installed setup "just works" with no
# further config.
_DEFAULT_ROOTFS_BASE = "/opt/qiling-rootfs"

# ELF e_machine -> qiling rootfs arch subdir stem. Only the common ones; anything unlisted falls
# back to using the base rootfs dir as-is.
_ELF_MACHINE = {0x03: "x86", 0x3E: "x8664", 0x28: "arm", 0xB7: "arm64", 0x08: "mips32"}
_PE_MACHINE = {0x14C: "x86", 0x8664: "x8664", 0x1C0: "arm", 0xAA64: "arm64"}


def _detect_rootfs_subdir(file_path: str) -> str | None:
    """Best-effort '<arch>_<os>' Qiling rootfs subdir name from the target's own header (PE/ELF/
    Mach-O), read with stdlib only. None when it can't be determined -- the caller then uses the
    base rootfs dir unchanged."""
    try:
        with open(file_path, "rb") as handle:
            head = handle.read(64)
    except OSError:
        return None
    if len(head) < 6:
        return None

    if head[:2] == b"MZ":  # PE / Windows
        try:
            pe_off = int.from_bytes(head[0x3C:0x40], "little")
            with open(file_path, "rb") as handle:
                handle.seek(pe_off)
                sig_machine = handle.read(6)
            if sig_machine[:4] == b"PE\x00\x00":
                arch = _PE_MACHINE.get(int.from_bytes(sig_machine[4:6], "little"))
                return f"{arch}_windows" if arch else None
        except (OSError, ValueError):
            return None
        return None

    if head[:4] == b"\x7fELF":  # ELF / Linux
        endian = "little" if head[5] == 1 else "big"
        arch = _ELF_MACHINE.get(int.from_bytes(head[18:20], endian))
        return f"{arch}_linux" if arch else None

    if head[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe"):
        return "x8664_macos"  # Mach-O; qiling ships a single x8664 macos rootfs
    return None


def _resolve_rootfs(file_path: str, base: str) -> str:
    """If `base` is a rootfs COLLECTION (holds per-arch subdirs like x8664_windows), pick the subdir
    matching this target. If it's already a specific rootfs, use it as-is."""
    subdir = _detect_rootfs_subdir(file_path)
    if subdir and os.path.isdir(os.path.join(base, subdir)):
        return os.path.join(base, subdir)
    return base


def _emit(result: dict) -> None:
    # Sentinel first so the parser can skip any output qiling wrote to stdout before this point.
    sys.stdout.flush()
    print(_RESULT_SENTINEL)
    print(json.dumps(result))
    sys.stdout.flush()


def _run(params: dict) -> dict:
    file_path = str(params.get("file_path") or "").strip()
    if not file_path or not os.path.isfile(file_path):
        return {"status": "error", "error": f"file_path does not exist: {file_path!r}"}

    base = str(params.get("rootfs") or os.getenv("QILING_ROOTFS") or "").strip()
    if not base and os.path.isdir(_DEFAULT_ROOTFS_BASE):
        base = _DEFAULT_ROOTFS_BASE
    if not base or not os.path.isdir(base):
        return {"status": "error",
                "error": "No usable Qiling rootfs. Qiling needs a rootfs directory holding the "
                         "target OS's system libraries (e.g. Windows DLLs for a PE) to emulate. "
                         "Run the Tools-page Install button (it fetches one to " + _DEFAULT_ROOTFS_BASE +
                         "), set QILING_ROOTFS in .env, or pass rootfs "
                         "(see github.com/qilingframework/rootfs).",
                "rootfs_tried": base}
    rootfs = _resolve_rootfs(file_path, base)

    try:
        from qiling import Qiling  # noqa: PLC0415 -- optional heavy dep, imported only when used
        from qiling.const import QL_VERBOSE  # noqa: PLC0415
    except ImportError as exc:
        return {"status": "error", "error": f"qiling is not importable: {exc}. Install with "
                                            "`pip install qiling` in the venv."}

    run_args = [str(a) for a in (params.get("args") or [])]
    max_instructions = int(params.get("max_instructions") or _DEFAULT_MAX_INSTRUCTIONS)

    try:
        ql = Qiling([file_path, *run_args], rootfs, verbose=QL_VERBOSE.DISABLED, console=False)
    except Exception as exc:  # noqa: BLE001 -- any qiling/loader error becomes a clean tool result
        return {"status": "error", "error": f"Qiling failed to load the target: {type(exc).__name__}: {exc}"}

    # Version-tolerant metadata reads -- qiling's attribute layout has shifted across releases, so
    # every field is best-effort and never allowed to abort the run.
    def _safe(getter, default=None):
        try:
            return getter()
        except Exception:  # noqa: BLE001
            return default

    os_type = _safe(lambda: ql.os.type.name) or _safe(lambda: str(ql.os.type))
    arch_type = _safe(lambda: ql.arch.type.name) or _safe(lambda: str(ql.arch.type))
    entry_point = _safe(lambda: ql.loader.entry_point)

    counter = {"n": 0}
    stopped_reason = "ran to completion"

    # qiling's hook_code callback signature is (ql, address, size) when no user_data is passed.
    def _count_hook(ql_, address, size):  # noqa: ANN001
        counter["n"] += 1
        if counter["n"] >= max_instructions:
            ql_.emu_stop()

    _safe(lambda: ql.hook_code(_count_hook))

    try:
        ql.run()
        if counter["n"] >= max_instructions:
            stopped_reason = f"instruction cap reached ({max_instructions})"
    except Exception as exc:  # noqa: BLE001 -- emulation faults are a normal, reportable outcome
        stopped_reason = f"emulation stopped: {type(exc).__name__}: {exc}"

    final_pc = _safe(lambda: ql.arch.regs.arch_pc)

    return {
        "status": "ok",
        "rootfs": rootfs,
        "os": os_type,
        "arch": arch_type,
        "entry_point": hex(entry_point) if isinstance(entry_point, int) else entry_point,
        "final_pc": hex(final_pc) if isinstance(final_pc, int) else final_pc,
        "instructions_executed": counter["n"],
        "stopped_reason": stopped_reason,
        "note": "Emulated under Qiling (CPU emulation, no real OS). Coverage of complex real-world "
                "binaries is not 100% -- an early 'emulation stopped' can mean an unimplemented API, "
                "not necessarily a bug in the target.",
    }


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        _emit({"status": "error", "error": "qiling_runner expects a JSON params blob as argv[1]."})
        return 0
    try:
        params = json.loads(argv[1])
    except json.JSONDecodeError as exc:
        _emit({"status": "error", "error": f"could not parse params JSON: {exc}"})
        return 0
    _emit(_run(params))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
