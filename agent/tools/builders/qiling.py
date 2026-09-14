"""build_command() + output parser + availability check for the `qiling_emulate` RE tool -- the
cross-platform replacement for the removed, Windows-only `cdb`. Qiling (github.com/qilingframework/
qiling, on Unicorn) emulates a Windows PE / Linux ELF / macOS Mach-O binary with a faked OS layer,
so a Windows .exe can be triaged on Linux/macOS with no real Windows and no wine.

Registered as a tier-2 (subprocess) tool even though Qiling is a Python library, on purpose: the
actual emulation runs in the standalone agent/tools/qiling_runner.py, launched as its OWN python
subprocess. That keeps Qiling (a heavy optional dependency that also runs an untrusted sample under
emulation) out of the server process, gives it runner.py's own hard wall-clock timeout for free,
and keeps the tool sitting in the SAME RE arsenal slot cdb occupied (so it shows up in the Tools
page's readiness check like any other external tool). Its real dependency -- the `qiling` package,
which the running Python code does not itself carry -- is reflected through availability_check
(qiling_available), exactly the pattern ToolSpec.availability_check documents for the browser tools'
Playwright download.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

from agent.tools.builders.validators import validate_safe_value
from agent.utils.logger import get_logger

logger = get_logger("TOOLS")

# Absolute path so runner.py can launch it regardless of the subprocess's cwd -- the runner is
# deliberately stdlib+qiling only, importable/runnable on its own with no package-path dependency.
_RUNNER_PATH = Path(__file__).resolve().parent.parent / "qiling_runner.py"
_RESULT_SENTINEL = "===QILING_RESULT==="


def qiling_available() -> bool:
    """Uncached on purpose: the operator can `pip install qiling` while the server is running, and
    the Tools page's readiness check should reflect that on the next click without a restart."""
    return importlib.util.find_spec("qiling") is not None


def build_qiling_command(params: dict) -> list[str]:
    file_path = validate_safe_value(str(params["file_path"]).strip())
    runner_params: dict = {"file_path": file_path}

    rootfs = str(params.get("rootfs") or "").strip()
    if rootfs:
        runner_params["rootfs"] = validate_safe_value(rootfs)
    if params.get("args"):
        runner_params["args"] = [validate_safe_value(str(a)) for a in params["args"]]
    if params.get("max_instructions"):
        runner_params["max_instructions"] = int(params["max_instructions"])

    logger.debug("build_qiling_command: file=%s rootfs=%s args=%s",
                 file_path, rootfs or "(from QILING_ROOTFS)", runner_params.get("args"))
    # sys.executable pins the SAME interpreter the server runs under -- the one that would have
    # `qiling` installed in its venv -- rather than whatever bare `python3` PATH happens to resolve.
    return [sys.executable, str(_RUNNER_PATH), json.dumps(runner_params)]


def parse_qiling_output(stdout: str) -> dict:
    """The runner prints its JSON result after a sentinel line; anything before it is stray output
    the emulator itself may have produced. Fall back to raw text if the sentinel/JSON is missing."""
    marker = stdout.rfind(_RESULT_SENTINEL)
    if marker == -1:
        return {"raw_output": stdout.strip()}
    payload = stdout[marker + len(_RESULT_SENTINEL):].strip()
    try:
        return json.loads(payload)
    except json.JSONDecodeError:
        return {"raw_output": stdout.strip()}
