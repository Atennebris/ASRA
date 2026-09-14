"""native_function bypass stubs for the 9 browser_* tools (agent/tools/browser_manager.py holds
the real, stateful async implementation). ToolSpec.__post_init__ requires tool_tier=1 to carry a
native_function, but agent/core.py's _dispatch_tool intercepts every browser_* call by name BEFORE
ever reaching the normal asyncio.to_thread(run_tool, spec, arguments) path these stubs would
otherwise be invoked through -- same reasoning, same pattern as agent/tools/__init__.py's own
_delegate_to_subagent_native. A real, working error message here (not a bare `pass`/None) means a
clear failure if that bypass check itself is ever broken, instead of a silent no-op or a crash.
"""


def _bypass_error(name: str) -> dict:
    return {
        "status": "error",
        "error": f"{name} must be dispatched via agent.core._dispatch_tool's async bypass, not the generic native-tool path",
    }


def _browser_navigate_native(params: dict) -> dict:
    return _bypass_error("browser_navigate")


def _browser_snapshot_native(params: dict) -> dict:
    return _bypass_error("browser_snapshot")


def _browser_click_native(params: dict) -> dict:
    return _bypass_error("browser_click")


def _browser_fill_native(params: dict) -> dict:
    return _bypass_error("browser_fill")


def _browser_select_option_native(params: dict) -> dict:
    return _bypass_error("browser_select_option")


def _browser_press_key_native(params: dict) -> dict:
    return _bypass_error("browser_press_key")


def _browser_evaluate_native(params: dict) -> dict:
    return _bypass_error("browser_evaluate")


def _browser_go_back_native(params: dict) -> dict:
    return _bypass_error("browser_go_back")


def _browser_close_session_native(params: dict) -> dict:
    return _bypass_error("browser_close_session")
