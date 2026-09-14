"""build_command() and output parser for ilspycmd -- .NET/C# decompilation for RE mode. Real gap
this closes: apktool/jadx cover JVM-based Android apps, radare2/gdb cover native binaries, but
nothing here could read a .NET assembly (.dll/.exe compiled from C#/VB.NET/F#) at all before this.

Three modes, cheapest-first (mirrors radare2.py's own "info before decompile_function" discipline
-- don't decompile a whole assembly when you only need to know what's in it):
- "list" (default): every class/interface/struct/delegate/enum in the assembly, by fully qualified
  name -- the safe first step, cheap even for a large assembly, tells you what's worth decompiling.
- "type": decompile ONE specific type by its fully qualified name (-t), the common case once
  "list" has pointed at something worth reading in full.
- "full": decompile the WHOLE assembly to stdout -- only for a genuinely small assembly; a large
  one would blow past the generic tool-result char limit and just get cut off mid-file.

Installed via `dotnet tool install -g ilspycmd --version 9.1.0.7988` (setup_tools.sh's own
install_ilspycmd), pinned rather than left floating -- confirmed live: `dotnet tool install -g
ilspycmd` with no version resolved to a genuinely broken NuGet package ("Settings file
'DotnetToolSettings.xml' was not found in the package"), and the next version tried (8.2.0.7535)
installed fine but targets the now-EOL .NET 6.0 runtime, which Ubuntu noble's own apt repos no
longer carry at all -- 9.1.0.7988 is the first version confirmed live to both install cleanly and
actually run against the .NET 8 SDK/runtime this project's own setup_tools.sh installs.
"""
from __future__ import annotations

from agent.tools.builders.validators import validate_safe_value

_VALID_MODES = {"list", "type", "full"}


def build_ilspycmd_command(params: dict) -> list[str]:
    file_path = validate_safe_value(str(params["file_path"]).strip())
    mode = params.get("mode", "list")
    if mode not in _VALID_MODES:
        raise ValueError(f"Unknown ilspycmd mode={mode!r} -- must be one of {sorted(_VALID_MODES)}")
    if mode == "list":
        # c(lass)/i(nterface)/s(truct)/d(elegate)/e(num) -- every entity kind ilspycmd's own -l
        # flag supports, so "list" genuinely means everything, not just classes. SPACE-separated
        # in ONE argument -- confirmed live: a comma-separated value ("c,i,s,d,e") is silently
        # treated as an unrecognized filter (prints nothing but the version-nag, exit code still
        # 0 -- no error to catch this on), and repeated -l flags only keep the LAST one given.
        return ["ilspycmd", "-l", "c i s d e", file_path]
    if mode == "type":
        type_name = params.get("type_name")
        if not type_name:
            raise ValueError("mode='type' requires a type_name (the fully qualified name from mode='list')")
        return ["ilspycmd", "-t", validate_safe_value(str(type_name).strip()), file_path]
    return ["ilspycmd", file_path]


def parse_ilspycmd_output(stdout: str) -> dict:
    """ilspycmd has no structured/JSON output mode for any of its three modes here -- both the
    type list and the decompiled C# source are genuinely meant to be read as text."""
    # A real, harmless-but-noisy side effect confirmed live: ilspycmd nags about a newer version
    # being available on every single invocation, appended after the real output -- stripped here
    # so it doesn't read like part of the decompiled code/type list.
    lines = stdout.splitlines()
    while lines and (lines[-1].startswith("You are not using the latest version") or lines[-1].startswith("Latest version is")):
        lines.pop()
    return {"output": "\n".join(lines).strip()}
