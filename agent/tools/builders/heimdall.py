"""build_command() and output parser for heimdall's `decompile` subcommand -- EVM bytecode
decompilation to pseudocode, for a smart contract with no available Solidity source (see
slither.py for the source-available case)."""
from __future__ import annotations

from agent.tools.builders.validators import validate_safe_value


def build_heimdall_command(params: dict) -> list[str]:
    target = validate_safe_value(str(params["bytecode_or_path"]).strip())
    return ["heimdall", "decompile", target]


def parse_heimdall_output(stdout: str) -> dict:
    return {"pseudocode": stdout.strip()}
