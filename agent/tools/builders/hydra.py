"""build_command() and output parser for Hydra (github.com/vanhauser-thc/thc-hydra) -- real
network-service and web-login-form credential brute-forcing.

Not wired through agent/tools/runner.py's generic subprocess path like nikto/whatweb/ffuf: a real
brute-force run genuinely takes many minutes, so it goes through agent/tools/background_jobs.py
instead (fire now, check later) -- this module only builds the command and parses the result,
agent/tools/native.py's hydra_start/hydra_check own the actual background-job lifecycle.

Confirmed live (a local throwaway test login server, not a real target) rather than assumed from
docs: "-o <file> -b json" needs a REAL file on disk, not a pipe -- same seekability lesson already
learned the hard way from Arjun's -oJ. Confirmed exact http-post-form module syntax
("<path>:<form-data>:<F=fail-string|S=success-string>") against hydra -U http-post-form's own
module help text, then verified end-to-end (a real "admin:letmein123" pair found and correctly
written to the JSON result file).
"""
from __future__ import annotations

import json
from pathlib import Path

from agent.tools.allowed_targets import extract_hostname
from agent.tools.builders.validators import validate_safe_value, validate_target
from agent.tools.wordlist_store import get_assigned_wordlist

_NETWORK_PROTOCOLS = {"ssh", "ftp", "telnet", "mysql", "postgres", "rdp", "smb"}
_HTTP_PROTOCOLS = {"http-post-form", "http-get-form"}
_ALL_PROTOCOLS = _NETWORK_PROTOCOLS | _HTTP_PROTOCOLS

# Small, always-available default -- no download, no setup_tools.sh opt-in flag needed, so Hydra
# works out of the box even on a machine that never ran the (opt-in, ~60-70MB) large-wordlist
# install step below.
_DEFAULT_USERNAMES = ["admin", "root", "administrator", "user", "test"]
_DEFAULT_PASSWORDS = ["admin", "password", "123456", "root", "toor", "letmein", "changeme", ""]
# Moderate, non-DoS-shaped default -- Hydra's own default is 16; this project already treats "more
# than a handful of concurrent requests" as a real abuse-shaped risk (see EXPLOIT_PROMPT's
# race-condition guidance, capped at 2-10) and a credential brute-force is the same class of
# traffic pattern, just against a login endpoint instead of a single stateful action.
_DEFAULT_THREADS = 4

# setup_tools.sh's install_large_wordlists (opt-in, INSTALL_LARGE_WORDLISTS=true) already fetches
# exactly these -- built originally "for real weak-password brute-forcing, not just default-creds
# checks" (that function's own comment). Reused here rather than inventing new wordlist
# infrastructure: if a model omits username_list/password_list and these exist on disk, they're
# used automatically; otherwise this falls back to the small built-in default above.
_LARGE_USERNAME_WORDLIST = "/usr/share/seclists/Usernames/top-usernames-shortlist.txt"
_LARGE_PASSWORD_WORDLISTS = (
    "/usr/share/wordlists/rockyou.txt",
    "/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt",
)


def _resolve_list_arg(
    flag_single: str, flag_file: str, explicit_single, explicit_list, default_values: list[str],
    large_wordlist_paths: tuple[str, ...], job_dir: Path, job_id: str, role: str,
    assigned_path: str | None = None,
) -> list[str]:
    """One value (-l/-p) if the model gave a single string; a file (-L/-P) otherwise -- precedence
    beyond that is: an explicit model-supplied list, then the operator's own Settings-UI wordlist
    assignment (agent/tools/wordlist_store.py) for this role, then an existing opt-in large
    SecLists/rockyou list if actually present on disk, then the small built-in default (also
    written to a temp file)."""
    if explicit_single:
        return [flag_single, validate_safe_value(str(explicit_single))]

    if explicit_list:
        values = [str(v) for v in explicit_list]
    else:
        if assigned_path:
            return [flag_file, assigned_path]
        for candidate in large_wordlist_paths:
            if Path(candidate).exists():
                return [flag_file, candidate]
        values = default_values

    path = job_dir / f"{job_id}_{role}.txt"
    # "\n".join(...) would silently drop a trailing blank entry ("" for testing an empty
    # password, deliberately in _DEFAULT_PASSWORDS) -- it becomes indistinguishable from the
    # file's own trailing newline, so Hydra would never actually see a genuine blank-password
    # line to test. Writing "value\n" per entry keeps it as a real, separate line.
    path.write_text("".join(f"{value}\n" for value in values), encoding="utf-8")
    return [flag_file, str(path)]


def build_hydra_command(params: dict, job_id: str, job_dir: Path) -> list[str]:
    target = validate_target(params["target"])
    protocol = str(params.get("protocol", "")).strip().lower()
    if protocol not in _ALL_PROTOCOLS:
        raise ValueError(f"protocol must be one of {sorted(_ALL_PROTOCOLS)}, got {protocol!r}")

    hostname = extract_hostname(target)
    if not hostname:
        raise ValueError(f"could not extract a hostname/IP from target {target!r}")

    threads = int(params.get("threads") or _DEFAULT_THREADS)
    result_path = job_dir / f"{job_id}_result.json"

    command = ["hydra", "-t", str(threads), "-o", str(result_path), "-b", "json"]

    port = params.get("port")
    if port:
        command += ["-s", str(int(port))]

    command += _resolve_list_arg(
        "-l", "-L", params.get("username"), params.get("username_list"),
        _DEFAULT_USERNAMES, (_LARGE_USERNAME_WORDLIST,), job_dir, job_id, "users",
        assigned_path=get_assigned_wordlist("hydra_usernames"),
    )
    command += _resolve_list_arg(
        "-p", "-P", params.get("password"), params.get("password_list"),
        _DEFAULT_PASSWORDS, _LARGE_PASSWORD_WORDLISTS, job_dir, job_id, "passwords",
        assigned_path=get_assigned_wordlist("hydra_passwords"),
    )

    if protocol in _HTTP_PROTOCOLS:
        login_path = params.get("login_path")
        if not login_path:
            raise ValueError(f"login_path is required for protocol={protocol!r}")
        username_field = validate_safe_value(str(params.get("username_field") or "username"))
        password_field = validate_safe_value(str(params.get("password_field") or "password"))
        extra_fields = params.get("extra_fields") or {}
        body_parts = [f"{username_field}=^USER^", f"{password_field}=^PASS^"]
        body_parts += [f"{validate_safe_value(str(k))}={validate_safe_value(str(v))}" for k, v in extra_fields.items()]
        body = "&".join(body_parts)

        failure_string = params.get("failure_string")
        success_string = params.get("success_string")
        if failure_string:
            condition = f"F={validate_safe_value(str(failure_string))}"
        elif success_string:
            condition = f"S={validate_safe_value(str(success_string))}"
        else:
            raise ValueError(f"failure_string or success_string is required for protocol={protocol!r}")

        module_arg = f"{validate_safe_value(str(login_path))}:{body}:{condition}"
        if target.lower().startswith("https://"):
            command.append("-S")
        command += [hostname, protocol, module_arg]
    else:
        command += [hostname, protocol]

    return command


def parse_hydra_result(result_path: Path) -> dict:
    """Reads Hydra's own -o/-b json structured output (written to a real file, never stdout --
    see the module docstring). Confirmed live: unlike Arjun, Hydra writes this file every time it
    actually runs to completion, zero credentials found or not ("results": [] either way) --
    {"credentials": []} here is only reached if the file is missing for some other reason (e.g.
    the process was killed before it could write anything at all)."""
    if not result_path.exists():
        return {"credentials": []}
    try:
        record = json.loads(result_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {"credentials": []}

    credentials = [
        {"host": item.get("host"), "login": item.get("login"), "password": item.get("password"), "port": item.get("port")}
        for item in record.get("results", [])
    ]
    return {"credentials": credentials}
