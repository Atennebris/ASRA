"""wp_batch_rce.py -- CVE-2026-63030 (REST /batch/v1 route confusion) + CVE-2026-60137
(author__not_in blind SQLi) chain. Pure-function logic (version-range detection, the shared
timing-oracle length/byte extraction, the root-prereq assessment) is tested directly; the six
native tool entry points are tested by monkeypatching the class-level methods that would otherwise
need real network timing (calibrate/detect/deploy) -- HTTP wiring itself (redirect-preserving POST,
wp_batch_scan's end-to-end fingerprint) is exercised for real via httpx.MockTransport, same
convention as test_authenticated_identity.py.
"""
import importlib
import re

import httpx
import pytest

from agent.tools.registry import get_tool

# agent/tools/__init__.py imports the wp_batch_rce *function* into the agent.tools
# package namespace, shadowing the wp_batch_rce *module* attribute -- "import
# agent.tools.wp_batch_rce as w" would silently bind w to that function instead
# (IMPORT_FROM resolves via getattr() before falling back to sys.modules), so the
# module must be fetched directly.
w = importlib.import_module("agent.tools.wp_batch_rce")

_RealHTTPXClient = httpx.Client  # captured before any test monkeypatches httpx.Client


def _mock_client(handler, **kwargs):
    return _RealHTTPXClient(transport=httpx.MockTransport(handler), **kwargs)


# --- registration wiring: every entry point exists with the right risk-tier gate ---

@pytest.mark.parametrize("name,requires_allowed_target,category", [
    ("wp_batch_scan", False, "scan"),
    ("wp_batch_sqli_check", True, "exploit"),
    ("wp_batch_sqli_read", True, "exploit"),
    ("wp_batch_rce", True, "exploit"),
    ("wp_batch_shell", True, "exploit"),
    ("wp_batch_root_prereq", True, "exploit"),
])
def test_tool_registered_with_expected_gate(name, requires_allowed_target, category):
    spec = get_tool(name)
    assert spec is not None, f"{name} not registered"
    assert spec.requires_allowed_target is requires_allowed_target
    assert spec.category == category
    assert spec.tool_tier == 1


# --- version-range detection ---

def test_version_sort_key_orders_prereleases_correctly():
    assert w._version_sort_key("7.1-beta1") < w._version_sort_key("7.1-beta2") < w._version_sort_key("7.1")


@pytest.mark.parametrize("version,expected_severity", [
    ("6.9.4", "RCE"),
    ("7.0.1", "RCE"),
    ("7.1-beta1", "RCE"),
    ("6.8.5", "SQLi"),
])
def test_affected_versions_flagged(version, expected_severity):
    hit = w._affected_by_batch_chain(version)
    assert hit is not None
    assert hit[0] == expected_severity


@pytest.mark.parametrize("version", ["6.9.5", "7.0.2", "7.1", "6.8.6", "6.7.0", None])
def test_patched_or_unrelated_versions_not_flagged(version):
    assert w._affected_by_batch_chain(version) is None


def test_affected_ignores_unparseable_version_string():
    assert w._affected_by_batch_chain("not-a-version") is None


# --- shared timing-oracle length/byte extraction ---

def test_extract_via_oracle_recovers_a_known_string():
    secret = "wp_pw"
    length_re = re.compile(r"CHAR_LENGTH\(.*\) >= (\d+)$")
    char_re = re.compile(r"SUBSTRING\(.*,(\d+),1\)\) >= (\d+)$")

    def fake_oracle(condition: str) -> bool:
        # Evaluate the exact same boolean condition _extract_via_oracle sends, against the
        # in-memory secret, instead of faking real timing -- proves the binary-search bit logic
        # itself is correct independent of any network behavior. Asserts the expression under
        # test really is "secret" (COALESCE((secret),0x00)) so a future signature change to
        # _extract_via_oracle can't silently go unnoticed here.
        assert "(secret)" in condition
        length_match = length_re.search(condition)
        if length_match:
            return len(secret) >= int(length_match.group(1))
        char_match = char_re.search(condition)
        assert char_match, f"condition matched neither length nor char pattern: {condition!r}"
        pos, threshold = int(char_match.group(1)), int(char_match.group(2))
        return ord(secret[pos - 1]) >= threshold

    result = w._extract_via_oracle(fake_oracle, "secret", max_len=32)
    assert result == secret


def test_extract_via_oracle_empty_value_returns_empty_string():
    assert w._extract_via_oracle(lambda cond: False, "missing", max_len=16) == ""


# --- root-prereq assessment (pure function) ---

def test_assess_root_prereqs_all_present_is_exploitable():
    outputs = {
        "uid": "uid=33(www-data) gid=33(www-data)\n33",
        "uname": "Linux 5.15.0",
        "arch": "x86_64",
        "python": "Python 3.10.6",
        "suid_scan": "/usr/bin/sudo\n/usr/bin/passwd",
        "container": "",
    }
    checks, exploitable, suid_lines = w._assess_root_prereqs(outputs)
    assert exploitable is True
    assert len(suid_lines) == 2
    assert dict((n, ok) for n, _, ok in checks)["non-root-web-user"] is True


def test_assess_root_prereqs_root_uid_fails_non_root_check():
    outputs = {"uid": "uid=0(root)\n0", "uname": "Linux", "arch": "x86_64", "python": "Python 3.9.0", "suid_scan": "", "container": ""}
    checks, exploitable, _ = w._assess_root_prereqs(outputs)
    assert exploitable is False
    assert dict((n, ok) for n, _, ok in checks)["non-root-web-user"] is False


def test_assess_root_prereqs_no_output_is_unexploitable():
    checks, exploitable, suid_lines = w._assess_root_prereqs({})
    assert exploitable is False
    assert suid_lines == []


# --- redirect-preserving POST: httpx's own automatic redirect handling downgrades POST->GET on
# 301/302/303 (the exact false-negative this helper exists to avoid) ---

def test_post_preserving_method_follows_301_and_keeps_the_body():
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.method, request.url.path, request.content))
        if request.url.path == "/old":
            return httpx.Response(301, headers={"location": "https://target.example/new"})
        return httpx.Response(200, json={"ok": True})

    with _mock_client(handler) as client:
        resp = w._post_preserving_method(client, "https://target.example/old", json_body={"a": 1})

    assert resp.status_code == 200
    assert [c[0] for c in calls] == ["POST", "POST"]
    assert calls[1][1] == "/new"
    assert b'"a"' in calls[1][2] and b"1" in calls[1][2]


def test_post_preserving_method_stops_after_max_hops():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": str(request.url)})

    with _mock_client(handler) as client:
        resp = w._post_preserving_method(client, "https://target.example/loop", json_body={}, max_hops=3)

    assert resp.status_code == 302


# --- wp_batch_scan: full end-to-end wiring over a mocked target ---

def test_wp_batch_scan_flags_a_vulnerable_affected_version():
    def handler(request: httpx.Request) -> httpx.Response:
        # Both requests share path "/" (rest_route is a query param) -- method is what actually
        # distinguishes the homepage GET from the batch-route probe POST here.
        if request.method == "GET":
            return httpx.Response(200, text='<meta name="generator" content="WordPress 6.9.3" />')
        if request.method == "POST" and "rest_route=/batch/v1" in str(request.url):
            return httpx.Response(400, json={"code": "rest_missing_callback_param"})
        return httpx.Response(404)

    real_client_cls = httpx.Client
    try:
        httpx.Client = lambda **kwargs: _mock_client(handler, **{k: v for k, v in kwargs.items()})
        result = w.wp_batch_scan({"target": "https://target.example"})
    finally:
        httpx.Client = real_client_cls

    assert result["status"] == "ok"
    assert result["version"] == "6.9.3"
    assert result["batch_route_reachable"] is True
    assert result["cve"] == "CVE-2026-63030 (chains CVE-2026-60137)"
    assert result["verdict"].startswith("vulnerable")


def test_wp_batch_scan_reports_unreachable_target():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    real_client_cls = httpx.Client
    try:
        httpx.Client = lambda **kwargs: _mock_client(handler, **kwargs)
        result = w.wp_batch_scan({"target": "https://dead.example"})
    finally:
        httpx.Client = real_client_cls

    assert result["status"] == "error"


# --- wp_batch_sqli_check / wp_batch_sqli_read: wired through _CategoriesBatchOracle, whose real
# timing methods are monkeypatched so the test doesn't depend on real elapsed time ---

def test_wp_batch_sqli_check_reports_vulnerable_on_a_clear_timing_margin(monkeypatch):
    monkeypatch.setattr(w._CategoriesBatchOracle, "calibrate", lambda self, rounds=3: (0.05, 0.20))
    result = w.wp_batch_sqli_check({"target": "https://target.example", "delay": 0.15})
    assert result["status"] == "ok"
    assert result["vulnerable"] is True


def test_wp_batch_sqli_check_reports_not_vulnerable_on_no_margin(monkeypatch):
    monkeypatch.setattr(w._CategoriesBatchOracle, "calibrate", lambda self, rounds=3: (0.05, 0.06))
    result = w.wp_batch_sqli_check({"target": "https://target.example", "delay": 0.15})
    assert result["vulnerable"] is False


def test_wp_batch_sqli_read_uses_the_requested_preset(monkeypatch):
    monkeypatch.setattr(w._CategoriesBatchOracle, "calibrate", lambda self, rounds=3: (0.0, 0.0))
    monkeypatch.setattr(w, "_extract_via_oracle", lambda oracle, expr, max_len: f"VALUE_FOR[{expr}]")
    result = w.wp_batch_sqli_read({"target": "https://target.example", "preset": "database"})
    assert result["status"] == "ok"
    assert result["expr"] == "DATABASE()"
    assert result["value"] == "VALUE_FOR[DATABASE()]"


def test_wp_batch_sqli_read_rejects_unknown_preset():
    result = w.wp_batch_sqli_read({"target": "https://target.example", "preset": "not_a_real_preset"})
    assert result["status"] == "error"
    assert "not_a_real_preset" in result["error"]


def test_wp_batch_sqli_read_prefers_explicit_expr_over_preset(monkeypatch):
    monkeypatch.setattr(w._CategoriesBatchOracle, "calibrate", lambda self, rounds=3: (0.0, 0.0))
    monkeypatch.setattr(w, "_extract_via_oracle", lambda oracle, expr, max_len: expr)
    result = w.wp_batch_sqli_read({"target": "https://target.example", "expr": "1+1", "preset": "users"})
    assert result["expr"] == "1+1"


# --- wp_batch_rce: detect()/deploy() monkeypatched at the class level (real timing/DB-forgery
# mechanics are exercised structurally by the payload-shape/extraction tests above) ---

def test_wp_batch_rce_stops_when_not_vulnerable(monkeypatch):
    monkeypatch.setattr(w._UsersBatchRce, "detect", lambda self, rounds=3: {"fast": 0.1, "slow": 0.12, "delta": 0.02, "vulnerable": False})
    result = w.wp_batch_rce({"target": "https://target.example"})
    assert result["status"] == "error"
    assert "not vulnerable" in result["error"]


def test_wp_batch_rce_runs_the_command_and_cleans_up_on_success(monkeypatch):
    cleanup_calls = []
    monkeypatch.setattr(w._UsersBatchRce, "detect", lambda self, rounds=3: {"fast": 0.1, "slow": 4.3, "delta": 4.2, "vulnerable": True})
    monkeypatch.setattr(
        w._UsersBatchRce, "deploy",
        lambda self: ("asra_abc123", "Asra!secret", lambda cmd: f"ran:{cmd}", lambda: cleanup_calls.append(True)),
    )
    result = w.wp_batch_rce({"target": "https://target.example", "cmd": "whoami"})
    assert result["status"] == "ok"
    assert result["output"] == "ran:whoami"
    assert result["forged_admin_username"] == "asra_abc123"
    assert cleanup_calls == [True]


def test_wp_batch_rce_reports_deploy_failure(monkeypatch):
    monkeypatch.setattr(w._UsersBatchRce, "detect", lambda self, rounds=3: {"fast": 0.1, "slow": 4.3, "delta": 4.2, "vulnerable": True})

    def fail_deploy(self):
        raise RuntimeError("no published post for oEmbed anchor")

    monkeypatch.setattr(w._UsersBatchRce, "deploy", fail_deploy)
    result = w.wp_batch_rce({"target": "https://target.example"})
    assert result["status"] == "error"
    assert "oEmbed anchor" in result["error"]


# --- wp_batch_shell / wp_batch_root_prereq: require a password, and wire through
# _run_authenticated_plugin_commands (monkeypatched to avoid a real login/upload flow) ---

def test_wp_batch_shell_requires_admin_password():
    result = w.wp_batch_shell({"target": "https://target.example"})
    assert result["status"] == "error"
    assert "admin_password" in result["error"]


def test_wp_batch_shell_returns_command_output(monkeypatch):
    monkeypatch.setattr(w, "_run_authenticated_plugin_commands", lambda client, base, user, pw, commands: {"cmd": "uid=33(www-data)"})
    result = w.wp_batch_shell({"target": "https://target.example", "admin_password": "cracked-pw", "cmd": "id"})
    assert result["status"] == "ok"
    assert result["output"] == "uid=33(www-data)"


def test_wp_batch_shell_surfaces_login_failure(monkeypatch):
    monkeypatch.setattr(w, "_run_authenticated_plugin_commands", lambda client, base, user, pw, commands: {"_error": "login failed (bad credentials or login hardening)"})
    result = w.wp_batch_shell({"target": "https://target.example", "admin_password": "wrong"})
    assert result["status"] == "error"
    assert "login failed" in result["error"]


def test_wp_batch_root_prereq_requires_admin_password():
    result = w.wp_batch_root_prereq({"target": "https://target.example"})
    assert result["status"] == "error"
    assert "admin_password" in result["error"]


def test_wp_batch_root_prereq_reports_exploitability(monkeypatch):
    monkeypatch.setattr(
        w, "_run_authenticated_plugin_commands",
        lambda client, base, user, pw, commands: {
            "uid": "uid=33(www-data)\n33", "uname": "Linux 5.15.0", "arch": "x86_64",
            "python": "Python 3.10.6", "suid_scan": "/usr/bin/sudo", "container": "",
        },
    )
    result = w.wp_batch_root_prereq({"target": "https://target.example", "admin_password": "cracked-pw"})
    assert result["status"] == "ok"
    assert result["exploitable"] is True
    assert "no local privilege escalation" in result["note"]
