"""agent/tools/browser_stealth.py's own pure pieces -- derive_stealth_user_agent/launch_headless
need no Playwright/browser at all, trivial pure-function tests. STEALTH_INIT_SCRIPT's actual
effect against a real browser is validated live (see the session's own manual smoke-test notes),
not re-proven here — this file only checks the wiring is structurally sound (a real script,
applies the expected substitution), same "mocked at the boundary" discipline every other test in
this project follows.
"""
from agent.tools.browser_stealth import STEALTH_INIT_SCRIPT, derive_stealth_user_agent, launch_headless


def test_derive_stealth_user_agent_strips_headless_prefix_only():
    real_ua = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/149.0.7827.55 Safari/537.36"
    stealth_ua = derive_stealth_user_agent(real_ua)
    assert stealth_ua == "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.7827.55 Safari/537.36"
    assert "Headless" not in stealth_ua


def test_derive_stealth_user_agent_keeps_the_real_version_untouched():
    """Deliberately derived from whatever's actually running, never a hardcoded guess -- a
    mismatched Chromium version in the UA would itself be a detectable inconsistency."""
    real_ua = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/200.1.2.3 Safari/537.36"
    assert "200.1.2.3" in derive_stealth_user_agent(real_ua)


def test_derive_stealth_user_agent_is_a_noop_on_an_already_non_headless_ua():
    ua = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.7827.55 Safari/537.36"
    assert derive_stealth_user_agent(ua) == ua


def test_stealth_init_script_patches_the_signals_live_confirmed_leaking():
    """Not a live browser check (that's the manual smoke test) -- just confirms the script text
    actually targets every signal live-confirmed leaking this session (navigator.webdriver=True,
    plugins.length=0, window.chrome absent, permissions.query notifications mismatch, WebGL
    vendor/renderer), so a future edit can't silently drop one of these without a test noticing."""
    assert "webdriver" in STEALTH_INIT_SCRIPT
    assert "plugins" in STEALTH_INIT_SCRIPT and "mimeTypes" in STEALTH_INIT_SCRIPT
    assert "window.chrome" in STEALTH_INIT_SCRIPT
    assert "languages" in STEALTH_INIT_SCRIPT
    assert "37445" in STEALTH_INIT_SCRIPT and "37446" in STEALTH_INIT_SCRIPT  # UNMASKED_VENDOR/RENDERER_WEBGL
    assert "notifications" in STEALTH_INIT_SCRIPT


def test_stealth_init_script_also_spoofs_tostring_on_every_patched_function():
    """The next-tier check this closes: calling Function.prototype.toString on a patched getter/
    method used to reveal its own real JS source instead of a native-looking stub -- itself a
    detectable tell. Confirms the override is registered for every signal above, not just some."""
    assert "Function.prototype.toString" in STEALTH_INIT_SCRIPT
    assert "nativeStubs" in STEALTH_INIT_SCRIPT
    for expected_stub in (
        "function get webdriver() { [native code] }",
        "function get plugins() { [native code] }",
        "function get mimeTypes() { [native code] }",
        "function get languages() { [native code] }",
        "function getParameter() { [native code] }",
        "function query() { [native code] }",
        "function loadTimes() { [native code] }",
        "function csi() { [native code] }",
    ):
        assert expected_stub in STEALTH_INIT_SCRIPT, expected_stub


# --- launch_headless -----------------------------------------------------------------------


def test_launch_headless_defaults_true_when_unset(monkeypatch):
    monkeypatch.delenv("BROWSER_HEADLESS", raising=False)
    assert launch_headless() is True


def test_launch_headless_false_disables_it(monkeypatch):
    monkeypatch.setenv("BROWSER_HEADLESS", "false")
    assert launch_headless() is False


def test_launch_headless_accepts_common_falsy_spellings(monkeypatch):
    for value in ("false", "False", "0", "no", " FALSE "):
        monkeypatch.setenv("BROWSER_HEADLESS", value)
        assert launch_headless() is False, value


def test_launch_headless_any_other_value_stays_true(monkeypatch):
    monkeypatch.setenv("BROWSER_HEADLESS", "true")
    assert launch_headless() is True
