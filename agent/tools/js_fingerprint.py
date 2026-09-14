"""Client-side (JS/DOM-executed) technology fingerprinting -- the gap WhatWeb's own HTTP-header/
cookie/meta static-HTML fingerprinting can't close: a technology that only ever proves itself via a
runtime JS global (window.jQuery, window.__NEXT_DATA__, ...) or a DOM shape produced by rendered JS
is invisible to a tool that only ever reads the raw HTML/headers a server returned. Wappalyzer/
WhatRuns close exactly this gap by running probes inside a real browser page -- this module does the
same, using the Playwright browser session infrastructure agent/tools/browser_manager.py already
owns, rather than any new browser-automation layer.

Signatures live in agent/tools/data/js_signatures.json -- pure data (name/categories/
base_confidence/detect_expr/version_expr), so adding a new detectable technology is a JSON edit,
never a code change (this project's own "no hardcoding" rule). One combined probe script, built
once per call from that data, is sent through a SINGLE manager.evaluate() -- not one round-trip per
signature -- and every individual signature's detect/version expression runs inside its own
try/catch in-page, so one bad expression can never take the rest down with it.
"""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

from agent.tools.browser_manager import _chromium_installed, get_browser_manager
from agent.utils.logger import get_logger

logger = get_logger("TOOLS")

_SIGNATURES_PATH = Path(__file__).resolve().parent / "data" / "js_signatures.json"
_signatures_cache: list[dict] | None = None


def _js_fingerprint_enabled() -> bool:
    return os.getenv("JS_FINGERPRINT_ENABLED", "true").strip().lower() not in ("false", "0", "no")


def _js_fingerprint_timeout_seconds() -> int:
    try:
        return int(os.getenv("JS_FINGERPRINT_TIMEOUT_SECONDS", "45"))
    except ValueError:
        return 45


def load_signatures() -> list[dict]:
    """Loaded once per process, not once per call -- the signature file is static, bundled data,
    never rewritten at runtime."""
    global _signatures_cache
    if _signatures_cache is not None:
        return _signatures_cache
    try:
        with open(_SIGNATURES_PATH, encoding="utf-8") as handle:
            _signatures_cache = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        logger.debug("js_fingerprint: failed to load %s (%s) -- fingerprinting disabled for this process", _SIGNATURES_PATH, exc)
        _signatures_cache = []
    return _signatures_cache


def build_probe_script(signatures: list[dict]) -> str:
    """One JS IIFE that probes every signature in-page and returns a JSON-serializable array of
    {name, categories, confidence, version} for whichever ones actually matched. detect_expr/
    version_expr come straight from our own trusted data file (never target-page or user-supplied
    content), so inlining them as raw JS source here carries no injection risk beyond what that
    data file itself already contains.
    """
    calls = []
    for sig in signatures:
        name_js = json.dumps(sig.get("name", ""))
        categories_js = json.dumps(sig.get("categories", []))
        confidence = sig.get("base_confidence", 50)
        detect_expr = sig.get("detect_expr") or "false"
        version_expr = sig.get("version_expr") or "null"
        calls.append(
            f"tryDetect({name_js}, {categories_js}, {confidence}, "
            f"function(){{ return {detect_expr}; }}, "
            f"function(){{ return {version_expr}; }});"
        )
    body = "\n    ".join(calls)
    return (
        "(function() {\n"
        "  var results = [];\n"
        "  function tryDetect(name, categories, baseConfidence, detectFn, versionFn) {\n"
        "    try {\n"
        "      if (!detectFn()) return;\n"
        "    } catch (e) { return; }\n"
        "    var version = null;\n"
        "    try { version = versionFn() || null; } catch (e) { version = null; }\n"
        "    results.push({name: name, categories: categories, confidence: baseConfidence, version: version});\n"
        "  }\n"
        f"    {body}\n"
        "  return results;\n"
        "})()"
    )


def _normalize_url(host: str) -> str:
    host = host.strip()
    if host.startswith(("http://", "https://")):
        return host
    return f"https://{host}"


async def run_js_fingerprint(session_id: str, host: str, out_of_scope_entries: list[str] | None = None) -> list[dict]:
    """Navigates a short-lived, dedicated browser context to `host` and runs the combined probe
    script once. Returns [] (never raises) on ANY failure -- Chromium missing, navigation error,
    scope rejection, evaluate() error, timeout -- this is an optional enrichment on top of an
    already-successful whatweb call, never something that can block or fail Analyze itself.

    `session_id` here is a fingerprinting-specific id (the caller mints e.g. f"jsfp-{session_id}-
    {host}"), never the operator's own interactive browser_* session id -- a short-lived context of
    its own that this function closes before returning, so it never lingers against
    BROWSER_MAX_CONCURRENT_CONTEXTS longer than the single probe actually needs.
    """
    if not _js_fingerprint_enabled():
        logger.debug("js_fingerprint: session=%s host=%r skipped -- JS_FINGERPRINT_ENABLED=false", session_id, host)
        return []
    signatures = load_signatures()
    if not signatures:
        return []
    if not await _chromium_installed_async():
        logger.debug("js_fingerprint: session=%s host=%r skipped -- Chromium not installed", session_id, host)
        return []

    manager = get_browser_manager()
    url = _normalize_url(host)
    try:
        async def _probe() -> list[dict]:
            nav_result = await manager.navigate(session_id, url, "domcontentloaded", out_of_scope_entries)
            if nav_result.get("status") != "ok":
                logger.debug("js_fingerprint: session=%s host=%r navigate failed: %s", session_id, host, nav_result.get("error") or nav_result.get("reason"))
                return []
            script = build_probe_script(signatures)
            eval_result = await manager.evaluate(session_id, script, out_of_scope_entries)
            if eval_result.get("status") != "ok":
                logger.debug("js_fingerprint: session=%s host=%r evaluate failed: %s", session_id, host, eval_result.get("error") or eval_result.get("reason"))
                return []
            detections = eval_result.get("eval_result")
            return detections if isinstance(detections, list) else []

        detections = await asyncio.wait_for(_probe(), timeout=_js_fingerprint_timeout_seconds())
    except Exception as exc:
        logger.debug("js_fingerprint: session=%s host=%r failed (%s)", session_id, host, exc)
        detections = []
    finally:
        try:
            await manager.close_session(session_id)
        except Exception as exc:
            logger.debug("js_fingerprint: session=%s host=%r error closing context (%s) -- ignored", session_id, host, exc)

    logger.debug("js_fingerprint: session=%s host=%r detected %d technology/ies client-side", session_id, host, len(detections))
    return detections


async def _chromium_installed_async() -> bool:
    return await asyncio.to_thread(_chromium_installed)
