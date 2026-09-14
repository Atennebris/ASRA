"""Vendor-agnostic operator notifications -- a plain webhook POST on session completion and on
any new Critical/High finding, so an operator running several unattended/scheduled sessions (see
[[fleet_mode]]) doesn't have to keep the UI open to know something needs attention.

Deliberately generic rather than a specific vendor's SDK: NOTIFY_WEBHOOK_URL, when set, receives a
JSON body carrying BOTH "content" (Discord's own incoming-webhook field name) and "text" (Slack's)
-- each platform's webhook receiver reads the field it recognizes and silently ignores the other,
so one payload shape genuinely works for both without picking a vendor at build time. A service
expecting a different shape (ntfy.sh's default publish endpoint wants a raw text body, not JSON)
needs its own thin adapter in front of this URL -- out of scope for this generic sender, which only
ever promises "a JSON POST with content/text fields", not "works with literally any webhook".

No-op (never raises, never blocks the caller more than a short timeout) whenever the env var is
unset -- purely additive, exactly like every other optional integration in this project.
"""
from __future__ import annotations

import os

import httpx

from agent.utils.logger import get_logger

logger = get_logger("TOOLS")

_WEBHOOK_TIMEOUT_SECONDS = 10.0


def notify(message: str) -> None:
    """Best-effort webhook POST -- failures are logged, never raised, so a flaky/misconfigured
    webhook can never take down the session that triggered it. Synchronous (a short blocking HTTP
    call) since every call site is already in a place that tolerates a few seconds of extra work
    at a natural checkpoint (a session ending, a finding being recorded) rather than deep inside a
    latency-sensitive loop.
    """
    webhook_url = os.getenv("NOTIFY_WEBHOOK_URL", "").strip()
    if not webhook_url:
        return
    try:
        httpx.post(webhook_url, json={"content": message, "text": message}, timeout=_WEBHOOK_TIMEOUT_SECONDS)
    except httpx.HTTPError as exc:
        logger.debug("notifications: webhook POST failed (%s)", exc)


def notify_session_ended(session_name: str, target: str, status: str, findings_count: int) -> None:
    emoji = "✅" if status == "completed" else "⚠️"
    notify(f"{emoji} ASRA session \"{session_name}\" ({target}) ended: {status} — {findings_count} finding(s).")


def notify_high_severity_finding(session_name: str, target: str, finding_title: str, severity: str) -> None:
    notify(f"🚨 ASRA — new {severity} finding on \"{session_name}\" ({target}): {finding_title}")
