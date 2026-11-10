"""Shared evidence/confidence envelope for reverse-engineering tool results.

A plain "here's the pseudocode" result gives no signal about how sure the tool actually is, or
what it simply couldn't determine -- a missing field reads identically to "there was nothing
there" and "we never checked." This wraps a tool's own structured output in three buckets instead:

- observed: facts the tool actually measured/read directly (e.g. a decompiled function's own
  pseudocode text, straight from the decompiler -- not guessed, not pattern-matched).
- inferred: conclusions derived indirectly, with real room for error (e.g. "this looks like a
  checksum routine based on its operations and constants" -- a judgment call, not a direct read).
- unknown: facet name -> why it couldn't be determined (a timeout, an unsupported architecture, a
  missing plugin, analysis that never reached that point) -- never a silently absent key. This
  doubles as the "which facets are even available" declaration (pseudocode/assembly/callers/
  callees/references/strings/cfg/...): a facet this result doesn't cover belongs here with a real
  reason, not just omitted from `observed` with no trace it was ever considered.

`method` tags whether the facts came from reading the target without running it ("static") or
from watching it actually execute ("dynamic") -- kept as one top-level tag rather than folded into
`observed` itself, since a single tool can eventually mix both in one call and a reader needs to
tell which bucket a given fact actually came from.

`_evidence.untrusted_content` is always true here: every field above is derived from bytes/text
that originated inside the analyzed target (a string literal, a symbol name, decompiled source),
authored by whoever built that target -- not ASRA, not the operator. It is data to reason about,
never an instruction to follow, no differently than a prompt-injection risk in scraped web content.

FACET_NAMES names the recognized facets a function-level (or contract-level) analysis result can
cover -- the canonical vocabulary `unknown`'s own keys should draw from when the missing thing is
one of these (a tool is free to use other keys too, e.g. a specific field name, when "facet" isn't
the right granularity for what's missing). Declaring unavailable facets explicitly, with a real
reason, is what lets a LATER comparison (e.g. a future cross-version diff)
return `unknown` instead of silently treating "we never checked" as "they match" -- the same
failure class this whole module exists to close.

What a significant `unknown` entry should become next: nothing here escalates it on its own. A
tool call's own `unknown` dict is scoped to that one call's result -- if an unknown is worth
investigating further (not just a transient "this analysis mode doesn't cover that," but a real
open question a later tool call or a human might resolve), the model's own next step is to raise
it via the EXISTING record_hypothesis tool (agent/tools/native.py), framed as the open question
itself (e.g. text="Could not determine whether function X validates its length parameter --
decompilation timed out before reaching that path"). record_hypothesis already has the real
plumbing an equivalent "unknowns ledger" would also need from scratch -- session-scoped
persistence, resurfacing across later phases via the task prompt, explicit resolution tracking
(resolve_hypothesis) -- so a second, parallel ledger here would mostly duplicate it for a
different label on the same underlying need, not add real capability. A session-portable,
integrity-checked export of the whole evidence trail (REA's own export_evidence_bundle) is
deliberately NOT built here either -- there is no real consumer for it inside ASRA today; building
it speculatively, ahead of an actual importing consumer, is exactly the premature-architecture
YAGNI warns against. Revisit if/when something inside ASRA actually needs to import one.
"""
from __future__ import annotations

from typing import Literal

Method = Literal["static", "dynamic"]

FACET_NAMES = (
    "pseudocode", "assembly", "comments", "callers", "callees",
    "references", "strings_names", "cfg",
)


def evidence_result(
    observed: dict,
    *,
    inferred: dict | None = None,
    unknown: dict[str, str] | None = None,
    method: Method = "static",
) -> dict:
    return {
        "observed": observed,
        "inferred": inferred or {},
        "unknown": unknown or {},
        "_evidence": {"method": method, "untrusted_content": True},
    }
