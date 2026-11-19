"""Single, derived verification status for a finding.

ASRA already grades confidence across several fields that each got added at a different time for a
different pass: record_finding's own `verification` (verified/inferred/needs_verification), the blind
end-of-scan skeptical pass (`skeptical_verification`), the optional cross-provider ensemble check
(`ensemble_disagreement`/`ensemble_secondary_verdict`), an explicit ruling-out
(`false_positive_reason`), and a rescan's reverify verdict (session["reverification_history"],
matched to a finding by title). An operator triaging a card has had to read all of those separately
to know "how sure are we, really" -- the competitor exposes one explicit `verify_status` instead.

This module is that one status, COMPUTED on read from the fields that already exist -- never a second
stored source of truth (DRY). The pure function here knows nothing about sessions or the LLM, so it
is trivially unit-testable; the caller passes in the one cross-finding fact it can't see (the last
reverify outcome for this title) rather than this reaching into session state itself. The UI layer
maps the returned canonical status to a label/color/icon (templates/macros/ui.html) -- this module
deliberately carries no presentation strings, only the machine-readable verdict and the context trail
behind it.
"""
from __future__ import annotations

# The one canonical status a finding resolves to, highest-precedence first. This ordering is the
# whole contract: when several signals apply at once, the earlier one wins because it is the more
# decision-relevant thing for an operator to see on the card.
#   false_positive    -- explicitly ruled out (a human/tool said "not real/applicable")
#   fixed             -- a rescan's reverify proved the bug is gone (confirmed_fixed)
#   disputed          -- two independent providers disagree about this finding (needs a human call)
#   refuted           -- the blind skeptical pass could not independently reproduce it
#   verified          -- an active check confirmed it (optionally reproduced a SECOND time, see
#                        independently_reproduced)
#   inferred          -- strong circumstantial evidence, no active confirmation yet
#   needs_verification-- recorded but never actively confirmed (the default/fallback tier)
STATUS_ORDER = (
    "false_positive",
    "fixed",
    "disputed",
    "refuted",
    "verified",
    "inferred",
    "needs_verification",
)


def derive_verification_status(finding: dict, reverify_outcome: str | None = None) -> dict:
    """Collapse a finding's scattered confidence signals into one derived status plus the
    machine-readable context trail that produced it.

    `reverify_outcome` is this finding title's most recent entry in
    session["reverification_history"] (confirmed_present / confirmed_fixed / inconclusive), or None
    for a finding that was never carried over from a prior scan. It is passed in rather than looked
    up here so this stays a pure function -- see the module docstring.

    Returns a dict with:
      status                   -- one value from STATUS_ORDER (the single badge to show)
      disagreement             -- True when the two ensemble providers reached opposite verdicts
      independently_reproduced -- True when the blind skeptical pass confirmed it a second time
      reverify_outcome         -- echoed back for the caller/UI (may be None)
      context                  -- ordered list of {source, outcome, note?, provider?}: what was
                                  checked, by which pass, and what it concluded. This is the
                                  `verification_context` the report/UI render -- one shape, built
                                  from the fields already on the finding, not a third schema.
    """
    verification = finding.get("verification") or "needs_verification"
    skeptical = finding.get("skeptical_verification")
    false_positive_reason = finding.get("false_positive_reason")
    disagreement = bool(finding.get("ensemble_disagreement"))
    ensemble_verdict = finding.get("ensemble_secondary_verdict")
    independently_reproduced = skeptical == "confirmed"

    context = _build_context(finding, verification, skeptical, ensemble_verdict, reverify_outcome)

    if false_positive_reason:
        status = "false_positive"
    elif reverify_outcome == "confirmed_fixed":
        status = "fixed"
    elif disagreement:
        status = "disputed"
    elif skeptical == "refuted":
        status = "refuted"
    elif verification == "verified":
        status = "verified"
    elif verification == "inferred":
        status = "inferred"
    else:
        status = "needs_verification"

    return {
        "status": status,
        "disagreement": disagreement,
        "independently_reproduced": independently_reproduced,
        "reverify_outcome": reverify_outcome,
        "context": context,
    }


def _build_context(
    finding: dict,
    verification: str,
    skeptical: str | None,
    ensemble_verdict: str | None,
    reverify_outcome: str | None,
) -> list[dict]:
    """The ordered "here's what actually checked this" trail. Each entry names the pass (source),
    its verdict (outcome), and, where one exists, the free-text note and the provider that ran it.
    Only passes that actually ran appear -- an absent signal is left out rather than rendered as a
    hollow "not checked" row, so the trail length itself tells an operator how hard a finding was
    looked at."""
    context: list[dict] = [{"source": "primary_analysis", "outcome": verification}]

    if skeptical:
        entry = {"source": "skeptical_verification", "outcome": skeptical}
        note = finding.get("skeptical_verification_note")
        if note:
            entry["note"] = note
        context.append(entry)

    if ensemble_verdict:
        entry = {"source": "ensemble_second_opinion", "outcome": ensemble_verdict}
        provider = finding.get("ensemble_secondary_provider")
        if provider:
            entry["provider"] = provider
        note = finding.get("ensemble_secondary_note")
        if note:
            entry["note"] = note
        context.append(entry)

    if reverify_outcome:
        context.append({"source": "reverify", "outcome": reverify_outcome})

    return context


# The exploit-outcome axis -- a different question from the verification-confidence status above
# (how sure are we it's real) vs. (did a real exploit actually succeed). Every surface that shows
# this -- the collapsed finding card's badge, the detail box, the small meta line, the downloadable
# report in every format -- must say the SAME word for the SAME state. They each used to re-derive it
# inline with subtly different branches and drifted: one finding read "Not exploited" in its meta
# line and "Not exploitable" in its badge/box at the same time. This is the single source for both
# the state partition (derive_exploit_status) and the word shown for it (EXPLOIT_STATUS_LABELS), so
# the words can only ever drift if someone edits this one dict.
#
# "Not exploited" is deliberate over the old "Not exploitable": a real attempt that didn't confirm
# exploitation (a missing credential this project never configured, a WAF block) does NOT mean the
# finding can't be exploited -- "exploitable" overclaims certainty the attempt never established.
EXPLOIT_STATUS_LABELS = {
    "exploited": "Exploited",
    "not_exploited": "Not exploited",
    "not_attempted": "Not attempted",
    "none": "",
}

# exploit_outcome values that mean "no real proof tool ever ran against this finding" (a skip), as
# opposed to "exploit_attempted" which is a real attempt that ran and simply didn't pan out. The
# distinction matters: a skip is not a disproof, so it must never read like one.
_EXPLOIT_SKIP_OUTCOMES = {"skipped_needs_verification", "skipped_no_suitable_tool"}


def derive_exploit_status(finding: dict) -> str:
    """Which of the four exploit-axis states a finding is in, as one machine-readable key from
    EXPLOIT_STATUS_LABELS. Pure, session-unaware, trivially unit-testable -- same contract as
    derive_verification_status above.

      exploited     -- a real exploit succeeded (finding["exploited"] is truthy)
      not_attempted -- a skip: no suitable tool, needs manual verification, an operator/scope
                       decision. A real tool never ran a proof here, so this is NOT a disproof.
      not_exploited -- a real attempt ran and did not confirm exploitation ("exploit_attempted"),
                       or legacy data carrying an advisory_note from before exploit_outcome existed.
      none          -- Exploit never reached this finding yet; there is nothing to say on this axis.
    """
    if finding.get("exploited"):
        return "exploited"
    outcome = finding.get("exploit_outcome")
    if outcome in _EXPLOIT_SKIP_OUTCOMES:
        return "not_attempted"
    if outcome == "exploit_attempted" or finding.get("advisory_note"):
        return "not_exploited"
    return "none"


def latest_reverify_outcome_by_title(reverification_history: list[dict] | None) -> dict[str, str]:
    """Build a title -> most-recent verification_outcome map from a session's reverification_history
    (agent/core.py's _run_reverify appends oldest-to-newest). The UI/report has the finding and this
    map; it looks up the finding's title here to get the one cross-finding fact
    derive_verification_status needs. Kept here, next to its one consumer's contract, rather than
    re-implemented at each call site."""
    outcomes: dict[str, str] = {}
    for entry in reverification_history or []:
        title = entry.get("title")
        outcome = entry.get("verification_outcome")
        if title and outcome:
            outcomes[title] = outcome
    return outcomes
