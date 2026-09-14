"""main.py's _resolve_pinned_refs (Jinja filter "resolve_pinned_refs") -- the collapsed-chat side
panel's Pinned rail resolves session["pinned_refs"] (the same F#/H#/R# ids chat_ref() already
renders everywhere, agent/chat.py's _session_snapshot numbers them identically) back into the real
finding/hypothesis/recon-target object each one refers to.
"""
import main


def _session(pinned_refs, findings=None, hypotheses=None, recon_targets=None):
    return {
        "pinned_refs": pinned_refs,
        "findings": findings or [],
        "hypotheses": hypotheses or [],
        "recon_result": {"targets": recon_targets or []},
    }


def test_resolves_a_pinned_finding():
    session = _session(["F1"], findings=[{"title": "SQLi in login", "severity": "High"}])
    resolved = main._resolve_pinned_refs(session)
    assert resolved == [{"ref": "F1", "kind": "finding", "title": "SQLi in login", "meta": "High"}]


def test_resolves_a_pinned_hypothesis():
    session = _session(["H1"], hypotheses=[{"text": "Maybe IDOR", "status": "open"}])
    resolved = main._resolve_pinned_refs(session)
    assert resolved == [{"ref": "H1", "kind": "hypothesis", "title": "Maybe IDOR", "meta": "open"}]


def test_resolves_a_pinned_recon_target():
    session = _session(["R1"], recon_targets=[{"host": "example.com", "port": 443, "service": "https"}])
    resolved = main._resolve_pinned_refs(session)
    assert resolved == [{"ref": "R1", "kind": "recon", "title": "example.com:443", "meta": "https"}]


def test_out_of_range_index_is_skipped_not_a_crash():
    session = _session(["F5"], findings=[{"title": "only one", "severity": "Low"}])
    assert main._resolve_pinned_refs(session) == []


def test_unknown_prefix_is_skipped():
    session = _session(["Z1"], findings=[{"title": "x", "severity": "Low"}])
    assert main._resolve_pinned_refs(session) == []


def test_malformed_ref_is_skipped():
    session = _session(["not-a-ref"])
    assert main._resolve_pinned_refs(session) == []


def test_empty_pinned_refs_returns_empty_list():
    assert main._resolve_pinned_refs(_session([])) == []
    assert main._resolve_pinned_refs({}) == []


def test_preserves_pinned_refs_order_and_resolves_several_kinds_together():
    session = _session(
        ["H1", "F1"],
        findings=[{"title": "finding one", "severity": "Critical"}],
        hypotheses=[{"text": "hypothesis one", "status": "confirmed"}],
    )
    resolved = main._resolve_pinned_refs(session)
    assert [item["ref"] for item in resolved] == ["H1", "F1"]
