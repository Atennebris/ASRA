"""Playbook manager: store list/update/delete/import/seed helpers + the routes behind the UI."""
import json

import pytest
from fastapi.testclient import TestClient

import main
from agent.tools import library_store
from agent.tools import playbook_store


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    monkeypatch.setattr(playbook_store, "PLAYBOOK_STORE_PATH", tmp_path / "playbook" / "techniques.json")
    monkeypatch.setattr(library_store, "resolve_global_app_dir", lambda: tmp_path)


def _seed_one(eid="t1", technique="double encoding", tech=None, waf=None, **extra):
    key = json.dumps({"tech": sorted(tech or ["php"]), "waf": sorted(waf or [])}, sort_keys=True)
    playbook_store.record_technique(key, {"id": eid, "technique": technique, "tech_keywords": sorted(tech or ["php"]),
                                          "waf_vendors": sorted(waf or []), "source_session_ids": ["s1"], **extra})


# --- store manager helpers ---


def test_list_all_techniques_flattens_with_success_rate():
    _seed_one("t1", injected_count=4, led_to_finding_count=2)
    items = playbook_store.list_all_techniques()
    assert len(items) == 1
    assert items[0]["_key"]
    assert items[0]["success_rate"] == 0.5
    assert items[0]["distinct_targets"] == 1


def test_update_technique_edits_soft_fields():
    _seed_one("t1", technique="old")
    assert playbook_store.update_technique("t1", {"technique": "new", "outcome": "failed", "vuln_class": "xss"}) is True
    entry = playbook_store.list_all_techniques()[0]
    assert entry["technique"] == "new"
    assert entry["outcome"] == "failed"
    assert entry["vuln_class"] == "xss"


def test_update_technique_unknown_id_returns_false():
    assert playbook_store.update_technique("nope", {"technique": "x"}) is False


def test_delete_technique_removes_and_drops_empty_key():
    _seed_one("t1")
    assert playbook_store.delete_technique("t1") is True
    assert playbook_store.load_playbook_store() == {}
    assert playbook_store.delete_technique("t1") is False


def test_import_entries_merges_and_dedupes_by_id():
    _seed_one("t1")
    exported = playbook_store.load_playbook_store()
    # importing the same export back adds nothing (dedup by id)
    assert playbook_store.import_entries(exported) == 0
    # a genuinely new entry under a new key is added
    new = {json.dumps({"tech": ["nginx"], "waf": []}, sort_keys=True): [{"id": "t2", "technique": "brand new"}]}
    assert playbook_store.import_entries(new) == 1
    assert playbook_store.count_techniques() == 2


def test_dedupe_all_techniques_merges_identical_text_across_different_keys():
    # Same confirmed technique, two operators, slightly different tech-stack extraction -> two
    # different fingerprint keys. Same "identical technique text" rule import already applies
    # within one key, just widened to the whole store.
    _seed_one("t1", technique="Bypass the WAF via double URL-encoding", tech=["php"], times_confirmed=1,
              last_seen="2026-08-01T00:00:00+00:00", source_session_ids=["s1"])
    _seed_one("t2", technique="bypass the waf via double url-encoding", tech=["php", "wordpress"], times_confirmed=2,
              last_seen="2026-08-20T00:00:00+00:00", source_session_ids=["s2"])  # case differs, newer
    _seed_one("t3", technique="Recover the origin IP via cert transparency logs", tech=["php"])

    removed = playbook_store.dedupe_all_techniques()
    assert removed == 1

    all_ids = {e["id"] for e in playbook_store.list_all_techniques()}
    assert all_ids == {"t2", "t3"}  # t2 is newer (last_seen), kept over t1
    kept = next(e for e in playbook_store.list_all_techniques() if e["id"] == "t2")
    assert kept["times_confirmed"] == 3  # 2 + 1, folded in
    assert set(kept["source_session_ids"]) == {"s1", "s2"}


def test_dedupe_all_techniques_leaves_distinct_techniques_alone():
    _seed_one("t1", technique="technique one")
    _seed_one("t2", technique="technique two")
    assert playbook_store.dedupe_all_techniques() == 0
    assert playbook_store.count_techniques() == 2


def test_find_duplicate_groups_groups_identical_text_across_keys():
    _seed_one("t1", technique="Double encoding bypass", tech=["php"])
    _seed_one("t2", technique="double encoding bypass", tech=["nginx"])  # same text, different case
    _seed_one("t3", technique="a completely different technique")

    groups = playbook_store.find_duplicate_groups()

    assert len(groups) == 1
    assert {e["id"] for e in groups[0]} == {"t1", "t2"}


def test_find_duplicate_groups_empty_when_nothing_duplicated():
    _seed_one("t1", technique="unique one")
    _seed_one("t2", technique="unique two")
    assert playbook_store.find_duplicate_groups() == []


def test_merge_duplicate_group_keeps_operator_chosen_entry_and_sums_attribution():
    _seed_one("t1", technique="dup text", tech=["php"], times_confirmed=2, source_session_ids=["s1"])
    _seed_one("t2", technique="dup text", tech=["nginx"], times_confirmed=3, source_session_ids=["s2"])

    # Deliberately keep the OLDER-looking one (t1), not whichever dedupe_all_techniques's own
    # "most recently confirmed" rule would have picked -- the whole point of a manual choice.
    removed = playbook_store.merge_duplicate_group("t1", ["t2"])

    assert removed == 1
    remaining = playbook_store.list_all_techniques()
    assert len(remaining) == 1
    kept = remaining[0]
    assert kept["id"] == "t1"
    assert kept["times_confirmed"] == 5
    assert set(kept["source_session_ids"]) == {"s1", "s2"}


def test_merge_duplicate_group_returns_zero_when_keep_id_not_found():
    _seed_one("t1", technique="something")
    assert playbook_store.merge_duplicate_group("nonexistent", ["t1"]) == 0
    assert playbook_store.count_techniques() == 1  # untouched


def test_bulk_mark_reviewed_confirms_only_this_sources_unreviewed_entries():
    _seed_one("t1", technique="from source A", source_id="srcA", confidence="unreviewed")
    _seed_one("t2", technique="also from source A", source_id="srcA", confidence="unreviewed")
    _seed_one("t3", technique="from source B", source_id="srcB", confidence="unreviewed")
    _seed_one("t4", technique="already reviewed from A", source_id="srcA", confidence="confirmed")

    affected = playbook_store.bulk_mark_reviewed("srcA", confirmed=True)

    assert affected == 2
    by_id = {e["id"]: e for e in playbook_store.list_all_techniques()}
    assert by_id["t1"]["confidence"] == "confirmed"
    assert by_id["t2"]["confidence"] == "confirmed"
    assert by_id["t3"]["confidence"] == "unreviewed"  # a different source -- must not be touched


def test_bulk_mark_reviewed_reject_deletes_only_this_sources_unreviewed_entries():
    _seed_one("t1", technique="from source A", source_id="srcA", confidence="unreviewed")
    _seed_one("t2", technique="from source B", source_id="srcB", confidence="unreviewed")

    affected = playbook_store.bulk_mark_reviewed("srcA", confirmed=False)

    assert affected == 1
    remaining_ids = {e["id"] for e in playbook_store.list_all_techniques()}
    assert remaining_ids == {"t2"}


def test_add_manual_technique_records_and_keys_it():
    tid = playbook_store.add_manual_technique(
        "Double-encode the payload past the WAF", payload_or_command="%2527",
        tech_keywords=["Nginx", "PHP"], waf_vendors=["Cloudflare"], vuln_class="sqli", worked=True,
    )
    assert tid
    entry = playbook_store.list_all_techniques()[0]
    assert entry["technique"] == "Double-encode the payload past the WAF"
    assert entry["tech_keywords"] == ["nginx", "php"]  # normalized (lowercased, sorted)
    assert entry["waf_vendors"] == ["cloudflare"]
    assert entry["outcome"] == "worked"
    assert entry["source_session_ids"] == ["manual"]
    assert entry["source_type"] == "live"
    assert entry["confidence"] == "confirmed"
    # keyed by the same fingerprint scheme so it's retrievable like any other
    assert entry["_key"] == playbook_store.make_fingerprint_key(["nginx", "php"], ["cloudflare"])


def test_add_manual_technique_empty_is_noop():
    assert playbook_store.add_manual_technique("   ") is None
    assert playbook_store.count_techniques() == 0


def test_playbook_add_route_creates_a_technique():
    client = TestClient(main.app)
    resp = client.post("/api/playbook/add", data={
        "technique": "Manual dead-end note", "tech_keywords": "drupal", "outcome": "failed",
    })
    assert resp.status_code == 200
    entry = playbook_store.list_all_techniques()[0]
    assert entry["technique"] == "Manual dead-end note"
    assert entry["outcome"] == "failed"


def test_import_seed_pack_is_idempotent():
    first = playbook_store.import_seed_pack()
    assert first > 0
    assert playbook_store.import_seed_pack() == 0  # stable ids -> re-import adds nothing


# --- routes ---


def test_playbook_page_renders():
    client = TestClient(main.app)
    resp = client.get("/playbook")
    assert resp.status_code == 200
    assert "Playbook" in resp.text


def test_playbook_page_renders_an_entry_with_cves_but_no_epss_max_key(monkeypatch):
    # Regression guard for a real, confirmed-live crash: a brand new
    # entry that names a CVE but hasn't gone through the separate threat-intel enrichment pass yet
    # (agent/tools/library_store.py's own extracted-technique entries are exactly this shape --
    # extract_cves() populates "cves" immediately, nothing ever sets "epss_max" on that same path)
    # has NO "epss_max" key at all -- not even None. templates/partials/playbook_list.html used to
    # check "t.epss_max is not none", which is True for a genuinely MISSING key too (Jinja's
    # Undefined != None), so it wrongly entered the block and crashed doing arithmetic on Undefined.
    _seed_one("t1", technique="exploit a real named cve", cves=["CVE-2021-41773"])
    client = TestClient(main.app)

    resp = client.get("/api/playbook")

    assert resp.status_code == 200
    assert "exploit a real named cve" in resp.text
    assert "CVE-2021-41773" in resp.text
    assert "border-severity-medium/40" not in resp.text  # the EPSS badge itself must not render, not crash


def test_playbook_list_filters_by_query():
    _seed_one("t1", technique="cloudflare origin exposure", tech=["php"], waf=["cloudflare"])
    _seed_one("t2", technique="drupal node access bug", tech=["drupal"])
    client = TestClient(main.app)

    all_resp = client.get("/api/playbook")
    assert "cloudflare origin exposure" in all_resp.text and "drupal node access bug" in all_resp.text

    filtered = client.get("/api/playbook", params={"q": "cloudflare"})
    assert "cloudflare origin exposure" in filtered.text
    assert "drupal node access bug" not in filtered.text


def test_playbook_list_filters_by_outcome():
    _seed_one("t1", technique="a working lead", outcome="worked")
    _seed_one("t2", technique="a confirmed dead-end", outcome="failed")
    client = TestClient(main.app)

    worked = client.get("/api/playbook", params={"outcome": "worked"})
    assert "a working lead" in worked.text and "a confirmed dead-end" not in worked.text

    failed = client.get("/api/playbook", params={"outcome": "failed"})
    assert "a confirmed dead-end" in failed.text and "a working lead" not in failed.text


def test_playbook_list_filters_by_rank():
    _seed_one("t1", technique="freshly added lead")  # times_confirmed defaults -> bronze
    _seed_one("t2", technique="proven across many targets", times_confirmed=10,
              source_session_ids=[f"s{i}" for i in range(10)], injected_count=10, led_to_finding_count=10)
    client = TestClient(main.app)

    bronze = client.get("/api/playbook", params={"rank": "bronze"})
    assert "freshly added lead" in bronze.text and "proven across many targets" not in bronze.text

    legendary = client.get("/api/playbook", params={"rank": "legendary"})
    assert "proven across many targets" in legendary.text and "freshly added lead" not in legendary.text


def test_playbook_list_sort_by_rank_orders_highest_first():
    _seed_one("t1", technique="weak lead")
    _seed_one("t2", technique="strong proven technique", times_confirmed=10,
              source_session_ids=[f"s{i}" for i in range(10)], injected_count=10, led_to_finding_count=10)
    client = TestClient(main.app)
    resp = client.get("/api/playbook", params={"sort": "rank"})
    assert resp.text.index("strong proven technique") < resp.text.index("weak lead")


def test_playbook_list_filters_by_source_id():
    # Real, confirmed operator complaint: "Review in Playbook" used to dump every unreviewed
    # technique from EVERY library source into one undifferentiated list ("не все вместе в
    # кашу") -- source_id scopes it to exactly one source's own extractions.
    _seed_one("t1", technique="from source A", source_id="srcA", source_type="extracted", confidence="unreviewed")
    _seed_one("t2", technique="from source B", source_id="srcB", source_type="extracted", confidence="unreviewed")
    client = TestClient(main.app)

    resp = client.get("/api/playbook", params={"source_id": "srcA"})

    assert "from source A" in resp.text
    assert "from source B" not in resp.text


def test_playbook_list_source_id_banner_shows_title_and_clear_link():
    _seed_one("t1", technique="a technique", source_id="srcA", source_type="extracted",
              source_title="xss-for-beginners.html", confidence="unreviewed")
    client = TestClient(main.app)

    resp = client.get("/api/playbook", params={"source_id": "srcA"})

    assert "Reviewing techniques extracted from" in resp.text
    assert "xss-for-beginners.html" in resp.text
    assert "Show all techniques" in resp.text


def test_playbook_list_source_id_banner_still_shows_title_when_everything_already_reviewed():
    # Everything from this source was already confirmed/rejected -- the scoped list itself is
    # empty, but the banner (and its title) must still render, not silently disappear.
    _seed_one("t1", technique="already reviewed", source_id="srcA", source_type="extracted",
              source_title="xss-for-beginners.html", confidence="confirmed")
    client = TestClient(main.app)

    resp = client.get("/api/playbook", params={"source_id": "srcA", "confidence": "unreviewed"})

    assert "No techniques match your filters" in resp.text
    assert "xss-for-beginners.html" in resp.text


def test_playbook_card_attribution_line_persists_after_confirm():
    # Real, confirmed operator ask: distinguish battlefield-proven techniques from ones found in
    # theory/articles/books -- the OLD "unreviewed" badge was the only marker of origin, and it
    # disappeared the instant an entry got confirmed, losing that distinction entirely.
    _seed_one("t1", technique="an extracted technique", source_id="srcA", source_type="extracted",
              source_title="some-book.pdf", source_author="Some Author", confidence="unreviewed")
    client = TestClient(main.app)

    before = client.get("/api/playbook")
    assert "From <span" in before.text or "some-book.pdf" in before.text

    client.post("/api/playbook/t1/review", data={"confirmed": "true"})
    after = client.get("/api/playbook")

    assert "some-book.pdf" in after.text
    assert "Some Author" in after.text
    entry = playbook_store.list_all_techniques()[0]
    assert entry["confidence"] == "confirmed"  # actually confirmed, not still unreviewed


def test_playbook_card_omits_attribution_line_for_live_entries():
    _seed_one("t1", technique="a real field-proven technique")  # no source_type -> defaults "live"
    client = TestClient(main.app)

    resp = client.get("/api/playbook")

    assert "an uploaded source" not in resp.text


def test_playbook_edit_form_shows_provenance_block_with_library_link_when_source_still_exists():
    sid = library_store.add_source(b"some real content here", "real-source.txt")
    _seed_one("t1", technique="an extracted technique", source_id=sid, source_type="extracted",
              source_title="real-source.txt", confidence="unreviewed")
    client = TestClient(main.app)

    resp = client.get("/api/playbook")

    assert "not a tested fact" in resp.text  # the provenance block's own review-caution copy
    assert "Open in Library" in resp.text


def test_playbook_edit_form_omits_library_link_when_source_was_deleted():
    # The Library source can be deleted independently -- the entries it produced survive on
    # purpose, but the link to a now-nonexistent source must not be offered.
    _seed_one("t1", technique="an extracted technique", source_id="long-gone-id", source_type="extracted",
              source_title="deleted-source.txt", confidence="unreviewed")
    client = TestClient(main.app)

    resp = client.get("/api/playbook")

    assert "deleted-source.txt" in resp.text
    assert "Open in Library" not in resp.text


def test_playbook_import_route_reports_added_and_skipped_counts():
    _seed_one("t1", technique="already known")
    client = TestClient(main.app)
    exported = playbook_store.load_playbook_store()
    key = json.dumps({"tech": ["nginx"], "waf": []}, sort_keys=True)
    exported.setdefault(key, []).append({"id": "new1", "technique": "brand new one"})
    resp = client.post("/api/playbook/import", data={"data": json.dumps(exported)})
    assert resp.status_code == 200
    assert "Added 1 new technique, skipped 1 already in your playbook." in resp.text
    assert playbook_store.count_techniques() == 2


def test_playbook_dedupe_route_reports_and_removes():
    _seed_one("t1", technique="same technique text", tech=["php"])
    _seed_one("t2", technique="same technique text", tech=["php", "wordpress"])
    client = TestClient(main.app)

    resp = client.post("/api/playbook/dedupe")
    assert resp.status_code == 200
    assert "Removed 1 duplicate technique" in resp.text
    assert playbook_store.count_techniques() == 1


def test_playbook_dedupe_route_reports_none_found():
    _seed_one("t1", technique="unique technique")
    client = TestClient(main.app)

    resp = client.post("/api/playbook/dedupe")
    assert resp.status_code == 200
    assert "No duplicates found." in resp.text


def test_playbook_update_and_delete_routes():
    _seed_one("t1", technique="before")
    client = TestClient(main.app)

    upd = client.post("/api/playbook/t1/update", data={"technique": "after", "outcome": "worked"})
    assert upd.status_code == 200
    assert playbook_store.list_all_techniques()[0]["technique"] == "after"

    dele = client.post("/api/playbook/t1/delete", data={"q": ""})
    assert dele.status_code == 200
    assert playbook_store.count_techniques() == 0


def test_playbook_review_route_confirmed_flips_confidence():
    _seed_one("t1", technique="from a book", source_type="extracted", confidence="unreviewed")
    client = TestClient(main.app)

    resp = client.post("/api/playbook/t1/review", data={"confirmed": "true"})

    assert resp.status_code == 200
    assert playbook_store.list_all_techniques()[0]["confidence"] == "confirmed"


def test_playbook_review_route_rejected_deletes_it():
    _seed_one("t1", technique="from a book", source_type="extracted", confidence="unreviewed")
    client = TestClient(main.app)

    resp = client.post("/api/playbook/t1/review", data={"confirmed": "false"})

    assert resp.status_code == 200
    assert playbook_store.count_techniques() == 0


def test_playbook_bulk_review_route_confirms_all_for_one_source():
    _seed_one("t1", technique="from source A #1", source_id="srcA", confidence="unreviewed")
    _seed_one("t2", technique="from source A #2", source_id="srcA", confidence="unreviewed")
    _seed_one("t3", technique="from source B", source_id="srcB", confidence="unreviewed")
    client = TestClient(main.app)

    resp = client.post("/api/playbook/bulk-review", data={"source_id": "srcA", "confirmed": "true"})

    assert resp.status_code == 200
    assert "Confirmed 2 technique" in resp.text
    by_id = {e["id"]: e for e in playbook_store.list_all_techniques()}
    assert by_id["t1"]["confidence"] == "confirmed"
    assert by_id["t2"]["confidence"] == "confirmed"
    assert by_id["t3"]["confidence"] == "unreviewed"


def test_playbook_bulk_review_route_rejects_all_for_one_source():
    _seed_one("t1", technique="from source A", source_id="srcA", confidence="unreviewed")
    client = TestClient(main.app)

    resp = client.post("/api/playbook/bulk-review", data={"source_id": "srcA", "confirmed": "false"})

    assert resp.status_code == 200
    assert playbook_store.count_techniques() == 0


def test_playbook_list_source_id_banner_shows_bulk_buttons_with_count():
    _seed_one("t1", technique="from source A #1", source_id="srcA", source_title="book.pdf", confidence="unreviewed")
    _seed_one("t2", technique="from source A #2", source_id="srcA", source_title="book.pdf", confidence="unreviewed")
    client = TestClient(main.app)

    resp = client.get("/api/playbook", params={"source_id": "srcA"})

    assert "Confirm all (2)" in resp.text
    assert "Reject all" in resp.text


def test_playbook_list_source_id_banner_omits_bulk_buttons_when_nothing_unreviewed():
    _seed_one("t1", technique="already reviewed", source_id="srcA", confidence="confirmed")
    client = TestClient(main.app)

    resp = client.get("/api/playbook", params={"source_id": "srcA"})

    assert "Confirm all" not in resp.text


def test_playbook_duplicates_route_lists_groups():
    _seed_one("t1", technique="dup text", tech=["php"])
    _seed_one("t2", technique="dup text", tech=["nginx"])
    _seed_one("t3", technique="unique one")
    client = TestClient(main.app)

    resp = client.get("/api/playbook/duplicates")

    assert resp.status_code == 200
    assert "dup text" in resp.text
    assert "unique one" not in resp.text  # not a duplicate -- not shown
    assert "1 duplicate group" in resp.text


def test_playbook_duplicates_route_reports_none_found():
    _seed_one("t1", technique="unique one")
    client = TestClient(main.app)

    resp = client.get("/api/playbook/duplicates")

    assert resp.status_code == 200
    assert "No duplicate techniques found." in resp.text


def test_playbook_duplicates_merge_route_keeps_the_chosen_entry():
    _seed_one("t1", technique="dup text", tech=["php"], times_confirmed=1)
    _seed_one("t2", technique="dup text", tech=["nginx"], times_confirmed=1)
    client = TestClient(main.app)

    resp = client.post("/api/playbook/duplicates/merge", data={"keep_id": "t2", "other_ids": "t1"})

    assert resp.status_code == 200
    remaining = playbook_store.list_all_techniques()
    assert len(remaining) == 1
    assert remaining[0]["id"] == "t2"
    assert "No duplicate techniques found." in resp.text  # re-rendered dialog, nothing left


def test_playbook_toolbar_button_renamed_to_check_duplicates():
    client = TestClient(main.app)
    _seed_one("t1", technique="something")

    resp = client.get("/playbook")

    assert "Check duplicates" in resp.text
    assert "Remove duplicates" not in resp.text


def test_playbook_list_filters_by_unreviewed_confidence():
    _seed_one("t1", technique="proven", source_type="live", confidence="confirmed")
    _seed_one("t2", technique="from a book", source_type="extracted", confidence="unreviewed")
    client = TestClient(main.app)

    resp = client.get("/api/playbook", params={"confidence": "unreviewed"})

    assert resp.status_code == 200
    assert "from a book" in resp.text
    assert "proven" not in resp.text


def test_playbook_update_route_rekeys_on_tech_change():
    _seed_one("t1", technique="before", tech=["php"], waf=[])
    old_key = json.dumps({"tech": ["php"], "waf": []}, sort_keys=True)
    client = TestClient(main.app)

    resp = client.post("/api/playbook/t1/update", data={
        "technique": "before", "outcome": "worked",
        "tech_keywords": "nginx, Cloudflare-Origin", "waf_vendors": "cloudflare",
    })
    assert resp.status_code == 200

    store = playbook_store.load_playbook_store()
    assert old_key not in store
    new_key = json.dumps({"tech": ["cloudflare-origin", "nginx"], "waf": ["cloudflare"]}, sort_keys=True)
    assert store[new_key][0]["id"] == "t1"


def test_playbook_export_returns_json_download():
    _seed_one("t1")
    client = TestClient(main.app)
    resp = client.get("/api/playbook/export")
    assert resp.status_code == 200
    assert "attachment" in resp.headers.get("content-disposition", "")
    assert json.loads(resp.text)  # valid JSON


def test_playbook_import_route_merges():
    client = TestClient(main.app)
    payload = json.dumps({json.dumps({"tech": ["php"], "waf": []}, sort_keys=True): [{"id": "imp1", "technique": "imported"}]})
    resp = client.post("/api/playbook/import", data={"data": payload})
    assert resp.status_code == 200
    assert playbook_store.count_techniques() == 1


def test_playbook_import_route_tolerates_bad_json():
    client = TestClient(main.app)
    resp = client.post("/api/playbook/import", data={"data": "{not json"})
    assert resp.status_code == 200
    assert playbook_store.count_techniques() == 0


def test_playbook_seed_route_adds_pack():
    client = TestClient(main.app)
    resp = client.post("/api/playbook/seed")
    assert resp.status_code == 200
    assert playbook_store.count_techniques() > 0
