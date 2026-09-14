"""Playbook threat-intel: CVE extraction, KEV/EPSS enrichment (mocked feeds), the refresh that
stamps entries, the actively-exploited ranking boost, and graceful offline behavior."""
import json

import pytest
from fastapi.testclient import TestClient

import main
from agent.tools import playbook_store, threat_intel


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    monkeypatch.setattr(playbook_store, "PLAYBOOK_STORE_PATH", tmp_path / "playbook" / "techniques.json")
    monkeypatch.setattr(threat_intel, "_KEV_CACHE_PATH", tmp_path / "kev.json")
    monkeypatch.setattr(threat_intel, "_EPSS_CACHE_PATH", tmp_path / "epss.json")


def _key(tech):
    return json.dumps({"tech": sorted(tech), "waf": []}, sort_keys=True)


# --- CVE extraction ---


def test_extract_cves_dedupes_and_uppercases():
    got = playbook_store.extract_cves("uses cve-2021-41773 and CVE-2021-41773 plus CVE-2023-1234")
    assert got == ["CVE-2021-41773", "CVE-2023-1234"]


# --- enrichment (mocked feeds) ---


def _fake_feeds(monkeypatch, kev=None, epss=None):
    def fake_get(url):
        if "known_exploited" in url:
            return {"vulnerabilities": [{"cveID": c} for c in (kev or [])]}
        if "epss" in url:
            return {"data": [{"cve": c, "epss": str(s)} for c, s in (epss or {}).items()]}
        return None
    monkeypatch.setattr(threat_intel, "_http_get_json", fake_get)


def test_enrich_cves_marks_kev_and_epss(monkeypatch):
    _fake_feeds(monkeypatch, kev=["CVE-2021-41773"], epss={"CVE-2021-41773": 0.97, "CVE-2020-0001": 0.02})
    out = threat_intel.enrich_cves(["CVE-2021-41773", "CVE-2020-0001"])
    assert out["CVE-2021-41773"] == {"kev": True, "epss": 0.97}
    assert out["CVE-2020-0001"] == {"kev": False, "epss": 0.02}


def test_enrich_offline_is_graceful(monkeypatch):
    monkeypatch.setattr(threat_intel, "_http_get_json", lambda url: None)  # network down
    out = threat_intel.enrich_cves(["CVE-2021-41773"])
    assert out["CVE-2021-41773"] == {"kev": False, "epss": None}  # no data, but no crash


# --- refresh stamps entries + ranking boost ---


def test_refresh_threat_intel_stamps_kev_and_epss(monkeypatch):
    _fake_feeds(monkeypatch, kev=["CVE-2021-41773"], epss={"CVE-2021-41773": 0.9})
    playbook_store.record_technique(_key(["apache"]), {"id": "t1", "technique": "path traversal", "cves": ["CVE-2021-41773"], "source_session_ids": ["s"]})
    playbook_store.record_technique(_key(["apache"]), {"id": "t2", "technique": "other", "cves": [], "source_session_ids": ["s"]})

    updated = playbook_store.refresh_threat_intel()
    assert updated == 1
    by_id = {e["id"]: e for e in playbook_store.list_all_techniques()}
    assert by_id["t1"]["kev"] is True
    assert by_id["t1"]["epss_max"] == 0.9
    assert by_id["t2"].get("kev") in (None, False)


def test_kev_boost_ranks_actively_exploited_higher():
    playbook_store.record_technique(_key(["apache"]), {"id": "hot", "technique": "a", "cves": ["CVE-2021-41773"], "kev": True, "epss_max": 0.9, "source_session_ids": ["s"]})
    playbook_store.record_technique(_key(["apache"]), {"id": "cold", "technique": "b", "cves": [], "source_session_ids": ["s"]})
    matches = playbook_store.find_similar_techniques({"apache"}, set(), 5)
    assert matches[0]["id"] == "hot"


# --- route ---


def test_refresh_intel_route(monkeypatch):
    _fake_feeds(monkeypatch, kev=["CVE-2021-41773"], epss={"CVE-2021-41773": 0.8})
    playbook_store.record_technique(_key(["apache"]), {"id": "t1", "technique": "x", "cves": ["CVE-2021-41773"], "source_session_ids": ["s"]})
    client = TestClient(main.app)
    resp = client.post("/api/playbook/refresh-intel")
    assert resp.status_code == 200
    assert playbook_store.list_all_techniques()[0]["kev"] is True
