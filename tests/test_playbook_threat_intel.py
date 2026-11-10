"""Playbook threat-intel: CVE extraction, KEV/EPSS/CVE-metadata/PoC enrichment (mocked feeds), the
refresh that stamps entries, the actively-exploited ranking boost, and graceful offline behavior."""
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
    monkeypatch.setattr(threat_intel, "_CVE_METADATA_CACHE_PATH", tmp_path / "cve_metadata.json")
    monkeypatch.setattr(threat_intel, "_POC_CACHE_PATH", tmp_path / "poc.json")


def _key(tech):
    return json.dumps({"tech": sorted(tech), "waf": []}, sort_keys=True)


# --- CVE extraction ---


def test_extract_cves_dedupes_and_uppercases():
    got = playbook_store.extract_cves("uses cve-2021-41773 and CVE-2021-41773 plus CVE-2023-1234")
    assert got == ["CVE-2021-41773", "CVE-2023-1234"]


# --- enrichment (mocked feeds) ---


def _fake_feeds(monkeypatch, kev=None, epss=None, cve_records=None, poc=None):
    def fake_get(url):
        if "known_exploited" in url:
            return {"vulnerabilities": [{"cveID": c} for c in (kev or [])]}
        if "epss" in url:
            return {"data": [{"cve": c, "epss": str(s)} for c, s in (epss or {}).items()]}
        if "cvelistV5" in url:
            for cve, record in (cve_records or {}).items():
                if url.endswith(f"/{cve}.json"):
                    return record
            return None
        if "poc-in-github" in url:
            cve = url.split("cve_id=")[-1].upper()
            pocs = (poc or {}).get(cve)
            return {"pocs": pocs} if pocs is not None else {"pocs": []}
        return None
    monkeypatch.setattr(threat_intel, "_http_get_json", fake_get)


_REAL_CVE_RECORD = {
    "containers": {
        "cna": {
            "descriptions": [{"lang": "en", "value": "Apache path traversal and RCE via CGI scripts."}],
            "metrics": [{"cvssV3_1": {"baseScore": 9.8, "baseSeverity": "CRITICAL", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}],
            "affected": [{"vendor": "Apache", "product": "HTTP Server"}],
            "references": [{"url": "https://httpd.apache.org/security/CVE-2021-41773.html"}],
        }
    }
}


def test_enrich_cves_marks_kev_and_epss(monkeypatch):
    _fake_feeds(monkeypatch, kev=["CVE-2021-41773"], epss={"CVE-2021-41773": 0.97, "CVE-2020-0001": 0.02})
    out = threat_intel.enrich_cves(["CVE-2021-41773", "CVE-2020-0001"])
    assert out["CVE-2021-41773"] == {"kev": True, "epss": 0.97}
    assert out["CVE-2020-0001"] == {"kev": False, "epss": 0.02}


def test_enrich_offline_is_graceful(monkeypatch):
    monkeypatch.setattr(threat_intel, "_http_get_json", lambda url: None)  # network down
    out = threat_intel.enrich_cves(["CVE-2021-41773"])
    assert out["CVE-2021-41773"] == {"kev": False, "epss": None}  # no data, but no crash


# --- CVE metadata (cvelistV5) ---


def test_cvelistv5_path_shards_by_thousands_bucket():
    assert threat_intel._cvelistv5_path("CVE-2024-1709") == "cves/2024/1xxx/CVE-2024-1709.json"
    assert threat_intel._cvelistv5_path("cve-2024-12345") == "cves/2024/12xxx/CVE-2024-12345.json"
    assert threat_intel._cvelistv5_path("not-a-cve") is None


def test_cve_metadata_extracts_description_and_cvss(monkeypatch):
    _fake_feeds(monkeypatch, cve_records={"CVE-2021-41773": _REAL_CVE_RECORD})
    out = threat_intel.cve_metadata(["CVE-2021-41773"])
    meta = out["CVE-2021-41773"]
    assert meta["description"] == "Apache path traversal and RCE via CGI scripts."
    assert meta["cvss_score"] == 9.8
    assert meta["cvss_vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert meta["affected"] == [{"vendor": "Apache", "product": "HTTP Server"}]


def test_cve_metadata_falls_back_to_adp_cvss_when_cna_has_none(monkeypatch):
    """Real, confirmed case (CVE-2021-41773): the CNA's own submission has only a free-text
    "critical" severity string, no structured CVSS -- CISA's own ADP "Vulnrichment" container for
    that same CVE carries a real CVSSv3.1 score. Skipping ADP would silently lose CVSS for exactly
    the older, under-scored CVEs most likely to matter."""
    record = {
        "containers": {
            "cna": {
                "descriptions": [{"lang": "en", "value": "Path traversal in Apache HTTP Server."}],
                "metrics": [{"other": {"type": "unknown", "content": {"other": "critical"}}}],
            },
            "adp": [
                {"title": "CVE Program Container"},
                {"title": "CISA ADP Vulnrichment", "metrics": [
                    {"cvssV3_1": {"baseScore": 7.5, "baseSeverity": "HIGH", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}},
                ]},
            ],
        }
    }
    _fake_feeds(monkeypatch, cve_records={"CVE-2021-41773": record})
    meta = threat_intel.cve_metadata(["CVE-2021-41773"])["CVE-2021-41773"]
    assert meta["cvss_score"] == 7.5
    assert meta["severity"] == "HIGH"


def test_cve_metadata_fetch_failure_leaves_cve_out_not_cached(monkeypatch):
    monkeypatch.setattr(threat_intel, "_http_get_json", lambda url: None)  # network down
    out = threat_intel.cve_metadata(["CVE-2021-41773"])
    assert out == {}  # no crash, no false entry


# --- public PoC-repo availability (poc-in-github) ---


def test_poc_availability_sorts_by_stars_and_caps_results(monkeypatch):
    pocs = [
        {"full_name": "a/low", "html_url": "https://github.com/a/low", "stargazers_count": "1"},
        {"full_name": "b/high", "html_url": "https://github.com/b/high", "stargazers_count": "500"},
        {"full_name": "c/mid", "html_url": "https://github.com/c/mid", "stargazers_count": "50"},
    ]
    monkeypatch.setattr(threat_intel, "_poc_result_limit", lambda: 2)
    _fake_feeds(monkeypatch, poc={"CVE-2021-44228": pocs})
    out = threat_intel.poc_availability(["CVE-2021-44228"])
    repos = out["CVE-2021-44228"]
    assert [r["repo"] for r in repos] == ["b/high", "c/mid"]  # sorted desc, capped to 2


def test_poc_availability_disabled_returns_empty(monkeypatch):
    monkeypatch.setenv("THREAT_INTEL_POC_LOOKUP_ENABLED", "false")
    _fake_feeds(monkeypatch, poc={"CVE-2021-44228": [{"full_name": "a/b", "html_url": "u", "stargazers_count": "1"}]})
    assert threat_intel.poc_availability(["CVE-2021-44228"]) == {}


def test_poc_availability_fetch_failure_leaves_cve_out_not_cached(monkeypatch):
    monkeypatch.setattr(threat_intel, "_http_get_json", lambda url: None)  # network down
    out = threat_intel.poc_availability(["CVE-2021-44228"])
    assert out == {}  # no crash, no false "no PoC" cached


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


def test_refresh_threat_intel_also_stamps_cve_metadata_and_poc(monkeypatch):
    pocs = [{"full_name": "a/poc", "html_url": "https://github.com/a/poc", "stargazers_count": "10"}]
    _fake_feeds(monkeypatch, cve_records={"CVE-2021-41773": _REAL_CVE_RECORD}, poc={"CVE-2021-41773": pocs})
    playbook_store.record_technique(_key(["apache"]), {"id": "t1", "technique": "path traversal", "cves": ["CVE-2021-41773"], "source_session_ids": ["s"]})

    updated = playbook_store.refresh_threat_intel()
    assert updated == 1
    entry = playbook_store.list_all_techniques()[0]
    assert entry["cve_description"] == "Apache path traversal and RCE via CGI scripts."
    assert entry["cve_cvss_score"] == 9.8
    assert entry["poc_repos"] == [{"repo": "a/poc", "url": "https://github.com/a/poc", "stars": 10}]


def test_editing_cves_clears_stamped_metadata_and_poc(monkeypatch):
    _fake_feeds(monkeypatch, kev=["CVE-2021-41773"], cve_records={"CVE-2021-41773": _REAL_CVE_RECORD})
    playbook_store.record_technique(_key(["apache"]), {"id": "t1", "technique": "x", "cves": ["CVE-2021-41773"], "source_session_ids": ["s"]})
    playbook_store.refresh_threat_intel()
    assert playbook_store.list_all_techniques()[0].get("cve_description")

    playbook_store.update_technique("t1", {}, cves=["CVE-2099-9999"])
    entry = playbook_store.list_all_techniques()[0]
    assert entry.get("cve_description") is None
    assert entry.get("poc_repos") is None
    assert entry.get("kev") is None


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
