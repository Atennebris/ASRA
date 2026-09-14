"""agent/tools/wordlist_catalog.py — read-only discovery of wordlist files already on disk under
known WSL install locations, plus list_all_wordlists()'s merge with operator-downloaded entries
(agent/tools/wordlist_store.py). Every test points _SCAN_ROOTS/WORDLIST_STORE_PATH at a real
tmp_path structure and reads real files back -- no mocking of the filesystem itself.
"""
from pathlib import Path

from agent.tools import wordlist_catalog, wordlist_store


def _isolate_store(tmp_path, monkeypatch):
    monkeypatch.setattr(wordlist_store, "WORDLIST_STORE_PATH", tmp_path / "assignments.json")


def test_scan_known_wordlists_finds_real_files_under_known_roots(tmp_path, monkeypatch):
    root = tmp_path / "wordlists"
    (root / "sub").mkdir(parents=True)
    (root / "passwords.txt").write_text("a\nb\nc\n", encoding="utf-8")
    (root / "sub" / "usernames.lst").write_text("root\nadmin\n", encoding="utf-8")
    (root / "notes.md").write_text("ignored — wrong extension", encoding="utf-8")

    monkeypatch.setattr(wordlist_catalog, "_SCAN_ROOTS", (root,))

    entries = wordlist_catalog.scan_known_wordlists()

    paths = {e["path"] for e in entries}
    assert str(root / "passwords.txt") in paths
    assert str(root / "sub" / "usernames.lst") in paths
    assert not any(p.endswith("notes.md") for p in paths)

    passwords_entry = next(e for e in entries if e["path"] == str(root / "passwords.txt"))
    assert passwords_entry["line_count"] == 3
    assert passwords_entry["kind"] == "passwords"
    assert passwords_entry["source"] == "detected"


def test_scan_known_wordlists_skips_a_root_that_does_not_exist(tmp_path, monkeypatch):
    monkeypatch.setattr(wordlist_catalog, "_SCAN_ROOTS", (tmp_path / "does-not-exist",))
    assert wordlist_catalog.scan_known_wordlists() == []


def test_scan_known_wordlists_respects_the_file_count_budget(tmp_path, monkeypatch):
    root = tmp_path / "wordlists"
    root.mkdir()
    for i in range(5):
        (root / f"list{i}.txt").write_text("x\n", encoding="utf-8")

    monkeypatch.setattr(wordlist_catalog, "_SCAN_ROOTS", (root,))
    monkeypatch.setattr(wordlist_catalog, "_MAX_FILES_SCANNED", 3)

    assert len(wordlist_catalog.scan_known_wordlists()) == 3


def test_count_lines_returns_none_for_a_file_over_the_size_cap(tmp_path, monkeypatch):
    big_file = tmp_path / "big.txt"
    big_file.write_text("x\n" * 100, encoding="utf-8")

    monkeypatch.setattr(wordlist_catalog, "_MAX_LINE_COUNT_BYTES", 10)
    assert wordlist_catalog._count_lines(big_file, big_file.stat().st_size) is None


def test_guess_kind_matches_known_hints():
    assert wordlist_catalog._guess_kind(Path("/usr/share/wordlists/rockyou.txt")) == "passwords"
    assert wordlist_catalog._guess_kind(Path("/usr/share/seclists/Usernames/top.txt")) == "usernames"
    assert wordlist_catalog._guess_kind(Path("/usr/share/wordlists/ffuf/common.txt")) == "content-discovery"
    assert wordlist_catalog._guess_kind(Path("/some/totally/unrelated/list.txt")) == "general"


def test_list_all_wordlists_merges_detected_and_downloaded(tmp_path, monkeypatch):
    _isolate_store(tmp_path, monkeypatch)
    detected_root = tmp_path / "detected"
    detected_root.mkdir()
    (detected_root / "common.txt").write_text("a\nb\n", encoding="utf-8")
    monkeypatch.setattr(wordlist_catalog, "_SCAN_ROOTS", (detected_root,))

    downloaded_file = tmp_path / "custom.txt"
    downloaded_file.write_text("x\ny\nz\n", encoding="utf-8")
    wordlist_store.add_downloaded_wordlist(str(downloaded_file), "custom.txt", "https://example.com/custom.txt", "passwords")

    combined = wordlist_catalog.list_all_wordlists()

    sources = {e["path"]: e["source"] for e in combined}
    assert sources[str(detected_root / "common.txt")] == "detected"
    assert sources[str(downloaded_file)] == "downloaded"
    downloaded_entry = next(e for e in combined if e["path"] == str(downloaded_file))
    assert downloaded_entry["line_count"] == 3
    assert downloaded_entry["source_url"] == "https://example.com/custom.txt"


def test_list_all_wordlists_omits_a_downloaded_entry_whose_file_is_gone(tmp_path, monkeypatch):
    _isolate_store(tmp_path, monkeypatch)
    monkeypatch.setattr(wordlist_catalog, "_SCAN_ROOTS", (tmp_path / "empty-root",))

    missing_path = tmp_path / "already_deleted.txt"
    wordlist_store.add_downloaded_wordlist(str(missing_path), "already_deleted.txt", "https://example.com/x.txt", "general")

    assert wordlist_catalog.list_all_wordlists() == []


def test_list_all_wordlists_does_not_duplicate_a_downloaded_file_that_is_also_detected(tmp_path, monkeypatch):
    _isolate_store(tmp_path, monkeypatch)
    root = tmp_path / "wordlists"
    root.mkdir()
    shared_path = root / "shared.txt"
    shared_path.write_text("a\n", encoding="utf-8")
    monkeypatch.setattr(wordlist_catalog, "_SCAN_ROOTS", (root,))

    wordlist_store.add_downloaded_wordlist(str(shared_path), "shared.txt", "https://example.com/shared.txt", "general")

    combined = wordlist_catalog.list_all_wordlists()
    assert len([e for e in combined if e["path"] == str(shared_path)]) == 1
