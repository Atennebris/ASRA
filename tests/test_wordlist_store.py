"""agent/tools/wordlist_store.py — persisted wordlist-catalog state (operator-downloaded metadata
+ per-tool-role assignments). Same on-disk convention as agent/tools/allowed_targets.py
(load/_write pair, atomic tmp+os.replace, corrupt/missing file treated as empty, never an error).
"""
import json

from agent.tools import wordlist_store


def _isolate(tmp_path, monkeypatch):
    monkeypatch.setattr(wordlist_store, "WORDLIST_STORE_PATH", tmp_path / "assignments.json")


def test_load_wordlist_store_returns_empty_shape_when_file_is_missing(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    assert wordlist_store.load_wordlist_store() == {"downloaded": [], "assignments": {}}


def test_load_wordlist_store_treats_corrupt_json_as_empty(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    wordlist_store.WORDLIST_STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
    wordlist_store.WORDLIST_STORE_PATH.write_text("{not valid json", encoding="utf-8")
    assert wordlist_store.load_wordlist_store() == {"downloaded": [], "assignments": {}}


def test_load_wordlist_store_treats_a_non_object_json_as_empty(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    wordlist_store.WORDLIST_STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
    wordlist_store.WORDLIST_STORE_PATH.write_text("[1, 2, 3]", encoding="utf-8")
    assert wordlist_store.load_wordlist_store() == {"downloaded": [], "assignments": {}}


def test_add_downloaded_wordlist_appends_a_real_persisted_entry(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    wordlist_store.add_downloaded_wordlist("/tmp/x.txt", "x.txt", "https://example.com/x.txt", "passwords")

    on_disk = json.loads(wordlist_store.WORDLIST_STORE_PATH.read_text(encoding="utf-8"))
    assert len(on_disk["downloaded"]) == 1
    assert on_disk["downloaded"][0]["path"] == "/tmp/x.txt"
    assert on_disk["downloaded"][0]["source_url"] == "https://example.com/x.txt"


def test_add_downloaded_wordlist_updates_in_place_on_re_download_of_the_same_path(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    wordlist_store.add_downloaded_wordlist("/tmp/x.txt", "x.txt", "https://example.com/x.txt", "general")
    wordlist_store.add_downloaded_wordlist("/tmp/x.txt", "x.txt", "https://example.com/x.txt", "passwords")

    store = wordlist_store.load_wordlist_store()
    assert len(store["downloaded"]) == 1
    assert store["downloaded"][0]["kind"] == "passwords"


def test_set_assignment_rejects_an_unknown_role(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    try:
        wordlist_store.set_assignment("not_a_real_role", "/tmp/x.txt")
        assert False, "expected ValueError"
    except ValueError:
        pass
    assert wordlist_store.load_wordlist_store()["assignments"] == {}


def test_set_assignment_sets_and_clears(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    wordlist_store.set_assignment("ffuf", "/tmp/x.txt")
    assert wordlist_store.load_wordlist_store()["assignments"]["ffuf"] == "/tmp/x.txt"

    wordlist_store.set_assignment("ffuf", None)
    assert "ffuf" not in wordlist_store.load_wordlist_store()["assignments"]


def test_get_assigned_wordlist_returns_none_when_nothing_assigned(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    assert wordlist_store.get_assigned_wordlist("ffuf") is None


def test_get_assigned_wordlist_returns_the_real_path_when_the_file_exists(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    real_file = tmp_path / "real.txt"
    real_file.write_text("a\n", encoding="utf-8")
    wordlist_store.set_assignment("hydra_passwords", str(real_file))

    assert wordlist_store.get_assigned_wordlist("hydra_passwords") == str(real_file)


def test_get_assigned_wordlist_falls_back_to_none_when_the_assigned_file_is_gone(tmp_path, monkeypatch):
    """A stale assignment (the file got deleted/moved outside this app) must never surface as a
    tool-breaking path -- every caller (ffuf/arjun/hydra/web_login_bruteforce builders) treats None
    as "use my own built-in default", so this is the one place that guarantee has to hold."""
    _isolate(tmp_path, monkeypatch)
    wordlist_store.set_assignment("arjun", str(tmp_path / "never_existed.txt"))
    assert wordlist_store.get_assigned_wordlist("arjun") is None
