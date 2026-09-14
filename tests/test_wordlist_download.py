"""agent/tools/wordlist_download.py — fetches an operator-supplied URL into data/wordlists/,
exclusively human-triggered (no ToolSpec registration, the LLM agent can never call this).

Same httpx.MockTransport pattern already used by tests/test_cors_check.py -- a real httpx.Client
runs against a fake transport, so the download function's own streaming/chunking/error-handling
code path is genuinely exercised, just without touching the real network.
"""
import httpx

from agent.tools import wordlist_download, wordlist_store

_RealHTTPXClient = httpx.Client


def _mock_httpx_client(handler):
    def factory(**kwargs):
        kwargs.pop("transport", None)
        return _RealHTTPXClient(transport=httpx.MockTransport(handler), **kwargs)
    return factory


def _isolate(tmp_path, monkeypatch):
    monkeypatch.setattr(wordlist_download, "DOWNLOAD_DIR", tmp_path / "wordlists")
    monkeypatch.setattr(wordlist_store, "WORDLIST_STORE_PATH", tmp_path / "assignments.json")


def test_download_wordlist_rejects_a_non_http_scheme(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    try:
        wordlist_download.download_wordlist("ftp://example.com/x.txt", "", "general")
        assert False, "expected ValueError"
    except ValueError as exc:
        assert "http" in str(exc)


def test_download_wordlist_writes_the_real_file_and_registers_metadata(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"admin\nroot\ntest\n")

    monkeypatch.setattr(wordlist_download.httpx, "Client", _mock_httpx_client(handler))

    result = wordlist_download.download_wordlist("https://example.com/users.txt", "", "usernames")

    dest = wordlist_download.DOWNLOAD_DIR / "users.txt"
    assert dest.read_bytes() == b"admin\nroot\ntest\n"
    assert result["downloaded"][0]["source_url"] == "https://example.com/users.txt"
    assert result["downloaded"][0]["kind"] == "usernames"
    # No leftover .part temp file once the real download completed successfully.
    assert not (wordlist_download.DOWNLOAD_DIR / "users.txt.part").exists()


def test_download_wordlist_raises_a_clean_error_on_http_failure_status(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404)

    monkeypatch.setattr(wordlist_download.httpx, "Client", _mock_httpx_client(handler))

    try:
        wordlist_download.download_wordlist("https://example.com/missing.txt", "", "general")
        assert False, "expected ValueError"
    except ValueError as exc:
        assert "download failed" in str(exc)
    # mkdir() runs before the request -- the directory exists, but nothing was ever written to it.
    assert list(wordlist_download.DOWNLOAD_DIR.glob("*")) == []


def test_download_wordlist_raises_and_cleans_up_when_the_size_cap_is_exceeded(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    monkeypatch.setattr(wordlist_download, "_MAX_DOWNLOAD_BYTES", 4)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"this response is way bigger than the cap")

    monkeypatch.setattr(wordlist_download.httpx, "Client", _mock_httpx_client(handler))

    try:
        wordlist_download.download_wordlist("https://example.com/big.txt", "", "general")
        assert False, "expected ValueError"
    except ValueError as exc:
        assert "download cap" in str(exc)

    # Neither the final file nor its .part temp file survive an aborted, oversized download.
    assert not (wordlist_download.DOWNLOAD_DIR / "big.txt").exists()
    assert not (wordlist_download.DOWNLOAD_DIR / "big.txt.part").exists()
    assert wordlist_store.load_wordlist_store()["downloaded"] == []


def test_download_wordlist_raises_a_clean_error_on_network_failure(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("simulated network failure", request=request)

    monkeypatch.setattr(wordlist_download.httpx, "Client", _mock_httpx_client(handler))

    try:
        wordlist_download.download_wordlist("https://example.com/x.txt", "", "general")
        assert False, "expected ValueError"
    except ValueError as exc:
        assert "download failed" in str(exc)


def test_download_wordlist_gives_a_different_path_to_an_unrelated_url_with_the_same_filename(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)

    def make_handler(body: bytes):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, content=body)
        return handler

    monkeypatch.setattr(wordlist_download.httpx, "Client", _mock_httpx_client(make_handler(b"first\n")))
    first = wordlist_download.download_wordlist("https://example.com/repo-a/common.txt", "common.txt", "general")

    monkeypatch.setattr(wordlist_download.httpx, "Client", _mock_httpx_client(make_handler(b"second\n")))
    second = wordlist_download.download_wordlist("https://example.com/repo-b/common.txt", "common.txt", "general")

    first_path = first["downloaded"][0]["path"]
    second_path = second["downloaded"][-1]["path"]
    assert first_path != second_path
    assert len(wordlist_store.load_wordlist_store()["downloaded"]) == 2


def test_download_wordlist_reuses_the_same_path_on_a_re_download_of_the_same_url(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)

    def make_handler(body: bytes):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, content=body)
        return handler

    monkeypatch.setattr(wordlist_download.httpx, "Client", _mock_httpx_client(make_handler(b"v1\n")))
    first = wordlist_download.download_wordlist("https://example.com/list.txt", "list.txt", "general")

    monkeypatch.setattr(wordlist_download.httpx, "Client", _mock_httpx_client(make_handler(b"v2\n")))
    second = wordlist_download.download_wordlist("https://example.com/list.txt", "list.txt", "general")

    assert first["downloaded"][0]["path"] == second["downloaded"][0]["path"]
    assert len(second["downloaded"]) == 1
    assert (wordlist_download.DOWNLOAD_DIR / "list.txt").read_bytes() == b"v2\n"
