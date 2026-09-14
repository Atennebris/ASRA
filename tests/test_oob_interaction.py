"""oob_generate/oob_poll: real out-of-band interaction confirmation for the one class of finding
no other tool here can confirm at all (blind SSRF/XSS/injection). Mocks _run_interactsh (the
subprocess boundary) so these tests never depend on interactsh-client actually being installed or
on network access to a real interactsh server -- the real binary was already verified live,
end-to-end, against oast.fun with a genuine triggered HTTP interaction during development.
"""
from agent.tools import native


def test_oob_generate_returns_tool_unavailable_without_the_binary(monkeypatch, tmp_path):
    monkeypatch.setattr(native, "_interactsh_client_path", lambda: None)
    result = native.oob_generate({})
    assert result == {"status": "tool_unavailable", "tool": "oob_generate"}


def test_oob_generate_parses_the_domain_from_client_output(monkeypatch, tmp_path):
    monkeypatch.setattr(native, "_interactsh_client_path", lambda: "/fake/interactsh-client")
    monkeypatch.setattr(native, "_OOB_SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(
        native,
        "_run_interactsh",
        lambda args, run_seconds: "[INF] Listing 1 payload for OOB Testing\n[INF] d9fq1f4kobtc5vq7tpo0nuuuxuu6n5ndc.oast.online\n",
    )

    result = native.oob_generate({})

    assert result["status"] == "ok"
    assert result["domain"] == "d9fq1f4kobtc5vq7tpo0nuuuxuu6n5ndc.oast.online"
    assert "token" in result


def test_oob_generate_errors_when_no_domain_appears_in_output(monkeypatch, tmp_path):
    monkeypatch.setattr(native, "_interactsh_client_path", lambda: "/fake/interactsh-client")
    monkeypatch.setattr(native, "_OOB_SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(native, "_run_interactsh", lambda args, run_seconds: "some unrelated error text")

    result = native.oob_generate({})

    assert result["status"] == "error"


def test_oob_poll_rejects_an_unknown_token(monkeypatch, tmp_path):
    monkeypatch.setattr(native, "_OOB_SESSIONS_DIR", tmp_path)
    result = native.oob_poll({"token": "does-not-exist"})
    assert result["status"] == "error"
    assert "does-not-exist" in result["error"]


def test_oob_poll_extracts_interaction_json_lines_and_ignores_banner_noise(monkeypatch, tmp_path):
    monkeypatch.setattr(native, "_OOB_SESSIONS_DIR", tmp_path)
    session_file = tmp_path / "abc123.json"
    session_file.write_text("{}")

    fake_output = (
        "    _       __\n"
        "[INF] Listing 1 payload for OOB Testing\n"
        "[INF] somedomain.oast.fun\n"
        '{"protocol":"http","unique-id":"x","raw-request":"GET /probe1 HTTP/1.1","remote-address":"1.2.3.4","timestamp":"now"}\n'
        '{"protocol":"dns","unique-id":"x","q-type":"A","remote-address":"5.6.7.8","timestamp":"now"}\n'
        "not json at all\n"
    )
    monkeypatch.setattr(native, "_interactsh_client_path", lambda: "/fake/interactsh-client")
    monkeypatch.setattr(native, "_run_interactsh", lambda args, run_seconds: fake_output)

    result = native.oob_poll({"token": "abc123"})

    assert result["status"] == "ok"
    assert result["interaction_count"] == 2
    assert result["interactions"][0]["protocol"] == "http"
    assert result["interactions"][1]["protocol"] == "dns"


def test_oob_poll_reports_no_interactions_when_none_happened_yet(monkeypatch, tmp_path):
    monkeypatch.setattr(native, "_OOB_SESSIONS_DIR", tmp_path)
    session_file = tmp_path / "abc123.json"
    session_file.write_text("{}")

    monkeypatch.setattr(native, "_interactsh_client_path", lambda: "/fake/interactsh-client")
    monkeypatch.setattr(native, "_run_interactsh", lambda args, run_seconds: "[INF] Listing 1 payload\n[INF] newdomain.oast.fun\n")

    result = native.oob_poll({"token": "abc123"})

    assert result["status"] == "ok"
    assert result["interaction_count"] == 0
    assert result["interactions"] == []
