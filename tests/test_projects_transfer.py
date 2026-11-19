"""Projects tab Export / Import (sessions/transfer.py + /api/projects/* routes): the archive is
untrusted input, so these pin the safety properties (no path escape, no overwrite without being
asked, no carried-over run state) as much as the happy path."""
import io
import json
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import main
from projects import paths as project_paths
from sessions import store, transfer
from sessions.store import create_session, load_session, save_session


@pytest.fixture()
def isolated(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path / "legacy")
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    monkeypatch.setattr(store, "SUMMARY_INDEX_PATH", tmp_path / "sessions_summary.json")
    monkeypatch.setenv("PROJECTS_DIR", str(tmp_path / "projects"))
    project_paths.resolve_projects_base_dir.cache_clear()
    yield tmp_path
    project_paths.resolve_projects_base_dir.cache_clear()


def _make_project(tmp_dir_unused=None, name="Acme", **overrides):
    session_id = create_session("https://example.com", name=name)
    data = load_session(session_id)
    data.update(overrides)
    save_session(session_id, data)
    return session_id, store.get_session_folder(session_id)


def _export_bytes(isolated, **kwargs) -> bytes:
    path = isolated / "export-under-test.zip"
    transfer.export_projects(path, **kwargs)
    return path.read_bytes()


def _archive_with(members: dict[str, bytes], projects: list[dict]) -> io.BytesIO:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("manifest.json", json.dumps({"format": "asra-projects", "version": 1, "projects": projects}))
        for name, content in members.items():
            archive.writestr(name, content)
    buffer.seek(0)
    return buffer


def test_roundtrip_into_an_empty_machine_restores_project(isolated):
    session_id, _ = _make_project(name="Acme", findings=[{"title": "XSS"}])
    blob = _export_bytes(isolated, session_ids=[session_id])
    store.delete_session(session_id)
    assert load_session(session_id) is None

    results = transfer.import_archive(io.BytesIO(blob))

    assert [r["status"] for r in results] == ["imported"]
    restored = load_session(session_id)
    assert restored["name"] == "Acme"
    assert restored["findings"] == [{"title": "XSS"}]


def test_running_project_arrives_interrupted_without_machine_bound_state(isolated):
    session_id, _ = _make_project(
        name="Live", status="processing", background_jobs={"j1": {"pid": 4242}}, identity_a_configured=True,
    )
    blob = _export_bytes(isolated, session_ids=[session_id])
    store.delete_session(session_id)

    transfer.import_archive(io.BytesIO(blob))

    restored = load_session(session_id)
    assert restored["status"] == "interrupted"
    assert restored["background_jobs"] == {}
    assert restored["identity_a_configured"] is False


def test_existing_project_is_skipped_by_default_and_left_untouched(isolated):
    session_id, _ = _make_project(name="Acme", goal="mine")
    blob = _export_bytes(isolated, session_ids=[session_id])
    data = load_session(session_id)
    data["goal"] = "changed locally"
    save_session(session_id, data)

    results = transfer.import_archive(io.BytesIO(blob))

    assert results[0]["status"] == "skipped"
    assert load_session(session_id)["goal"] == "changed locally"


def test_copy_mode_creates_a_second_project_with_a_new_id_and_unique_name(isolated):
    session_id, _ = _make_project(name="Acme")
    blob = _export_bytes(isolated, session_ids=[session_id])

    results = transfer.import_archive(io.BytesIO(blob), transfer.CONFLICT_COPY)

    new_id = results[0]["session_id"]
    assert results[0]["status"] == "copied" and new_id != session_id
    assert load_session(new_id)["name"] == "Acme (copy)"
    assert load_session(session_id)["name"] == "Acme"


def test_replace_mode_overwrites_but_never_a_running_project(isolated):
    session_id, _ = _make_project(name="Acme", goal="from archive")
    blob = _export_bytes(isolated, session_ids=[session_id])
    data = load_session(session_id)
    data["goal"] = "local edit"
    save_session(session_id, data)

    assert transfer.import_archive(io.BytesIO(blob), transfer.CONFLICT_REPLACE)[0]["status"] == "replaced"
    assert load_session(session_id)["goal"] == "from archive"

    data = load_session(session_id)
    data["status"] = "processing"
    data["goal"] = "running now"
    save_session(session_id, data)
    assert transfer.import_archive(io.BytesIO(blob), transfer.CONFLICT_REPLACE)[0]["status"] == "skipped"
    assert load_session(session_id)["goal"] == "running now"


def test_export_leaves_out_logs_and_backups_unless_asked_and_strips_headers(isolated):
    session_id, folder = _make_project(name="Acme", custom_headers="Authorization: Bearer secret")
    (Path(folder) / "debug.log").write_text("log line")
    (Path(folder) / "backups").mkdir()
    (Path(folder) / "backups" / "backup-1.tar.gz").write_bytes(b"x")

    plain = zipfile.ZipFile(io.BytesIO(_export_bytes(isolated, session_ids=[session_id])))
    assert not any(n.endswith("debug.log") or "/backups/" in n for n in plain.namelist())
    session_member = next(n for n in plain.namelist() if n.endswith("/session.json"))
    assert json.loads(plain.read(session_member))["custom_headers"] == ""

    full = zipfile.ZipFile(io.BytesIO(_export_bytes(isolated, session_ids=[session_id], include_logs=True, include_headers=True)))
    assert any(n.endswith("debug.log") for n in full.namelist())
    assert not any("/backups/" in n for n in full.namelist())
    assert "secret" in full.read(session_member).decode()


@pytest.mark.parametrize("evil", [
    "projects/Acme-usr_aaaaaa/../../escape.txt",
    "/etc/passwd",
    "projects/Acme-usr_aaaaaa/..\\..\\escape.txt",
    "C:/Windows/evil.txt",
])
def test_archive_with_an_escaping_member_path_is_rejected_before_anything_is_written(isolated, evil):
    entry = {"session_id": "usr_aaaaaa", "name": "Acme", "dirname": "Acme-usr_aaaaaa"}
    archive = _archive_with({"projects/Acme-usr_aaaaaa/session.json": b"{}", evil: b"pwned"}, [entry])

    with pytest.raises(transfer.ProjectTransferError):
        transfer.import_archive(archive)

    assert not (isolated / "escape.txt").exists()
    assert store.list_session_summaries() == []


def test_non_archive_inputs_are_rejected_with_a_clear_error(isolated):
    with pytest.raises(transfer.ProjectTransferError, match="valid .zip"):
        transfer.import_archive(io.BytesIO(b"not a zip"))

    plain = io.BytesIO()
    with zipfile.ZipFile(plain, "w") as archive:
        archive.writestr("hello.txt", "hi")
    plain.seek(0)
    with pytest.raises(transfer.ProjectTransferError, match="not an ASRA"):
        transfer.import_archive(plain)


def test_unpacked_size_cap_stops_a_bomb(isolated, monkeypatch):
    monkeypatch.setenv("PROJECTS_IMPORT_MAX_UNPACKED_MB", "1")
    entry = {"session_id": "usr_aaaaaa", "name": "Big", "dirname": "Big-usr_aaaaaa"}
    archive = _archive_with(
        {"projects/Big-usr_aaaaaa/session.json": b"{}", "projects/Big-usr_aaaaaa/blob.bin": b"0" * (2 * 1024 * 1024)},
        [entry],
    )
    with pytest.raises(transfer.ProjectTransferError, match="limit"):
        transfer.import_archive(archive)


def test_routes_export_download_and_import_roundtrip(isolated):
    session_id, _ = _make_project(name="Route Project")
    client = TestClient(main.app)

    response = client.get("/api/projects/export", params={"ids": session_id})
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/zip"
    assert "attachment" in response.headers["content-disposition"]
    store.delete_session(session_id)

    reply = client.post("/api/projects/import", files={"file": ("a.zip", response.content, "application/zip")}, data={"conflict": "skip"})
    assert reply.status_code == 200
    assert reply.json()["results"][0]["status"] == "imported"

    bad = client.post("/api/projects/import", files={"file": ("a.zip", b"nope", "application/zip")})
    assert bad.status_code == 400 and bad.json()["ok"] is False
    assert client.get("/api/projects/export", params={"ids": "usr_zzzzzz"}).status_code == 400
