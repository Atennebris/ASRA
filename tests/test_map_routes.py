"""main.py's Map tab CRUD routes (POST /api/session/{id}/map/...) -- operator-authored nodes/edges
and drag-position persistence merged into _build_attack_surface_graph, see tests/test_attack_surface_graph.py
for that merge logic's own coverage. These tests exercise the actual HTTP routes: reload_merge_save
writing through to session.json, and the validation each route is responsible for.
"""
from fastapi.testclient import TestClient

import main
from sessions import store


def _session(session_id, **extra):
    return {
        "session_id": session_id, "name": "test", "target": "example.com", "status": "processing",
        "mode": "agent", "created_at": "2026-01-01T00:00:00+00:00", "logs": [], "findings": [],
        "approvals": [], "chat": {"summary": "", "messages": []},
        "recon_result": {"targets": [{"host": "example.com", "port": 443}]},
        **extra,
    }


def test_create_map_node_persists_and_returns_ok():
    session_id = "usr_map_node_create"
    store.save_session(session_id, _session(session_id))
    client = TestClient(main.app)

    resp = client.post(f"/api/session/{session_id}/map/node", data={"label": "Third-party VPN", "kind": "actor", "notes": "external"})
    assert resp.status_code == 200
    nodes = store.load_session(session_id)["map_manual"]["nodes"]
    assert len(nodes) == 1
    assert nodes[0]["label"] == "Third-party VPN"
    assert nodes[0]["kind"] == "actor"
    assert nodes[0]["id"].startswith("manual-")
    store.delete_session(session_id)


def test_create_map_node_rejects_an_unknown_kind():
    session_id = "usr_map_node_bad_kind"
    store.save_session(session_id, _session(session_id))
    client = TestClient(main.app)

    resp = client.post(f"/api/session/{session_id}/map/node", data={"label": "X", "kind": "spaceship"})
    assert resp.status_code == 400
    assert store.load_session(session_id).get("map_manual") is None
    store.delete_session(session_id)


def test_create_map_node_rejects_a_blank_label():
    session_id = "usr_map_node_blank_label"
    store.save_session(session_id, _session(session_id))
    client = TestClient(main.app)

    resp = client.post(f"/api/session/{session_id}/map/node", data={"label": "   ", "kind": "host"})
    assert resp.status_code == 400
    store.delete_session(session_id)


def test_edit_map_node_updates_fields():
    session_id = "usr_map_node_edit"
    store.save_session(session_id, _session(session_id, map_manual={"nodes": [{"id": "manual-x", "label": "Old", "kind": "host", "notes": ""}], "edges": [], "positions": {}}))
    client = TestClient(main.app)

    resp = client.post(f"/api/session/{session_id}/map/node/manual-x/edit", data={"label": "New", "kind": "service", "notes": "updated"})
    assert resp.status_code == 200
    node = store.load_session(session_id)["map_manual"]["nodes"][0]
    assert node["label"] == "New"
    assert node["kind"] == "service"
    assert node["notes"] == "updated"
    store.delete_session(session_id)


def test_edit_map_node_404s_for_a_node_that_does_not_exist():
    session_id = "usr_map_node_edit_missing"
    store.save_session(session_id, _session(session_id))
    client = TestClient(main.app)

    resp = client.post(f"/api/session/{session_id}/map/node/manual-nope/edit", data={"label": "New", "kind": "host"})
    assert resp.status_code == 404
    store.delete_session(session_id)


def test_delete_map_node_rejects_a_real_recon_derived_node_id():
    session_id = "usr_map_node_delete_guard"
    store.save_session(session_id, _session(session_id))
    client = TestClient(main.app)

    resp = client.post(f"/api/session/{session_id}/map/node/example.com/delete")
    assert resp.status_code == 400
    store.delete_session(session_id)


def test_delete_map_node_cascades_to_its_own_manual_edges():
    session_id = "usr_map_node_delete_cascade"
    store.save_session(session_id, _session(session_id, map_manual={
        "nodes": [{"id": "manual-a", "label": "A", "kind": "actor", "notes": ""}],
        "edges": [{"id": "manual-e1", "source": "manual-a", "target": "example.com", "direction": "forward",
                   "data_type": "", "volume": "", "format": "", "interval": "", "label": "", "notes": ""}],
        "positions": {"manual-a": {"x": 1, "y": 2}},
    }))
    client = TestClient(main.app)

    resp = client.post(f"/api/session/{session_id}/map/node/manual-a/delete")
    assert resp.status_code == 200
    manual = store.load_session(session_id)["map_manual"]
    assert manual["nodes"] == []
    assert manual["edges"] == []
    assert "manual-a" not in manual["positions"]
    store.delete_session(session_id)


def test_create_map_edge_between_two_real_nodes():
    session_id = "usr_map_edge_create"
    store.save_session(session_id, _session(session_id, recon_result={"targets": [
        {"host": "a.example.com", "port": 443}, {"host": "b.example.com", "port": 443},
    ]}))
    client = TestClient(main.app)

    resp = client.post(f"/api/session/{session_id}/map/edge", data={
        "source": "a.example.com", "target": "b.example.com", "direction": "bidirectional",
        "data_type": "lateral movement", "volume": "", "format": "", "interval": "", "label": "", "notes": "",
    })
    assert resp.status_code == 200
    edges = store.load_session(session_id)["map_manual"]["edges"]
    assert len(edges) == 1
    assert edges[0]["source"] == "a.example.com"
    assert edges[0]["target"] == "b.example.com"
    assert edges[0]["direction"] == "bidirectional"
    store.delete_session(session_id)


def test_create_map_edge_rejects_an_unknown_node_id():
    session_id = "usr_map_edge_bad_node"
    store.save_session(session_id, _session(session_id))
    client = TestClient(main.app)

    resp = client.post(f"/api/session/{session_id}/map/edge", data={"source": "example.com", "target": "ghost-host", "direction": "forward"})
    assert resp.status_code == 400
    store.delete_session(session_id)


def test_create_map_edge_rejects_a_self_loop():
    session_id = "usr_map_edge_self_loop"
    store.save_session(session_id, _session(session_id))
    client = TestClient(main.app)

    resp = client.post(f"/api/session/{session_id}/map/edge", data={"source": "example.com", "target": "example.com", "direction": "forward"})
    assert resp.status_code == 400
    store.delete_session(session_id)


def test_delete_map_edge_removes_it():
    session_id = "usr_map_edge_delete"
    store.save_session(session_id, _session(session_id, map_manual={
        "nodes": [], "edges": [{"id": "manual-e1", "source": "example.com", "target": "example.com",
                                 "direction": "forward", "data_type": "", "volume": "", "format": "",
                                 "interval": "", "label": "", "notes": ""}], "positions": {},
    }))
    client = TestClient(main.app)

    resp = client.post(f"/api/session/{session_id}/map/edge/manual-e1/delete")
    assert resp.status_code == 200
    assert store.load_session(session_id)["map_manual"]["edges"] == []
    store.delete_session(session_id)


def test_save_map_position_persists_coordinates():
    session_id = "usr_map_position"
    store.save_session(session_id, _session(session_id))
    client = TestClient(main.app)

    resp = client.post(f"/api/session/{session_id}/map/position", data={"node_id": "example.com", "x": "12.5", "y": "-4"})
    assert resp.status_code == 200
    positions = store.load_session(session_id)["map_manual"]["positions"]
    assert positions["example.com"] == {"x": 12.5, "y": -4.0}
    store.delete_session(session_id)


def test_map_routes_404_for_a_missing_session():
    client = TestClient(main.app)
    assert client.post("/api/session/usr_does_not_exist/map/node", data={"label": "X"}).status_code == 404
    assert client.post("/api/session/usr_does_not_exist/map/position", data={"node_id": "x", "x": "0", "y": "0"}).status_code == 404


def test_hide_map_node_removes_it_from_the_graph_without_deleting_recon_data():
    session_id = "usr_map_hide_node"
    store.save_session(session_id, _session(session_id))
    client = TestClient(main.app)

    resp = client.post(f"/api/session/{session_id}/map/node/example.com/hide", data={"hidden": "true"})
    assert resp.status_code == 200
    saved = store.load_session(session_id)
    assert saved["map_manual"]["hidden_node_ids"] == ["example.com"]
    # Real recon data untouched -- hiding is a pure display preference, not a deletion.
    assert saved["recon_result"]["targets"] == [{"host": "example.com", "port": 443}]
    graph = main._build_attack_surface_graph(saved)
    assert graph["nodes"] == []
    assert graph["hidden_count"] == 1
    store.delete_session(session_id)


def test_unhide_map_node_brings_it_back():
    session_id = "usr_map_unhide_node"
    store.save_session(session_id, _session(session_id, map_manual={"nodes": [], "edges": [], "positions": {}, "hidden_node_ids": ["example.com"]}))
    client = TestClient(main.app)

    resp = client.post(f"/api/session/{session_id}/map/node/example.com/hide", data={"hidden": "false"})
    assert resp.status_code == 200
    saved = store.load_session(session_id)
    assert saved["map_manual"]["hidden_node_ids"] == []
    assert len(main._build_attack_surface_graph(saved)["nodes"]) == 1
    store.delete_session(session_id)


def test_unhide_all_clears_every_hidden_node():
    session_id = "usr_map_unhide_all"
    store.save_session(session_id, _session(session_id, map_manual={"nodes": [], "edges": [], "positions": {}, "hidden_node_ids": ["example.com", "ghost.example.com"]}))
    client = TestClient(main.app)

    resp = client.post(f"/api/session/{session_id}/map/unhide-all")
    assert resp.status_code == 200
    assert store.load_session(session_id)["map_manual"]["hidden_node_ids"] == []
    store.delete_session(session_id)
