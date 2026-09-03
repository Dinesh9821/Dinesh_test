from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health():
    assert client.get("/api/v1/health").json()["status"] == "ok"


def test_topology_api_shape():
    r = client.get("/api/v1/topology", params={"seed": "10.10.10.1", "demo": True})
    assert r.status_code == 200
    body = r.json()
    assert body["nodes"]
    assert body["edges"]
    node = body["nodes"][0]["data"]
    assert "id" in node and "name" in node and "type" in node
    edge = body["edges"][0]["data"]
    assert "source" in edge and "target" in edge and "interface" in edge


def test_topology_unknown_seed():
    r = client.get("/api/v1/topology", params={"seed": "no-such-box"})
    assert r.status_code == 404


def test_arp_api():
    r = client.get("/api/v1/arp", params={"ip": "10.20.10.45"})
    assert r.status_code == 200
    body = r.json()
    assert body["found"]
    assert body["lan"]["access_switch"]["port"] == "GigabitEthernet1/0/1"
    assert body["nodes"]
    assert body["edges"]


def test_arp_requires_key():
    assert client.get("/api/v1/arp").status_code == 400


def test_ui_served():
    r = client.get("/")
    assert r.status_code == 200
    assert b"cytoscape" in r.text.encode() or "Site Fabric" in r.text
