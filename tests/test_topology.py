from app.discovery.boundary import is_internet_neighbor
from app.services.topology import build_topology


def _names(graph):
    return {n.data["name"] for n in graph.nodes}


def test_seed_access_switch_builds_full_site():
    g = build_topology(seed_host="SW-MUM-ACC-01")
    names = _names(g)
    assert "VEDGE-MUM-001" in names
    assert "RTR-MUM-CORE" in names
    assert "SW-MUM-DIST" in names
    assert "SW-MUM-ACC-02" in names
    assert "WLC-MUM-01" in names
    assert "AP-MUM-01" in names
    assert "MS-MUM-01" in names
    assert "MR-MUM-01" in names
    assert "Internet" in names
    assert "ISP-AIRTEL-PE-MUM" not in names


def test_seed_router_same_site():
    from_sw = _names(build_topology(seed_host="10.10.1.12"))
    from_rtr = _names(build_topology(seed_host="RTR-MUM-CORE"))
    assert from_sw == from_rtr


def test_seed_meraki_and_viptela():
    assert "SW-MUM-DIST" in _names(build_topology(seed_host="MS-MUM-01"))
    assert "RTR-MUM-CORE" in _names(build_topology(seed_host="VEDGE-MUM-001"))


def test_cytoscape_required_fields():
    g = build_topology(seed_host="SW-MUM-DIST")
    for n in g.nodes:
        d = n.data
        assert {"id", "name", "type", "cpu", "status"} <= d.keys()
        assert d["type"] in {"router", "switch", "wlc", "ap", "meraki", "viptela", "internet", "host"}
        assert d["color"]
        assert d["symbol"]
    for e in g.edges:
        d = e.data
        assert {"id", "source", "target", "interface", "utilization", "latency", "packet_loss"} <= d.keys()
        ids = {n.data["id"] for n in g.nodes}
        assert d["source"] in ids and d["target"] in ids


def test_internet_is_leaf_only_on_vedge():
    g = build_topology()
    inet = next(e for e in g.edges if e.data["target"] == "INTERNET" or e.data["source"] == "INTERNET")
    ends = {inet.data["source"], inet.data["target"]}
    assert "VEDGE-MUM-001" in ends
    wan_edges = [e for e in g.edges if e.data.get("boundary")]
    assert len(wan_edges) == 1


def test_isp_hostname_is_boundary():
    assert is_internet_neighbor("ISP-AIRTEL-PE-MUM", "wan", "49.36.12.9")
    assert not is_internet_neighbor("SW-MUM-DIST", "lan", "10.10.1.11")
