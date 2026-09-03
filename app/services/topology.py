from app.discovery.engine import TopologyDiscovery
from app.models.schemas import SeedRequest, TopologyGraph


def build_topology(demo: bool = True, seed_host: str = "10.10.1.12", site_id: str = "MUM-01") -> TopologyGraph:
    disc = TopologyDiscovery(demo=demo)
    graph = disc.discover(
        SeedRequest(host=seed_host, protocol="demo" if demo else "ssh", site_id=site_id)
    )
    for node in graph.nodes:
        node.data["label"] = f"{node.data.get('symbol', '')}  {node.data.get('name')}"
    for edge in graph.edges:
        edge.data["iflabel"] = edge.data.get("interface") or ""
    return graph
