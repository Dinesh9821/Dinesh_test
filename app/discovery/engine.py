from __future__ import annotations

from collections import deque

from app.collectors.mock import MockCollector, get_lab
from app.discovery.boundary import classify_interface, is_internet_neighbor, slug_id
from app.models.schemas import (
    CytoscapeEdge,
    CytoscapeNode,
    DeviceIdentity,
    Neighbor,
    SeedRequest,
    TopologyGraph,
)
from app.style import cytoscape_stylesheet, type_color, type_shape, type_symbol

INTERNET_NODE_ID = "INTERNET"


class TopologyDiscovery:
    """Walk CDP/LLDP/CAPWAP/Meraki/vManage neighbors from a seed.

    Stops at WAN/Internet boundaries so overlay/underlay peers and ISP PEs
    are not expanded into other sites.
    """

    def __init__(self, demo: bool = True) -> None:
        self.demo = demo
        self.lab = get_lab() if demo else None

    def discover(self, seed: SeedRequest) -> TopologyGraph:
        start = seed.host
        snapshots = {}
        internet_edges: list[tuple[str, Neighbor]] = []
        queue: deque[str] = deque([start])
        seen: set[str] = set()

        while queue:
            key = queue.popleft()
            lookup = key.lower()
            if lookup in seen:
                continue
            seen.add(lookup)
            snap = self._collect(key, seed)
            if snap is None:
                continue
            name = snap.identity.name
            seen.add(name.lower())
            snapshots[name] = snap

            iface_role = {i.name: i.role for i in snap.interfaces}
            for nbr in snap.neighbors:
                role = iface_role.get(nbr.local_interface) or classify_interface(
                    nbr.local_interface, "", nbr.remote_mgmt_ip
                )
                if nbr.remote_type == "internet" or is_internet_neighbor(
                    nbr.remote_hostname, role, nbr.remote_mgmt_ip
                ):
                    internet_edges.append((name, nbr))
                    continue
                remote = nbr.remote_hostname
                if remote.lower() not in seen:
                    queue.append(remote)

            for ap in snap.aps:
                if ap.name.lower() not in seen:
                    queue.append(ap.name)

        nodes: list[CytoscapeNode] = []
        edges: list[CytoscapeEdge] = []
        edge_keys: set[str] = set()

        for name, snap in snapshots.items():
            ident = snap.identity
            nodes.append(self._node(ident))
            iface_map = {i.name: i for i in snap.interfaces}
            for nbr in snap.neighbors:
                if nbr.remote_type == "internet" or is_internet_neighbor(
                    nbr.remote_hostname,
                    iface_map.get(nbr.local_interface).role if nbr.local_interface in iface_map else "lan",
                    nbr.remote_mgmt_ip,
                ):
                    continue
                if nbr.remote_hostname not in snapshots:
                    continue
                src, dst = ident.id, slug_id(nbr.remote_hostname)
                key = tuple(sorted((src, dst))) + (nbr.protocol,)
                # Prefer a single undirected edge, keep local interface on source side
                undirected = "-".join(sorted((src, dst)))
                if undirected in edge_keys:
                    continue
                edge_keys.add(undirected)
                local_if = iface_map.get(nbr.local_interface)
                util = 0
                latency = 1.0
                loss = 0.0
                if local_if:
                    util = int(max(local_if.rx_util_pct, local_if.tx_util_pct))
                    latency = local_if.latency_ms
                    loss = local_if.packet_loss_pct
                edges.append(
                    CytoscapeEdge(
                        data={
                            "id": undirected,
                            "source": src,
                            "target": dst,
                            "interface": nbr.local_interface,
                            "peer_interface": nbr.remote_interface,
                            "utilization": util,
                            "latency": latency,
                            "packet_loss": loss,
                            "protocol": nbr.protocol,
                            "link_type": "capwap" if nbr.protocol == "capwap" else "l2",
                        },
                        classes=self._edge_class(util, nbr.protocol),
                    )
                )

        if internet_edges:
            nodes.append(
                self._node(
                    DeviceIdentity(
                        id=INTERNET_NODE_ID,
                        name="Internet",
                        type="internet",
                        platform="internet",
                        vendor="",
                        status="up",
                        cpu=0,
                        site_id=seed.site_id or "MUM-01",
                    )
                )
            )
            for local_name, nbr in internet_edges:
                src = slug_id(local_name)
                eid = f"{src}-{INTERNET_NODE_ID}"
                if eid in edge_keys:
                    continue
                edge_keys.add(eid)
                snap = snapshots[local_name]
                local_if = next((i for i in snap.interfaces if i.name == nbr.local_interface), None)
                util = int(max(local_if.rx_util_pct, local_if.tx_util_pct)) if local_if else 0
                edges.append(
                    CytoscapeEdge(
                        data={
                            "id": eid,
                            "source": src,
                            "target": INTERNET_NODE_ID,
                            "interface": nbr.local_interface,
                            "peer_interface": nbr.remote_interface,
                            "utilization": util,
                            "latency": local_if.latency_ms if local_if else 12,
                            "packet_loss": local_if.packet_loss_pct if local_if else 0.3,
                            "protocol": "wan",
                            "link_type": "wan",
                            "boundary": True,
                        },
                        classes="wan " + self._edge_class(util, "wan"),
                    )
                )

        types = {}
        for n in nodes:
            types[n.data["type"]] = types.get(n.data["type"], 0) + 1

        return TopologyGraph(
            nodes=nodes,
            edges=edges,
            site_id=seed.site_id or "MUM-01",
            seed=start,
            legend=legend(),
            style=cytoscape_stylesheet(),
            summary={
                "devices": len([n for n in nodes if n.data["type"] != "internet"]),
                "links": len(edges),
                "by_type": types,
                "boundary": "Internet uplink is a leaf. Other SD-WAN sites and ISP PEs are not expanded.",
            },
        )

    def _collect(self, key: str, seed: SeedRequest):
        if self.demo and self.lab:
            coll = self.lab.collector_for(key)
            if coll is None and key == seed.host:
                coll = self.lab.collector_for(seed.host)
            return coll.snapshot() if coll else None
        # Live path: only the seed is connected directly; neighbors require inventory.
        from app.collectors.cisco_cli import CiscoCliCollector, NetmikoRunner

        if key != seed.host:
            return None
        runner = NetmikoRunner(seed.host, seed.username, seed.password, seed.port)
        return CiscoCliCollector(runner, seed.host).snapshot()

    def _node(self, ident: DeviceIdentity) -> CytoscapeNode:
        color = type_color(ident.type)
        return CytoscapeNode(
            data={
                "id": ident.id,
                "name": ident.name,
                "type": ident.type,
                "cpu": ident.cpu,
                "status": ident.status,
                "vendor": ident.vendor,
                "platform": ident.platform,
                "model": ident.model,
                "mgmt_ip": ident.mgmt_ip,
                "serial": ident.serial,
                "version": ident.version,
                "site": ident.site_id,
                "color": color,
                "shape": type_shape(ident.type),
                "symbol": type_symbol(ident.type),
            },
            classes=f"{ident.type} {ident.status}",
        )

    @staticmethod
    def _edge_class(util: int, protocol: str) -> str:
        if protocol in {"wan", "capwap"}:
            extra = protocol
        else:
            extra = "l2"
        if util >= 80:
            return f"{extra} hot"
        if util >= 50:
            return f"{extra} warm"
        return f"{extra} cool"


def legend() -> dict:
    return {
        "nodes": [
            {"type": "router", "color": type_color("router"), "shape": "diamond", "symbol": type_symbol("router"), "label": "Router (IOS / IOS-XE)"},
            {"type": "switch", "color": type_color("switch"), "shape": "rectangle", "symbol": type_symbol("switch"), "label": "Switch"},
            {"type": "wlc", "color": type_color("wlc"), "shape": "hexagon", "symbol": type_symbol("wlc"), "label": "Wireless LAN Controller"},
            {"type": "ap", "color": type_color("ap"), "shape": "star", "symbol": type_symbol("ap"), "label": "Access Point"},
            {"type": "meraki", "color": type_color("meraki"), "shape": "round-rectangle", "symbol": type_symbol("meraki"), "label": "Meraki (MS/MX)"},
            {"type": "viptela", "color": type_color("viptela"), "shape": "octagon", "symbol": type_symbol("viptela"), "label": "Viptela / cEdge"},
            {"type": "host", "color": type_color("host"), "shape": "ellipse", "symbol": type_symbol("host"), "label": "Endpoint / user"},
            {"type": "internet", "color": type_color("internet"), "shape": "triangle", "symbol": type_symbol("internet"), "label": "Internet (site boundary)"},
        ],
        "edges": [
            {"class": "cool", "color": "#64748b", "label": "Utilization < 50%"},
            {"class": "warm", "color": "#f59e0b", "label": "Utilization 50–79%"},
            {"class": "hot", "color": "#ef4444", "label": "Utilization ≥ 80%"},
            {"class": "wan", "color": "#e11d48", "label": "WAN / Internet (do not traverse)"},
            {"class": "capwap", "color": "#a855f7", "label": "CAPWAP (AP to WLC)"},
        ],
    }
