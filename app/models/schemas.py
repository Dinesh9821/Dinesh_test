from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


DeviceType = Literal[
    "router",
    "switch",
    "wlc",
    "ap",
    "meraki",
    "viptela",
    "host",
    "internet",
    "unknown",
]

Platform = Literal[
    "ios",
    "ios-xe",
    "wlc-9800",
    "wlc-aireos",
    "meraki",
    "viptela",
    "host",
    "internet",
    "auto",
]


class DeviceIdentity(BaseModel):
    id: str
    name: str
    type: DeviceType
    platform: Platform
    vendor: str = "cisco"
    model: str = ""
    mgmt_ip: str = ""
    serial: str = ""
    site_id: str = ""
    version: str = ""
    cpu: int = 0
    status: Literal["up", "down", "degraded"] = "up"


class InterfaceFact(BaseModel):
    name: str
    admin_status: str = "up"
    oper_status: str = "up"
    description: str = ""
    ip_address: str = ""
    subnet: str = ""
    mac: str = ""
    bandwidth_mbps: int = 1000
    rx_util_pct: float = 0.0
    tx_util_pct: float = 0.0
    latency_ms: float = 0.0
    packet_loss_pct: float = 0.0
    role: Literal["lan", "wan", "capwap", "trunk", "access", "mgmt", "unknown"] = "unknown"
    vlan: int | None = None


class Neighbor(BaseModel):
    local_interface: str
    remote_interface: str
    remote_hostname: str
    remote_mgmt_ip: str = ""
    remote_platform: str = ""
    remote_type: DeviceType = "unknown"
    protocol: Literal["cdp", "lldp", "capwap", "meraki", "viptela", "arp"] = "cdp"
    capabilities: str = ""


class ArpEntry(BaseModel):
    ip: str
    mac: str
    interface: str
    vlan: int | None = None
    age: str = ""
    arpa_type: str = "ARPA"
    vrf: str = "default"
    learned_on: str = ""


class MacEntry(BaseModel):
    mac: str
    vlan: int
    interface: str
    type: str = "DYNAMIC"


class Route(BaseModel):
    prefix: str
    nexthop: str = ""
    interface: str = ""
    protocol: str = ""
    is_default: bool = False


class WirelessAP(BaseModel):
    name: str
    mac: str = ""
    ip: str = ""
    model: str = ""
    status: str = "up"
    switch_hostname: str = ""
    switch_port: str = ""
    wlc_name: str = ""
    clients: int = 0


class WirelessClient(BaseModel):
    ip: str = ""
    mac: str
    username: str = ""
    hostname: str = ""
    ap_name: str = ""
    ssid: str = ""
    vlan: int | None = None
    rssi: int | None = None
    status: str = "associated"


class CytoscapeNode(BaseModel):
    data: dict
    classes: str = ""


class CytoscapeEdge(BaseModel):
    data: dict
    classes: str = ""


class TopologyGraph(BaseModel):
    nodes: list[CytoscapeNode]
    edges: list[CytoscapeEdge]
    site_id: str = ""
    seed: str = ""
    legend: dict = Field(default_factory=dict)
    style: list[dict] = Field(default_factory=list)
    summary: dict = Field(default_factory=dict)


class SeedRequest(BaseModel):
    host: str
    username: str = ""
    password: str = ""
    platform: Platform = "auto"
    protocol: Literal["ssh", "meraki", "vmanage", "demo"] = "ssh"
    port: int = 22
    site_id: str = ""


class TopologyRequest(BaseModel):
    seed: SeedRequest | None = None
    demo: bool = True
    site_id: str = "MUM-01"


class ArpQuery(BaseModel):
    ip: str | None = None
    mac: str | None = None
    username: str | None = None
    hostname: str | None = None
    demo: bool = True
    site_id: str = "MUM-01"
