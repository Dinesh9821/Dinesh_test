from __future__ import annotations

from dataclasses import dataclass, field

from app.discovery.boundary import classify_interface, slug_id
from app.models.schemas import (
    ArpEntry,
    DeviceIdentity,
    InterfaceFact,
    MacEntry,
    Neighbor,
    Route,
    WirelessAP,
    WirelessClient,
)


@dataclass
class LabDevice:
    identity: DeviceIdentity
    interfaces: list[InterfaceFact] = field(default_factory=list)
    neighbors: list[Neighbor] = field(default_factory=list)
    arp: list[ArpEntry] = field(default_factory=list)
    mac: list[MacEntry] = field(default_factory=list)
    routes: list[Route] = field(default_factory=list)
    aps: list[WirelessAP] = field(default_factory=list)
    clients: list[WirelessClient] = field(default_factory=list)
    aliases: list[str] = field(default_factory=list)


SITE_ID = "MUM-01"
SITE_CIDRS = ["10.10.0.0/16", "10.20.0.0/16", "10.30.0.0/16", "10.40.0.0/16", "10.50.0.0/16"]


def _id(name: str, dtype: str, platform: str, **kwargs) -> DeviceIdentity:
    return DeviceIdentity(
        id=slug_id(name),
        name=name,
        type=dtype,  # type: ignore[arg-type]
        platform=platform,  # type: ignore[arg-type]
        site_id=SITE_ID,
        **kwargs,
    )


def _iface(
    name: str,
    desc: str = "",
    ip: str = "",
    rx: float = 5.0,
    tx: float = 4.0,
    latency: float = 1.0,
    loss: float = 0.0,
    bw: int = 1000,
    oper: str = "up",
    vlan: int | None = None,
    mac: str = "",
) -> InterfaceFact:
    role = classify_interface(name, desc, ip)
    return InterfaceFact(
        name=name,
        description=desc,
        ip_address=ip.split("/")[0] if ip else "",
        subnet=ip,
        rx_util_pct=rx,
        tx_util_pct=tx,
        latency_ms=latency,
        packet_loss_pct=loss,
        bandwidth_mbps=bw,
        oper_status=oper,
        admin_status="up" if oper == "up" else "down",
        role=role,  # type: ignore[arg-type]
        vlan=vlan,
        mac=mac,
    )


def _nbr(local: str, remote_if: str, host: str, ip: str, ntype: str, proto: str = "cdp") -> Neighbor:
    return Neighbor(
        local_interface=local,
        remote_interface=remote_if,
        remote_hostname=host,
        remote_mgmt_ip=ip,
        remote_type=ntype,  # type: ignore[arg-type]
        protocol=proto,  # type: ignore[arg-type]
    )


def build_mumbai_lab() -> dict[str, LabDevice]:
    """Mixed Cisco IOS / IOS-XE / WLC / AP / Meraki / Viptela site.

    Internet is represented only as a boundary node hanging off the vEdge WAN
    TLOC. Discovery must not walk past that link.
    """
    devices: dict[str, LabDevice] = {}

    ved = LabDevice(
        identity=_id(
            "VEDGE-MUM-001",
            "viptela",
            "viptela",
            vendor="cisco",
            model="C8000V",
            mgmt_ip="10.10.10.2",
            serial="VEDGE9K001",
            version="17.12.3",
            cpu=28,
        ),
        interfaces=[
            _iface("GigabitEthernet0/0/0", "WAN-DIA-ISP-AIRTEL", "49.36.12.10/30", rx=41, tx=62, latency=12, loss=0.3, bw=100),
            _iface("GigabitEthernet0/0/1", "LAN-TO-CORE", "10.10.10.2/30", rx=22, tx=18, latency=1, loss=0.0, bw=1000),
            _iface("Loopback0", "SDWAN-SYSTEM-IP", "10.10.255.2/32", rx=0, tx=0),
        ],
        neighbors=[
            _nbr("GigabitEthernet0/0/0", "GigabitEthernet0/1", "ISP-AIRTEL-PE-MUM", "49.36.12.9", "internet"),
            _nbr("GigabitEthernet0/0/1", "GigabitEthernet0/0/0", "RTR-MUM-CORE", "10.10.10.1", "router"),
        ],
        arp=[
            ArpEntry(ip="49.36.12.9", mac="00:11:22:33:44:01", interface="GigabitEthernet0/0/0", learned_on="VEDGE-MUM-001"),
            ArpEntry(ip="10.10.10.1", mac="00:1a:2b:3c:4d:01", interface="GigabitEthernet0/0/1", learned_on="VEDGE-MUM-001"),
        ],
        routes=[
            Route(prefix="0.0.0.0/0", nexthop="49.36.12.9", interface="GigabitEthernet0/0/0", protocol="static", is_default=True),
            Route(prefix="10.10.0.0/16", nexthop="10.10.10.1", interface="GigabitEthernet0/0/1", protocol="ospf"),
            Route(prefix="10.20.0.0/16", nexthop="10.10.10.1", interface="GigabitEthernet0/0/1", protocol="ospf"),
            Route(prefix="10.40.0.0/16", nexthop="10.10.10.1", interface="GigabitEthernet0/0/1", protocol="ospf"),
        ],
        aliases=["10.10.10.2", "10.10.255.2", "vedge-mum-001"],
    )
    # Loopback role
    ved.interfaces[2].role = "mgmt"
    devices[ved.identity.name] = ved

    core = LabDevice(
        identity=_id(
            "RTR-MUM-CORE",
            "router",
            "ios-xe",
            model="ISR4331/K9",
            mgmt_ip="10.10.10.1",
            serial="FCZ1234CORE",
            version="17.9.4a",
            cpu=32,
        ),
        interfaces=[
            _iface("GigabitEthernet0/0/0", "TO-VEDGE-MUM-001", "10.10.10.1/30", rx=18, tx=22, latency=1, bw=1000),
            _iface("GigabitEthernet0/0/1", "TO-SW-MUM-DIST TRUNK", "10.10.20.1/30", rx=45, tx=38, latency=1, bw=10000),
            _iface("Vlan10", "MGMT", "10.10.1.1/24", rx=1, tx=1),
            _iface("Vlan20", "USER-DATA SVI", "10.20.10.1/24", rx=12, tx=9),
            _iface("Vlan40", "WIFI SVI", "10.40.10.1/24", rx=8, tx=6),
            _iface("Vlan50", "IOT SVI", "10.50.10.1/24", rx=2, tx=1),
        ],
        neighbors=[
            _nbr("GigabitEthernet0/0/0", "GigabitEthernet0/0/1", "VEDGE-MUM-001", "10.10.10.2", "viptela"),
            _nbr("GigabitEthernet0/0/1", "TenGigabitEthernet1/1/1", "SW-MUM-DIST", "10.10.1.11", "switch"),
        ],
        arp=[
            ArpEntry(ip="10.10.10.2", mac="00:aa:bb:cc:dd:02", interface="GigabitEthernet0/0/0", learned_on="RTR-MUM-CORE"),
            ArpEntry(ip="10.10.20.2", mac="00:aa:bb:cc:dd:11", interface="GigabitEthernet0/0/1", learned_on="RTR-MUM-CORE"),
            ArpEntry(ip="10.20.10.45", mac="aa:bb:cc:11:22:45", interface="Vlan20", vlan=20, learned_on="RTR-MUM-CORE"),
            ArpEntry(ip="10.20.10.46", mac="aa:bb:cc:11:22:46", interface="Vlan20", vlan=20, learned_on="RTR-MUM-CORE"),
            ArpEntry(ip="10.40.10.88", mac="aa:bb:cc:40:10:88", interface="Vlan40", vlan=40, learned_on="RTR-MUM-CORE"),
            ArpEntry(ip="10.40.10.89", mac="aa:bb:cc:40:10:89", interface="Vlan40", vlan=40, learned_on="RTR-MUM-CORE"),
            ArpEntry(ip="10.50.10.12", mac="aa:bb:cc:50:10:12", interface="Vlan50", vlan=50, learned_on="RTR-MUM-CORE"),
            ArpEntry(ip="10.10.1.11", mac="00:aa:bb:cc:dd:11", interface="Vlan10", vlan=10, learned_on="RTR-MUM-CORE"),
            ArpEntry(ip="10.10.1.12", mac="00:aa:bb:cc:dd:12", interface="Vlan10", vlan=10, learned_on="RTR-MUM-CORE"),
            ArpEntry(ip="10.10.1.13", mac="00:aa:bb:cc:dd:13", interface="Vlan10", vlan=10, learned_on="RTR-MUM-CORE"),
            ArpEntry(ip="10.10.1.21", mac="00:aa:bb:cc:dd:21", interface="Vlan10", vlan=10, learned_on="RTR-MUM-CORE"),
            ArpEntry(ip="10.10.1.31", mac="e0:55:3d:00:00:01", interface="Vlan10", vlan=10, learned_on="RTR-MUM-CORE"),
        ],
        routes=[
            Route(prefix="0.0.0.0/0", nexthop="10.10.10.2", interface="GigabitEthernet0/0/0", protocol="static", is_default=True),
            Route(prefix="10.20.10.0/24", nexthop="", interface="Vlan20", protocol="connected"),
            Route(prefix="10.40.10.0/24", nexthop="", interface="Vlan40", protocol="connected"),
        ],
        aliases=["10.10.10.1", "10.10.1.1", "rtr-mum-core", "rtr-mum-001"],
    )
    devices[core.identity.name] = core

    dist = LabDevice(
        identity=_id(
            "SW-MUM-DIST",
            "switch",
            "ios-xe",
            model="C9300-24T",
            mgmt_ip="10.10.1.11",
            serial="FCW9300DIST",
            version="17.9.4",
            cpu=45,
        ),
        interfaces=[
            _iface("TenGigabitEthernet1/1/1", "UPLINK-CORE", "", rx=38, tx=45, bw=10000),
            _iface("GigabitEthernet1/0/1", "TO-SW-MUM-ACC-01", "", rx=22, tx=19),
            _iface("GigabitEthernet1/0/2", "TO-SW-MUM-ACC-02", "", rx=17, tx=14),
            _iface("GigabitEthernet1/0/3", "TO-WLC-MUM-01", "", rx=9, tx=7),
            _iface("GigabitEthernet1/0/4", "TO-MS-MUM-01-MERAKI", "", rx=11, tx=8),
            _iface("Vlan10", "MGMT", "10.10.1.11/24", rx=1, tx=1),
        ],
        neighbors=[
            _nbr("TenGigabitEthernet1/1/1", "GigabitEthernet0/0/1", "RTR-MUM-CORE", "10.10.10.1", "router"),
            _nbr("GigabitEthernet1/0/1", "GigabitEthernet1/0/24", "SW-MUM-ACC-01", "10.10.1.12", "switch"),
            _nbr("GigabitEthernet1/0/2", "GigabitEthernet1/0/24", "SW-MUM-ACC-02", "10.10.1.13", "switch"),
            _nbr("GigabitEthernet1/0/3", "GigabitEthernet0/0/1", "WLC-MUM-01", "10.10.1.21", "wlc"),
            _nbr("GigabitEthernet1/0/4", "1", "MS-MUM-01", "10.10.1.31", "meraki", "lldp"),
        ],
        mac=[
            MacEntry(mac="aa:bb:cc:11:22:45", vlan=20, interface="GigabitEthernet1/0/1"),
            MacEntry(mac="aa:bb:cc:11:22:46", vlan=20, interface="GigabitEthernet1/0/1"),
            MacEntry(mac="aa:bb:cc:40:10:88", vlan=40, interface="GigabitEthernet1/0/2"),
            MacEntry(mac="aa:bb:cc:40:10:89", vlan=40, interface="GigabitEthernet1/0/3"),
            MacEntry(mac="aa:bb:cc:50:10:12", vlan=50, interface="GigabitEthernet1/0/4"),
            MacEntry(mac="00:1a:2b:aa:01:01", vlan=40, interface="GigabitEthernet1/0/2"),
            MacEntry(mac="00:1a:2b:aa:01:02", vlan=40, interface="GigabitEthernet1/0/2"),
        ],
        arp=[
            ArpEntry(ip="10.10.1.1", mac="00:1a:2b:3c:4d:01", interface="Vlan10", vlan=10, learned_on="SW-MUM-DIST"),
        ],
        aliases=["10.10.1.11", "sw-mum-dist", "sw-mum-001"],
    )
    devices[dist.identity.name] = dist

    acc1 = LabDevice(
        identity=_id(
            "SW-MUM-ACC-01",
            "switch",
            "ios",
            model="C9200-48P",
            mgmt_ip="10.10.1.12",
            serial="FCW9200ACC1",
            version="17.6.5",
            cpu=18,
        ),
        interfaces=[
            _iface("GigabitEthernet1/0/1", "USER-DINESH-LAPTOP ACCESS VLAN20", "", rx=8, tx=5, vlan=20),
            _iface("GigabitEthernet1/0/2", "PRINTER-MUM-01 ACCESS VLAN20", "", rx=1, tx=1, vlan=20),
            _iface("GigabitEthernet1/0/24", "UPLINK-DIST", "", rx=19, tx=22),
            _iface("Vlan10", "MGMT", "10.10.1.12/24"),
        ],
        neighbors=[
            _nbr("GigabitEthernet1/0/24", "GigabitEthernet1/0/1", "SW-MUM-DIST", "10.10.1.11", "switch"),
        ],
        mac=[
            MacEntry(mac="aa:bb:cc:11:22:45", vlan=20, interface="GigabitEthernet1/0/1"),
            MacEntry(mac="aa:bb:cc:11:22:46", vlan=20, interface="GigabitEthernet1/0/2"),
        ],
        arp=[
            ArpEntry(ip="10.10.1.1", mac="00:1a:2b:3c:4d:01", interface="Vlan10", vlan=10, learned_on="SW-MUM-ACC-01"),
        ],
        aliases=["10.10.1.12", "sw-mum-acc-01"],
    )
    devices[acc1.identity.name] = acc1

    acc2 = LabDevice(
        identity=_id(
            "SW-MUM-ACC-02",
            "switch",
            "ios-xe",
            model="C9200-24P",
            mgmt_ip="10.10.1.13",
            serial="FCW9200ACC2",
            version="17.9.4",
            cpu=21,
        ),
        interfaces=[
            _iface("GigabitEthernet1/0/1", "AP-MUM-01", "", rx=14, tx=11, vlan=40),
            _iface("GigabitEthernet1/0/2", "AP-MUM-02", "", rx=9, tx=7, vlan=40),
            _iface("GigabitEthernet1/0/24", "UPLINK-DIST", "", rx=14, tx=17),
            _iface("Vlan10", "MGMT", "10.10.1.13/24"),
        ],
        neighbors=[
            _nbr("GigabitEthernet1/0/24", "GigabitEthernet1/0/2", "SW-MUM-DIST", "10.10.1.11", "switch"),
            _nbr("GigabitEthernet1/0/1", "GigabitEthernet0", "AP-MUM-01", "10.40.1.11", "ap", "cdp"),
            _nbr("GigabitEthernet1/0/2", "GigabitEthernet0", "AP-MUM-02", "10.40.1.12", "ap", "cdp"),
        ],
        mac=[
            MacEntry(mac="00:1a:2b:aa:01:01", vlan=40, interface="GigabitEthernet1/0/1"),
            MacEntry(mac="00:1a:2b:aa:01:02", vlan=40, interface="GigabitEthernet1/0/2"),
            MacEntry(mac="aa:bb:cc:40:10:88", vlan=40, interface="GigabitEthernet1/0/1"),
        ],
        aliases=["10.10.1.13", "sw-mum-acc-02"],
    )
    devices[acc2.identity.name] = acc2

    wlc = LabDevice(
        identity=_id(
            "WLC-MUM-01",
            "wlc",
            "wlc-9800",
            model="C9800-40-K9",
            mgmt_ip="10.10.1.21",
            serial="FCW9800WLC1",
            version="17.12.3",
            cpu=37,
        ),
        interfaces=[
            _iface("GigabitEthernet0/0/1", "TO-SW-MUM-DIST", "10.10.1.21/24", rx=7, tx=9),
            _iface("Vlan40", "WIFI", "10.40.10.2/24", rx=6, tx=5),
        ],
        neighbors=[
            _nbr("GigabitEthernet0/0/1", "GigabitEthernet1/0/3", "SW-MUM-DIST", "10.10.1.11", "switch"),
        ],
        aps=[
            WirelessAP(
                name="AP-MUM-01",
                mac="00:1a:2b:aa:01:01",
                ip="10.40.1.11",
                model="C9120AXI",
                status="up",
                switch_hostname="SW-MUM-ACC-02",
                switch_port="GigabitEthernet1/0/1",
                wlc_name="WLC-MUM-01",
                clients=1,
            ),
            WirelessAP(
                name="AP-MUM-02",
                mac="00:1a:2b:aa:01:02",
                ip="10.40.1.12",
                model="C9120AXI",
                status="up",
                switch_hostname="SW-MUM-ACC-02",
                switch_port="GigabitEthernet1/0/2",
                wlc_name="WLC-MUM-01",
                clients=0,
            ),
        ],
        clients=[
            WirelessClient(
                ip="10.40.10.88",
                mac="aa:bb:cc:40:10:88",
                username="priya.nair",
                hostname="PRIYA-MBP",
                ap_name="AP-MUM-01",
                ssid="MUM-CORP",
                vlan=40,
                rssi=-62,
            )
        ],
        arp=[
            ArpEntry(ip="10.40.10.88", mac="aa:bb:cc:40:10:88", interface="Vlan40", vlan=40, learned_on="WLC-MUM-01"),
            ArpEntry(ip="10.40.1.11", mac="00:1a:2b:aa:01:01", interface="Vlan40", vlan=40, learned_on="WLC-MUM-01"),
            ArpEntry(ip="10.40.1.12", mac="00:1a:2b:aa:01:02", interface="Vlan40", vlan=40, learned_on="WLC-MUM-01"),
        ],
        aliases=["10.10.1.21", "wlc-mum-01"],
    )
    devices[wlc.identity.name] = wlc

    for ap in wlc.aps:
        devices[ap.name] = LabDevice(
            identity=_id(ap.name, "ap", "ios", model=ap.model, mgmt_ip=ap.ip, cpu=12, vendor="cisco"),
            interfaces=[_iface("GigabitEthernet0", f"CAPWAP to {wlc.identity.name}", ap.ip + "/24", rx=10, tx=8)],
            neighbors=[
                _nbr("GigabitEthernet0", "GigabitEthernet1/0/1" if ap.name.endswith("01") else "GigabitEthernet1/0/2", "SW-MUM-ACC-02", "10.10.1.13", "switch"),
                Neighbor(
                    local_interface="CAPWAP0",
                    remote_interface="CAPWAP",
                    remote_hostname="WLC-MUM-01",
                    remote_mgmt_ip="10.10.1.21",
                    remote_type="wlc",
                    protocol="capwap",
                ),
            ],
            aliases=[ap.ip, ap.name.lower()],
        )

    meraki_sw = LabDevice(
        identity=_id(
            "MS-MUM-01",
            "meraki",
            "meraki",
            vendor="meraki",
            model="MS120-8FP",
            mgmt_ip="10.10.1.31",
            serial="Q2XX-MS12-0001",
            version="MS 15.21",
            cpu=9,
        ),
        interfaces=[
            _iface("1", "UPLINK-SW-MUM-DIST", "", rx=8, tx=11),
            _iface("5", "IOT-CAMERA-01 VLAN50", "", rx=3, tx=2, vlan=50),
            _iface("8", "MR-MUM-01", "", rx=6, tx=5),
        ],
        neighbors=[
            _nbr("1", "GigabitEthernet1/0/4", "SW-MUM-DIST", "10.10.1.11", "switch", "lldp"),
            _nbr("8", "wired0", "MR-MUM-01", "10.10.1.32", "ap", "lldp"),
        ],
        mac=[
            MacEntry(mac="aa:bb:cc:50:10:12", vlan=50, interface="5"),
            MacEntry(mac="e0:55:3d:aa:00:32", vlan=10, interface="8"),
            MacEntry(mac="aa:bb:cc:40:10:89", vlan=40, interface="8"),
        ],
        aliases=["10.10.1.31", "ms-mum-01", "Q2XX-MS12-0001"],
    )
    devices[meraki_sw.identity.name] = meraki_sw

    meraki_ap = LabDevice(
        identity=_id(
            "MR-MUM-01",
            "ap",
            "meraki",
            vendor="meraki",
            model="MR46",
            mgmt_ip="10.10.1.32",
            serial="Q2XX-MR46-0001",
            version="MR 30.7",
            cpu=14,
        ),
        interfaces=[_iface("wired0", "TO-MS-MUM-01", "10.10.1.32/24", rx=5, tx=6)],
        neighbors=[_nbr("wired0", "8", "MS-MUM-01", "10.10.1.31", "meraki", "lldp")],
        clients=[
            WirelessClient(
                ip="10.40.10.89",
                mac="aa:bb:cc:40:10:89",
                username="rahul.shah",
                hostname="RAHUL-PIXEL",
                ap_name="MR-MUM-01",
                ssid="MUM-GUEST",
                vlan=40,
                rssi=-58,
            )
        ],
        aliases=["10.10.1.32", "mr-mum-01", "Q2XX-MR46-0001"],
    )
    devices[meraki_ap.identity.name] = meraki_ap

    devices["_hosts"] = LabDevice(
        identity=_id("_HOST-INDEX", "unknown", "host", mgmt_ip="0.0.0.0"),
    )
    devices["_hosts"].clients = [
        WirelessClient(ip="10.20.10.45", mac="aa:bb:cc:11:22:45", username="dinesh.velapure", hostname="LAPTOP-DINESH", ap_name="", ssid="", vlan=20),
        WirelessClient(ip="10.20.10.46", mac="aa:bb:cc:11:22:46", username="print-svc", hostname="PRINTER-MUM-01", vlan=20),
        WirelessClient(ip="10.40.10.88", mac="aa:bb:cc:40:10:88", username="priya.nair", hostname="PRIYA-MBP", ap_name="AP-MUM-01", ssid="MUM-CORP", vlan=40),
        WirelessClient(ip="10.40.10.89", mac="aa:bb:cc:40:10:89", username="rahul.shah", hostname="RAHUL-PIXEL", ap_name="MR-MUM-01", ssid="MUM-GUEST", vlan=40),
        WirelessClient(ip="10.50.10.12", mac="aa:bb:cc:50:10:12", username="cam-lobby", hostname="IOT-CAMERA-01", vlan=50),
    ]

    return devices


# Fix unused variable - I used a walrus incorrectly. Let me not use extra_clients.
