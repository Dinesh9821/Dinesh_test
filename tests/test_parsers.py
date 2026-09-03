from __future__ import annotations

from app.mock_lab.cli_samples import (
    SHOW_AP_SUMMARY,
    SHOW_ARP,
    SHOW_CDP_DETAIL,
    SHOW_CLIENTS,
    SHOW_CPU,
    SHOW_INTERFACES,
    SHOW_MAC,
    SHOW_ROUTE,
    SHOW_VERSION_IOSXE,
)
from app.parsers.neighbors import parse_cdp_neighbors_detail
from app.parsers.tables import parse_arp, parse_interfaces, parse_mac_table, parse_routes
from app.parsers.version import parse_cpu, parse_show_version
from app.parsers.wireless import parse_ap_summary, parse_wireless_clients


def test_show_version_iosxe():
    ident = parse_show_version(SHOW_VERSION_IOSXE, "10.10.10.1")
    assert ident.name == "RTR-MUM-CORE"
    assert ident.platform == "ios-xe"
    assert ident.type == "router"
    assert ident.model.startswith("ISR4331")
    assert ident.serial == "FCZ1234CORE"


def test_cpu():
    assert parse_cpu(SHOW_CPU) == 32


def test_cdp_detail():
    nbrs = parse_cdp_neighbors_detail(SHOW_CDP_DETAIL)
    names = {n.remote_hostname for n in nbrs}
    assert names == {"SW-MUM-DIST", "VEDGE-MUM-001"}
    dist = next(n for n in nbrs if n.remote_hostname == "SW-MUM-DIST")
    assert dist.local_interface == "GigabitEthernet0/0/1"
    assert dist.remote_interface == "TenGigabitEthernet1/1/1"
    assert dist.remote_type == "switch"


def test_arp_mac_normalize():
    arp = parse_arp(SHOW_ARP, "RTR")
    dinesh = next(e for e in arp if e.ip == "10.20.10.45")
    assert dinesh.mac == "aa:bb:cc:11:22:45"
    assert dinesh.vlan == 20


def test_mac_table():
    macs = parse_mac_table(SHOW_MAC)
    assert any(m.mac == "aa:bb:cc:11:22:45" and m.interface == "Gi1/0/1" for m in macs)


def test_interfaces_utilization():
    ifaces = parse_interfaces(SHOW_INTERFACES)
    assert len(ifaces) == 1
    assert ifaces[0].name == "GigabitEthernet0/0/0"
    assert ifaces[0].rx_util_pct == 18.0
    assert ifaces[0].description == "TO-VEDGE-MUM-001"


def test_default_route_is_flagged():
    routes = parse_routes(SHOW_ROUTE)
    assert any(r.is_default and r.nexthop == "10.10.10.2" for r in routes)


def test_wlc_ap_and_client():
    aps = parse_ap_summary(SHOW_AP_SUMMARY, "WLC-MUM-01")
    assert {a.name for a in aps} == {"AP-MUM-01", "AP-MUM-02"}
    clients = parse_wireless_clients(SHOW_CLIENTS)
    assert clients[0].ip == "10.40.10.88"
    assert clients[0].ap_name == "AP-MUM-01"
