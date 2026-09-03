from __future__ import annotations

from app.collectors.base import DeviceCollector, DeviceSnapshot
from app.discovery.boundary import classify_interface
from app.models.schemas import DeviceIdentity
from app.parsers.neighbors import parse_cdp_neighbors_detail, parse_lldp_neighbors_detail
from app.parsers.tables import parse_arp, parse_interfaces, parse_mac_table, parse_routes
from app.parsers.version import parse_cpu, parse_show_version
from app.parsers.wireless import parse_ap_summary, parse_wireless_clients


class CommandRunner:
    def send(self, command: str) -> str:
        raise NotImplementedError


class CiscoCliCollector(DeviceCollector):
    """SSH collector for IOS / IOS-XE / 9800 WLC. Commands are real Cisco CLI."""

    def __init__(self, runner: CommandRunner, mgmt_ip: str = "") -> None:
        self.runner = runner
        self.mgmt_ip = mgmt_ip

    def snapshot(self) -> DeviceSnapshot:
        version = self.runner.send("show version")
        identity = parse_show_version(version, self.mgmt_ip)
        identity.cpu = parse_cpu(self.runner.send("show processes cpu"))
        interfaces = parse_interfaces(self.runner.send("show interfaces"))
        for iface in interfaces:
            iface.role = classify_interface(iface.name, iface.description, iface.ip_address)  # type: ignore[assignment]
        neighbors = parse_cdp_neighbors_detail(self.runner.send("show cdp neighbors detail"))
        try:
            neighbors.extend(parse_lldp_neighbors_detail(self.runner.send("show lldp neighbors detail")))
        except Exception:
            pass
        arp = parse_arp(self.runner.send("show ip arp"), learned_on=identity.name)
        mac: list = []
        try:
            mac = parse_mac_table(self.runner.send("show mac address-table"))
        except Exception:
            pass
        routes = parse_routes(self.runner.send("show ip route"))
        aps = []
        clients = []
        if identity.type == "wlc" or identity.platform in {"wlc-9800", "wlc-aireos"}:
            aps = parse_ap_summary(self.runner.send("show ap summary"), identity.name)
            clients = parse_wireless_clients(self.runner.send("show wireless client summary"))
        return DeviceSnapshot(identity, interfaces, neighbors, arp, mac, routes, aps, clients)


class NetmikoRunner(CommandRunner):
    def __init__(self, host: str, username: str, password: str, port: int = 22, device_type: str = "cisco_xe") -> None:
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.device_type = device_type
        self._conn = None

    def send(self, command: str) -> str:
        from netmiko import ConnectHandler

        if self._conn is None:
            self._conn = ConnectHandler(
                device_type=self.device_type,
                host=self.host,
                username=self.username,
                password=self.password,
                port=self.port,
                conn_timeout=12,
            )
        return self._conn.send_command(command)
