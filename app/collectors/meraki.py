from __future__ import annotations

import httpx

from app.collectors.base import DeviceCollector, DeviceSnapshot
from app.discovery.boundary import slug_id
from app.models.schemas import DeviceIdentity, InterfaceFact, Neighbor, WirelessClient


class MerakiCollector(DeviceCollector):
    """Cisco Meraki Dashboard API collector (devices + LLDP/CDP + clients)."""

    def __init__(self, api_key: str, serial: str, base_url: str = "https://api.meraki.com/api/v1") -> None:
        self.api_key = api_key
        self.serial = serial
        self.base_url = base_url.rstrip("/")

    def _get(self, path: str) -> dict | list:
        headers = {"X-Cisco-Meraki-API-Key": self.api_key, "Accept": "application/json"}
        with httpx.Client(timeout=20.0) as client:
            r = client.get(f"{self.base_url}{path}", headers=headers)
            r.raise_for_status()
            return r.json()

    def snapshot(self) -> DeviceSnapshot:
        dev = self._get(f"/devices/{self.serial}")
        if not isinstance(dev, dict):
            raise RuntimeError("Unexpected Meraki device payload")
        name = str(dev.get("name") or self.serial)
        model = str(dev.get("model") or "")
        dtype = "ap" if model.upper().startswith("MR") else "meraki" if model.upper().startswith("MS") else "meraki"
        if model.upper().startswith("MX"):
            dtype = "router"
        identity = DeviceIdentity(
            id=slug_id(name),
            name=name,
            type=dtype,  # type: ignore[arg-type]
            platform="meraki",
            vendor="meraki",
            model=model,
            mgmt_ip=str(dev.get("lanIp") or dev.get("wan1Ip") or ""),
            serial=self.serial,
            version=str(dev.get("firmware") or ""),
            status="up" if dev.get("status", "online") in {"online", "up"} else "down",
        )
        neighbors: list[Neighbor] = []
        try:
            lldp = self._get(f"/devices/{self.serial}/lldpCdp")
            ports = lldp.get("ports", {}) if isinstance(lldp, dict) else {}
            for port, body in ports.items():
                for proto in ("cdp", "lldp"):
                    info = (body or {}).get(proto) or {}
                    if not info:
                        continue
                    neighbors.append(
                        Neighbor(
                            local_interface=str(port),
                            remote_interface=str(info.get("portId") or info.get("port") or ""),
                            remote_hostname=str(info.get("deviceId") or info.get("systemName") or ""),
                            remote_mgmt_ip=str(info.get("address") or info.get("managementAddress") or ""),
                            protocol=proto,  # type: ignore[arg-type]
                        )
                    )
        except Exception:
            pass
        clients: list[WirelessClient] = []
        try:
            raw_clients = self._get(f"/devices/{self.serial}/clients")
            if isinstance(raw_clients, list):
                for c in raw_clients:
                    clients.append(
                        WirelessClient(
                            ip=str(c.get("ip") or ""),
                            mac=str(c.get("mac") or ""),
                            username=str(c.get("user") or c.get("description") or ""),
                            hostname=str(c.get("description") or ""),
                            ap_name=name if dtype == "ap" else "",
                            ssid=str(c.get("ssid") or ""),
                            vlan=c.get("vlan"),
                        )
                    )
        except Exception:
            pass
        interfaces = [
            InterfaceFact(name="lan", ip_address=identity.mgmt_ip, role="lan", oper_status=identity.status)
        ]
        return DeviceSnapshot(identity, interfaces, neighbors, clients=clients)
