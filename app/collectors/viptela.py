from __future__ import annotations

import httpx

from app.collectors.base import DeviceCollector, DeviceSnapshot
from app.discovery.boundary import classify_interface, slug_id
from app.models.schemas import ArpEntry, DeviceIdentity, InterfaceFact, Neighbor, Route


class ViptelaCollector(DeviceCollector):
    """Cisco SD-WAN (vManage) collector. Scoped to a single site-id."""

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        system_ip: str,
        site_id: str = "",
        port: int = 443,
    ) -> None:
        self.base = f"https://{host}:{port}"
        self.username = username
        self.password = password
        self.system_ip = system_ip
        self.site_id = site_id
        self._client: httpx.Client | None = None

    def _session(self) -> httpx.Client:
        if self._client is None:
            c = httpx.Client(base_url=self.base, verify=False, timeout=20.0)
            r = c.post(
                "/j_security_check",
                data={"j_username": self.username, "j_password": self.password},
            )
            r.raise_for_status()
            tok = c.get("/dataservice/client/token")
            if tok.status_code == 200:
                c.headers["X-XSRF-TOKEN"] = tok.text
            self._client = c
        return self._client

    def _get(self, path: str) -> dict:
        r = self._session().get(path)
        r.raise_for_status()
        return r.json()

    def snapshot(self) -> DeviceSnapshot:
        data = self._get(f"/dataservice/device?system-ip={self.system_ip}")
        rows = data.get("data") if isinstance(data, dict) else data
        row = (rows or [{}])[0] if isinstance(rows, list) else {}
        name = str(row.get("host-name") or self.system_ip)
        site = str(row.get("site-id") or self.site_id)
        identity = DeviceIdentity(
            id=slug_id(name),
            name=name,
            type="viptela",
            platform="viptela",
            vendor="cisco",
            model=str(row.get("device-model") or row.get("deviceModel") or ""),
            mgmt_ip=str(row.get("system-ip") or self.system_ip),
            version=str(row.get("version") or ""),
            site_id=site,
            cpu=int(float(row.get("cpu-load") or row.get("cpuLoad") or 0)),
            status="up" if str(row.get("reachability", "reachable")).lower() in {"reachable", "up"} else "down",
        )
        interfaces: list[InterfaceFact] = []
        try:
            idata = self._get(f"/dataservice/device/interface?deviceId={self.system_ip}")
            for item in idata.get("data") or []:
                iname = str(item.get("ifname") or item.get("vdevice-name") or "")
                ip = str(item.get("ip-address") or item.get("ipAddress") or "")
                desc = str(item.get("desc") or item.get("description") or "")
                fact = InterfaceFact(
                    name=iname,
                    ip_address=ip,
                    description=desc,
                    oper_status=str(item.get("if-oper-status") or item.get("status") or "up").lower(),
                )
                fact.role = classify_interface(iname, desc, ip)  # type: ignore[assignment]
                # TLOC / tunnel / ge0/0 internet color is WAN and must not be walked
                vpn = str(item.get("vpn-id") or item.get("vpnId") or "")
                if vpn in {"0", "512"} or "tloc" in desc.lower() or iname.lower().startswith(("ge0/0", "gigabitethernet0/0/0")):
                    if "lan" not in desc.lower():
                        fact.role = "wan"
                interfaces.append(fact)
        except Exception:
            pass
        neighbors: list[Neighbor] = []
        try:
            ndata = self._get(f"/dataservice/device/cdp/neighbor?deviceId={self.system_ip}")
            for item in ndata.get("data") or []:
                neighbors.append(
                    Neighbor(
                        local_interface=str(item.get("ifname") or item.get("local-interface") or ""),
                        remote_interface=str(item.get("port") or item.get("remote-interface") or ""),
                        remote_hostname=str(item.get("system-name") or item.get("deviceId") or ""),
                        remote_mgmt_ip=str(item.get("ip") or ""),
                        protocol="cdp",
                    )
                )
        except Exception:
            pass
        arp: list[ArpEntry] = []
        try:
            adata = self._get(f"/dataservice/device/arp?deviceId={self.system_ip}")
            for item in adata.get("data") or []:
                arp.append(
                    ArpEntry(
                        ip=str(item.get("ip") or item.get("ip-addr") or ""),
                        mac=str(item.get("mac") or item.get("hw-addr") or ""),
                        interface=str(item.get("ifname") or ""),
                        learned_on=name,
                    )
                )
        except Exception:
            pass
        routes = [
            Route(prefix="0.0.0.0/0", nexthop="", interface="GigabitEthernet0/0/0", protocol="dia", is_default=True)
        ]
        return DeviceSnapshot(identity, interfaces, neighbors, arp, routes=routes)
