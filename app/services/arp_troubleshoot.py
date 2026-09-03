from __future__ import annotations

from app.collectors.mock import get_lab
from app.discovery.boundary import normalize_mac, slug_id
from app.discovery.engine import TopologyDiscovery, legend
from app.models.schemas import CytoscapeEdge, CytoscapeNode, DeviceIdentity, SeedRequest, WirelessClient
from app.style import cytoscape_stylesheet, type_color, type_shape, type_symbol


class ArpTroubleshoot:
    """LAN + WAN view of a user for a network engineer.

    LAN answers: which VLAN, which access port or AP, is the MAC learned,
    is the gateway ARP complete?
    WAN answers: how that user exits the site (core -> cEdge -> DIA),
    and whether the Internet handoff is congested or lossy.
    """

    def __init__(self, demo: bool = True) -> None:
        self.demo = demo
        self.lab = get_lab() if demo else None

    def query(
        self,
        ip: str | None = None,
        mac: str | None = None,
        username: str | None = None,
        hostname: str | None = None,
        site_id: str = "MUM-01",
    ) -> dict:
        if not self.lab:
            raise RuntimeError("Live ARP correlation requires demo lab or an inventory snapshot")
        ident = self._identify(ip, mac, username, hostname)
        if ident is None:
            return {
                "found": False,
                "query": {"ip": ip, "mac": mac, "username": username, "hostname": hostname},
                "message": "No ARP/MAC/client match in this site. Try a campus IP, MAC, or username.",
                "nodes": [],
                "edges": [],
                "legend": legend(),
                "style": cytoscape_stylesheet(),
            }

        lan = self._lan_view(ident)
        wan = self._wan_view(ident, lan)
        path = self._path_graph(ident, lan, wan)
        findings = lan["findings"] + wan["findings"]
        verdict = self._verdict(findings, lan, wan)
        return {
            "found": True,
            "query": {"ip": ip, "mac": mac, "username": username, "hostname": hostname},
            "identity": {
                "ip": ident.ip,
                "mac": ident.mac,
                "username": ident.username,
                "hostname": ident.hostname,
                "vlan": ident.vlan,
                "ssid": ident.ssid,
            },
            "lan": lan,
            "wan": wan,
            "findings": findings,
            "verdict": verdict,
            "engineer_notes": self._notes(ident, lan, wan),
            "nodes": path["nodes"],
            "edges": path["edges"],
            "legend": legend(),
            "style": cytoscape_stylesheet(),
            "site_id": site_id,
        }

    def _identify(self, ip, mac, username, hostname) -> WirelessClient | None:
        mac_n = normalize_mac(mac) if mac else None
        ip_n = (ip or "").strip()
        user_n = (username or "").strip().lower()
        host_n = (hostname or "").strip().lower()
        for c in self.lab.hosts:
            if ip_n and c.ip == ip_n:
                return c
            if mac_n and normalize_mac(c.mac) == mac_n:
                return c
            if user_n and c.username.lower() == user_n:
                return c
            if host_n and c.hostname.lower() == host_n:
                return c
        # Fall back to device ARP tables
        for dev in self.lab.devices.values():
            for e in dev.arp:
                if ip_n and e.ip == ip_n:
                    return WirelessClient(ip=e.ip, mac=e.mac, vlan=e.vlan, hostname=e.ip)
                if mac_n and normalize_mac(e.mac) == mac_n:
                    return WirelessClient(ip=e.ip, mac=e.mac, vlan=e.vlan, hostname=e.ip)
        return None

    def _lan_view(self, ident: WirelessClient) -> dict:
        findings: list[dict] = []
        access = None
        port = None
        ap = None
        wlc = None
        meraki_ap = None
        gateway = None
        arp_ok = False
        mac_n = normalize_mac(ident.mac)

        for name, dev in self.lab.devices.items():
            for e in dev.arp:
                if e.ip == ident.ip or normalize_mac(e.mac) == mac_n:
                    if e.interface.lower().startswith("vlan"):
                        arp_ok = True
                        gateway = {
                            "device": name,
                            "svi": e.interface,
                            "gateway_ip": next(
                                (i.ip_address for i in dev.interfaces if i.name.lower() == e.interface.lower()),
                                "",
                            ),
                        }
            for m in dev.mac:
                if normalize_mac(m.mac) == mac_n:
                    # Prefer access switch over distribution
                    if access is None or "ACC" in name or name.startswith("MS-"):
                        if "DIST" in name and access and "ACC" in str(access.get("device", "")):
                            continue
                        access = {
                            "device": name,
                            "type": dev.identity.type,
                            "port": m.interface,
                            "vlan": m.vlan,
                            "mac_type": m.type,
                        }
                        port = m.interface

        if ident.ap_name:
            ap_dev = self.lab.devices.get(ident.ap_name)
            if ap_dev:
                ap = {
                    "name": ap_dev.identity.name,
                    "model": ap_dev.identity.model,
                    "mgmt_ip": ap_dev.identity.mgmt_ip,
                    "vendor": ap_dev.identity.vendor,
                    "ssid": ident.ssid,
                    "rssi": ident.rssi,
                }
                if ap_dev.identity.vendor == "meraki":
                    meraki_ap = ap
            for d in self.lab.devices.values():
                for wap in d.aps:
                    if wap.name == ident.ap_name:
                        wlc = {"name": d.identity.name, "model": d.identity.model, "mgmt_ip": d.identity.mgmt_ip}
                        access = {
                            "device": wap.switch_hostname,
                            "port": wap.switch_port,
                            "vlan": ident.vlan,
                            "type": "switch",
                            "note": "AP ethernet uplink (client is wireless)",
                        }

        if ident.rssi is not None and ident.rssi < -75:
            findings.append(
                {
                    "severity": "warn",
                    "domain": "lan",
                    "code": "WEAK_RSSI",
                    "detail": f"Client RSSI {ident.rssi} dBm on {ident.ap_name}. Suspect RF, not WAN.",
                }
            )
        if not arp_ok:
            findings.append(
                {
                    "severity": "error",
                    "domain": "lan",
                    "code": "ARP_MISSING",
                    "detail": "No complete ARP on the L3 SVI. Client may be isolated, wrong VLAN, or silent.",
                }
            )
        else:
            findings.append(
                {
                    "severity": "ok",
                    "domain": "lan",
                    "code": "ARP_COMPLETE",
                    "detail": f"Gateway ARP for {ident.ip} is complete on {gateway['device'] if gateway else 'SVI'}.",
                }
            )
        if access:
            findings.append(
                {
                    "severity": "ok",
                    "domain": "lan",
                    "code": "MAC_LEARNED",
                    "detail": f"MAC {ident.mac} learned on {access['device']} {access['port']} VLAN {access.get('vlan')}.",
                }
            )
        else:
            findings.append(
                {
                    "severity": "error",
                    "domain": "lan",
                    "code": "MAC_UNKNOWN",
                    "detail": "MAC not in any switch CAM table. Check VLAN, port security, or wireless roam.",
                }
            )
        if ident.ssid == "MUM-GUEST":
            findings.append(
                {
                    "severity": "info",
                    "domain": "lan",
                    "code": "GUEST_POLICY",
                    "detail": "Client is on guest SSID. Internet may be allowed while east-west LAN is blocked by policy.",
                }
            )

        access_type = "wireless" if ident.ap_name else "wired"
        return {
            "access_type": access_type,
            "vlan": ident.vlan,
            "gateway": gateway,
            "access_switch": access,
            "ap": ap or meraki_ap,
            "wlc": wlc,
            "arp_complete": arp_ok,
            "findings": findings,
        }

    def _wan_view(self, ident: WirelessClient, lan: dict) -> dict:
        findings: list[dict] = []
        core = self.lab.devices.get("RTR-MUM-CORE")
        ved = self.lab.devices.get("VEDGE-MUM-001")
        wan_if = next((i for i in ved.interfaces if i.role == "wan"), None) if ved else None
        default = next((r for r in (ved.routes if ved else []) if r.is_default), None)
        util = int(max(wan_if.rx_util_pct, wan_if.tx_util_pct)) if wan_if else 0
        latency = wan_if.latency_ms if wan_if else None
        loss = wan_if.packet_loss_pct if wan_if else None

        if wan_if and wan_if.oper_status != "up":
            findings.append(
                {
                    "severity": "error",
                    "domain": "wan",
                    "code": "WAN_DOWN",
                    "detail": f"{ved.identity.name} {wan_if.name} is {wan_if.oper_status}. Site is isolated from Internet.",
                }
            )
        if util >= 80:
            findings.append(
                {
                    "severity": "warn",
                    "domain": "wan",
                    "code": "WAN_CONGESTION",
                    "detail": f"DIA {wan_if.name} utilization {util}%. User slowness is likely WAN, not LAN switching.",
                }
            )
        elif util:
            findings.append(
                {
                    "severity": "ok",
                    "domain": "wan",
                    "code": "WAN_HEADROOM",
                    "detail": f"DIA {wan_if.name} utilization {util}% — not congested.",
                }
            )
        if loss and loss > 0:
            findings.append(
                {
                    "severity": "warn",
                    "domain": "wan",
                    "code": "WAN_LOSS",
                    "detail": f"Packet loss {loss}% and latency {latency} ms on the Airtel DIA TLOC. Compare with LAN ARP health.",
                }
            )
        # NAT / overlay
        nat = {
            "type": "DIA PAT",
            "inside": ident.ip,
            "outside_interface": wan_if.name if wan_if else "GigabitEthernet0/0/0",
            "outside_ip": wan_if.ip_address if wan_if else "",
            "note": "User sourced traffic is PAT'd on the site cEdge. Other Viptela sites are not in this path.",
        }
        sdwan = {
            "site_id": "100",
            "system_ip": ved.identity.mgmt_ip if ved else "",
            "color": "biz-internet",
            "tloc": wan_if.name if wan_if else "",
            "overlay_peers_ignored": True,
        }
        if lan.get("arp_complete"):
            findings.append(
                {
                    "severity": "ok",
                    "domain": "wan",
                    "code": "GATEWAY_REACHABLE",
                    "detail": "LAN default gateway ARP is present, so a 'no Internet' ticket should focus on DIA/NAT/DNS next.",
                }
            )
        return {
            "core": core.identity.name if core else None,
            "edge": ved.identity.name if ved else None,
            "default_route": {
                "nexthop": default.nexthop if default else None,
                "interface": default.interface if default else None,
                "peer": "ISP-AIRTEL-PE-MUM",
            },
            "dia": {
                "interface": wan_if.name if wan_if else None,
                "utilization": util,
                "latency_ms": latency,
                "packet_loss_pct": loss,
                "oper_status": wan_if.oper_status if wan_if else None,
            },
            "nat": nat,
            "sdwan": sdwan,
            "findings": findings,
        }

    def _path_graph(self, ident: WirelessClient, lan: dict, wan: dict) -> dict:
        hops: list[DeviceIdentity] = []
        host = DeviceIdentity(
            id=slug_id(ident.hostname or ident.ip),
            name=ident.hostname or ident.ip,
            type="host",
            platform="host",
            mgmt_ip=ident.ip,
            cpu=0,
            status="up",
        )
        hops.append(host)
        chain_names: list[str] = [host.name]
        if ident.ap_name and ident.ap_name in self.lab.devices:
            hops.append(self.lab.devices[ident.ap_name].identity)
            chain_names.append(ident.ap_name)
        if lan.get("wlc"):
            hops.append(self.lab.devices[lan["wlc"]["name"]].identity)
            chain_names.append(lan["wlc"]["name"])
        acc = lan.get("access_switch") or {}
        acc_name = acc.get("device")
        if acc_name and acc_name in self.lab.devices and acc_name not in chain_names:
            hops.append(self.lab.devices[acc_name].identity)
            chain_names.append(acc_name)
        for name in ("SW-MUM-DIST", "RTR-MUM-CORE", "VEDGE-MUM-001"):
            if name in self.lab.devices and name not in chain_names:
                hops.append(self.lab.devices[name].identity)
                chain_names.append(name)
        inet = DeviceIdentity(
            id="INTERNET",
            name="Internet",
            type="internet",
            platform="internet",
            status="up",
            cpu=0,
        )
        hops.append(inet)
        chain_names.append(inet.name)

        nodes = []
        for h in hops:
            nodes.append(
                {
                    "data": {
                        "id": h.id,
                        "name": h.name,
                        "type": h.type,
                        "cpu": h.cpu,
                        "status": h.status,
                        "mgmt_ip": h.mgmt_ip,
                        "model": h.model,
                        "color": type_color(h.type),
                        "shape": type_shape(h.type),
                        "symbol": type_symbol(h.type),
                        "label": f"{type_symbol(h.type)}  {h.name}",
                    },
                    "classes": f"{h.type} {h.status} path",
                }
            )
        edges = []
        ifaces = {
            (ident.hostname or ident.ip, ident.ap_name): ident.ssid or "wifi",
            (ident.ap_name, acc_name): (acc.get("port") or "Gi0"),
            (acc_name, "SW-MUM-DIST"): "uplink",
            ("MS-MUM-01", "SW-MUM-DIST"): "1",
            ("SW-MUM-DIST", "RTR-MUM-CORE"): "Te1/1/1",
            ("RTR-MUM-CORE", "VEDGE-MUM-001"): "Gi0/0/0",
            ("VEDGE-MUM-001", "Internet"): "Gi0/0/0 DIA",
            (ident.hostname or ident.ip, acc_name): acc.get("port") or "access",
            (ident.ap_name, "WLC-MUM-01"): "CAPWAP",
            ("WLC-MUM-01", "SW-MUM-DIST"): "Gi0/0/1",
            ("MR-MUM-01", "MS-MUM-01"): "wired0",
        }
        for a, b in zip(chain_names, chain_names[1:]):
            src, dst = slug_id(a), slug_id(b)
            label = ifaces.get((a, b)) or ifaces.get((b, a)) or ""
            wan_edge = b == "Internet"
            edges.append(
                {
                    "data": {
                        "id": f"{src}-{dst}",
                        "source": src,
                        "target": dst,
                        "interface": label,
                        "utilization": wan["dia"]["utilization"] if wan_edge else 10,
                        "latency": wan["dia"]["latency_ms"] if wan_edge else 1,
                        "packet_loss": wan["dia"]["packet_loss_pct"] if wan_edge else 0,
                        "iflabel": label,
                    },
                    "classes": "path wan" if wan_edge else "path cool",
                }
            )
        return {"nodes": nodes, "edges": edges}

    def _verdict(self, findings, lan, wan) -> dict:
        errors = [f for f in findings if f["severity"] == "error"]
        warns = [f for f in findings if f["severity"] == "warn"]
        if errors:
            scope = errors[0]["domain"].upper()
            return {"level": "red", "summary": f"Break is on the {scope} side: {errors[0]['detail']}"}
        if warns:
            scope = warns[0]["domain"].upper()
            return {"level": "amber", "summary": f"{scope} degraded: {warns[0]['detail']}"}
        return {
            "level": "green",
            "summary": "LAN ARP/MAC healthy. User traffic can reach the site DIA edge.",
        }

    def _notes(self, ident, lan, wan) -> list[str]:
        notes = [
            f"Start with CAM/ARP: confirm {ident.mac} on the access port and {ident.ip} on the VLAN {ident.vlan} SVI.",
            "If ARP is complete but the user has no Internet, skip L2 and jump to DIA utilization, NAT, DNS.",
            "SD-WAN overlay peers and other sites are out of scope — this path stops at the local Internet TLOC.",
        ]
        if lan["access_type"] == "wireless":
            notes.insert(
                1,
                "Wireless: split RF (RSSI/SSID/AP) from wired CAPWAP uplink. A healthy AP ethernet port with bad RSSI is not a switch problem.",
            )
        return notes
