from __future__ import annotations

import re

from app.discovery.boundary import normalize_mac
from app.models.schemas import ArpEntry, InterfaceFact, MacEntry, Route


def parse_arp(output: str, learned_on: str = "") -> list[ArpEntry]:
    entries: list[ArpEntry] = []
    for line in (output or "").splitlines():
        # Internet  10.20.10.45            0   aabb.ccdd.eeff  ARPA   Vlan20
        m = re.search(
            r"Internet\s+(\d+\.\d+\.\d+\.\d+)\s+(\S+)\s+([0-9a-fA-F.]+)\s+ARPA\s+(\S+)",
            line,
        )
        if m:
            iface = m.group(4)
            vlan = _vlan_from_iface(iface)
            entries.append(
                ArpEntry(
                    ip=m.group(1),
                    mac=normalize_mac(m.group(3)),
                    interface=iface,
                    vlan=vlan,
                    age=m.group(2),
                    learned_on=learned_on,
                )
            )
            continue
        # 10.20.10.45    00:11:22:33:44:55   vlan20   GigabitEthernet1/0/1
        m = re.search(
            r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:.-]{11,17})\s+(\S+)\s+(\S+)",
            line,
        )
        if m and "protocol" not in line.lower() and "address" not in line.lower():
            entries.append(
                ArpEntry(
                    ip=m.group(1),
                    mac=normalize_mac(m.group(2)),
                    interface=m.group(4),
                    vlan=_vlan_from_iface(m.group(3)),
                    learned_on=learned_on,
                )
            )
    return entries


def parse_mac_table(output: str) -> list[MacEntry]:
    entries: list[MacEntry] = []
    for line in (output or "").splitlines():
        m = re.search(
            r"\s*(\d+)\s+([0-9a-fA-F.]+)\s+(DYNAMIC|STATIC|STATIC)\s+(\S+)",
            line,
            re.I,
        )
        if not m:
            m = re.search(
                r"\s*(\d+)\s+([0-9a-fA-F:]{14,17})\s+(DYNAMIC|STATIC)\s+(\S+)",
                line,
                re.I,
            )
        if m:
            entries.append(
                MacEntry(
                    mac=normalize_mac(m.group(2)),
                    vlan=int(m.group(1)),
                    interface=m.group(4),
                    type=m.group(3).upper(),
                )
            )
    return entries


def parse_ip_interfaces_brief(output: str) -> list[InterfaceFact]:
    facts: list[InterfaceFact] = []
    started = False
    for line in (output or "").splitlines():
        if re.search(r"Interface\s+IP-Address", line, re.I):
            started = True
            continue
        if not started or not line.strip():
            continue
        parts = line.split()
        if len(parts) < 6:
            continue
        name, ip, ok, method, status, protocol = parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]
        facts.append(
            InterfaceFact(
                name=name,
                ip_address="" if ip.lower() in {"unassigned", "unset"} else ip,
                admin_status=status.lower(),
                oper_status=protocol.lower(),
            )
        )
    return facts


def parse_interfaces(output: str) -> list[InterfaceFact]:
    """Parse `show interfaces` blocks for rates and status."""
    facts: list[InterfaceFact] = []
    blocks = re.split(r"\n(?=\S+\s+is (?:up|down|administratively down))", output or "")
    for block in blocks:
        m = re.match(r"(\S+)\s+is\s+(administratively down|up|down),\s+line protocol is\s+(up|down)", block)
        if not m:
            continue
        desc = _field(r"Description:\s*([^\n]+)", block) or ""
        bw = _field(r"BW\s+(\d+)\s+Kbit", block)
        ip = _field(r"Internet address is\s+(\S+)", block) or ""
        mac = _field(r"address is\s+([0-9a-fA-F.]+)", block) or ""
        in_rate = _field(r"5 minute input rate\s+(\d+)\s+bits", block)
        out_rate = _field(r"5 minute output rate\s+(\d+)\s+bits", block)
        bw_mbps = int(bw) / 1000 if bw else 1000
        rx = _util(in_rate, bw_mbps)
        tx = _util(out_rate, bw_mbps)
        facts.append(
            InterfaceFact(
                name=m.group(1),
                admin_status="down" if "administratively" in m.group(2) else m.group(2),
                oper_status=m.group(3),
                description=desc.strip(),
                ip_address=ip.split("/")[0],
                subnet=ip if "/" in ip else "",
                mac=mac,
                bandwidth_mbps=int(bw_mbps) if bw_mbps else 1000,
                rx_util_pct=rx,
                tx_util_pct=tx,
            )
        )
    return facts


def parse_routes(output: str) -> list[Route]:
    routes: list[Route] = []
    for line in (output or "").splitlines():
        m = re.search(
            r"^(?:S\*|S|D|O|C|B|R|L)\s+(\S+)\s+(?:\[\S+\] via\s+(\S+),)?\s*(\S+)?",
            line,
        )
        default = False
        prefix = ""
        nexthop = ""
        iface = ""
        proto = ""
        if line.strip().startswith("S*") or "0.0.0.0/0" in line or "0.0.0.0 0.0.0.0" in line:
            default = True
            prefix = "0.0.0.0/0"
            nh = re.search(r"via\s+(\S+)", line)
            ifc = re.search(r",\s*(\S+)$", line.strip())
            nexthop = nh.group(1).rstrip(",") if nh else ""
            iface = ifc.group(1) if ifc else ""
            proto = "static"
        else:
            m = re.search(r"^([A-Z*]+)\s+(\d+\.\d+\.\d+\.\d+(?:/\d+)?)\s+", line)
            if not m:
                continue
            proto = m.group(1)
            prefix = m.group(2)
            nh = re.search(r"via\s+(\S+)", line)
            nexthop = nh.group(1).rstrip(",") if nh else ""
            ifc = re.search(r"(?:is directly connected,|,)\s+(\S+)$", line.strip())
            iface = ifc.group(1) if ifc else ""
        routes.append(
            Route(prefix=prefix, nexthop=nexthop, interface=iface, protocol=proto, is_default=default)
        )
    return routes


def _util(bits_per_sec: str | None, bw_mbps: float) -> float:
    if not bits_per_sec or not bw_mbps:
        return 0.0
    cap = bw_mbps * 1_000_000
    if cap <= 0:
        return 0.0
    return round(min(100.0, int(bits_per_sec) / cap * 100), 1)


def _vlan_from_iface(iface: str) -> int | None:
    m = re.search(r"vlan\s*(\d+)", iface or "", re.I)
    return int(m.group(1)) if m else None


def _field(pattern: str, text: str) -> str | None:
    m = re.search(pattern, text, re.I)
    return m.group(1) if m else None
