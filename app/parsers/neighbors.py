from __future__ import annotations

import re

from app.models.schemas import Neighbor


def parse_cdp_neighbors_detail(output: str) -> list[Neighbor]:
    blocks = re.split(r"-{5,}|Device ID:", output or "")
    neighbors: list[Neighbor] = []
    # First split piece is header; subsequent pieces start after Device ID
    raw_parts = re.split(r"\n(?=Device ID:)", output or "")
    for part in raw_parts:
        if "Device ID:" not in part and "Device ID :" not in part:
            if "-------------------------" in (output or "") and "Platform:" in part:
                pass
            else:
                continue
        device = _field(r"Device ID:\s*(\S+)", part)
        if not device:
            continue
        local = _field(r"Interface:\s*([^,\n]+)", part) or ""
        remote = _field(r"Port ID \(outgoing port\):\s*(\S+)", part) or _field(
            r"Port ID:\s*(\S+)", part
        ) or ""
        platform = _field(r"Platform:\s*([^,\n]+)", part) or ""
        ip = _field(r"IP address:\s*(\S+)", part) or _field(r"IPv4 Address:\s*(\S+)", part) or ""
        caps = _field(r"Capabilities:\s*([^\n]+)", part) or ""
        neighbors.append(
            Neighbor(
                local_interface=local.strip(),
                remote_interface=remote.strip(),
                remote_hostname=_strip_domain(device),
                remote_mgmt_ip=ip,
                remote_platform=platform.strip(),
                remote_type=_type_from_caps(caps, platform, device),
                protocol="cdp",
                capabilities=caps.strip(),
            )
        )
    if neighbors:
        return neighbors
    return parse_cdp_neighbors_table(output)


def parse_cdp_neighbors_table(output: str) -> list[Neighbor]:
    """Parse compact `show cdp neighbors` table."""
    neighbors: list[Neighbor] = []
    lines = (output or "").splitlines()
    started = False
    for line in lines:
        if re.search(r"Device[- ]ID", line, re.I):
            started = True
            continue
        if not started or not line.strip() or line.startswith("-"):
            continue
        # DeviceID LocalIntf Holdtime Capability Platform PortID
        m = re.match(
            r"(\S+)\s+(\S+\s*\S*)\s+\d+\s+([A-Z\s]+?)\s+(\S+)\s+(\S+)$",
            line.strip(),
        )
        if not m:
            parts = line.split()
            if len(parts) >= 5:
                neighbors.append(
                    Neighbor(
                        local_interface=parts[1],
                        remote_interface=parts[-1],
                        remote_hostname=_strip_domain(parts[0]),
                        remote_platform=parts[-2],
                        remote_type=_type_from_caps(" ".join(parts[2:-2]), parts[-2], parts[0]),
                        protocol="cdp",
                    )
                )
            continue
        neighbors.append(
            Neighbor(
                local_interface=m.group(2).strip(),
                remote_interface=m.group(5).strip(),
                remote_hostname=_strip_domain(m.group(1)),
                remote_platform=m.group(4),
                remote_type=_type_from_caps(m.group(3), m.group(4), m.group(1)),
                protocol="cdp",
            )
        )
    return neighbors


def parse_lldp_neighbors_detail(output: str) -> list[Neighbor]:
    parts = re.split(r"\n(?=Local Intf:|Chassis id:|System Name:)", output or "")
    neighbors: list[Neighbor] = []
    current: dict[str, str] = {}
    for part in re.split(r"-{5,}", output or ""):
        if "System Name:" not in part and "System name:" not in part:
            continue
        name = _field(r"System Name:\s*(\S+)", part) or _field(r"System name:\s*(\S+)", part)
        local = _field(r"Local Intf:\s*(\S+)", part) or _field(r"Interface:\s*(\S+)", part) or ""
        remote = (
            _field(r"Port id:\s*(\S+)", part)
            or _field(r"Port ID:\s*(\S+)", part)
            or _field(r"Port Description:\s*(\S+)", part)
            or ""
        )
        ip = _field(r"Management Address:\s*(\S+)", part) or _field(r"IP:\s*(\S+)", part) or ""
        caps = _field(r"System Capabilities:\s*([^\n]+)", part) or ""
        if name:
            neighbors.append(
                Neighbor(
                    local_interface=local,
                    remote_interface=remote,
                    remote_hostname=_strip_domain(name),
                    remote_mgmt_ip=ip,
                    remote_type=_type_from_caps(caps, "", name),
                    protocol="lldp",
                    capabilities=caps,
                )
            )
    return neighbors


def _type_from_caps(caps: str, platform: str, hostname: str) -> str:
    blob = f"{caps} {platform} {hostname}".lower()
    if "vedge" in blob or "viptela" in blob or "sd-wan" in blob:
        return "viptela"
    if "meraki" in blob:
        return "meraki"
    if "aironet" in blob or "air-cap" in blob or hostname.lower().startswith("ap"):
        return "ap"
    if "wireless" in blob or "wlc" in blob or "9800" in blob:
        return "wlc"
    if "switch" in blob or "trans-bridge" in blob or hostname.lower().startswith("sw"):
        return "switch"
    if "router" in blob or "source-route" in blob or hostname.lower().startswith("rtr"):
        return "router"
    if "r " in f" {caps.lower()} " or caps.strip().upper().startswith("R"):
        return "router"
    return "unknown"


def _strip_domain(name: str) -> str:
    return name.split(".")[0].strip()


def _field(pattern: str, text: str) -> str | None:
    m = re.search(pattern, text, re.I)
    return m.group(1) if m else None
