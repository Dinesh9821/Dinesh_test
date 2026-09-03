from __future__ import annotations

import re
from ipaddress import ip_address, ip_network

WAN_HINTS = (
    "wan",
    "internet",
    "dia",
    "isp",
    "mpls",
    "outside",
    "underlay",
    "tloc",
    "public-internet",
    "biz-internet",
    "lte",
    "cellular",
)

INTERNET_NEIGHBOR_HINTS = (
    "isp",
    "pe-",
    "pe_",
    "internet",
    "ixp",
    "transit",
    "telco",
    "airtel",
    "jio",
    "tata",
    "reliance",
    "bsnl",
    "verizon",
    "att",
    "lumen",
    "ntt",
    "cogent",
)


def classify_interface(name: str, description: str = "", ip: str = "") -> str:
    blob = f"{name} {description}".lower()
    if any(h in blob for h in WAN_HINTS):
        return "wan"
    if "capwap" in blob or name.lower().startswith("capwap"):
        return "capwap"
    if "mgmt" in blob or "management" in blob:
        return "mgmt"
    if ip:
        try:
            addr = ip.split("/")[0]
            if ip_address(addr).is_global:
                return "wan"
        except ValueError:
            pass
    lname = name.lower()
    if lname.startswith(("gi", "te", "fa", "eth", "twe")):
        return "lan"
    return "unknown"


def is_internet_neighbor(hostname: str, local_role: str, remote_ip: str = "") -> bool:
    if local_role == "wan":
        return True
    hn = (hostname or "").lower()
    if any(h in hn for h in INTERNET_NEIGHBOR_HINTS):
        return True
    if remote_ip:
        try:
            addr = remote_ip.split("/")[0]
            if ip_address(addr).is_global:
                return True
        except ValueError:
            pass
    return False


def is_rfc1918(ip: str) -> bool:
    try:
        return ip_address(ip.split("/")[0]).is_private
    except ValueError:
        return False


def same_site_prefix(ip: str, site_cidrs: list[str]) -> bool:
    try:
        addr = ip_address(ip.split("/")[0])
    except ValueError:
        return False
    for cidr in site_cidrs:
        try:
            if addr in ip_network(cidr, strict=False):
                return True
        except ValueError:
            continue
    return False


def slug_id(name: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9]+", "-", name.strip()).strip("-")
    return cleaned.upper() or "NODE"


def normalize_mac(mac: str) -> str:
    hexes = re.findall(r"[0-9A-Fa-f]", mac or "")
    if len(hexes) != 12:
        return (mac or "").lower()
    h = "".join(hexes).lower()
    return ":".join(h[i : i + 2] for i in range(0, 12, 2))
