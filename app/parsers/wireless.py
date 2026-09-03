from __future__ import annotations

import re

from app.discovery.boundary import normalize_mac
from app.models.schemas import WirelessAP, WirelessClient


def parse_ap_summary(output: str, wlc_name: str = "") -> list[WirelessAP]:
    aps: list[WirelessAP] = []
    started = False
    for line in (output or "").splitlines():
        if re.search(r"AP Name", line, re.I) and re.search(r"Slots|State|Model", line, re.I):
            started = True
            continue
        if not started or not line.strip() or set(line.strip()) <= {"-", " "}:
            continue
        parts = line.split()
        if len(parts) < 3:
            continue
        name = parts[0]
        # 9800: AP Name Slots AP Model Ethernet MAC Radio MAC State
        mac = ""
        model = ""
        status = "up"
        ip = ""
        for p in parts[1:]:
            if re.fullmatch(r"[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}", p) or re.fullmatch(
                r"([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", p
            ):
                mac = normalize_mac(p)
            elif re.fullmatch(r"\d+\.\d+\.\d+\.\d+", p):
                ip = p
            elif p.lower() in {"registered", "enabled", "up"}:
                status = "up"
            elif p.lower() in {"down", "disabled", "not"}:
                status = "down"
            elif any(c.isalpha() for c in p) and p.upper() not in {"AP", "RADIO", "MAC"}:
                if not model and not re.fullmatch(r"\d+", p):
                    model = p
        aps.append(
            WirelessAP(name=name, mac=mac, ip=ip, model=model, status=status, wlc_name=wlc_name)
        )
    return aps


def parse_wireless_clients(output: str) -> list[WirelessClient]:
    clients: list[WirelessClient] = []
    started = False
    for line in (output or "").splitlines():
        if re.search(r"MAC Address", line, re.I) and re.search(r"AP Name|SSID", line, re.I):
            started = True
            continue
        if not started or not line.strip() or set(line.strip()) <= {"-", " "}:
            continue
        parts = line.split()
        if len(parts) < 3:
            continue
        mac = normalize_mac(parts[0]) if re.search(r"[0-9a-fA-F]{4}\.", parts[0]) or ":" in parts[0] else ""
        ip = next((p for p in parts if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", p)), "")
        ap = ""
        ssid = ""
        user = ""
        for p in parts[1:]:
            if p.lower().startswith("ap-") or p.upper().startswith("AP"):
                ap = p
            elif not ssid and any(c.isalpha() for c in p) and p not in {ap, ip} and not re.search(r"\d+\.\d+", p):
                if p.lower() not in {"run", "associated", "up"}:
                    if not user and p[0].isalpha():
                        user = p
                    else:
                        ssid = p
        clients.append(
            WirelessClient(ip=ip, mac=mac or normalize_mac(parts[0]), ap_name=ap, ssid=ssid, username=user)
        )
    return clients
