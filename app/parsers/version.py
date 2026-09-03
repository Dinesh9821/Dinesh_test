from __future__ import annotations

import re

from app.models.schemas import DeviceIdentity, DeviceType, Platform


_IOSXE_HINTS = ("ios-xe", "iosxe", "cisco ios xe", "asr", "isr", "catalyst 9", "c9", "9800")
_WLC_HINTS = ("wireless lan controller", "cisco controller", "air-ct", "c9800", "ewlc")
_VIPT_HINTS = ("viptela", "vedge", "cedge", "sd-wan", "vmanage")


def parse_show_version(output: str, mgmt_ip: str = "") -> DeviceIdentity:
    text = output or ""
    hostname = _first(r"(\S+)\s+uptime is", text) or _first(r"hostname\s+(\S+)", text) or "unknown"
    version = (
        _first(r"Cisco IOS XE Software, Version\s+(\S+)", text)
        or _first(r"Cisco IOS Software.*Version\s+([^,\s]+)", text)
        or _first(r"System image file is \"([^\"]+)\"", text)
        or ""
    )
    model = (
        _first(r"cisco\s+([A-Z0-9][A-Z0-9/-]+)\s+\(", text)
        or _first(r"Model Number\s*:\s*(\S+)", text)
        or _first(r"PID:\s*(\S+)", text)
        or ""
    )
    serial = _first(r"Processor board ID\s+(\S+)", text) or _first(r"System Serial Number\s*:\s*(\S+)", text) or ""
    platform, dtype = classify_platform(text, hostname, model)
    status = "up" if "uptime is" in text.lower() or "cisco" in text.lower() else "up"
    return DeviceIdentity(
        id=hostname.upper(),
        name=hostname,
        type=dtype,
        platform=platform,
        vendor="cisco" if "meraki" not in text.lower() else "meraki",
        model=model,
        mgmt_ip=mgmt_ip,
        serial=serial,
        version=version,
        status=status,
    )


def classify_platform(text: str, hostname: str = "", model: str = "") -> tuple[Platform, DeviceType]:
    blob = f"{text} {hostname} {model}".lower()
    if any(h in blob for h in _VIPT_HINTS) or hostname.lower().startswith(("vedge", "cedge", "viptela")):
        return "viptela", "viptela"
    if "meraki" in blob:
        return "meraki", "meraki"
    if any(h in blob for h in _WLC_HINTS) or hostname.lower().startswith("wlc"):
        if "ios xe" in blob or "9800" in blob:
            return "wlc-9800", "wlc"
        return "wlc-aireos", "wlc"
    if "air-cap" in blob or "air-ap" in blob or hostname.lower().startswith("ap-"):
        return "ios", "ap"
    if any(h in blob for h in _IOSXE_HINTS) or "ios xe" in blob:
        if _is_switch(blob, hostname):
            return "ios-xe", "switch"
        return "ios-xe", "router"
    if _is_switch(blob, hostname):
        return "ios", "switch"
    return "ios", "router"


def _is_switch(blob: str, hostname: str) -> bool:
    return (
        hostname.lower().startswith("sw")
        or "switch" in blob
        or "catalyst" in blob
        or "ws-c" in blob
        or "c9200" in blob
        or "c9300" in blob
        or "c3850" in blob
        or "l2" in blob
    )


def parse_cpu(output: str) -> int:
    m = re.search(
        r"CPU utilization for five seconds:\s*(\d+)%/(\d+)%;\s*one minute:\s*(\d+)%;\s*five minutes:\s*(\d+)%",
        output or "",
        re.I,
    )
    if m:
        return int(m.group(4))
    m = re.search(r"one minute:\s*(\d+)%", output or "", re.I)
    if m:
        return int(m.group(1))
    m = re.search(r"CPU\s*[:=]\s*(\d+)", output or "", re.I)
    return int(m.group(1)) if m else 0


def _first(pattern: str, text: str) -> str | None:
    m = re.search(pattern, text, re.I)
    return m.group(1) if m else None
