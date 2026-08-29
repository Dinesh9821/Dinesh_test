"""
Network Operations REST API backend.

Production-oriented FastAPI service that connects to Cisco IOS/IOS-XE/NX-OS/ASA/SD-WAN
devices (Netmiko) and Cisco Meraki (Dashboard API), executes operational commands,
and returns normalized JSON for a NOC / monitoring UI.

This module is intentionally a single file for the initial delivery, but is
internally partitioned so it can later be split into:

    routers/  services/  models/  connectors/  utils/
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import os
import re
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime, timezone
from enum import Enum
from functools import lru_cache
from typing import Any, Callable, Iterator, Optional, Protocol, Sequence
import httpx
from fastapi import APIRouter, FastAPI, Path, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from starlette.middleware.base import BaseHTTPMiddleware

try:
    from netmiko import ConnectHandler
    from netmiko.exceptions import (
        NetmikoAuthenticationException,
        NetmikoTimeoutException,
    )
except ImportError:  # pragma: no cover - optional at import time for unit tests
    ConnectHandler = None  # type: ignore[assignment,misc]

    class NetmikoAuthenticationException(Exception):  # type: ignore[no-redef]
        """Fallback when netmiko is not installed."""

    class NetmikoTimeoutException(Exception):  # type: ignore[no-redef]
        """Fallback when netmiko is not installed."""


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SERVICE_NAME = "network-operations-api"
SERVICE_VERSION = "1.0.0"
API_V1_PREFIX = "/api/v1"

SECRET_FIELD_NAMES = frozenset(
    {
        "password",
        "api_key",
        "apikey",
        "token",
        "secret",
        "authorization",
        "auth_token",
        "access_token",
        "private_key",
        "enable_secret",
        "enable_password",
    }
)

DANGEROUS_COMMAND_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"^\s*conf(igure)?(\s+terminal|\s+t)?\s*$", re.I),
    re.compile(r"^\s*conf\s+t\b", re.I),
    re.compile(r"^\s*reload\b", re.I),
    re.compile(r"^\s*write\s+erase\b", re.I),
    re.compile(r"^\s*erase\b", re.I),
    re.compile(r"^\s*delete\b", re.I),
    re.compile(r"^\s*format\b", re.I),
    re.compile(r"^\s*shutdown\b", re.I),
    re.compile(r"^\s*no\s+", re.I),
    re.compile(r"^\s*clear\s+", re.I),
    re.compile(r"^\s*wr(ite)?(\s+memory)?\s*$", re.I),
    re.compile(r"^\s*copy\s+", re.I),
    re.compile(r"^\s*debug\b", re.I),
    re.compile(r"^\s*undebug\b", re.I),
    re.compile(r"^\s*request\s+platform\b", re.I),
    re.compile(r"^\s*install\b", re.I),
)

ALLOWED_COMMAND_PREFIXES = (
    "show ",
    "ping ",
    "traceroute ",
    "tracert ",
)

CISCO_PLATFORMS = frozenset(
    {
        "cisco_ios",
        "cisco_iosxe",
        "cisco_xe",
        "cisco_nxos",
        "cisco_asa",
        "cisco_xr",
        "cisco_viptela",
        "cisco_sdwan",
        "cisco_router",
        "cisco_switch",
        "cisco_firewall",
    }
)

MERAKI_PLATFORMS = frozenset(
    {
        "meraki",
        "meraki_switch",
        "meraki_appliance",
        "meraki_wireless",
        "meraki_camera",
        "meraki_sensor",
        "cisco_meraki",
    }
)

NETMIKO_DEVICE_TYPE_MAP: dict[str, str] = {
    "cisco_ios": "cisco_ios",
    "cisco_iosxe": "cisco_xe",
    "cisco_xe": "cisco_xe",
    "cisco_nxos": "cisco_nxos",
    "cisco_asa": "cisco_asa",
    "cisco_xr": "cisco_xr",
    "cisco_viptela": "cisco_viptela",
    "cisco_sdwan": "cisco_viptela",
    "cisco_router": "cisco_ios",
    "cisco_switch": "cisco_ios",
    "cisco_firewall": "cisco_asa",
}


# ---------------------------------------------------------------------------
# Settings (environment-driven; no hardcoded credentials)
# ---------------------------------------------------------------------------


class Settings(BaseSettings):
    """Runtime configuration loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    app_name: str = SERVICE_NAME
    app_version: str = SERVICE_VERSION
    log_level: str = Field(default="INFO", validation_alias="LOG_LEVEL")
    api_prefix: str = API_V1_PREFIX

    network_ssh_timeout: int = Field(default=30, validation_alias="NETWORK_SSH_TIMEOUT")
    network_connection_timeout: int = Field(
        default=20, validation_alias="NETWORK_CONNECTION_TIMEOUT"
    )
    network_command_timeout: int = Field(
        default=60, validation_alias="NETWORK_COMMAND_TIMEOUT"
    )
    network_connection_retries: int = Field(
        default=1, validation_alias="NETWORK_CONNECTION_RETRIES"
    )
    network_max_workers: int = Field(default=16, validation_alias="NETWORK_MAX_WORKERS")

    meraki_api_base_url: str = Field(
        default="https://api.meraki.com/api/v1",
        validation_alias="MERAKI_API_BASE_URL",
    )
    meraki_api_timeout: int = Field(default=30, validation_alias="MERAKI_API_TIMEOUT")
    meraki_max_retries: int = Field(default=3, validation_alias="MERAKI_MAX_RETRIES")

    redis_url: Optional[str] = Field(default=None, validation_alias="REDIS_URL")
    inventory_backend: str = Field(default="request", validation_alias="INVENTORY_BACKEND")
    secret_backend: str = Field(default="request", validation_alias="SECRET_BACKEND")
    cors_allow_origins: str = Field(default="", validation_alias="CORS_ALLOW_ORIGINS")


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


# ---------------------------------------------------------------------------
# Structured logging with credential masking
# ---------------------------------------------------------------------------


def mask_secret_value(_value: Any = None) -> str:
    return "********"


def mask_mapping(data: Any) -> Any:
    """Recursively mask secret keys in dict/list structures."""
    if isinstance(data, dict):
        masked: dict[str, Any] = {}
        for key, value in data.items():
            if str(key).lower() in SECRET_FIELD_NAMES:
                masked[key] = mask_secret_value(value)
            else:
                masked[key] = mask_mapping(value)
        return masked
    if isinstance(data, list):
        return [mask_mapping(item) for item in data]
    return data


_SECRET_KV_RE = re.compile(
    r"(?i)\b(" + "|".join(re.escape(k) for k in sorted(SECRET_FIELD_NAMES)) + r")\s*[=:]\s*([^\s,;]+)"
)
_BEARER_RE = re.compile(r"(?i)(bearer\s+)(\S+)")
_X_CISCO_RE = re.compile(r"(?i)(X-Cisco-Meraki-API-Key\s*[:=]\s*)(\S+)")


def mask_text(message: str) -> str:
    """Mask secrets that appear as key=value or Authorization headers in log text."""
    redacted = _SECRET_KV_RE.sub(lambda m: f"{m.group(1)}={mask_secret_value()}", message)
    redacted = _BEARER_RE.sub(lambda m: f"{m.group(1)}{mask_secret_value()}", redacted)
    redacted = _X_CISCO_RE.sub(lambda m: f"{m.group(1)}{mask_secret_value()}", redacted)
    return redacted


class SecretMaskFilter(logging.Filter):
    """Logging filter that never emits passwords, API keys, or tokens."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = mask_text(record.msg)
        if record.args:
            if isinstance(record.args, dict):
                record.args = mask_mapping(record.args)
            elif isinstance(record.args, tuple):
                record.args = tuple(
                    mask_text(a) if isinstance(a, str) else mask_mapping(a) for a in record.args
                )
        return True


def configure_logging(level: str) -> logging.Logger:
    logger = logging.getLogger("network_ops")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(
            logging.Formatter(
                "%(asctime)s %(levelname)s request_id=%(request_id)s %(message)s"
            )
        )
        handler.addFilter(SecretMaskFilter())
        logger.addHandler(handler)
    logger.propagate = False
    return logger


class _RequestIdFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if not hasattr(record, "request_id"):
            record.request_id = "-"
        return True


LOGGER = configure_logging(os.getenv("LOG_LEVEL", "INFO"))
LOGGER.addFilter(_RequestIdFilter())


def log_operation(
    *,
    request_id: str,
    endpoint: str,
    device: Optional[str],
    device_ip: Optional[str],
    operation: str,
    execution_time: float,
    status: str,
    extra: Optional[str] = None,
) -> None:
    parts = [
        f"endpoint={endpoint}",
        f"device={device or '-'}",
        f"device_ip={device_ip or '-'}",
        f"operation={operation}",
        f"execution_time={execution_time:.2f}",
        f"status={status}",
    ]
    if extra:
        parts.append(extra)
    LOGGER.info(" ".join(parts), extra={"request_id": request_id})


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class Vendor(str, Enum):
    CISCO = "cisco"
    MERAKI = "meraki"
    ARISTA = "arista"
    FORTINET = "fortinet"
    PALO_ALTO = "paloalto"
    JUNIPER = "juniper"
    VIPTELA = "viptela"


class ConnectionType(str, Enum):
    SSH = "ssh"
    TELNET = "telnet"
    API = "api"
    NETCONF = "netconf"


class ErrorCode(str, Enum):
    DEVICE_CONNECTION_FAILED = "DEVICE_CONNECTION_FAILED"
    SSH_AUTHENTICATION_FAILED = "SSH_AUTHENTICATION_FAILED"
    SSH_TIMEOUT = "SSH_TIMEOUT"
    DEVICE_UNREACHABLE = "DEVICE_UNREACHABLE"
    INVALID_CREDENTIALS = "INVALID_CREDENTIALS"
    COMMAND_TIMEOUT = "COMMAND_TIMEOUT"
    UNSUPPORTED_COMMAND = "UNSUPPORTED_COMMAND"
    COMMAND_NOT_ALLOWED = "COMMAND_NOT_ALLOWED"
    MERAKI_AUTH_ERROR = "MERAKI_AUTH_ERROR"
    MERAKI_RATE_LIMITED = "MERAKI_RATE_LIMITED"
    MERAKI_API_ERROR = "MERAKI_API_ERROR"
    INVALID_DEVICE_TYPE = "INVALID_DEVICE_TYPE"
    MISSING_PARAMETERS = "MISSING_PARAMETERS"
    VALIDATION_ERROR = "VALIDATION_ERROR"
    INVENTORY_NOT_FOUND = "INVENTORY_NOT_FOUND"
    PARSER_ERROR = "PARSER_ERROR"
    INTERNAL_ERROR = "INTERNAL_ERROR"


# ---------------------------------------------------------------------------
# Domain exceptions
# ---------------------------------------------------------------------------


class NetworkOpsError(Exception):
    """Base error for the Network Operations API."""

    def __init__(
        self,
        code: ErrorCode,
        message: str,
        details: str = "",
        http_status: int = 400,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details
        self.http_status = http_status


class DeviceConnectionError(NetworkOpsError):
    def __init__(self, details: str = "", code: ErrorCode = ErrorCode.DEVICE_CONNECTION_FAILED) -> None:
        super().__init__(code, "Unable to connect to device", details, 502)


class CommandNotAllowedError(NetworkOpsError):
    def __init__(self, command: str) -> None:
        super().__init__(
            ErrorCode.COMMAND_NOT_ALLOWED,
            "Command is not allowed",
            "Operational show commands only; configuration and destructive commands are blocked",
            403,
        )
        self.command = command


class UnsupportedCommandError(NetworkOpsError):
    def __init__(self, details: str = "") -> None:
        super().__init__(
            ErrorCode.UNSUPPORTED_COMMAND,
            "Command is not supported on this platform",
            details,
            400,
        )


class InvalidDeviceTypeError(NetworkOpsError):
    def __init__(self, device_type: str) -> None:
        super().__init__(
            ErrorCode.INVALID_DEVICE_TYPE,
            "Invalid or unsupported device type",
            device_type,
            400,
        )


class MissingParametersError(NetworkOpsError):
    def __init__(self, details: str) -> None:
        super().__init__(ErrorCode.MISSING_PARAMETERS, "Required parameters are missing", details, 400)


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class DeviceRequest(BaseModel):
    """Generic device request used by most operational APIs.

    Credentials are accepted on the request for the prototype. Production
    deployments should resolve them via Vault, CyberArk, or a secret manager
    through SecretProvider without changing these endpoints.
    """

    model_config = ConfigDict(
        extra="ignore",
        json_schema_extra={
            "examples": [
                {
                    "username": "admin",
                    "password": "password",
                    "login_ip": "10.10.10.10",
                    "device_name": "RTR-001",
                    "device_type": "cisco_router",
                    "vendor": "cisco",
                    "connection_type": "ssh",
                    "port": 22,
                    "site_id": "SITE001",
                    "region": "APAC",
                    "country": "India",
                },
                {
                    "vendor": "meraki",
                    "device_type": "meraki_switch",
                    "api_key": "xxxxx",
                    "organization_id": "123456",
                    "network_id": "N_123456",
                    "device_name": "SW-001",
                    "serial": "Q2XX-XXXX-XXXX",
                },
            ]
        },
    )

    username: Optional[str] = Field(None, description="SSH username")
    password: Optional[SecretStr] = Field(None, description="SSH password (never logged or returned)")
    login_ip: Optional[str] = Field(None, description="Management IP or FQDN")
    device_name: Optional[str] = Field(None, description="Inventory hostname")
    device_type: Optional[str] = Field(
        None, description="cisco_router, cisco_switch, cisco_iosxe, meraki_switch, ..."
    )
    vendor: Optional[str] = Field(None, description="cisco | meraki | arista | ...")
    connection_type: Optional[str] = Field(None, description="ssh | api | telnet")
    port: Optional[int] = Field(None, ge=1, le=65535, description="SSH/API port")
    site_id: Optional[str] = Field(None, description="Site identifier for inventory lookup")
    region: Optional[str] = Field(None)
    country: Optional[str] = Field(None)
    api_key: Optional[SecretStr] = Field(None, description="Meraki Dashboard API key")
    organization_id: Optional[str] = Field(None, description="Meraki organization ID")
    network_id: Optional[str] = Field(None, description="Meraki network ID")
    serial: Optional[str] = Field(None, description="Meraki device serial")
    vrf: Optional[str] = Field(None, description="Optional VRF name")
    secret: Optional[SecretStr] = Field(None, description="Enable secret if required")
    timeout: Optional[int] = Field(None, ge=1, le=300, description="Per-request command timeout override")

    @field_validator("vendor", "device_type", "connection_type", mode="before")
    @classmethod
    def _normalize_lower(cls, value: Any) -> Any:
        if isinstance(value, str):
            return value.strip().lower()
        return value

    def plain_password(self) -> Optional[str]:
        return self.password.get_secret_value() if self.password else None

    def plain_api_key(self) -> Optional[str]:
        return self.api_key.get_secret_value() if self.api_key else None

    def plain_secret(self) -> Optional[str]:
        return self.secret.get_secret_value() if self.secret else None

    def safe_dict(self) -> dict[str, Any]:
        payload = self.model_dump(exclude={"password", "api_key", "secret"})
        if self.password is not None:
            payload["password"] = mask_secret_value()
        if self.api_key is not None:
            payload["api_key"] = mask_secret_value()
        if self.secret is not None:
            payload["secret"] = mask_secret_value()
        return payload


class CommandRequest(DeviceRequest):
    command: str = Field(..., description="Operational command (show * only)")


class TroubleshootRequest(DeviceRequest):
    target_ip: str = Field(..., description="IP address to troubleshoot")
    target_interface: Optional[str] = Field(None)


class FilterRequest(DeviceRequest):
    ip: Optional[str] = None
    mac: Optional[str] = None
    interface: Optional[str] = None
    vlan: Optional[str] = None
    protocol: Optional[str] = None
    prefix: Optional[str] = None
    neighbor: Optional[str] = None


class DeviceInfo(BaseModel):
    name: Optional[str] = None
    ip: Optional[str] = None
    type: Optional[str] = None
    vendor: Optional[str] = None
    site_id: Optional[str] = None
    region: Optional[str] = None
    country: Optional[str] = None


class Metadata(BaseModel):
    command: Optional[str] = None
    commands: Optional[list[str]] = None
    execution_time: float = 0.0
    timestamp: str
    request_id: Optional[str] = None
    parsed: Optional[bool] = None
    platform: Optional[str] = None


class ErrorBody(BaseModel):
    code: str
    message: str
    details: str = ""


class ErrorResponse(BaseModel):
    status: str = "error"
    error: ErrorBody


class OperationResponse(BaseModel):
    status: str = "success"
    device: DeviceInfo = Field(default_factory=DeviceInfo)
    data: Any = None
    raw_output: Optional[Any] = None
    metadata: Metadata
    parsed: Optional[bool] = None


class ServiceHealthResponse(BaseModel):
    status: str
    service: str
    version: str


class ProbeResponse(BaseModel):
    status: str


# ---------------------------------------------------------------------------
# Command registry (platform-keyed; not hardcoded in each endpoint)
# ---------------------------------------------------------------------------

COMMANDS: dict[str, dict[str, str]] = {
    "version": {
        "cisco_ios": "show version",
        "cisco_iosxe": "show version",
        "cisco_nxos": "show version",
        "cisco_asa": "show version",
        "cisco_sdwan": "show version",
    },
    "inventory": {
        "cisco_ios": "show inventory",
        "cisco_iosxe": "show inventory",
        "cisco_nxos": "show inventory",
        "cisco_asa": "show inventory",
    },
    "running_config": {
        "cisco_ios": "show running-config",
        "cisco_iosxe": "show running-config",
        "cisco_nxos": "show running-config",
        "cisco_asa": "show running-config",
    },
    "startup_config": {
        "cisco_ios": "show startup-config",
        "cisco_iosxe": "show startup-config",
        "cisco_nxos": "show startup-config",
    },
    "platform": {
        "cisco_ios": "show platform",
        "cisco_iosxe": "show platform",
        "cisco_nxos": "show platform",
    },
    "cpu": {
        "cisco_ios": "show processes cpu",
        "cisco_iosxe": "show processes cpu",
        "cisco_nxos": "show processes cpu",
        "cisco_asa": "show cpu usage",
    },
    "memory": {
        "cisco_ios": "show processes memory",
        "cisco_iosxe": "show processes memory",
        "cisco_nxos": "show system resources",
        "cisco_asa": "show memory",
    },
    "memory_statistics": {
        "cisco_ios": "show memory statistics",
        "cisco_iosxe": "show memory statistics",
        "cisco_nxos": "show system resources",
    },
    "environment": {
        "cisco_ios": "show environment",
        "cisco_iosxe": "show environment",
        "cisco_nxos": "show environment",
        "cisco_asa": "show environment",
    },
    "logging": {
        "cisco_ios": "show logging",
        "cisco_iosxe": "show logging",
        "cisco_nxos": "show logging last 50",
        "cisco_asa": "show logging",
    },
    "interfaces": {
        "cisco_ios": "show ip interface brief",
        "cisco_iosxe": "show ip interface brief",
        "cisco_nxos": "show ip interface brief",
        "cisco_asa": "show interface ip brief",
        "cisco_sdwan": "show sdwan interface",
    },
    "interfaces_detail": {
        "cisco_ios": "show interfaces",
        "cisco_iosxe": "show interfaces",
        "cisco_nxos": "show interface",
        "cisco_asa": "show interface",
    },
    "interfaces_status": {
        "cisco_ios": "show interfaces status",
        "cisco_iosxe": "show interfaces status",
        "cisco_nxos": "show interface status",
    },
    "interfaces_counters": {
        "cisco_ios": "show interfaces counters",
        "cisco_iosxe": "show interfaces counters",
        "cisco_nxos": "show interface counters",
    },
    "interfaces_description": {
        "cisco_ios": "show interfaces description",
        "cisco_iosxe": "show interfaces description",
        "cisco_nxos": "show interface description",
    },
    "arp": {
        "cisco_ios": "show ip arp",
        "cisco_iosxe": "show ip arp",
        "cisco_nxos": "show ip arp",
        "cisco_asa": "show arp",
    },
    "mac": {
        "cisco_ios": "show mac address-table",
        "cisco_iosxe": "show mac address-table",
        "cisco_nxos": "show mac address-table",
    },
    "mac_dynamic": {
        "cisco_ios": "show mac address-table dynamic",
        "cisco_iosxe": "show mac address-table dynamic",
        "cisco_nxos": "show mac address-table dynamic",
    },
    "routing": {
        "cisco_ios": "show ip route",
        "cisco_iosxe": "show ip route",
        "cisco_nxos": "show ip route",
        "cisco_asa": "show route",
        "cisco_sdwan": "show ip route",
    },
    "routing_summary": {
        "cisco_ios": "show ip route summary",
        "cisco_iosxe": "show ip route summary",
        "cisco_nxos": "show ip route summary",
    },
    "routing_protocol": {
        "cisco_ios": "show ip protocols",
        "cisco_iosxe": "show ip protocols",
        "cisco_nxos": "show ip protocols",
    },
    "bgp": {
        "cisco_ios": "show ip bgp",
        "cisco_iosxe": "show ip bgp",
        "cisco_nxos": "show bgp ipv4 unicast",
    },
    "bgp_summary": {
        "cisco_ios": "show ip bgp summary",
        "cisco_iosxe": "show ip bgp summary",
        "cisco_nxos": "show bgp ipv4 unicast summary",
        "cisco_sdwan": "show sdwan bgp summary",
    },
    "bgp_neighbors": {
        "cisco_ios": "show ip bgp neighbors",
        "cisco_iosxe": "show ip bgp neighbors",
        "cisco_nxos": "show bgp ipv4 unicast neighbors",
    },
    "ospf": {
        "cisco_ios": "show ip ospf",
        "cisco_iosxe": "show ip ospf",
        "cisco_nxos": "show ip ospf",
    },
    "ospf_neighbors": {
        "cisco_ios": "show ip ospf neighbor",
        "cisco_iosxe": "show ip ospf neighbor",
        "cisco_nxos": "show ip ospf neighbors",
    },
    "ospf_interfaces": {
        "cisco_ios": "show ip ospf interface",
        "cisco_iosxe": "show ip ospf interface",
        "cisco_nxos": "show ip ospf interface",
    },
    "ospf_database": {
        "cisco_ios": "show ip ospf database",
        "cisco_iosxe": "show ip ospf database",
        "cisco_nxos": "show ip ospf database",
    },
    "eigrp": {
        "cisco_ios": "show ip eigrp neighbors",
        "cisco_iosxe": "show ip eigrp neighbors",
        "cisco_nxos": "show ip eigrp neighbors",
    },
    "vlans": {
        "cisco_ios": "show vlan brief",
        "cisco_iosxe": "show vlan brief",
        "cisco_nxos": "show vlan brief",
    },
    "trunks": {
        "cisco_ios": "show interfaces trunk",
        "cisco_iosxe": "show interfaces trunk",
        "cisco_nxos": "show interface trunk",
    },
    "cdp": {
        "cisco_ios": "show cdp neighbors detail",
        "cisco_iosxe": "show cdp neighbors detail",
        "cisco_nxos": "show cdp neighbors detail",
    },
    "lldp": {
        "cisco_ios": "show lldp neighbors detail",
        "cisco_iosxe": "show lldp neighbors detail",
        "cisco_nxos": "show lldp neighbors detail",
    },
    "dhcp_bindings": {
        "cisco_ios": "show ip dhcp binding",
        "cisco_iosxe": "show ip dhcp binding",
        "cisco_nxos": "show ip dhcp snooping binding",
    },
    "dhcp_pools": {
        "cisco_ios": "show ip dhcp pool",
        "cisco_iosxe": "show ip dhcp pool",
    },
    "dhcp_conflict": {
        "cisco_ios": "show ip dhcp conflict",
        "cisco_iosxe": "show ip dhcp conflict",
    },
    "vpn_isakmp": {
        "cisco_ios": "show crypto isakmp sa",
        "cisco_iosxe": "show crypto isakmp sa",
        "cisco_asa": "show crypto ikev1 sa",
    },
    "vpn_ipsec": {
        "cisco_ios": "show crypto ipsec sa",
        "cisco_iosxe": "show crypto ipsec sa",
        "cisco_asa": "show crypto ipsec sa",
    },
    "vpn_session": {
        "cisco_ios": "show crypto session",
        "cisco_iosxe": "show crypto session",
        "cisco_asa": "show vpn-sessiondb",
    },
    "vpn_tunnel": {
        "cisco_ios": "show interfaces tunnel",
        "cisco_iosxe": "show interfaces tunnel",
        "cisco_nxos": "show interface tunnel",
    },
    "vpn_gre": {
        "cisco_ios": "show interfaces tunnel",
        "cisco_iosxe": "show interfaces tunnel",
    },
    "wan_sdwan_control": {
        "cisco_sdwan": "show sdwan control connections",
        "cisco_iosxe": "show sdwan control connections",
    },
    "wan_sdwan_omp": {
        "cisco_sdwan": "show sdwan omp peers",
        "cisco_iosxe": "show sdwan omp peers",
    },
    "wan_sdwan_bfd": {
        "cisco_sdwan": "show sdwan bfd sessions",
        "cisco_iosxe": "show sdwan bfd sessions",
    },
    "wan_sdwan_interface": {
        "cisco_sdwan": "show sdwan interface",
        "cisco_iosxe": "show sdwan interface",
    },
    "wan_sdwan_tunnel": {
        "cisco_sdwan": "show sdwan tunnel",
        "cisco_iosxe": "show sdwan tunnel",
    },
    "stp": {
        "cisco_ios": "show spanning-tree summary",
        "cisco_iosxe": "show spanning-tree summary",
        "cisco_nxos": "show spanning-tree summary",
    },
    "lacp": {
        "cisco_ios": "show etherchannel summary",
        "cisco_iosxe": "show etherchannel summary",
        "cisco_nxos": "show port-channel summary",
    },
    "acl": {
        "cisco_ios": "show ip access-lists",
        "cisco_iosxe": "show ip access-lists",
        "cisco_nxos": "show ip access-lists",
        "cisco_asa": "show access-list",
    },
    "nat": {
        "cisco_ios": "show ip nat translations",
        "cisco_iosxe": "show ip nat translations",
        "cisco_asa": "show nat",
    },
    "optics": {
        "cisco_ios": "show interfaces transceiver",
        "cisco_iosxe": "show interfaces transceiver",
        "cisco_nxos": "show interface transceiver",
    },
}

PLATFORM_ALIASES: dict[str, str] = {
    "cisco_router": "cisco_ios",
    "cisco_switch": "cisco_ios",
    "cisco_xe": "cisco_iosxe",
    "cisco_viptela": "cisco_sdwan",
    "cisco_firewall": "cisco_asa",
}


def normalize_platform(device_type: Optional[str], vendor: Optional[str] = None) -> str:
    dtype = (device_type or "").strip().lower()
    vend = (vendor or "").strip().lower()
    if vend in MERAKI_PLATFORMS or dtype in MERAKI_PLATFORMS or dtype.startswith("meraki"):
        return "meraki"
    if dtype in PLATFORM_ALIASES:
        return PLATFORM_ALIASES[dtype]
    if dtype in COMMANDS.get("version", {}) or dtype in CISCO_PLATFORMS:
        if dtype in {"cisco_router", "cisco_switch"}:
            return "cisco_ios"
        if dtype in {"cisco_xe"}:
            return "cisco_iosxe"
        if dtype in {"cisco_viptela"}:
            return "cisco_sdwan"
        return dtype
    if vend == Vendor.VIPTELA.value:
        return "cisco_sdwan"
    if vend == Vendor.CISCO.value:
        return dtype or "cisco_ios"
    if dtype:
        return dtype
    if not vend:
        return "cisco_ios"
    raise InvalidDeviceTypeError(device_type or vendor or "unknown")


def is_meraki(device: DeviceRequest) -> bool:
    vendor = (device.vendor or "").lower()
    dtype = (device.device_type or "").lower()
    if vendor in MERAKI_PLATFORMS or dtype in MERAKI_PLATFORMS:
        return True
    if dtype.startswith("meraki"):
        return True
    if device.api_key and not device.login_ip and vendor != "cisco":
        return True
    return False


def is_cisco_cli(device: DeviceRequest) -> bool:
    return not is_meraki(device)


def lookup_command(operation: str, platform: str) -> str:
    table = COMMANDS.get(operation)
    if not table:
        raise UnsupportedCommandError(f"Unknown operation '{operation}'")
    if platform in table:
        return table[platform]
    if platform in PLATFORM_ALIASES and PLATFORM_ALIASES[platform] in table:
        return table[PLATFORM_ALIASES[platform]]
    # Prefer IOS as a reasonable Cisco default when the platform is Cisco-family.
    if platform.startswith("cisco") and "cisco_ios" in table:
        return table["cisco_ios"]
    raise UnsupportedCommandError(f"Operation '{operation}' is not mapped for platform '{platform}'")


def format_command(template: str, **kwargs: str) -> str:
    command = template
    for key, value in kwargs.items():
        command = command.replace("{" + key + "}", value)
    return command


# ---------------------------------------------------------------------------
# Command allowlist / dangerous-command rejection
# ---------------------------------------------------------------------------


def normalize_command(command: str) -> str:
    cleaned = command.strip()
    cleaned = re.sub(r"\s+", " ", cleaned)
    return cleaned


def is_command_allowed(command: str) -> bool:
    """Return True only for operational (primarily show) commands."""
    cmd = normalize_command(command)
    if not cmd:
        return False
    for pattern in DANGEROUS_COMMAND_PATTERNS:
        if pattern.search(cmd):
            return False
    lowered = cmd.lower()
    if any(lowered.startswith(prefix) for prefix in ALLOWED_COMMAND_PREFIXES):
        return True
    # Allow registered commands even if prefix varies (e.g. NX-OS syntax)
    for mapping in COMMANDS.values():
        if cmd in mapping.values() or lowered in {v.lower() for v in mapping.values()}:
            return True
    return False


def validate_command(command: str) -> str:
    cmd = normalize_command(command)
    if not is_command_allowed(cmd):
        raise CommandNotAllowedError(cmd)
    return cmd


def validate_device_type(device_type: Optional[str], vendor: Optional[str] = None) -> str:
    if not device_type and not vendor:
        raise InvalidDeviceTypeError("missing")
    platform = normalize_platform(device_type, vendor)
    if platform == "meraki":
        return platform
    if platform.startswith("cisco") or platform in CISCO_PLATFORMS or platform in PLATFORM_ALIASES:
        return platform
    # Future vendors are accepted as opaque platforms but flagged if unknown.
    known = CISCO_PLATFORMS | MERAKI_PLATFORMS | set(PLATFORM_ALIASES) | {"meraki"}
    if platform not in known and not platform.startswith("cisco"):
        raise InvalidDeviceTypeError(device_type or vendor or platform)
    return platform


# ---------------------------------------------------------------------------
# Inventory + secret provider interfaces (replaceable later)
# ---------------------------------------------------------------------------


class InventoryProvider(Protocol):
    def get_device_details(
        self, site_id: Optional[str], device_name: Optional[str]
    ) -> Optional[dict[str, Any]]: ...


class RequestInventoryProvider:
    """Uses the request payload as the inventory source (prototype).

    Replace with NetBox / CMDB / ServiceNow / IP Fabric without changing routes.
    """

    def get_device_details(
        self, site_id: Optional[str], device_name: Optional[str]
    ) -> Optional[dict[str, Any]]:
        if not site_id and not device_name:
            return None
        return {
            "site_id": site_id,
            "device_name": device_name,
            "source": "request",
        }


class SecretProvider(Protocol):
    def resolve(self, device: DeviceRequest) -> DeviceRequest: ...


class RequestSecretProvider:
    """Credentials come from the request body (prototype)."""

    def resolve(self, device: DeviceRequest) -> DeviceRequest:
        return device


class EnvironmentSecretProvider:
    """Optional overlay from environment variables (no hardcoded secrets)."""

    def resolve(self, device: DeviceRequest) -> DeviceRequest:
        updates: dict[str, Any] = {}
        if not device.username and os.getenv("NETWORK_DEFAULT_USERNAME"):
            updates["username"] = os.getenv("NETWORK_DEFAULT_USERNAME")
        if not device.password and os.getenv("NETWORK_DEFAULT_PASSWORD"):
            updates["password"] = os.getenv("NETWORK_DEFAULT_PASSWORD")
        if not device.api_key and os.getenv("MERAKI_API_KEY"):
            updates["api_key"] = os.getenv("MERAKI_API_KEY")
        if updates:
            return device.model_copy(update=updates)
        return device


class VaultSecretProvider:
    """Placeholder for HashiCorp Vault / CyberArk integration."""

    def resolve(self, device: DeviceRequest) -> DeviceRequest:
        LOGGER.info(
            "secret_backend=vault not configured; using request credentials",
            extra={"request_id": "-"},
        )
        return device


def get_secret_provider() -> SecretProvider:
    backend = get_settings().secret_backend.lower()
    if backend in {"env", "environment"}:
        return EnvironmentSecretProvider()
    if backend in {"vault", "cyberark"}:
        return VaultSecretProvider()
    return RequestSecretProvider()


def get_device_details(site_id: Optional[str], device_name: Optional[str]) -> Optional[dict[str, Any]]:
    """Inventory lookup hook. Currently returns request-derived identity."""
    return RequestInventoryProvider().get_device_details(site_id, device_name)


def resolve_device_request(device: DeviceRequest) -> DeviceRequest:
    inventory = get_device_details(device.site_id, device.device_name)
    updates: dict[str, Any] = {}
    if inventory:
        if not device.login_ip and inventory.get("login_ip"):
            updates["login_ip"] = inventory["login_ip"]
        if not device.device_type and inventory.get("device_type"):
            updates["device_type"] = inventory["device_type"]
    resolved = device.model_copy(update=updates) if updates else device
    return get_secret_provider().resolve(resolved)


# ---------------------------------------------------------------------------
# Cache protocol (Redis-ready; null backend by default)
# ---------------------------------------------------------------------------


class CacheBackend(Protocol):
    def get(self, key: str) -> Optional[str]: ...
    def set(self, key: str, value: str, ttl: int) -> None: ...


class NullCache:
    def get(self, key: str) -> Optional[str]:
        return None

    def set(self, key: str, value: str, ttl: int) -> None:
        return None


def get_cache() -> CacheBackend:
    # REDIS_URL is reserved for a future RedisCache implementation.
    return NullCache()


# ---------------------------------------------------------------------------
# Parsers (conservative; parser-ready for TextFSM / ntc-templates / Genie)
# ---------------------------------------------------------------------------


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _unparsed(raw: str, reason: str = "unable to reliably parse output") -> dict[str, Any]:
    return {"parsed": False, "reason": reason, "raw_output": raw}


def parse_show_ip_int_brief(raw: str) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for line in raw.splitlines():
        if not line.strip() or line.lower().startswith("interface"):
            continue
        parts = line.split()
        if len(parts) < 6:
            continue
        if not re.match(r"^[A-Za-z]", parts[0]):
            continue
        protocol = parts[-1]
        status = parts[-2]
        ip_address = parts[1]
        rows.append(
            {
                "interface": parts[0],
                "ip_address": None if ip_address.lower() in {"unassigned", "unset"} else ip_address,
                "ok": parts[2] if len(parts) > 2 else None,
                "method": parts[3] if len(parts) > 3 else None,
                "status": status,
                "protocol": protocol,
            }
        )
    if not rows:
        return _unparsed(raw)
    return {"parsed": True, "interfaces": rows}


def parse_show_ip_arp(raw: str) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    for line in raw.splitlines():
        if "incomplete" in line.lower() and not re.search(r"\d+\.\d+\.\d+\.\d+", line):
            continue
        match = re.search(
            r"(?P<ip>\d+\.\d+\.\d+\.\d+)\s+(?P<age>\S+)\s+(?P<mac>[0-9a-fA-F.]{14}|incomplete)\s+(?P<type>\S+)\s+(?P<intf>\S+)",
            line,
        )
        if not match:
            continue
        entries.append(
            {
                "ip": match.group("ip"),
                "age": match.group("age"),
                "mac": match.group("mac"),
                "type": match.group("type").lower(),
                "interface": match.group("intf"),
            }
        )
    if not entries:
        return _unparsed(raw)
    return {"parsed": True, "entries": entries}


def parse_mac_table(raw: str) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    for line in raw.splitlines():
        match = re.search(
            r"^\s*(?P<vlan>\d+|All|-)\s+(?P<mac>[0-9a-fA-F.]{14})\s+(?P<type>\S+)\s+(?P<intf>\S+)",
            line,
        )
        if not match:
            continue
        vlan_raw = match.group("vlan")
        vlan: Optional[int]
        try:
            vlan = int(vlan_raw)
        except ValueError:
            vlan = None
        entries.append(
            {
                "vlan": vlan,
                "mac": match.group("mac").lower(),
                "type": match.group("type").lower(),
                "interface": match.group("intf"),
            }
        )
    if not entries:
        return _unparsed(raw)
    return {"parsed": True, "entries": entries}


def parse_ip_route(raw: str) -> dict[str, Any]:
    codes = {
        "C": "Connected",
        "L": "Local",
        "S": "Static",
        "O": "OSPF",
        "B": "BGP",
        "D": "EIGRP",
        "R": "RIP",
        "*": "Candidate default",
    }
    routes: list[dict[str, Any]] = []
    current: Optional[dict[str, Any]] = None
    for line in raw.splitlines():
        header = re.match(
            r"^(?P<codes>[A-Za-z*\s]{1,4})\s+(?P<prefix>\d+\.\d+\.\d+\.\d+)(?P<mask>/\d+)?",
            line,
        )
        via = re.search(
            r"via\s+(?P<nh>\d+\.\d+\.\d+\.\d+)(?:,\s*(?P<intf>\S+))?",
            line,
        )
        metric = re.search(r"\[(?P<ad>\d+)/(?P<metric>\d+)\]", line)
        if header:
            code = header.group("codes").strip().replace(" ", "")
            proto = "Unknown"
            for letter, name in codes.items():
                if letter in code:
                    proto = name
                    break
            if "*" in code:
                proto = "Default" if proto in {"Unknown", "Static"} else proto
            current = {
                "prefix": header.group("prefix") + (header.group("mask") or ""),
                "protocol": proto,
                "next_hop": None,
                "interface": None,
                "metric": None,
                "administrative_distance": None,
            }
            if via:
                current["next_hop"] = via.group("nh")
                current["interface"] = via.group("intf")
            if metric:
                current["administrative_distance"] = int(metric.group("ad"))
                current["metric"] = int(metric.group("metric"))
            routes.append(current)
        elif via and current is not None:
            current["next_hop"] = via.group("nh")
            if via.group("intf"):
                current["interface"] = via.group("intf")
            if metric:
                current["administrative_distance"] = int(metric.group("ad"))
                current["metric"] = int(metric.group("metric"))
    if not routes:
        return _unparsed(raw)
    return {"parsed": True, "routes": routes}


def parse_bgp_summary(raw: str) -> dict[str, Any]:
    local_as = None
    router_id = None
    as_match = re.search(r"local AS number\s+(\d+)", raw, re.I)
    rid_match = re.search(r"BGP router identifier\s+(\d+\.\d+\.\d+\.\d+)", raw, re.I)
    if as_match:
        local_as = int(as_match.group(1))
    if rid_match:
        router_id = rid_match.group(1)
    neighbors: list[dict[str, Any]] = []
    for line in raw.splitlines():
        match = re.match(
            r"^(?P<nbr>\d+\.\d+\.\d+\.\d+)\s+\d+\s+(?P<asn>\d+)\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+(?P<up>\S+)\s+(?P<state>\S+)",
            line.strip(),
        )
        if not match:
            continue
        state = match.group("state")
        prefixes: Optional[int] = None
        if state.isdigit():
            prefixes = int(state)
            state = "Established"
        neighbors.append(
            {
                "neighbor": match.group("nbr"),
                "remote_as": int(match.group("asn")),
                "state": state,
                "uptime": match.group("up"),
                "prefixes_received": prefixes,
                "prefixes_sent": None,
            }
        )
    if local_as is None and not neighbors:
        return _unparsed(raw)
    return {
        "parsed": True,
        "local_as": local_as,
        "router_id": router_id,
        "neighbors": neighbors,
    }


def parse_ospf_neighbors(raw: str) -> dict[str, Any]:
    neighbors: list[dict[str, Any]] = []
    for line in raw.splitlines():
        match = re.match(
            r"^(?P<nid>\d+\.\d+\.\d+\.\d+)\s+\d+\s+(?P<state>\S+)/(?P<role>\S+)\s+(?P<dead>\S+)\s+(?P<addr>\d+\.\d+\.\d+\.\d+)\s+(?P<intf>\S+)",
            line.strip(),
        )
        if not match:
            continue
        neighbors.append(
            {
                "neighbor_id": match.group("nid"),
                "state": match.group("state").upper(),
                "role": match.group("role"),
                "dead_time": match.group("dead"),
                "address": match.group("addr"),
                "interface": match.group("intf"),
            }
        )
    if not neighbors:
        return _unparsed(raw)
    return {"parsed": True, "neighbors": neighbors}


def parse_version(raw: str) -> dict[str, Any]:
    hostname = None
    hn = re.search(r"(?im)^\s*(\S+)\s+uptime is\s+(.+)$", raw)
    uptime = None
    if hn:
        hostname = hn.group(1)
        uptime = hn.group(2).strip()
    version = None
    ver = re.search(r"Version\s+([0-9A-Za-z().]+)", raw)
    if ver:
        version = ver.group(1)
    model = None
    mdl = re.search(r"(?im)^cisco\s+(\S+)", raw)
    if mdl:
        model = mdl.group(1)
    serial = None
    sn = re.search(r"Processor board ID\s+(\S+)", raw, re.I)
    if sn:
        serial = sn.group(1)
    if not any([hostname, version, model, serial, uptime]):
        return _unparsed(raw)
    return {
        "parsed": True,
        "hostname": hostname,
        "model": model,
        "ios_version": version,
        "serial_number": serial,
        "uptime": uptime,
    }


def parse_cpu(raw: str) -> dict[str, Any]:
    match = re.search(
        r"CPU utilization for five seconds:\s*(\d+)%/(\d+)%;\s*one minute:\s*(\d+)%;\s*five minutes:\s*(\d+)%",
        raw,
        re.I,
    )
    if not match:
        return _unparsed(raw)
    return {
        "parsed": True,
        "cpu_5s": int(match.group(1)),
        "cpu_5s_interrupt": int(match.group(2)),
        "cpu_1m": int(match.group(3)),
        "cpu_5m": int(match.group(4)),
        "cpu": int(match.group(3)),
    }


def parse_memory(raw: str) -> dict[str, Any]:
    match = re.search(
        r"Processor\s+\S+\s+(\d+)\s+(\d+)\s+(\d+)",
        raw,
        re.I,
    )
    if not match:
        used_match = re.search(r"Used:\s*(\d+).*Free:\s*(\d+)", raw, re.I | re.S)
        if not used_match:
            return _unparsed(raw)
        used = int(used_match.group(1))
        free = int(used_match.group(2))
        total = used + free
        pct = int(used * 100 / total) if total else None
        return {"parsed": True, "used": used, "free": free, "total": total, "memory": pct}
    total, used, free = int(match.group(1)), int(match.group(2)), int(match.group(3))
    pct = int(used * 100 / total) if total else None
    return {"parsed": True, "total": total, "used": used, "free": free, "memory": pct}


def parse_vlan_brief(raw: str) -> dict[str, Any]:
    vlans: list[dict[str, Any]] = []
    current: Optional[dict[str, Any]] = None
    for line in raw.splitlines():
        match = re.match(
            r"^(?P<id>\d+)\s+(?P<name>\S+)\s+(?P<status>\S+)\s*(?P<ports>.*)$",
            line.strip(),
        )
        if match:
            ports = [p.strip().rstrip(",") for p in match.group("ports").split() if p.strip()]
            current = {
                "vlan_id": int(match.group("id")),
                "name": match.group("name"),
                "status": match.group("status"),
                "ports": ports,
            }
            vlans.append(current)
        elif current and line.startswith(" "):
            extra = [p.strip().rstrip(",") for p in line.split() if p.strip()]
            current["ports"].extend(extra)
    if not vlans:
        return _unparsed(raw)
    return {"parsed": True, "vlans": vlans}


def parse_cdp_detail(raw: str) -> dict[str, Any]:
    neighbors: list[dict[str, Any]] = []
    blocks = re.split(r"-{5,}|Device ID:", raw)
    # Also split by Device ID header
    chunks = re.split(r"(?=Device ID:)", raw)
    for chunk in chunks:
        if "Device ID:" not in chunk and "System Name:" not in chunk:
            continue
        device_id = _search_group(r"Device ID:\s*(\S+)", chunk)
        platform = _search_group(r"Platform:\s*([^,]+)", chunk)
        local_intf = _search_group(r"Interface:\s*([^,]+)", chunk)
        remote_intf = _search_group(r"Port ID\s*\(outgoing port\):\s*(\S+)", chunk)
        ip_addr = _search_group(r"IP address:\s*(\d+\.\d+\.\d+\.\d+)", chunk)
        if not device_id and not local_intf:
            continue
        neighbors.append(
            {
                "local_interface": (local_intf or "").strip(),
                "neighbor": device_id,
                "neighbor_ip": ip_addr,
                "neighbor_interface": remote_intf,
                "platform": (platform or "").strip() or None,
            }
        )
    if not neighbors:
        return _unparsed(raw)
    return {"parsed": True, "neighbors": neighbors}


def parse_lldp_detail(raw: str) -> dict[str, Any]:
    neighbors: list[dict[str, Any]] = []
    chunks = re.split(r"(?=Local Intf:|Local Port:|Chassis id:)", raw)
    for chunk in chunks:
        local_intf = _search_group(r"Local Intf:\s*(\S+)", chunk) or _search_group(
            r"Local Port:\s*(\S+)", chunk
        )
        neighbor = _search_group(r"System Name:\s*(\S+)", chunk)
        neighbor_ip = _search_group(r"Management Address:\s*(\S+)", chunk)
        remote_intf = _search_group(r"Port id:\s*(\S+)", chunk) or _search_group(
            r"Port Description:\s*(\S+)", chunk
        )
        platform = _search_group(r"System Description:\s*(.+)", chunk)
        if not local_intf and not neighbor:
            continue
        neighbors.append(
            {
                "local_interface": local_intf,
                "neighbor": neighbor,
                "neighbor_ip": neighbor_ip,
                "neighbor_interface": remote_intf,
                "platform": (platform or "").strip() or None,
            }
        )
    if not neighbors:
        return _unparsed(raw)
    return {"parsed": True, "neighbors": neighbors}


def parse_dhcp_binding(raw: str) -> dict[str, Any]:
    bindings: list[dict[str, Any]] = []
    for line in raw.splitlines():
        match = re.search(
            r"(?P<ip>\d+\.\d+\.\d+\.\d+)\s+(?P<mac>\S+)\s+(?P<lease>\S+)\s+(?P<type>\S+)",
            line,
        )
        if match:
            bindings.append(match.groupdict())
    if not bindings:
        return _unparsed(raw)
    return {"parsed": True, "bindings": bindings}


def parse_crypto_session(raw: str) -> dict[str, Any]:
    sessions: list[dict[str, Any]] = []
    for block in re.split(r"\n(?=Interface:)", raw):
        tunnel = _search_group(r"Interface:\s*(\S+)", block)
        status = _search_group(r"Session status:\s*(\S+)", block)
        peer = _search_group(r"Peer:\s*(\S+)", block)
        if tunnel or peer:
            sessions.append(
                {
                    "tunnel": tunnel,
                    "status": (status or "").lower() or None,
                    "remote_peer": peer,
                    "packets_in": None,
                    "packets_out": None,
                }
            )
    if not sessions:
        return _unparsed(raw)
    return {"parsed": True, "sessions": sessions}


def parse_interfaces_status(raw: str) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for line in raw.splitlines():
        match = re.match(
            r"^(?P<intf>\S+)\s+(?P<desc>.*?)\s+(?P<status>connected|notconnect|disabled|err-disabled|inactive)\s+(?P<vlan>\S+)\s+(?P<duplex>\S+)\s+(?P<speed>\S+)\s+(?P<type>.*)$",
            line.strip(),
            re.I,
        )
        if not match:
            continue
        rows.append(
            {
                "interface": match.group("intf"),
                "description": match.group("desc").strip(),
                "status": match.group("status").lower(),
                "vlan": match.group("vlan"),
                "duplex": match.group("duplex"),
                "speed": match.group("speed"),
                "type": match.group("type").strip(),
            }
        )
    if not rows:
        return _unparsed(raw)
    return {"parsed": True, "interfaces": rows}


def _search_group(pattern: str, text: str) -> Optional[str]:
    match = re.search(pattern, text, re.I)
    return match.group(1).strip() if match else None


PARSER_REGISTRY: dict[str, Callable[[str], dict[str, Any]]] = {
    "interfaces": parse_show_ip_int_brief,
    "interfaces_status": parse_interfaces_status,
    "arp": parse_show_ip_arp,
    "mac": parse_mac_table,
    "mac_dynamic": parse_mac_table,
    "routing": parse_ip_route,
    "bgp_summary": parse_bgp_summary,
    "ospf_neighbors": parse_ospf_neighbors,
    "version": parse_version,
    "cpu": parse_cpu,
    "memory": parse_memory,
    "vlans": parse_vlan_brief,
    "cdp": parse_cdp_detail,
    "lldp": parse_lldp_detail,
    "dhcp_bindings": parse_dhcp_binding,
    "vpn_session": parse_crypto_session,
    "vpn_tunnel": parse_crypto_session,
}


def parse_output(operation: str, raw: str) -> dict[str, Any]:
    parser = PARSER_REGISTRY.get(operation)
    if not parser or not raw or not raw.strip():
        return _unparsed(raw or "", "no parser registered or empty output")
    try:
        return parser(raw)
    except Exception as exc:  # pragma: no cover - defensive
        LOGGER.warning("parser_failed operation=%s error=%s", operation, exc, extra={"request_id": "-"})
        return _unparsed(raw, "parser exception")


def filter_arp_entries(
    data: dict[str, Any],
    *,
    ip: Optional[str] = None,
    mac: Optional[str] = None,
    interface: Optional[str] = None,
    vlan: Optional[str] = None,
) -> dict[str, Any]:
    if not data.get("parsed"):
        return data
    entries = list(data.get("entries") or [])
    if ip:
        entries = [e for e in entries if e.get("ip") == ip]
    if mac:
        needle = mac.lower().replace(":", "").replace(".", "").replace("-", "")
        entries = [
            e
            for e in entries
            if str(e.get("mac", "")).lower().replace(":", "").replace(".", "").replace("-", "") == needle
        ]
    if interface:
        entries = [e for e in entries if str(e.get("interface", "")).lower() == interface.lower()]
    if vlan:
        entries = [e for e in entries if str(e.get("vlan")) == str(vlan)]
    return {**data, "entries": entries}


def filter_mac_entries(
    data: dict[str, Any],
    *,
    mac: Optional[str] = None,
    interface: Optional[str] = None,
    vlan: Optional[str] = None,
) -> dict[str, Any]:
    if not data.get("parsed"):
        return data
    entries = list(data.get("entries") or [])
    if mac:
        needle = mac.lower().replace(":", "").replace(".", "").replace("-", "")
        entries = [
            e
            for e in entries
            if str(e.get("mac", "")).lower().replace(":", "").replace(".", "").replace("-", "") == needle
        ]
    if interface:
        entries = [e for e in entries if str(e.get("interface", "")).lower() == interface.lower()]
    if vlan:
        entries = [e for e in entries if str(e.get("vlan")) == str(vlan)]
    return {**data, "entries": entries}


def filter_routes(data: dict[str, Any], *, prefix: Optional[str] = None, protocol: Optional[str] = None) -> dict[str, Any]:
    if not data.get("parsed"):
        return data
    routes = list(data.get("routes") or [])
    if prefix:
        routes = [r for r in routes if prefix in str(r.get("prefix"))]
    if protocol:
        routes = [r for r in routes if str(r.get("protocol", "")).lower() == protocol.lower()]
    return {**data, "routes": routes}


# ---------------------------------------------------------------------------
# Connectors
# ---------------------------------------------------------------------------


def map_netmiko_type(device: DeviceRequest) -> str:
    platform = normalize_platform(device.device_type, device.vendor)
    return NETMIKO_DEVICE_TYPE_MAP.get(platform, NETMIKO_DEVICE_TYPE_MAP.get(device.device_type or "", "cisco_ios"))


def connect_cisco(device: DeviceRequest) -> Any:
    """Open a Netmiko session to a Cisco device. Blocking; run in a worker thread."""
    if ConnectHandler is None:
        raise DeviceConnectionError("netmiko is not installed on this host")
    if not device.login_ip:
        raise MissingParametersError("login_ip is required for Cisco CLI connectivity")
    if not device.username or not device.plain_password():
        raise MissingParametersError("username and password are required for SSH")
    settings = get_settings()
    params: dict[str, Any] = {
        "device_type": map_netmiko_type(device),
        "host": device.login_ip,
        "username": device.username,
        "password": device.plain_password(),
        "port": device.port or 22,
        "timeout": settings.network_ssh_timeout,
        "conn_timeout": settings.network_connection_timeout,
        "auth_timeout": settings.network_ssh_timeout,
        "banner_timeout": settings.network_connection_timeout,
        "fast_cli": False,
        "allow_auto_change": True,
    }
    if device.plain_secret():
        params["secret"] = device.plain_secret()
    last_exc: Optional[Exception] = None
    attempts = max(1, settings.network_connection_retries + 1)
    for attempt in range(1, attempts + 1):
        try:
            LOGGER.info(
                "cisco_connect host=%s device_type=%s attempt=%s",
                device.login_ip,
                params["device_type"],
                attempt,
                extra={"request_id": "-"},
            )
            connection = ConnectHandler(**params)
            return connection
        except NetmikoAuthenticationException as exc:
            raise DeviceConnectionError(
                "SSH authentication failed",
                ErrorCode.SSH_AUTHENTICATION_FAILED,
            ) from exc
        except NetmikoTimeoutException as exc:
            last_exc = exc
            if attempt >= attempts:
                raise DeviceConnectionError("SSH connection timed out", ErrorCode.SSH_TIMEOUT) from exc
        except OSError as exc:
            last_exc = exc
            if attempt >= attempts:
                raise DeviceConnectionError("Device unreachable", ErrorCode.DEVICE_UNREACHABLE) from exc
        except Exception as exc:  # pragma: no cover - netmiko vendor exceptions
            last_exc = exc
            message = str(exc).lower()
            if "auth" in message:
                raise DeviceConnectionError(
                    "SSH authentication failed",
                    ErrorCode.INVALID_CREDENTIALS,
                ) from exc
            if attempt >= attempts:
                raise DeviceConnectionError("Unable to establish SSH session") from exc
    raise DeviceConnectionError(str(last_exc) if last_exc else "Unable to establish SSH session")


def execute_cisco_command(connection: Any, command: str, timeout: Optional[int] = None) -> str:
    """Execute a single operational command on an open Netmiko session."""
    cmd = validate_command(command)
    settings = get_settings()
    read_timeout = timeout or settings.network_command_timeout
    try:
        output = connection.send_command(cmd, read_timeout=read_timeout)
        return output if isinstance(output, str) else str(output)
    except Exception as exc:
        text = str(exc).lower()
        if "timeout" in text:
            raise NetworkOpsError(
                ErrorCode.COMMAND_TIMEOUT,
                "Command execution timed out",
                "The device did not return output in time",
                504,
            ) from exc
        if "invalid" in text or "unknown" in text or "ambiguous" in text:
            raise UnsupportedCommandError("Device rejected the command") from exc
        LOGGER.exception("cisco_command_failed command=%s", cmd, extra={"request_id": "-"})
        raise NetworkOpsError(
            ErrorCode.INTERNAL_ERROR,
            "Failed to execute command on device",
            "See server logs for details",
            502,
        ) from exc


def _unsupported_cli_output(output: str) -> bool:
    markers = (
        "invalid input detected",
        "unknown command",
        "ambiguous command",
        "% incomplete command",
        "syntax error",
        "not supported",
    )
    lowered = output.lower()
    return any(marker in lowered for marker in markers)


@contextmanager
def cisco_session(device: DeviceRequest) -> Iterator[Any]:
    connection = connect_cisco(device)
    try:
        yield connection
    finally:
        try:
            connection.disconnect()
        except Exception:
            LOGGER.debug("cisco_disconnect_failed host=%s", device.login_ip, extra={"request_id": "-"})


def execute_meraki_api(
    method: str,
    path: str,
    api_key: str,
    params: Optional[dict[str, Any]] = None,
    json_body: Optional[Any] = None,
    client: Optional[httpx.Client] = None,
) -> Any:
    """Call the Cisco Meraki Dashboard API. Blocking; run in a worker thread."""
    if not api_key:
        raise MissingParametersError("api_key is required for Meraki operations")
    settings = get_settings()
    url = path if path.startswith("http") else settings.meraki_api_base_url.rstrip("/") + "/" + path.lstrip("/")
    headers = {
        "X-Cisco-Meraki-API-Key": api_key,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    owns_client = client is None
    http_client = client or httpx.Client(timeout=settings.meraki_api_timeout)
    retries = max(1, settings.meraki_max_retries)
    last_exc: Optional[Exception] = None
    try:
        for attempt in range(1, retries + 1):
            try:
                response = http_client.request(
                    method.upper(),
                    url,
                    headers=headers,
                    params=params,
                    json=json_body,
                )
            except httpx.TimeoutException as exc:
                last_exc = exc
                if attempt >= retries:
                    raise NetworkOpsError(
                        ErrorCode.MERAKI_API_ERROR,
                        "Meraki API request timed out",
                        "Dashboard API did not respond in time",
                        504,
                    ) from exc
                time.sleep(min(2 ** attempt, 8))
                continue
            except httpx.HTTPError as exc:
                raise NetworkOpsError(
                    ErrorCode.MERAKI_API_ERROR,
                    "Meraki API request failed",
                    "Unable to reach Meraki Dashboard API",
                    502,
                ) from exc

            if response.status_code == 401:
                raise NetworkOpsError(
                    ErrorCode.MERAKI_AUTH_ERROR,
                    "Meraki API authentication failed",
                    "Invalid API key or insufficient permissions",
                    401,
                )
            if response.status_code == 429:
                retry_after = response.headers.get("Retry-After")
                if attempt < retries:
                    delay = float(retry_after) if retry_after else min(2 ** attempt, 8)
                    time.sleep(delay)
                    continue
                raise NetworkOpsError(
                    ErrorCode.MERAKI_RATE_LIMITED,
                    "Meraki API rate limit exceeded",
                    "Retry later",
                    429,
                )
            if response.status_code >= 400:
                raise NetworkOpsError(
                    ErrorCode.MERAKI_API_ERROR,
                    "Meraki API request failed",
                    f"HTTP {response.status_code}",
                    502,
                )
            if not response.content:
                return None
            try:
                return response.json()
            except json.JSONDecodeError:
                return {"parsed": False, "raw_output": response.text}
        raise NetworkOpsError(
            ErrorCode.MERAKI_API_ERROR,
            "Meraki API request failed",
            str(last_exc) if last_exc else "exhausted retries",
            502,
        )
    finally:
        if owns_client:
            http_client.close()


class NetworkDevice:
    """Vendor-agnostic device abstraction used by the API layer."""

    vendor_name: str = "unknown"

    def __init__(self, device: DeviceRequest) -> None:
        self.device = resolve_device_request(device)
        self.platform = normalize_platform(self.device.device_type, self.device.vendor)

    def identity(self) -> DeviceInfo:
        return DeviceInfo(
            name=self.device.device_name,
            ip=self.device.login_ip,
            type=self.device.device_type,
            vendor=self.device.vendor,
            site_id=self.device.site_id,
            region=self.device.region,
            country=self.device.country,
        )

    def execute(self, operation: str, **command_kwargs: str) -> dict[str, Any]:
        raise NotImplementedError

    def execute_many(self, operations: Sequence[str]) -> dict[str, dict[str, Any]]:
        raise NotImplementedError

    def execute_raw(self, command: str) -> dict[str, Any]:
        raise NotImplementedError

    def test_connection(self) -> dict[str, Any]:
        raise NotImplementedError


class CiscoCLIDevice(NetworkDevice):
    vendor_name = "cisco"

    def _run_commands(self, commands: Sequence[str], timeout: Optional[int] = None) -> list[tuple[str, str, bool]]:
        results: list[tuple[str, str, bool]] = []
        with cisco_session(self.device) as connection:
            for command in commands:
                output = execute_cisco_command(connection, command, timeout=timeout)
                unsupported = _unsupported_cli_output(output)
                results.append((command, output, unsupported))
        return results

    def execute(self, operation: str, **command_kwargs: str) -> dict[str, Any]:
        command = format_command(lookup_command(operation, self.platform), **command_kwargs)
        started = time.perf_counter()
        (_, output, unsupported), = self._run_commands([command], timeout=self.device.timeout)
        elapsed = time.perf_counter() - started
        parsed = parse_output(operation, output)
        return {
            "command": command,
            "raw_output": output,
            "data": parsed,
            "parsed": bool(parsed.get("parsed")) and not unsupported,
            "unsupported": unsupported,
            "execution_time": elapsed,
        }

    def execute_many(self, operations: Sequence[str]) -> dict[str, dict[str, Any]]:
        commands: list[tuple[str, str]] = []
        for operation in operations:
            try:
                commands.append((operation, lookup_command(operation, self.platform)))
            except UnsupportedCommandError:
                continue
        started = time.perf_counter()
        collected: dict[str, dict[str, Any]] = {}
        with cisco_session(self.device) as connection:
            for operation, command in commands:
                cmd_started = time.perf_counter()
                try:
                    output = execute_cisco_command(connection, command, timeout=self.device.timeout)
                    unsupported = _unsupported_cli_output(output)
                    parsed = parse_output(operation, output)
                    collected[operation] = {
                        "command": command,
                        "raw_output": output,
                        "data": parsed,
                        "parsed": bool(parsed.get("parsed")) and not unsupported,
                        "unsupported": unsupported,
                        "execution_time": time.perf_counter() - cmd_started,
                    }
                except NetworkOpsError as exc:
                    collected[operation] = {
                        "command": command,
                        "error": {"code": exc.code.value, "message": exc.message},
                        "parsed": False,
                        "execution_time": time.perf_counter() - cmd_started,
                    }
        collected["_total_execution_time"] = {"execution_time": time.perf_counter() - started}  # type: ignore[assignment]
        return collected

    def execute_raw(self, command: str) -> dict[str, Any]:
        cmd = validate_command(command)
        started = time.perf_counter()
        (_, output, unsupported), = self._run_commands([cmd], timeout=self.device.timeout)
        return {
            "command": cmd,
            "raw_output": output,
            "unsupported": unsupported,
            "execution_time": time.perf_counter() - started,
        }

    def test_connection(self) -> dict[str, Any]:
        result = self.execute("version")
        return {"ok": not result.get("unsupported"), "data": result}


class MerakiAPIDevice(NetworkDevice):
    vendor_name = "meraki"

    def _key(self) -> str:
        key = self.device.plain_api_key()
        if not key:
            raise MissingParametersError("api_key is required for Meraki operations")
        return key

    def _get(self, path: str, params: Optional[dict[str, Any]] = None) -> Any:
        started = time.perf_counter()
        payload = execute_meraki_api("GET", path, self._key(), params=params)
        return {"data": payload, "execution_time": time.perf_counter() - started, "path": path}

    def execute(self, operation: str, **command_kwargs: str) -> dict[str, Any]:
        mapping = {
            "organizations": "/organizations",
            "networks": f"/organizations/{command_kwargs.get('organization_id', self.device.organization_id)}/networks",
            "devices": f"/organizations/{command_kwargs.get('organization_id', self.device.organization_id)}/devices",
            "device_status": f"/organizations/{command_kwargs.get('organization_id', self.device.organization_id)}/devices/statuses",
            "clients": f"/networks/{command_kwargs.get('network_id', self.device.network_id)}/clients",
            "interfaces": f"/devices/{command_kwargs.get('serial', self.device.serial)}/switch/ports",
            "vlans": f"/networks/{command_kwargs.get('network_id', self.device.network_id)}/appliance/vlans",
            "firmware": f"/organizations/{command_kwargs.get('organization_id', self.device.organization_id)}/firmware/upgrades",
            "uplinks": f"/organizations/{command_kwargs.get('organization_id', self.device.organization_id)}/uplinks/statuses",
            "usage": f"/organizations/{command_kwargs.get('organization_id', self.device.organization_id)}/devices/uplinks/usage/byNetwork",
            "wireless": f"/networks/{command_kwargs.get('network_id', self.device.network_id)}/wireless/ssids",
            "appliance": f"/networks/{command_kwargs.get('network_id', self.device.network_id)}/appliance/uplink/statuses",
        }
        if operation not in mapping:
            raise UnsupportedCommandError(f"Meraki operation '{operation}' is not mapped")
        path = mapping[operation]
        if "None" in path:
            raise MissingParametersError(
                "Meraki path is missing organization_id, network_id, or serial for this operation"
            )
        result = self._get(path)
        return {
            "command": f"GET {path}",
            "raw_output": result["data"],
            "data": result["data"],
            "parsed": True,
            "execution_time": result["execution_time"],
        }

    def execute_many(self, operations: Sequence[str]) -> dict[str, dict[str, Any]]:
        collected: dict[str, dict[str, Any]] = {}
        started = time.perf_counter()
        for operation in operations:
            try:
                collected[operation] = self.execute(operation)
            except NetworkOpsError as exc:
                collected[operation] = {
                    "error": {"code": exc.code.value, "message": exc.message},
                    "parsed": False,
                }
        collected["_total_execution_time"] = {"execution_time": time.perf_counter() - started}  # type: ignore[assignment]
        return collected

    def execute_raw(self, command: str) -> dict[str, Any]:
        raise CommandNotAllowedError(command)

    def test_connection(self) -> dict[str, Any]:
        return {"ok": True, "data": self.execute("organizations")}


def get_device_connector(device_request: DeviceRequest) -> NetworkDevice:
    """Factory: Cisco CLI -> Netmiko, Meraki -> Dashboard API."""
    resolved = resolve_device_request(device_request)
    if is_meraki(resolved):
        return MerakiAPIDevice(resolved)
    vendor = (resolved.vendor or "cisco").lower()
    if vendor in {Vendor.ARISTA.value, Vendor.JUNIPER.value, Vendor.FORTINET.value, Vendor.PALO_ALTO.value}:
        raise InvalidDeviceTypeError(f"{vendor} connector is not implemented yet")
    validate_device_type(resolved.device_type or "cisco_ios", resolved.vendor or "cisco")
    return CiscoCLIDevice(resolved)


# ---------------------------------------------------------------------------
# Response helpers / services
# ---------------------------------------------------------------------------

_EXECUTOR: Optional[ThreadPoolExecutor] = None


def get_executor() -> ThreadPoolExecutor:
    """Return a live thread pool, recreating it after lifespan shutdown (e.g. tests)."""
    global _EXECUTOR
    if _EXECUTOR is None or getattr(_EXECUTOR, "_shutdown", False):
        _EXECUTOR = ThreadPoolExecutor(
            max_workers=get_settings().network_max_workers,
            thread_name_prefix="netops",
        )
    return _EXECUTOR


async def run_blocking(func: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    """Run blocking device I/O off the event loop."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(get_executor(), lambda: func(*args, **kwargs))


def device_info_from(device: DeviceRequest) -> DeviceInfo:
    return DeviceInfo(
        name=device.device_name,
        ip=device.login_ip,
        type=device.device_type,
        vendor=device.vendor,
        site_id=device.site_id,
        region=device.region,
        country=device.country,
    )


def success_response(
    device: DeviceRequest,
    data: Any,
    *,
    raw_output: Any = None,
    command: Optional[str] = None,
    commands: Optional[list[str]] = None,
    execution_time: float = 0.0,
    parsed: Optional[bool] = None,
    request_id: str = "-",
    extra: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "status": "success",
        "device": device_info_from(device).model_dump(),
        "data": data,
        "raw_output": raw_output,
        "parsed": parsed,
        "metadata": {
            "command": command,
            "commands": commands,
            "execution_time": round(execution_time, 3),
            "timestamp": utc_now(),
            "request_id": request_id,
            "parsed": parsed,
            "platform": None,
        },
    }
    if extra:
        payload.update(extra)
    return payload


def error_payload(exc: NetworkOpsError, request_id: str = "-") -> dict[str, Any]:
    return {
        "status": "error",
        "error": {
            "code": exc.code.value,
            "message": exc.message,
            "details": exc.details,
        },
        "metadata": {"timestamp": utc_now(), "request_id": request_id},
    }


def _extract_parsed_data(result: dict[str, Any]) -> Any:
    data = result.get("data")
    if isinstance(data, dict) and data.get("parsed") is True:
        for key in (
            "interfaces",
            "entries",
            "routes",
            "neighbors",
            "vlans",
            "bindings",
            "sessions",
        ):
            if key in data:
                if key in {"neighbors"} and "local_as" in data:
                    break
                if key == "neighbors" and "local_as" not in data:
                    return data[key]
                if key != "neighbors":
                    return data[key]
        cleaned = {k: v for k, v in data.items() if k not in {"parsed", "raw_output", "reason"}}
        return cleaned
    return data


async def run_operation(
    request: Request,
    device: DeviceRequest,
    operation: str,
    **command_kwargs: str,
) -> JSONResponse:
    request_id = getattr(request.state, "request_id", str(uuid.uuid4()))
    started = time.perf_counter()
    try:
        connector = get_device_connector(device)
        result = await run_blocking(connector.execute, operation, **command_kwargs)
        elapsed = time.perf_counter() - started
        log_operation(
            request_id=request_id,
            endpoint=str(request.url.path),
            device=device.device_name,
            device_ip=device.login_ip,
            operation=operation,
            execution_time=elapsed,
            status="success",
        )
        body = success_response(
            connector.device,
            _extract_parsed_data(result) if result.get("parsed") else result.get("data"),
            raw_output=result.get("raw_output"),
            command=result.get("command"),
            execution_time=result.get("execution_time", elapsed),
            parsed=result.get("parsed"),
            request_id=request_id,
        )
        if result.get("unsupported"):
            body["data"] = {
                "parsed": False,
                "reason": "command not supported on this platform",
                "raw_output": result.get("raw_output"),
            }
            body["parsed"] = False
        return JSONResponse(body)
    except NetworkOpsError as exc:
        elapsed = time.perf_counter() - started
        log_operation(
            request_id=request_id,
            endpoint=str(request.url.path),
            device=device.device_name,
            device_ip=device.login_ip,
            operation=operation,
            execution_time=elapsed,
            status="error",
            extra=f"code={exc.code.value}",
        )
        LOGGER.warning(
            "operation_failed code=%s details=%s",
            exc.code.value,
            mask_text(exc.details or exc.message),
            extra={"request_id": request_id},
        )
        return JSONResponse(error_payload(exc, request_id), status_code=exc.http_status)


async def run_many(
    request: Request,
    device: DeviceRequest,
    operations: Sequence[str],
) -> dict[str, Any]:
    request_id = getattr(request.state, "request_id", str(uuid.uuid4()))
    connector = get_device_connector(device)
    return await run_blocking(connector.execute_many, operations), connector, request_id


# ---------------------------------------------------------------------------
# FastAPI app, middleware, exception handlers
# ---------------------------------------------------------------------------


class RequestContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Callable) -> Any:
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        request.state.request_id = request_id
        started = time.perf_counter()
        response = await call_next(request)
        elapsed = time.perf_counter() - started
        response.headers["X-Request-ID"] = request_id
        LOGGER.info(
            "http_request method=%s endpoint=%s status=%s execution_time=%.3f",
            request.method,
            request.url.path,
            response.status_code,
            elapsed,
            extra={"request_id": request_id},
        )
        return response


@asynccontextmanager
async def lifespan(app: FastAPI) -> Any:
    settings = get_settings()
    global LOGGER
    LOGGER = configure_logging(settings.log_level)
    LOGGER.addFilter(_RequestIdFilter())
    executor = get_executor()
    LOGGER.info("service_start version=%s workers=%s", settings.app_version, settings.network_max_workers, extra={"request_id": "-"})
    yield
    executor.shutdown(wait=False)
    LOGGER.info("service_stop", extra={"request_id": "-"})


def create_app() -> FastAPI:
    settings = get_settings()
    application = FastAPI(
        title="Network Operations API",
        description=(
            "Production-ready Network Operations / NOC backend. "
            "The UI requests operational data (ARP, routing, BGP, Meraki clients, device summary); "
            "this API selects the connector, collects CLI or Dashboard data, and returns normalized JSON."
        ),
        version=settings.app_version,
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        lifespan=lifespan,
        contact={"name": "Network Automation Platform"},
    )
    origins = [o.strip() for o in settings.cors_allow_origins.split(",") if o.strip()]
    if origins:
        application.add_middleware(
            CORSMiddleware,
            allow_origins=origins,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
    application.add_middleware(RequestContextMiddleware)

    @application.exception_handler(NetworkOpsError)
    async def _ops_error_handler(request: Request, exc: NetworkOpsError) -> JSONResponse:
        request_id = getattr(request.state, "request_id", "-")
        return JSONResponse(error_payload(exc, request_id), status_code=exc.http_status)

    @application.exception_handler(RequestValidationError)
    async def _validation_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
        request_id = getattr(request.state, "request_id", "-")
        return JSONResponse(
            {
                "status": "error",
                "error": {
                    "code": ErrorCode.VALIDATION_ERROR.value,
                    "message": "Malformed request",
                    "details": "One or more fields failed validation",
                },
                "metadata": {"timestamp": utc_now(), "request_id": request_id},
            },
            status_code=422,
        )

    @application.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
        request_id = getattr(request.state, "request_id", "-")
        LOGGER.exception("unhandled_error", extra={"request_id": request_id})
        return JSONResponse(
            error_payload(
                NetworkOpsError(
                    ErrorCode.INTERNAL_ERROR,
                    "Internal server error",
                    "An unexpected error occurred",
                    500,
                ),
                request_id,
            ),
            status_code=500,
        )

    return application


app = create_app()

auth_router = APIRouter(prefix=API_V1_PREFIX, tags=["Authentication"])
device_router = APIRouter(prefix=f"{API_V1_PREFIX}/device", tags=["Device"])
interfaces_router = APIRouter(prefix=f"{API_V1_PREFIX}/interfaces", tags=["Interfaces"])
arp_router = APIRouter(prefix=f"{API_V1_PREFIX}/arp", tags=["ARP"])
mac_router = APIRouter(prefix=f"{API_V1_PREFIX}/mac", tags=["MAC"])
routing_router = APIRouter(prefix=f"{API_V1_PREFIX}/routing", tags=["Routing"])
bgp_router = APIRouter(prefix=f"{API_V1_PREFIX}/bgp", tags=["BGP"])
ospf_router = APIRouter(prefix=f"{API_V1_PREFIX}/ospf", tags=["OSPF"])
wan_router = APIRouter(prefix=f"{API_V1_PREFIX}/wan", tags=["WAN"])
vpn_router = APIRouter(prefix=f"{API_V1_PREFIX}/vpn", tags=["VPN"])
firewall_router = APIRouter(prefix=API_V1_PREFIX, tags=["Firewall"])
vlan_router = APIRouter(prefix=f"{API_V1_PREFIX}/vlans", tags=["Device"])
topo_router = APIRouter(prefix=API_V1_PREFIX, tags=["Troubleshooting"])
dhcp_router = APIRouter(prefix=f"{API_V1_PREFIX}/dhcp", tags=["Device"])
system_router = APIRouter(prefix=API_V1_PREFIX, tags=["System"])
monitoring_router = APIRouter(prefix=API_V1_PREFIX, tags=["Monitoring"])
meraki_router = APIRouter(prefix=f"{API_V1_PREFIX}/meraki", tags=["Meraki"])
command_router = APIRouter(prefix=API_V1_PREFIX, tags=["Troubleshooting"])


# ---------------------------------------------------------------------------
# Service health (process) vs device health (POST /api/v1/health)
# ---------------------------------------------------------------------------


@app.get(
    "/health",
    tags=["System"],
    response_model=ServiceHealthResponse,
    summary="Service health",
    responses={200: {"description": "Service is healthy"}},
)
async def service_health() -> ServiceHealthResponse:
    settings = get_settings()
    return ServiceHealthResponse(status="healthy", service=settings.app_name, version=settings.app_version)


@app.get(f"{API_V1_PREFIX}/health/liveness", tags=["System"], response_model=ProbeResponse)
async def liveness() -> ProbeResponse:
    return ProbeResponse(status="alive")


@app.get(f"{API_V1_PREFIX}/health/readiness", tags=["System"], response_model=ProbeResponse)
async def readiness() -> ProbeResponse:
    # Ready when the worker pool can be created; optional Redis is not required.
    get_executor()
    return ProbeResponse(status="ready")


@auth_router.post(
    "/auth/test",
    summary="Validate credentials by opening a device session",
    description="Tests SSH (Cisco) or Dashboard API (Meraki) authentication. Credentials are never returned.",
)
async def auth_test(request: Request, body: DeviceRequest) -> JSONResponse:
    request_id = getattr(request.state, "request_id", str(uuid.uuid4()))
    started = time.perf_counter()
    try:
        connector = get_device_connector(body)
        result = await run_blocking(connector.test_connection)
        elapsed = time.perf_counter() - started
        log_operation(
            request_id=request_id,
            endpoint="/api/v1/auth/test",
            device=body.device_name,
            device_ip=body.login_ip,
            operation="auth_test",
            execution_time=elapsed,
            status="success",
        )
        return JSONResponse(
            success_response(
                connector.device,
                {"authenticated": True},
                raw_output=None,
                execution_time=elapsed,
                parsed=True,
                request_id=request_id,
            )
        )
    except NetworkOpsError as exc:
        return JSONResponse(error_payload(exc, request_id), status_code=exc.http_status)


# ---------------------------------------------------------------------------
# Device facts + summary
# ---------------------------------------------------------------------------


@device_router.post(
    "/facts",
    summary="Collect device facts",
    description="Runs show version / inventory / CPU / memory and returns structured facts plus raw output.",
)
async def device_facts(request: Request, body: DeviceRequest) -> JSONResponse:
    if is_meraki(body):
        return await run_operation(request, body, "device_status")
    operations = ["version", "inventory", "cpu", "memory", "platform"]
    started = time.perf_counter()
    collected, connector, request_id = await run_many(request, body, operations)
    elapsed = time.perf_counter() - started
    version_data = (collected.get("version") or {}).get("data") or {}
    cpu_data = (collected.get("cpu") or {}).get("data") or {}
    mem_data = (collected.get("memory") or {}).get("data") or {}
    facts = {
        "hostname": version_data.get("hostname") or body.device_name,
        "model": version_data.get("model"),
        "ios_version": version_data.get("ios_version"),
        "serial_number": version_data.get("serial_number"),
        "uptime": version_data.get("uptime"),
        "cpu": cpu_data.get("cpu"),
        "memory": mem_data.get("memory"),
    }
    parsed = all(
        [
            version_data.get("parsed", True) if isinstance(version_data, dict) else False,
        ]
    )
    raw = {k: v.get("raw_output") for k, v in collected.items() if not k.startswith("_") and isinstance(v, dict)}
    log_operation(
        request_id=request_id,
        endpoint="/api/v1/device/facts",
        device=body.device_name,
        device_ip=body.login_ip,
        operation="device_facts",
        execution_time=elapsed,
        status="success",
    )
    return JSONResponse(
        success_response(
            connector.device,
            facts,
            raw_output=raw,
            commands=[v.get("command") for v in collected.values() if isinstance(v, dict) and v.get("command")],
            execution_time=elapsed,
            parsed=bool(version_data.get("parsed")) if isinstance(version_data, dict) else False,
            request_id=request_id,
        )
    )


SUMMARY_OPERATIONS = (
    "version",
    "cpu",
    "memory",
    "environment",
    "interfaces",
    "interfaces_status",
    "arp",
    "mac",
    "routing",
    "bgp_summary",
    "ospf_neighbors",
    "cdp",
    "lldp",
    "vpn_session",
    "vlans",
    "logging",
    "wan_sdwan_interface",
)


def _section(collected: dict[str, Any], key: str, inner: Optional[str] = None) -> Any:
    item = collected.get(key) or {}
    if item.get("error"):
        return {"parsed": False, "error": item["error"]}
    data = item.get("data")
    if inner and isinstance(data, dict) and inner in data:
        return data[inner]
    return data


@device_router.post(
    "/summary",
    summary="Full operational snapshot for a dashboard",
    description=(
        "Collects facts, interfaces, WAN, ARP, MAC, routing, BGP, OSPF, CDP/LLDP, "
        "CPU, memory, environment, VPN, VLANs, and logs on a single SSH session "
        "(or Meraki Dashboard calls). Unsupported platform commands are skipped."
    ),
)
async def device_summary(request: Request, body: DeviceRequest) -> JSONResponse:
    started = time.perf_counter()
    request_id = getattr(request.state, "request_id", str(uuid.uuid4()))
    try:
        connector = get_device_connector(body)
        if isinstance(connector, MerakiAPIDevice):
            ops = ["device_status", "devices", "uplinks", "clients"]
            collected = await run_blocking(connector.execute_many, ops)
            elapsed = time.perf_counter() - started
            payload = {
                "status": "success",
                "device": device_info_from(connector.device).model_dump(),
                "health": {"status": "unknown", "cpu": None, "memory": None},
                "interfaces": collected.get("devices", {}).get("data"),
                "wan": collected.get("uplinks", {}).get("data"),
                "arp": [],
                "mac": [],
                "routing": [],
                "bgp": {},
                "ospf": {},
                "vpn": [],
                "vlans": [],
                "neighbors": [],
                "environment": {},
                "logging": [],
                "clients": collected.get("clients", {}).get("data"),
                "device_status": collected.get("device_status", {}).get("data"),
                "metadata": {
                    "timestamp": utc_now(),
                    "execution_time": round(elapsed, 3),
                    "request_id": request_id,
                },
            }
            return JSONResponse(payload)

        collected = await run_blocking(connector.execute_many, SUMMARY_OPERATIONS)
        elapsed = time.perf_counter() - started
        version = (collected.get("version") or {}).get("data") or {}
        cpu = (collected.get("cpu") or {}).get("data") or {}
        mem = (collected.get("memory") or {}).get("data") or {}
        cpu_val = cpu.get("cpu") if isinstance(cpu, dict) else None
        mem_val = mem.get("memory") if isinstance(mem, dict) else None
        health_status = "healthy"
        if isinstance(cpu_val, int) and cpu_val >= 90:
            health_status = "degraded"
        if isinstance(mem_val, int) and mem_val >= 90:
            health_status = "degraded"

        log_operation(
            request_id=request_id,
            endpoint="/api/v1/device/summary",
            device=body.device_name,
            device_ip=body.login_ip,
            operation="device_summary",
            execution_time=elapsed,
            status="success",
        )
        payload = {
            "status": "success",
            "device": device_info_from(connector.device).model_dump(),
            "health": {"status": health_status, "cpu": cpu_val, "memory": mem_val},
            "facts": {
                "hostname": version.get("hostname") if isinstance(version, dict) else None,
                "model": version.get("model") if isinstance(version, dict) else None,
                "ios_version": version.get("ios_version") if isinstance(version, dict) else None,
                "serial_number": version.get("serial_number") if isinstance(version, dict) else None,
                "uptime": version.get("uptime") if isinstance(version, dict) else None,
            },
            "interfaces": _section(collected, "interfaces", "interfaces"),
            "wan": _section(collected, "wan_sdwan_interface"),
            "arp": _section(collected, "arp", "entries"),
            "mac": _section(collected, "mac", "entries"),
            "routing": _section(collected, "routing", "routes"),
            "bgp": _section(collected, "bgp_summary"),
            "ospf": _section(collected, "ospf_neighbors"),
            "vpn": _section(collected, "vpn_session", "sessions"),
            "vlans": _section(collected, "vlans", "vlans"),
            "neighbors": {
                "cdp": _section(collected, "cdp", "neighbors"),
                "lldp": _section(collected, "lldp", "neighbors"),
            },
            "environment": _section(collected, "environment"),
            "logging": _section(collected, "logging"),
            "raw_output": {
                k: v.get("raw_output")
                for k, v in collected.items()
                if not str(k).startswith("_") and isinstance(v, dict)
            },
            "metadata": {
                "timestamp": utc_now(),
                "execution_time": round(elapsed, 3),
                "request_id": request_id,
                "commands": [
                    v.get("command")
                    for v in collected.values()
                    if isinstance(v, dict) and v.get("command")
                ],
            },
        }
        return JSONResponse(payload)
    except NetworkOpsError as exc:
        return JSONResponse(error_payload(exc, request_id), status_code=exc.http_status)



# ---------------------------------------------------------------------------
# Interfaces
# ---------------------------------------------------------------------------


@interfaces_router.post("", summary="List interfaces (show ip interface brief)")
async def list_interfaces(request: Request, body: FilterRequest) -> JSONResponse:
    return await run_operation(request, body, "interfaces")


@interfaces_router.post("/status", summary="Interface operational status")
async def interfaces_status(request: Request, body: DeviceRequest) -> JSONResponse:
    return await run_operation(request, body, "interfaces_status")


@interfaces_router.post("/counters", summary="Interface counters")
async def interfaces_counters(request: Request, body: DeviceRequest) -> JSONResponse:
    return await run_operation(request, body, "interfaces_counters")


@interfaces_router.post("/{interface_name:path}", summary="Single interface details")
async def interface_detail(
    request: Request,
    body: DeviceRequest,
    interface_name: str = Path(..., description="Interface name, e.g. GigabitEthernet0/0"),
) -> JSONResponse:
    request_id = getattr(request.state, "request_id", str(uuid.uuid4()))
    started = time.perf_counter()
    try:
        connector = get_device_connector(body)
        if isinstance(connector, MerakiAPIDevice):
            result = await run_blocking(connector.execute, "interfaces")
            elapsed = time.perf_counter() - started
            return JSONResponse(
                success_response(
                    connector.device,
                    result.get("data"),
                    raw_output=result.get("raw_output"),
                    command=result.get("command"),
                    execution_time=elapsed,
                    parsed=True,
                    request_id=request_id,
                )
            )
        command = f"show interfaces {interface_name}"
        result = await run_blocking(connector.execute_raw, command)
        parsed = parse_output("interfaces_detail", result["raw_output"])
        elapsed = time.perf_counter() - started
        return JSONResponse(
            success_response(
                connector.device,
                parsed if not parsed.get("parsed") else parsed,
                raw_output=result["raw_output"],
                command=result["command"],
                execution_time=elapsed,
                parsed=bool(parsed.get("parsed")),
                request_id=request_id,
            )
        )
    except NetworkOpsError as exc:
        return JSONResponse(error_payload(exc, request_id), status_code=exc.http_status)


# ---------------------------------------------------------------------------
# ARP
# ---------------------------------------------------------------------------


@arp_router.post("", summary="ARP table")
async def list_arp(request: Request, body: FilterRequest) -> JSONResponse:
    result = await run_operation(request, body, "arp")
    if body.ip or body.mac or body.interface or body.vlan:
        payload = json.loads(result.body.decode())
        if payload.get("status") == "success" and isinstance(payload.get("data"), dict):
            payload["data"] = filter_arp_entries(
                payload["data"]
                if "entries" in (payload.get("data") or {})
                else {"parsed": True, "entries": payload.get("data") or []},
                ip=body.ip,
                mac=body.mac,
                interface=body.interface,
                vlan=body.vlan,
            )
            if "entries" in payload["data"]:
                payload["data"] = payload["data"]["entries"]
            result = JSONResponse(payload, status_code=result.status_code)
    return result


@arp_router.post("/{ip_address}", summary="ARP entry for an IP")
async def arp_for_ip(
    request: Request,
    body: DeviceRequest,
    ip_address: str = Path(..., description="IPv4 address"),
) -> JSONResponse:
    try:
        ipaddress.ip_address(ip_address)
    except ValueError as exc:
        raise MissingParametersError("ip_address must be a valid IP") from exc
    request_id = getattr(request.state, "request_id", str(uuid.uuid4()))
    try:
        connector = get_device_connector(body)
        if isinstance(connector, MerakiAPIDevice):
            raise UnsupportedCommandError("ARP lookup is not available via Meraki Dashboard in this mapping")
        command = f"show ip arp {ip_address}"
        result = await run_blocking(connector.execute_raw, command)
        parsed = parse_show_ip_arp(result["raw_output"])
        return JSONResponse(
            success_response(
                connector.device,
                parsed.get("entries") if parsed.get("parsed") else parsed,
                raw_output=result["raw_output"],
                command=result["command"],
                execution_time=result["execution_time"],
                parsed=bool(parsed.get("parsed")),
                request_id=request_id,
            )
        )
    except NetworkOpsError as exc:
        return JSONResponse(error_payload(exc, request_id), status_code=exc.http_status)


# ---------------------------------------------------------------------------
# MAC
# ---------------------------------------------------------------------------


@mac_router.post("", summary="MAC address table")
async def list_mac(request: Request, body: FilterRequest) -> JSONResponse:
    return await run_operation(request, body, "mac")


@mac_router.post("/interface/{interface_name:path}", summary="MAC table for an interface")
async def mac_for_interface(
    request: Request,
    body: DeviceRequest,
    interface_name: str = Path(...),
) -> JSONResponse:
    request_id = getattr(request.state, "request_id", str(uuid.uuid4()))
    try:
        connector = get_device_connector(body)
        command = f"show mac address-table interface {interface_name}"
        result = await run_blocking(connector.execute_raw, command)
        parsed = parse_mac_table(result["raw_output"])
        return JSONResponse(
            success_response(
                connector.device,
                parsed.get("entries") if parsed.get("parsed") else parsed,
                raw_output=result["raw_output"],
                command=result["command"],
                execution_time=result["execution_time"],
                parsed=bool(parsed.get("parsed")),
                request_id=request_id,
            )
        )
    except NetworkOpsError as exc:
        return JSONResponse(error_payload(exc, request_id), status_code=exc.http_status)


@mac_router.post("/vlan/{vlan_id}", summary="MAC table for a VLAN")
async def mac_for_vlan(
    request: Request,
    body: DeviceRequest,
    vlan_id: int = Path(..., ge=1, le=4094),
) -> JSONResponse:
    request_id = getattr(request.state, "request_id", str(uuid.uuid4()))
    try:
        connector = get_device_connector(body)
        command = f"show mac address-table vlan {vlan_id}"
        result = await run_blocking(connector.execute_raw, command)
        parsed = parse_mac_table(result["raw_output"])
        return JSONResponse(
            success_response(
                connector.device,
                parsed.get("entries") if parsed.get("parsed") else parsed,
                raw_output=result["raw_output"],
                command=result["command"],
                execution_time=result["execution_time"],
                parsed=bool(parsed.get("parsed")),
                request_id=request_id,
            )
        )
    except NetworkOpsError as exc:
        return JSONResponse(error_payload(exc, request_id), status_code=exc.http_status)


@mac_router.post("/{mac_address}", summary="Lookup a MAC address")
async def mac_lookup(
    request: Request,
    body: DeviceRequest,
    mac_address: str = Path(...),
) -> JSONResponse:
    request_id = getattr(request.state, "request_id", str(uuid.uuid4()))
    try:
        connector = get_device_connector(body)
        result = await run_blocking(connector.execute, "mac")
        parsed = result.get("data") or {}
        if isinstance(parsed, dict):
            parsed = filter_mac_entries(parsed, mac=mac_address)
        return JSONResponse(
            success_response(
                connector.device,
                parsed.get("entries") if isinstance(parsed, dict) and parsed.get("parsed") else parsed,
                raw_output=result.get("raw_output"),
                command=result.get("command"),
                execution_time=result.get("execution_time", 0.0),
                parsed=bool(isinstance(parsed, dict) and parsed.get("parsed")),
                request_id=request_id,
            )
        )
    except NetworkOpsError as exc:
        return JSONResponse(error_payload(exc, request_id), status_code=exc.http_status)


# ---------------------------------------------------------------------------
# Routing / BGP / OSPF
# ---------------------------------------------------------------------------


@routing_router.post("", summary="Routing table")
async def list_routes(request: Request, body: FilterRequest) -> JSONResponse:
    return await run_operation(request, body, "routing")


@routing_router.post("/protocol", summary="Routing protocol configuration (show ip protocols)")
async def routing_protocol(request: Request, body: DeviceRequest) -> JSONResponse:
    return await run_operation(request, body, "routing_protocol")


@routing_router.post("/{prefix:path}", summary="Lookup a prefix in the RIB")
async def route_for_prefix(
    request: Request,
    body: DeviceRequest,
    prefix: str = Path(..., description="Prefix or host, e.g. 10.20.30.0/24"),
) -> JSONResponse:
    request_id = getattr(request.state, "request_id", str(uuid.uuid4()))
    try:
        connector = get_device_connector(body)
        command = f"show ip route {prefix}"
        result = await run_blocking(connector.execute_raw, command)
        parsed = parse_ip_route(result["raw_output"])
        return JSONResponse(
            success_response(
                connector.device,
                parsed.get("routes") if parsed.get("parsed") else parsed,
                raw_output=result["raw_output"],
                command=result["command"],
                execution_time=result["execution_time"],
                parsed=bool(parsed.get("parsed")),
                request_id=request_id,
            )
        )
    except NetworkOpsError as exc:
        return JSONResponse(error_payload(exc, request_id), status_code=exc.http_status)


@bgp_router.post("", summary="BGP table")
async def bgp_table(request: Request, body: DeviceRequest) -> JSONResponse:
    return await run_operation(request, body, "bgp")


@bgp_router.post("/neighbors", summary="BGP neighbors")
async def bgp_neighbors(request: Request, body: FilterRequest) -> JSONResponse:
    if body.neighbor:
        request_id = getattr(request.state, "request_id", str(uuid.uuid4()))
        try:
            connector = get_device_connector(body)
            command = f"show ip bgp neighbors {body.neighbor}"
            result = await run_blocking(connector.execute_raw, command)
            return JSONResponse(
                success_response(
                    connector.device,
                    {"parsed": False, "raw_output": result["raw_output"]},
                    raw_output=result["raw_output"],
                    command=result["command"],
                    execution_time=result["execution_time"],
                    parsed=False,
                    request_id=request_id,
                )
            )
        except NetworkOpsError as exc:
            return JSONResponse(error_payload(exc, request_id), status_code=exc.http_status)
    return await run_operation(request, body, "bgp_neighbors")


@bgp_router.post("/routes", summary="BGP routes")
async def bgp_routes(request: Request, body: DeviceRequest) -> JSONResponse:
    return await run_operation(request, body, "bgp")


@bgp_router.post("/summary", summary="BGP summary")
async def bgp_summary(request: Request, body: DeviceRequest) -> JSONResponse:
    return await run_operation(request, body, "bgp_summary")


@ospf_router.post("", summary="OSPF process")
async def ospf_process(request: Request, body: DeviceRequest) -> JSONResponse:
    return await run_operation(request, body, "ospf")


@ospf_router.post("/neighbors", summary="OSPF neighbors")
async def ospf_neighbors(request: Request, body: DeviceRequest) -> JSONResponse:
    return await run_operation(request, body, "ospf_neighbors")


@ospf_router.post("/interfaces", summary="OSPF interfaces")
async def ospf_interfaces(request: Request, body: DeviceRequest) -> JSONResponse:
    return await run_operation(request, body, "ospf_interfaces")


@ospf_router.post("/database", summary="OSPF LSDB")
async def ospf_database(request: Request, body: DeviceRequest) -> JSONResponse:
    return await run_operation(request, body, "ospf_database")


# ---------------------------------------------------------------------------
# WAN / VPN / Firewall
# ---------------------------------------------------------------------------


@wan_router.post("", summary="WAN / SD-WAN overview")
async def wan_overview(request: Request, body: DeviceRequest) -> JSONResponse:
    operations = [
        "interfaces",
        "interfaces_counters",
        "wan_sdwan_control",
        "wan_sdwan_omp",
        "wan_sdwan_bfd",
        "wan_sdwan_interface",
        "wan_sdwan_tunnel",
    ]
    started = time.perf_counter()
    collected, connector, request_id = await run_many(request, body, operations)
    elapsed = time.perf_counter() - started
    return JSONResponse(
        success_response(
            connector.device,
            {k: v for k, v in collected.items() if not str(k).startswith("_")},
            raw_output={
                k: v.get("raw_output")
                for k, v in collected.items()
                if isinstance(v, dict) and not str(k).startswith("_")
            },
            commands=[v.get("command") for v in collected.values() if isinstance(v, dict) and v.get("command")],
            execution_time=elapsed,
            parsed=None,
            request_id=request_id,
        )
    )


@wan_router.post("/status", summary="WAN interface / tunnel status")
async def wan_status(request: Request, body: DeviceRequest) -> JSONResponse:
    return await run_operation(request, body, "wan_sdwan_interface")


@wan_router.post("/utilization", summary="WAN utilization (interface counters)")
async def wan_utilization(request: Request, body: DeviceRequest) -> JSONResponse:
    return await run_operation(request, body, "interfaces_counters")


@wan_router.post("/errors", summary="WAN errors / drops / CRC (interface details)")
async def wan_errors(request: Request, body: DeviceRequest) -> JSONResponse:
    return await run_operation(request, body, "interfaces_detail")


@vpn_router.post("", summary="VPN sessions")
async def vpn_overview(request: Request, body: DeviceRequest) -> JSONResponse:
    return await run_operation(request, body, "vpn_session")


@vpn_router.post("/ipsec", summary="IPsec SAs")
async def vpn_ipsec(request: Request, body: DeviceRequest) -> JSONResponse:
    return await run_operation(request, body, "vpn_ipsec")


@vpn_router.post("/gre", summary="GRE / tunnel interfaces")
async def vpn_gre(request: Request, body: DeviceRequest) -> JSONResponse:
    return await run_operation(request, body, "vpn_gre")


@vpn_router.post("/tunnel", summary="Tunnel interfaces")
async def vpn_tunnel(request: Request, body: DeviceRequest) -> JSONResponse:
    return await run_operation(request, body, "vpn_tunnel")


@firewall_router.post("/firewall", summary="Firewall / ACL overview")
async def firewall_overview(request: Request, body: DeviceRequest) -> JSONResponse:
    return await run_operation(request, body, "acl")


@firewall_router.post("/acl", summary="IP access lists")
async def acl_overview(request: Request, body: DeviceRequest) -> JSONResponse:
    return await run_operation(request, body, "acl")


@firewall_router.post("/nat", summary="NAT translations")
async def nat_overview(request: Request, body: DeviceRequest) -> JSONResponse:
    return await run_operation(request, body, "nat")


# ---------------------------------------------------------------------------
# VLANs, CDP/LLDP, DHCP
# ---------------------------------------------------------------------------


@vlan_router.post("", summary="VLAN brief")
async def list_vlans(request: Request, body: DeviceRequest) -> JSONResponse:
    return await run_operation(request, body, "vlans")


@vlan_router.post("/{vlan_id}", summary="Single VLAN")
async def vlan_detail(
    request: Request,
    body: DeviceRequest,
    vlan_id: int = Path(..., ge=1, le=4094),
) -> JSONResponse:
    result = await run_operation(request, body, "vlans")
    payload = json.loads(result.body.decode())
    if payload.get("status") == "success":
        data = payload.get("data")
        if isinstance(data, list):
            payload["data"] = [v for v in data if v.get("vlan_id") == vlan_id]
        elif isinstance(data, dict) and isinstance(data.get("vlans"), list):
            payload["data"] = [v for v in data["vlans"] if v.get("vlan_id") == vlan_id]
        result = JSONResponse(payload, status_code=result.status_code)
    return result


@topo_router.post("/cdp", summary="CDP neighbors", tags=["Troubleshooting"])
async def cdp_neighbors(request: Request, body: DeviceRequest) -> JSONResponse:
    return await run_operation(request, body, "cdp")


@topo_router.post("/lldp", summary="LLDP neighbors")
async def lldp_neighbors(request: Request, body: DeviceRequest) -> JSONResponse:
    return await run_operation(request, body, "lldp")


@topo_router.post("/topology", summary="Combined CDP/LLDP topology edges")
async def topology(request: Request, body: DeviceRequest) -> JSONResponse:
    started = time.perf_counter()
    collected, connector, request_id = await run_many(request, body, ["cdp", "lldp"])
    elapsed = time.perf_counter() - started
    neighbors = []
    for proto in ("cdp", "lldp"):
        section = _section(collected, proto, "neighbors")
        if isinstance(section, list):
            for item in section:
                neighbors.append({"protocol": proto, **item})
    return JSONResponse(
        success_response(
            connector.device,
            neighbors,
            raw_output={k: (collected.get(k) or {}).get("raw_output") for k in ("cdp", "lldp")},
            commands=[v.get("command") for v in collected.values() if isinstance(v, dict) and v.get("command")],
            execution_time=elapsed,
            parsed=True,
            request_id=request_id,
        )
    )


@dhcp_router.post("", summary="DHCP overview")
async def dhcp_overview(request: Request, body: DeviceRequest) -> JSONResponse:
    started = time.perf_counter()
    collected, connector, request_id = await run_many(
        request, body, ["dhcp_bindings", "dhcp_pools", "dhcp_conflict"]
    )
    elapsed = time.perf_counter() - started
    return JSONResponse(
        success_response(
            connector.device,
            {k: v for k, v in collected.items() if not str(k).startswith("_")},
            execution_time=elapsed,
            request_id=request_id,
        )
    )


@dhcp_router.post("/bindings", summary="DHCP bindings")
async def dhcp_bindings(request: Request, body: DeviceRequest) -> JSONResponse:
    return await run_operation(request, body, "dhcp_bindings")


@dhcp_router.post("/pools", summary="DHCP pools")
async def dhcp_pools(request: Request, body: DeviceRequest) -> JSONResponse:
    return await run_operation(request, body, "dhcp_pools")


# ---------------------------------------------------------------------------
# System / monitoring (device-level POST health)
# ---------------------------------------------------------------------------


@system_router.post("/health", summary="Device health (CPU, memory, environment)")
async def device_health(request: Request, body: DeviceRequest) -> JSONResponse:
    started = time.perf_counter()
    collected, connector, request_id = await run_many(request, body, ["cpu", "memory", "environment", "version"])
    elapsed = time.perf_counter() - started
    cpu = (collected.get("cpu") or {}).get("data") or {}
    mem = (collected.get("memory") or {}).get("data") or {}
    data = {
        "cpu": cpu.get("cpu") if isinstance(cpu, dict) else cpu,
        "memory": mem.get("memory") if isinstance(mem, dict) else mem,
        "environment": (collected.get("environment") or {}).get("data"),
        "version": (collected.get("version") or {}).get("data"),
    }
    return JSONResponse(
        success_response(connector.device, data, execution_time=elapsed, request_id=request_id)
    )


@monitoring_router.post("/cpu", summary="CPU utilization")
async def cpu_util(request: Request, body: DeviceRequest) -> JSONResponse:
    return await run_operation(request, body, "cpu")


@monitoring_router.post("/memory", summary="Memory utilization")
async def memory_util(request: Request, body: DeviceRequest) -> JSONResponse:
    return await run_operation(request, body, "memory")


@monitoring_router.post("/environment", summary="Environment (temp, power, fans)")
async def environment(request: Request, body: DeviceRequest) -> JSONResponse:
    return await run_operation(request, body, "environment")


@monitoring_router.post("/logs", summary="Device logs")
async def device_logs(request: Request, body: DeviceRequest) -> JSONResponse:
    return await run_operation(request, body, "logging")


# ---------------------------------------------------------------------------
# Troubleshooting + generic command
# ---------------------------------------------------------------------------


@command_router.post(
    "/troubleshoot",
    summary="Collect troubleshooting evidence for a target IP",
    description="Runs interface, route, ARP, logs, OSPF, and BGP commands. No AI diagnosis.",
)
async def troubleshoot(request: Request, body: TroubleshootRequest) -> JSONResponse:
    request_id = getattr(request.state, "request_id", str(uuid.uuid4()))
    started = time.perf_counter()
    try:
        connector = get_device_connector(body)
        if isinstance(connector, MerakiAPIDevice):
            clients = await run_blocking(connector.execute, "clients")
            elapsed = time.perf_counter() - started
            return JSONResponse(
                {
                    "status": "success",
                    "target": body.target_ip,
                    "analysis": {
                        "arp_found": None,
                        "route_found": None,
                        "interface_up": None,
                        "ospf_healthy": None,
                        "bgp_healthy": None,
                    },
                    "raw_data": {"clients": clients.get("data")},
                    "execution_time": round(elapsed, 3),
                    "device": device_info_from(connector.device).model_dump(),
                }
            )

        def _collect() -> dict[str, Any]:
            commands = [
                ("interfaces", lookup_command("interfaces", connector.platform)),
                ("route", f"show ip route {body.target_ip}"),
                ("arp", f"show ip arp {body.target_ip}"),
                ("interfaces_detail", lookup_command("interfaces_detail", connector.platform)),
                ("logging", lookup_command("logging", connector.platform)),
                ("ospf_neighbors", lookup_command("ospf_neighbors", connector.platform)),
                ("bgp_summary", lookup_command("bgp_summary", connector.platform)),
            ]
            raw: dict[str, Any] = {}
            with cisco_session(connector.device) as connection:
                for name, command in commands:
                    try:
                        output = execute_cisco_command(connection, command, timeout=body.timeout)
                        raw[name] = {"command": command, "raw_output": output, "unsupported": _unsupported_cli_output(output)}
                    except NetworkOpsError as exc:
                        raw[name] = {"command": command, "error": exc.code.value}
            return raw

        raw_data = await run_blocking(_collect)
        elapsed = time.perf_counter() - started
        arp_parsed = parse_show_ip_arp((raw_data.get("arp") or {}).get("raw_output") or "")
        route_parsed = parse_ip_route((raw_data.get("route") or {}).get("raw_output") or "")
        intf_parsed = parse_show_ip_int_brief((raw_data.get("interfaces") or {}).get("raw_output") or "")
        ospf_parsed = parse_ospf_neighbors((raw_data.get("ospf_neighbors") or {}).get("raw_output") or "")
        bgp_parsed = parse_bgp_summary((raw_data.get("bgp_summary") or {}).get("raw_output") or "")

        arp_found = bool(arp_parsed.get("parsed") and arp_parsed.get("entries"))
        route_found = bool(route_parsed.get("parsed") and route_parsed.get("routes"))
        interface_up = False
        if intf_parsed.get("parsed"):
            interface_up = any(
                str(i.get("status", "")).lower() == "up" and str(i.get("protocol", "")).lower() == "up"
                for i in intf_parsed.get("interfaces") or []
            )
        ospf_healthy = False
        if ospf_parsed.get("parsed"):
            ospf_healthy = any(str(n.get("state", "")).upper() == "FULL" for n in ospf_parsed.get("neighbors") or [])
        bgp_healthy = False
        if bgp_parsed.get("parsed"):
            bgp_healthy = any(
                str(n.get("state", "")).lower() == "established" for n in bgp_parsed.get("neighbors") or []
            )

        log_operation(
            request_id=request_id,
            endpoint="/api/v1/troubleshoot",
            device=body.device_name,
            device_ip=body.login_ip,
            operation="troubleshoot",
            execution_time=elapsed,
            status="success",
        )
        return JSONResponse(
            {
                "status": "success",
                "target": body.target_ip,
                "analysis": {
                    "arp_found": arp_found,
                    "route_found": route_found,
                    "interface_up": interface_up,
                    "ospf_healthy": ospf_healthy,
                    "bgp_healthy": bgp_healthy,
                },
                "raw_data": raw_data,
                "execution_time": round(elapsed, 3),
                "device": device_info_from(connector.device).model_dump(),
            }
        )
    except NetworkOpsError as exc:
        return JSONResponse(error_payload(exc, request_id), status_code=exc.http_status)


@command_router.post(
    "/command",
    summary="Run an allowlisted operational command",
    description="Only show/ping/traceroute commands are accepted. Configuration and destructive commands are rejected.",
)
async def generic_command(request: Request, body: CommandRequest) -> JSONResponse:
    request_id = getattr(request.state, "request_id", str(uuid.uuid4()))
    started = time.perf_counter()
    try:
        cmd = validate_command(body.command)
        connector = get_device_connector(body)
        if isinstance(connector, MerakiAPIDevice):
            raise CommandNotAllowedError("Meraki does not accept raw CLI via /command")
        result = await run_blocking(connector.execute_raw, cmd)
        elapsed = time.perf_counter() - started
        log_operation(
            request_id=request_id,
            endpoint="/api/v1/command",
            device=body.device_name,
            device_ip=body.login_ip,
            operation=cmd,
            execution_time=elapsed,
            status="success",
        )
        return JSONResponse(
            {
                "status": "success",
                "command": result["command"],
                "raw_output": result["raw_output"],
                "execution_time": round(result["execution_time"], 3),
                "device": device_info_from(connector.device).model_dump(),
                "metadata": {"timestamp": utc_now(), "request_id": request_id},
            }
        )
    except NetworkOpsError as exc:
        elapsed = time.perf_counter() - started
        log_operation(
            request_id=request_id,
            endpoint="/api/v1/command",
            device=body.device_name,
            device_ip=body.login_ip,
            operation=body.command,
            execution_time=elapsed,
            status="error",
            extra=f"code={exc.code.value}",
        )
        return JSONResponse(error_payload(exc, request_id), status_code=exc.http_status)


# ---------------------------------------------------------------------------
# Meraki
# ---------------------------------------------------------------------------


async def _meraki_op(request: Request, body: DeviceRequest, operation: str) -> JSONResponse:
    meraki_body = body
    if not meraki_body.vendor:
        meraki_body = body.model_copy(update={"vendor": "meraki", "device_type": body.device_type or "meraki"})
    elif not is_meraki(meraki_body):
        meraki_body = body.model_copy(update={"vendor": "meraki"})
    return await run_operation(request, meraki_body, operation)


@meraki_router.post("/organizations", summary="List Meraki organizations")
async def meraki_organizations(request: Request, body: DeviceRequest) -> JSONResponse:
    return await _meraki_op(request, body, "organizations")


@meraki_router.post("/networks", summary="List Meraki networks")
async def meraki_networks(request: Request, body: DeviceRequest) -> JSONResponse:
    return await _meraki_op(request, body, "networks")


@meraki_router.post("/devices", summary="List Meraki devices")
async def meraki_devices(request: Request, body: DeviceRequest) -> JSONResponse:
    return await _meraki_op(request, body, "devices")


@meraki_router.post("/device/status", summary="Meraki device statuses")
async def meraki_device_status(request: Request, body: DeviceRequest) -> JSONResponse:
    return await _meraki_op(request, body, "device_status")


@meraki_router.post("/clients", summary="Meraki clients")
async def meraki_clients(request: Request, body: DeviceRequest) -> JSONResponse:
    return await _meraki_op(request, body, "clients")


@meraki_router.post("/interfaces", summary="Meraki switch ports")
async def meraki_interfaces(request: Request, body: DeviceRequest) -> JSONResponse:
    return await _meraki_op(request, body, "interfaces")


@meraki_router.post("/vlans", summary="Meraki appliance VLANs")
async def meraki_vlans(request: Request, body: DeviceRequest) -> JSONResponse:
    return await _meraki_op(request, body, "vlans")


@meraki_router.post("/firmware", summary="Meraki firmware upgrades")
async def meraki_firmware(request: Request, body: DeviceRequest) -> JSONResponse:
    return await _meraki_op(request, body, "firmware")


@meraki_router.post("/uplinks", summary="Meraki uplink statuses")
async def meraki_uplinks(request: Request, body: DeviceRequest) -> JSONResponse:
    return await _meraki_op(request, body, "uplinks")


@meraki_router.post("/usage", summary="Meraki uplink usage")
async def meraki_usage(request: Request, body: DeviceRequest) -> JSONResponse:
    return await _meraki_op(request, body, "usage")


# ---------------------------------------------------------------------------
# Router registration
# ---------------------------------------------------------------------------

for _router in (
    auth_router,
    device_router,
    interfaces_router,
    arp_router,
    mac_router,
    routing_router,
    bgp_router,
    ospf_router,
    wan_router,
    vpn_router,
    firewall_router,
    vlan_router,
    topo_router,
    dhcp_router,
    system_router,
    monitoring_router,
    meraki_router,
    command_router,
):
    app.include_router(_router)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "network_api:app",
        host=os.getenv("HOST", "0.0.0.0"),
        port=int(os.getenv("PORT", "8000")),
        reload=os.getenv("RELOAD", "false").lower() == "true",
        workers=1,
    )

