from __future__ import annotations

from abc import ABC, abstractmethod

from app.models.schemas import (
    ArpEntry,
    DeviceIdentity,
    InterfaceFact,
    MacEntry,
    Neighbor,
    Route,
    WirelessAP,
    WirelessClient,
)


class DeviceCollector(ABC):
    """Vendor-agnostic snapshot of a single network node."""

    @abstractmethod
    def snapshot(self) -> "DeviceSnapshot":
        raise NotImplementedError


class DeviceSnapshot:
    def __init__(
        self,
        identity: DeviceIdentity,
        interfaces: list[InterfaceFact] | None = None,
        neighbors: list[Neighbor] | None = None,
        arp: list[ArpEntry] | None = None,
        mac: list[MacEntry] | None = None,
        routes: list[Route] | None = None,
        aps: list[WirelessAP] | None = None,
        clients: list[WirelessClient] | None = None,
        extra: dict | None = None,
    ) -> None:
        self.identity = identity
        self.interfaces = interfaces or []
        self.neighbors = neighbors or []
        self.arp = arp or []
        self.mac = mac or []
        self.routes = routes or []
        self.aps = aps or []
        self.clients = clients or []
        self.extra = extra or {}

    @property
    def name(self) -> str:
        return self.identity.name
