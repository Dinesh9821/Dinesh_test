from __future__ import annotations

from app.collectors.base import DeviceCollector, DeviceSnapshot
from app.mock_lab.site_mumbai import LabDevice, build_mumbai_lab


class MockCollector(DeviceCollector):
    def __init__(self, device: LabDevice) -> None:
        self.device = device

    def snapshot(self) -> DeviceSnapshot:
        d = self.device
        return DeviceSnapshot(
            identity=d.identity,
            interfaces=list(d.interfaces),
            neighbors=list(d.neighbors),
            arp=list(d.arp),
            mac=list(d.mac),
            routes=list(d.routes),
            aps=list(d.aps),
            clients=list(d.clients),
        )


class MockLab:
    def __init__(self) -> None:
        self.devices = {k: v for k, v in build_mumbai_lab().items() if k != "_hosts"}
        lab = build_mumbai_lab()
        self.hosts = lab["_hosts"].clients
        self._index: dict[str, str] = {}
        for name, dev in self.devices.items():
            self._index[name.lower()] = name
            self._index[dev.identity.mgmt_ip] = name
            for alias in dev.aliases:
                self._index[alias.lower()] = name

    def resolve(self, seed: str) -> LabDevice | None:
        name = self._index.get(seed.strip().lower())
        if not name:
            return None
        return self.devices[name]

    def collector_for(self, seed: str) -> MockCollector | None:
        dev = self.resolve(seed)
        if not dev:
            return None
        return MockCollector(dev)


_LAB: MockLab | None = None


def get_lab() -> MockLab:
    global _LAB
    if _LAB is None:
        _LAB = MockLab()
    return _LAB
