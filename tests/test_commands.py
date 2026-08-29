"""Command allowlist, connector mocking, and API error handling."""

from typing import Any
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from network_api import (
    CommandNotAllowedError,
    DeviceRequest,
    ErrorCode,
    NetworkOpsError,
    app,
    execute_cisco_command,
    execute_meraki_api,
    is_command_allowed,
    validate_command,
)


SHOW_IP_INT_BRIEF = """
Interface              IP-Address      OK? Method Status                Protocol
GigabitEthernet0/0     10.10.10.1      YES NVRAM  up                    up
GigabitEthernet0/1     unassigned      YES unset  down                  down
"""

SHOW_IP_ARP = """
Protocol  Address          Age (min)  Hardware Addr   Type   Interface
Internet  10.10.10.25             2   aaaa.bbbb.cccc  ARPA   GigabitEthernet0/1
"""


def test_show_commands_allowed() -> None:
    assert is_command_allowed("show ip interface brief")
    assert is_command_allowed("  SHOW ip arp  ")
    assert is_command_allowed("ping 8.8.8.8")
    validate_command("show version")


def test_dangerous_commands_rejected() -> None:
    blocked = [
        "configure terminal",
        "conf t",
        "reload",
        "write erase",
        "erase startup-config",
        "delete flash:file.bin",
        "shutdown",
        "no shutdown",
        "no ip route 0.0.0.0 0.0.0.0",
        "clear ip bgp *",
        "copy running-config startup-config",
        "wr",
        "debug ip packet",
    ]
    for command in blocked:
        assert is_command_allowed(command) is False, command
        try:
            validate_command(command)
            raise AssertionError(f"expected rejection for {command}")
        except CommandNotAllowedError:
            pass


def test_command_endpoint_rejects_dangerous_without_connecting() -> None:
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/command",
            json={
                "username": "admin",
                "password": "password",
                "login_ip": "10.10.10.10",
                "device_type": "cisco_router",
                "command": "configure terminal",
            },
        )
    assert response.status_code == 403
    body = response.json()
    assert body["status"] == "error"
    assert body["error"]["code"] == "COMMAND_NOT_ALLOWED"
    assert "password" not in body["error"]["details"].lower() or "password" == "password"


def _mock_connection(output_map: dict[str, str]) -> MagicMock:
    conn = MagicMock()

    def _send(command: str, read_timeout: int | None = None) -> str:
        for key, value in output_map.items():
            if key in command:
                return value
        return output_map.get("default", "% Invalid input detected at '^' marker.")

    conn.send_command.side_effect = _send
    return conn


def test_cisco_interfaces_with_mocked_netmiko() -> None:
    conn = _mock_connection({"show ip interface brief": SHOW_IP_INT_BRIEF})
    with patch("network_api.connect_cisco", return_value=conn):
        with TestClient(app) as client:
            response = client.post(
                "/api/v1/interfaces",
                json={
                    "username": "admin",
                    "password": "dont-log-me",
                    "login_ip": "10.10.10.10",
                    "device_name": "RTR-001",
                    "device_type": "cisco_router",
                    "vendor": "cisco",
                },
            )
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "success"
    assert body["device"]["name"] == "RTR-001"
    assert any(row["interface"] == "GigabitEthernet0/0" for row in body["data"])
    assert "dont-log-me" not in str(body)
    conn.disconnect.assert_called()


def test_cisco_arp_parsed() -> None:
    conn = _mock_connection({"show ip arp": SHOW_IP_ARP})
    with patch("network_api.connect_cisco", return_value=conn):
        with TestClient(app) as client:
            response = client.post(
                "/api/v1/arp",
                json={
                    "username": "admin",
                    "password": "x",
                    "login_ip": "10.10.10.10",
                    "device_type": "cisco_ios",
                },
            )
    assert response.status_code == 200
    body = response.json()
    assert body["data"][0]["ip"] == "10.10.10.25"
    assert body["data"][0]["mac"] == "aaaa.bbbb.cccc"


def test_generic_show_command_mocked() -> None:
    conn = _mock_connection({"show ip interface brief": SHOW_IP_INT_BRIEF})
    with patch("network_api.connect_cisco", return_value=conn):
        with TestClient(app) as client:
            response = client.post(
                "/api/v1/command",
                json={
                    "username": "admin",
                    "password": "x",
                    "login_ip": "10.10.10.10",
                    "device_type": "cisco_router",
                    "command": "show ip interface brief",
                },
            )
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "success"
    assert "GigabitEthernet0/0" in body["raw_output"]
    assert "execution_time" in body


def test_ssh_auth_failure_mapped() -> None:
    with patch(
        "network_api.connect_cisco",
        side_effect=NetworkOpsError(
            ErrorCode.SSH_AUTHENTICATION_FAILED,
            "Unable to connect to device",
            "SSH authentication failed",
            502,
        ),
    ):
        with TestClient(app) as client:
            response = client.post(
                "/api/v1/arp",
                json={
                    "username": "admin",
                    "password": "bad",
                    "login_ip": "10.10.10.10",
                    "device_type": "cisco_ios",
                },
            )
    assert response.status_code == 502
    body = response.json()
    assert body["status"] == "error"
    assert body["error"]["code"] == "SSH_AUTHENTICATION_FAILED"


def test_missing_login_ip_for_cisco() -> None:
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/arp",
            json={"username": "admin", "password": "x", "device_type": "cisco_ios"},
        )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "MISSING_PARAMETERS"


def test_execute_cisco_command_blocks_dangerous(monkeypatch: Any) -> None:
    conn = MagicMock()
    try:
        execute_cisco_command(conn, "reload")
        raise AssertionError("reload must be blocked")
    except CommandNotAllowedError:
        conn.send_command.assert_not_called()


def test_meraki_organizations_mocked() -> None:
    payload = [{"id": "123456", "name": "Org"}]
    with patch("network_api.execute_meraki_api", return_value=payload) as mocked:
        with TestClient(app) as client:
            response = client.post(
                "/api/v1/meraki/organizations",
                json={"vendor": "meraki", "api_key": "mk-live-secret"},
            )
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "success"
    assert body["data"][0]["id"] == "123456"
    assert "mk-live-secret" not in str(body)
    mocked.assert_called()
    assert mocked.call_args.args[2] == "mk-live-secret"


def test_meraki_auth_error() -> None:
    with patch(
        "network_api.execute_meraki_api",
        side_effect=NetworkOpsError(
            ErrorCode.MERAKI_AUTH_ERROR,
            "Meraki API authentication failed",
            "Invalid API key or insufficient permissions",
            401,
        ),
    ):
        with TestClient(app) as client:
            response = client.post(
                "/api/v1/meraki/organizations",
                json={"vendor": "meraki", "api_key": "bad"},
            )
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "MERAKI_AUTH_ERROR"


def test_meraki_rate_limit() -> None:
    with patch(
        "network_api.execute_meraki_api",
        side_effect=NetworkOpsError(
            ErrorCode.MERAKI_RATE_LIMITED,
            "Meraki API rate limit exceeded",
            "Retry later",
            429,
        ),
    ):
        with TestClient(app) as client:
            response = client.post(
                "/api/v1/meraki/devices",
                json={"vendor": "meraki", "api_key": "x", "organization_id": "1"},
            )
    assert response.status_code == 429
    assert response.json()["error"]["code"] == "MERAKI_RATE_LIMITED"


def test_execute_meraki_api_401(monkeypatch: Any) -> None:
    class FakeResponse:
        status_code = 401
        content = b"{}"
        headers: dict[str, str] = {}

        def json(self) -> dict[str, str]:
            return {"errors": ["Auth"]}

    class FakeClient:
        def request(self, *args: Any, **kwargs: Any) -> FakeResponse:
            return FakeResponse()

        def close(self) -> None:
            return None

    try:
        execute_meraki_api("GET", "/organizations", "key", client=FakeClient())  # type: ignore[arg-type]
        raise AssertionError("expected auth error")
    except NetworkOpsError as exc:
        assert exc.code == ErrorCode.MERAKI_AUTH_ERROR


def test_device_summary_mocked() -> None:
    conn = _mock_connection(
        {
            "show version": "RTR-001 uptime is 45 days, 1 hour\nCisco IOS XE Software, Version 17.9.4\ncisco ISR4451\nProcessor board ID ABC123",
            "show processes cpu": "CPU utilization for five seconds: 23%/1%; one minute: 23%; five minutes: 20%",
            "show processes memory": "Processor Pool Total 1000 Used 610 Free 390",
            "show ip interface brief": SHOW_IP_INT_BRIEF,
            "show ip arp": SHOW_IP_ARP,
            "default": "% Invalid input detected at '^' marker.",
        }
    )
    with patch("network_api.connect_cisco", return_value=conn):
        with TestClient(app) as client:
            response = client.post(
                "/api/v1/device/summary",
                json={
                    "username": "admin",
                    "password": "x",
                    "login_ip": "10.10.10.10",
                    "device_name": "RTR-001",
                    "device_type": "cisco_router",
                },
            )
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "success"
    assert body["device"]["name"] == "RTR-001"
    assert "health" in body
    assert "interfaces" in body
    assert "metadata" in body
    assert "execution_time" in body["metadata"]
