"""Pydantic and device-type validation."""

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from network_api import (
    DeviceRequest,
    InvalidDeviceTypeError,
    TroubleshootRequest,
    app,
    is_command_allowed,
    is_meraki,
    mask_mapping,
    mask_text,
    normalize_platform,
    validate_device_type,
)


def test_device_request_optional_fields() -> None:
    model = DeviceRequest()
    assert model.login_ip is None
    assert model.username is None


def test_device_request_secret_not_in_safe_dict() -> None:
    model = DeviceRequest(username="admin", password="super-secret", api_key="mk-secret")
    dumped = model.safe_dict()
    assert dumped["password"] == "********"
    assert dumped["api_key"] == "********"
    assert "super-secret" not in str(dumped)
    serialized = model.model_dump()
    assert serialized["password"] != "super-secret"


def test_device_request_normalizes_vendor() -> None:
    model = DeviceRequest(vendor="Cisco", device_type="Cisco_Router")
    assert model.vendor == "cisco"
    assert model.device_type == "cisco_router"


def test_invalid_port_rejected() -> None:
    with pytest.raises(ValidationError):
        DeviceRequest(port=70000)


def test_validate_device_type_cisco() -> None:
    assert validate_device_type("cisco_router", "cisco") == "cisco_ios"
    assert validate_device_type("cisco_iosxe", "cisco") == "cisco_iosxe"
    assert validate_device_type("meraki_switch", "meraki") == "meraki"


def test_validate_device_type_missing() -> None:
    with pytest.raises(InvalidDeviceTypeError):
        validate_device_type(None, None)


def test_validate_device_type_unknown_vendor() -> None:
    with pytest.raises(InvalidDeviceTypeError):
        validate_device_type("something_odd", "acme")


def test_normalize_platform_meraki_from_api_key() -> None:
    req = DeviceRequest(api_key="xxxxx", device_name="SW-001")
    assert is_meraki(req) is True
    assert normalize_platform(req.device_type, req.vendor) == "meraki"


def test_troubleshoot_requires_target_ip() -> None:
    with pytest.raises(ValidationError):
        TroubleshootRequest(login_ip="10.10.10.10")


def test_malformed_json_returns_consistent_error() -> None:
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/arp",
            content="{not-json",
            headers={"Content-Type": "application/json"},
        )
    assert response.status_code == 422
    body = response.json()
    assert body["status"] == "error"
    assert body["error"]["code"] == "VALIDATION_ERROR"


def test_invalid_device_type_on_api() -> None:
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/interfaces",
            json={
                "username": "admin",
                "password": "x",
                "login_ip": "10.10.10.10",
                "vendor": "acme",
                "device_type": "toaster",
            },
        )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "INVALID_DEVICE_TYPE"


def test_secret_masking_helpers() -> None:
    assert "secretpass" not in mask_text("password=secretpass api_key=abcd")
    assert mask_mapping({"password": "x", "nested": {"api_key": "y"}}) == {
        "password": "********",
        "nested": {"api_key": "********"},
    }
    assert is_command_allowed("show ip arp") is True
