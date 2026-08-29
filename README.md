# Network Operations REST API

Production-oriented FastAPI backend for Network Operations / NOC workflows. The UI asks for operational data (ARP, routing, BGP, device summary, Meraki clients). This service selects the connector (Cisco CLI via Netmiko, or Meraki Dashboard API), collects results, and returns normalized JSON plus raw output.

Frontend callers do **not** need to know Cisco vs Meraki command syntax.

## 1. Installation

Python 3.11+ is required.

```bash
git clone <repository-url>
cd <repository>
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install --upgrade pip
pip install -r requirements.txt
```

## 2. Virtual environment

Keep dependencies isolated:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## 3. Configuration

Copy the example environment file and adjust timeouts, worker count, and Meraki base URL. **Do not put production secrets in source control.**

```bash
cp .env.example .env
```

| Variable | Purpose |
| --- | --- |
| `LOG_LEVEL` | Logging level (`INFO`, `DEBUG`, …) |
| `NETWORK_SSH_TIMEOUT` | SSH auth / banner timeout (seconds) |
| `NETWORK_CONNECTION_TIMEOUT` | TCP connect timeout (seconds) |
| `NETWORK_COMMAND_TIMEOUT` | CLI command read timeout (seconds) |
| `NETWORK_MAX_WORKERS` | Thread pool size for blocking Netmiko / HTTP calls |
| `MERAKI_API_BASE_URL` | Meraki Dashboard API base (`https://api.meraki.com/api/v1`) |
| `MERAKI_API_TIMEOUT` | HTTP timeout for Meraki |
| `REDIS_URL` | Reserved for a future cache backend (no-op if empty) |
| `SECRET_BACKEND` | `request` (default), `env`, or `vault` (stub) |
| `INVENTORY_BACKEND` | Prototype uses the request body; NetBox/CMDB can replace `get_device_details()` |

Credentials are accepted on the request body for this prototype. The code is structured so HashiCorp Vault, CyberArk, environment variables, or another secret manager can be plugged in via `SecretProvider` without changing API paths.

## 4. Starting FastAPI

Development (auto-reload optional):

```bash
uvicorn network_api:app --host 0.0.0.0 --port 8000 --reload
```

Or:

```bash
python network_api.py
```

## 5. Swagger / OpenAPI

| URL | Description |
| --- | --- |
| http://127.0.0.1:8000/docs | Swagger UI |
| http://127.0.0.1:8000/redoc | ReDoc |
| http://127.0.0.1:8000/openapi.json | OpenAPI schema |
| http://127.0.0.1:8000/health | Process health |

## 6. Example API calls

Replace host, credentials, and IPs with your values. Passwords and API keys are never returned in responses and are masked in logs.

**Service health**

```bash
curl -s http://127.0.0.1:8000/health
```

**Device facts (Cisco)**

```bash
curl -s -X POST http://127.0.0.1:8000/api/v1/device/facts \
  -H 'Content-Type: application/json' \
  -d '{
    "username": "admin",
    "password": "password",
    "login_ip": "10.10.10.10",
    "device_name": "RTR-001",
    "device_type": "cisco_router",
    "vendor": "cisco",
    "site_id": "SITE001",
    "region": "APAC",
    "country": "India"
  }'
```

**Device summary (dashboard snapshot)**

```bash
curl -s -X POST http://127.0.0.1:8000/api/v1/device/summary \
  -H 'Content-Type: application/json' \
  -d '{
    "username": "admin",
    "password": "password",
    "login_ip": "10.10.10.10",
    "device_name": "RTR-001",
    "device_type": "cisco_router",
    "vendor": "cisco"
  }'
```

**ARP / interfaces / BGP**

```bash
curl -s -X POST http://127.0.0.1:8000/api/v1/arp \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"password","login_ip":"10.10.10.10","device_type":"cisco_ios"}'

curl -s -X POST http://127.0.0.1:8000/api/v1/interfaces \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"password","login_ip":"10.10.10.10","device_type":"cisco_ios"}'

curl -s -X POST http://127.0.0.1:8000/api/v1/bgp/summary \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"password","login_ip":"10.10.10.10","device_type":"cisco_iosxe"}'
```

**Troubleshoot a target IP**

```bash
curl -s -X POST http://127.0.0.1:8000/api/v1/troubleshoot \
  -H 'Content-Type: application/json' \
  -d '{
    "username": "admin",
    "password": "password",
    "login_ip": "10.10.10.10",
    "device_name": "RTR-001",
    "device_type": "cisco_router",
    "target_ip": "10.20.30.40"
  }'
```

**Allowlisted operational command (show only)**

```bash
curl -s -X POST http://127.0.0.1:8000/api/v1/command \
  -H 'Content-Type: application/json' \
  -d '{
    "username": "admin",
    "password": "password",
    "login_ip": "10.10.10.10",
    "device_type": "cisco_router",
    "command": "show ip interface brief"
  }'
```

**Meraki organizations / devices**

```bash
curl -s -X POST http://127.0.0.1:8000/api/v1/meraki/organizations \
  -H 'Content-Type: application/json' \
  -d '{"vendor":"meraki","api_key":"xxxxx"}'

curl -s -X POST http://127.0.0.1:8000/api/v1/meraki/devices \
  -H 'Content-Type: application/json' \
  -d '{"vendor":"meraki","api_key":"xxxxx","organization_id":"123456"}'
```

## 7. Cisco connectivity requirements

- SSH reachability from the API host to the device management VRF/IP.
- A local or AAA user with authorization for operational `show` commands.
- Netmiko device type is derived from `device_type` / `vendor` (`cisco_ios`, `cisco_iosxe`, `cisco_nxos`, `cisco_asa`, `cisco_sdwan`, …).
- Commands that a given platform does not support are detected from CLI error text and returned as `parsed: false` rather than failing the whole snapshot.
- Blocking SSH work runs in a thread pool (`asyncio` + `ThreadPoolExecutor`) so the FastAPI event loop is not blocked.

## 8. Meraki API configuration

- Create a Dashboard API key with least-privilege access to the required organizations.
- Pass `api_key` on the request (or later via `MERAKI_API_KEY` when `SECRET_BACKEND=env`).
- Supply `organization_id`, `network_id`, and/or `serial` depending on the endpoint.
- Base URL defaults to `https://api.meraki.com/api/v1` and is overridable with `MERAKI_API_BASE_URL` (including dashboard regional endpoints).
- HTTP 401 maps to `MERAKI_AUTH_ERROR`; HTTP 429 is retried then returned as `MERAKI_RATE_LIMITED`.

Meraki logic is isolated in `execute_meraki_api()` / `MerakiAPIDevice`. Cisco logic is isolated in `connect_cisco()` / `execute_cisco_command()` / `CiscoCLIDevice`.

## 9. Security considerations

- Passwords, API keys, and tokens are **never** written to logs (key=value masking) and are **never** included in API responses (`SecretStr` + explicit exclusion).
- `/api/v1/command` rejects configuration and destructive commands (`configure`, `reload`, `write erase`, `erase`, `delete`, `shutdown`, `no …`, `clear`, `copy`, `debug`, …). Only `show` / `ping` / `traceroute` (and registry-mapped operational commands) are allowed.
- Treat this service as an internal Network Operations plane: put it behind SSO/mTLS, restrict source networks, and move credentials to Vault/CyberArk before production use.
- Do not log full running-config dumps to shared log aggregators without redaction.

## 10. Production deployment (Gunicorn + Uvicorn workers)

```bash
gunicorn network_api:app \
  --worker-class uvicorn.workers.UvicornWorker \
  --workers 4 \
  --bind 0.0.0.0:8000 \
  --timeout 120 \
  --graceful-timeout 30 \
  --keep-alive 5 \
  --access-logfile - \
  --error-logfile -
```

Tune `--workers` against CPU and expected concurrent SSH sessions. `NETWORK_MAX_WORKERS` sizes the **per-process** thread pool used for Netmiko/Meraki I/O. Use a reverse proxy (nginx/Caddy) for TLS.

### Tests

```bash
pytest -q
```

Unit tests mock Netmiko and Meraki HTTP; they do not require live devices.

### Extending vendors

`get_device_connector()` is the factory. Add an `AristaDevice` / `JuniperDevice` class and map it from `vendor` without changing REST paths. Operational commands live in the `COMMANDS` registry keyed by platform (`cisco_ios`, `cisco_iosxe`, `cisco_nxos`, …).
