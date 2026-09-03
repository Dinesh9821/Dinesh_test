# Site topology and ARP troubleshooting API

Build a **site-scoped** network diagram from a single seed switch or router, then trace any user from **LAN (ARP/CAM/AP)** and **WAN (DIA/NAT/SD-WAN TLOC)** for Cytoscape.js.

The fabric is mixed: **Cisco IOS, IOS-XE, Catalyst 9800 WLC, Aironet/Catalyst APs, Meraki MS/MR, Viptela cEdge**. Discovery never walks past the Internet handoff — overlay peers and ISP PEs are leaves, not neighbors to expand.

## Demo lab (Mumbai site)

Until you point the collectors at live gear, `demo=true` uses a faithful in-process site:

```
Internet (Airtel DIA)  ← site boundary
        |
  VEDGE-MUM-001  (Viptela / cEdge IOS-XE)
        |
  RTR-MUM-CORE   (ISR 4331 IOS-XE)
        |
  SW-MUM-DIST    (C9300)
   |      |       |        |
 ACC-01 ACC-02  WLC-9800  MS-MUM-01 (Meraki)
   |      |       |        |
 users   AP-01/02 CAPWAP   MR-MUM-01
```

Seed any device (`SW-MUM-ACC-01`, `10.10.10.1`, `MS-MUM-01`, `VEDGE-MUM-001`, …). The graph is the same site.

## Run

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Open http://127.0.0.1:8000 for the Cytoscape UI (colors + symbols per device class).

```bash
pytest -q
```

## Topology API

`GET /api/v1/topology?seed=SW-MUM-ACC-01&demo=true`

`POST /api/v1/topology` with `{ "seed": { "host": "10.10.1.12" }, "demo": true, "site_id": "MUM-01" }`

Each node includes the fields you asked for, plus vendor metadata used by the UI:

```json
{
  "nodes": [
    {
      "data": {
        "id": "RTR-MUM-CORE",
        "name": "RTR-MUM-CORE",
        "type": "router",
        "cpu": 32,
        "status": "up",
        "color": "#2563eb",
        "shape": "diamond",
        "symbol": "◆"
      }
    }
  ],
  "edges": [
    {
      "data": {
        "id": "RTR-MUM-CORE-SW-MUM-DIST",
        "source": "RTR-MUM-CORE",
        "target": "SW-MUM-DIST",
        "interface": "GigabitEthernet0/0/1",
        "utilization": 45,
        "latency": 1,
        "packet_loss": 0.0
      }
    }
  ]
}
```

How accuracy is produced:

1. Identify the seed (`show version` / Meraki / vManage).
2. Pull CDP/LLDP (and CAPWAP AP lists, Meraki `lldpCdp`, vManage CDP).
3. Classify each local interface as LAN vs WAN (description, NAT outside, public IP, TLOC/DIA).
4. Enqueue only LAN-side neighbors in the same site.
5. Attach a single **Internet** node on the WAN TLOC and stop.

Live SSH uses the same parsers (`CiscoCliCollector` + Netmiko). Meraki Dashboard and vManage collectors are in `app/collectors/`. Pass `demo=false` plus seed credentials when the box is reachable.

## ARP / user path API

`GET /api/v1/arp?ip=10.20.10.45`

Also `mac`, `username`, `hostname`.

The payload is a Cytoscape graph of the **user path** plus structured LAN and WAN evidence:

| Side | What a NOC engineer gets |
|------|--------------------------|
| LAN | Wired CAM port vs wireless AP/SSID/RSSI/WLC, VLAN, SVI gateway, ARP complete or missing |
| WAN | Core → cEdge → DIA, TLOC color, PAT, utilization / latency / loss on the Internet handoff |
| Verdict | Green / amber / red with the domain to work first (RF vs CAM vs DIA) |

Sample users in the demo site:

- `10.20.10.45` / `dinesh.velapure` — wired on `SW-MUM-ACC-01 Gi1/0/1`
- `10.40.10.88` / `priya.nair` — Cisco AP `AP-MUM-01` SSID `MUM-CORP`
- `10.40.10.89` / `rahul.shah` — Meraki `MR-MUM-01` guest SSID
- `10.50.10.12` — IoT camera on Meraki MS port 5

## Color and symbols (Cytoscape)

| Type | Color | Shape | Symbol |
|------|--------|--------|--------|
| Router | `#2563eb` | diamond | ◆ |
| Switch | `#0d9488` | rectangle | ▣ |
| WLC | `#7c3aed` | hexagon | ⬡ |
| AP | `#ea580c` | star | ✶ |
| Meraki | `#16a34a` | round-rectangle | ◉ |
| Viptela | `#4f46e5` | octagon | ⬣ |
| Host | `#64748b` | ellipse | ● |
| Internet | `#e11d48` | triangle | ▲ |

Edge color follows utilization (grey &lt; 50%, amber 50–79%, red ≥ 80%). WAN is dashed; CAPWAP is dotted.

`GET /api/v1/style` returns the stylesheet if you render in your own Cytoscape app. The topology payload already includes `style` and `legend`.
