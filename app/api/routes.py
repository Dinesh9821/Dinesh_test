from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query

from app.models.schemas import SeedRequest, TopologyRequest
from app.services.arp_troubleshoot import ArpTroubleshoot
from app.services.topology import build_topology
from app.style import cytoscape_stylesheet

router = APIRouter(prefix="/api/v1")


@router.post("/topology")
def post_topology(body: TopologyRequest):
    seed = body.seed.host if body.seed else "10.10.1.12"
    graph = build_topology(demo=body.demo, seed_host=seed, site_id=body.site_id)
    return graph.model_dump()


@router.get("/topology")
def get_topology(
    seed: str = Query("10.10.1.12", description="Any site switch or router mgmt IP or hostname"),
    demo: bool = True,
    site_id: str = "MUM-01",
):
    graph = build_topology(demo=demo, seed_host=seed, site_id=site_id)
    if not graph.nodes:
        raise HTTPException(404, f"Seed {seed} not reachable in site {site_id}")
    return graph.model_dump()


@router.get("/arp")
def get_arp(
    ip: str | None = None,
    mac: str | None = None,
    username: str | None = None,
    hostname: str | None = None,
    demo: bool = True,
    site_id: str = "MUM-01",
):
    if not any([ip, mac, username, hostname]):
        raise HTTPException(400, "Provide ip, mac, username, or hostname")
    return ArpTroubleshoot(demo=demo).query(ip, mac, username, hostname, site_id)


@router.get("/style")
def get_style():
    return {"style": cytoscape_stylesheet()}


@router.get("/health")
def health():
    return {"status": "ok"}
