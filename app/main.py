from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.api.routes import router

STATIC = Path(__file__).resolve().parent / "static"

app = FastAPI(
    title="Site Topology & ARP Troubleshoot API",
    version="1.0.0",
    description=(
        "Build a site-scoped Cytoscape topology from a single seed device "
        "(Cisco IOS, IOS-XE, WLC, AP, Meraki, Viptela) and troubleshoot a user "
        "from LAN ARP/CAM plus WAN DIA."
    ),
)
app.include_router(router)


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")


app.mount("/static", StaticFiles(directory=STATIC), name="static")
