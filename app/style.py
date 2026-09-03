from __future__ import annotations

# Color + shape + unicode symbol for Cytoscape.js
TYPE_STYLE = {
    "router": {"color": "#2563eb", "shape": "diamond", "symbol": "◆", "label": "Router"},
    "switch": {"color": "#0d9488", "shape": "rectangle", "symbol": "▣", "label": "Switch"},
    "wlc": {"color": "#7c3aed", "shape": "hexagon", "symbol": "⬡", "label": "WLC"},
    "ap": {"color": "#ea580c", "shape": "star", "symbol": "✶", "label": "AP"},
    "meraki": {"color": "#16a34a", "shape": "round-rectangle", "symbol": "◉", "label": "Meraki"},
    "viptela": {"color": "#4f46e5", "shape": "octagon", "symbol": "⬣", "label": "Viptela"},
    "host": {"color": "#64748b", "shape": "ellipse", "symbol": "●", "label": "Host"},
    "internet": {"color": "#e11d48", "shape": "triangle", "symbol": "▲", "label": "Internet"},
    "unknown": {"color": "#94a3b8", "shape": "ellipse", "symbol": "?", "label": "Unknown"},
}


def type_color(dtype: str) -> str:
    return TYPE_STYLE.get(dtype, TYPE_STYLE["unknown"])["color"]


def type_shape(dtype: str) -> str:
    return TYPE_STYLE.get(dtype, TYPE_STYLE["unknown"])["shape"]


def type_symbol(dtype: str) -> str:
    return TYPE_STYLE.get(dtype, TYPE_STYLE["unknown"])["symbol"]


def cytoscape_stylesheet() -> list[dict]:
    sheets = [
        {
            "selector": "node",
            "style": {
                "label": "data(label)",
                "color": "#e2e8f0",
                "font-size": 11,
                "font-family": "Inter, Segoe UI, sans-serif",
                "text-valign": "bottom",
                "text-margin-y": 6,
                "background-color": "data(color)",
                "shape": "data(shape)",
                "width": 42,
                "height": 42,
                "border-width": 2,
                "border-color": "#0f172a",
                "text-outline-color": "#020617",
                "text-outline-width": 2,
            },
        },
        {
            "selector": "edge",
            "style": {
                "curve-style": "bezier",
                "width": 3,
                "line-color": "#64748b",
                "target-arrow-shape": "none",
                "label": "data(iflabel)",
                "font-size": 8,
                "color": "#94a3b8",
                "text-rotation": "autorotate",
            },
        },
        {"selector": "edge.hot", "style": {"line-color": "#ef4444", "width": 5}},
        {"selector": "edge.warm", "style": {"line-color": "#f59e0b", "width": 4}},
        {"selector": "edge.cool", "style": {"line-color": "#64748b"}},
        {"selector": "edge.wan", "style": {"line-style": "dashed", "line-color": "#e11d48", "width": 4}},
        {"selector": "edge.capwap", "style": {"line-style": "dotted", "line-color": "#a855f7"}},
        {"selector": "node.down", "style": {"opacity": 0.45, "border-color": "#ef4444", "border-width": 4}},
        {"selector": "node.host", "style": {"width": 28, "height": 28}},
        {"selector": "node.internet", "style": {"width": 50, "height": 50}},
        {"selector": ".path", "style": {"border-width": 4, "border-color": "#facc15"}},
        {"selector": "edge.path", "style": {"line-color": "#facc15", "width": 6}},
    ]
    return sheets
