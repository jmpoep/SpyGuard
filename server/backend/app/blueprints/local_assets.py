#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Status of on-disk caches under /usr/share/spyguard/assets (Umbrella, ip2asn)."""

from __future__ import annotations

import os
from datetime import datetime, timezone

from flask import Blueprint, jsonify

from app.decorators import require_header_token

local_assets_bp = Blueprint("local_assets", __name__)

# Kept in sync with watchers.py / analysis engine paths.
_ASSET_ENTRIES: tuple[dict[str, str], ...] = (
    {
        "id": "umbrella",
        "label": "Cisco Umbrella Top 1M",
        "filename": "umbrella-top-1m.json",
        "path": "/usr/share/spyguard/assets/umbrella-top-1m.json",
    },
    {
        "id": "ip2asn",
        "label": "ip2asn IPv4 (iptoasn.com)",
        "filename": "ip2asn-v4.tsv.gz",
        "path": "/usr/share/spyguard/assets/ip2asn-v4.tsv.gz",
    },
)


def _format_mtime_utc(ts: float) -> str:
    dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


def _file_status(path: str) -> dict[str, object]:
    present = os.path.isfile(path)
    out: dict[str, object] = {
        "present": present,
        "size_bytes": None,
        "mtime": None,
    }
    if not present:
        return out
    try:
        st = os.stat(path)
        out["size_bytes"] = int(st.st_size)
        out["mtime"] = _format_mtime_utc(st.st_mtime)
    except OSError:
        out["present"] = False
    return out


@local_assets_bp.route("/status", methods=["GET"])
@require_header_token
def get_status():
    """Return presence, size, and last modification time for each local asset file."""
    results = []
    for meta in _ASSET_ENTRIES:
        path = meta["path"]
        st = _file_status(path)
        row = {
            "id": meta["id"],
            "label": meta["label"],
            "filename": meta["filename"],
            "path": path,
            "present": st["present"],
            "size_bytes": st["size_bytes"],
            "mtime": st["mtime"],
        }
        results.append(row)
    return jsonify({"results": results})
