#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import subprocess as sp
from flask import Blueprint, jsonify
from app.utils import *
from app.classes.capture import stop_monitoring
import re
import sys
import os
import sqlite3

misc_bp = Blueprint("misc", __name__)


@misc_bp.route("/delete-captures", methods=["GET"])
def api_delete_captures():
    """
        Delete the zombies capture folders (if any)
    """
    if delete_captures() and stop_monitoring():
        return jsonify({"message": "Captures deleted", "status": True})
    else:
        return jsonify({"message": "Issue while removing captures", "status": False})


@misc_bp.route("/reboot", methods=["GET"])
def api_reboot():
    """
        Reboot the device
    """
    if read_config(("frontend", "reboot_option")):
        sp.Popen(["shutdown", "-r", "now"])
        return jsonify({"mesage": "Let's reboot."})
    else:
        return jsonify({"message": "Option disabled", "status": False})


@misc_bp.route("/quit", methods=["GET"])
def api_quit():
    """
        Quit the interface (Chromium browser)
    """
    if read_config(("frontend", "quit_option")):
        sp.Popen('pkill -INT -f "chromium-browser"', shell=True)
        return jsonify({"message": "Let's quit", "status": True})
    else:
        return jsonify({"message": "Option disabled", "status": False})


@misc_bp.route("/shutdown", methods=["GET"])
def api_shutdown():
    """
        Reboot the device
    """
    if read_config(("frontend", "shutdown_option")):
        sp.Popen("shutdown -h now", shell=True)
        return jsonify({"message": "Let's shutdown", "status": True})
    else:
        return jsonify({"message": "Option disabled", "status": False})


@misc_bp.route("/config", methods=["GET"])
def get_config():
    """
        Get configuration keys relative to the GUI
    """
    return jsonify({
        "battery_level" : get_battery_level(),
        "wifi_level" : get_wifi_level(),
        "virtual_keyboard": read_config(("frontend", "virtual_keyboard")),
        "capture_export": effective_capture_export(),
        "sparklines": read_config(("frontend", "sparklines")),
        "shutdown_option": read_config(("frontend", "shutdown_option")),
        "backend_option": read_config(("frontend", "backend_option")),
        "remote_backend" : read_config(("backend", "remote_access")),
        "iface_out": read_config(("network", "out")),
        "user_lang": read_config(("frontend", "user_lang")),
        "choose_net": read_config(("frontend", "choose_net")),
        "slideshow": read_config(("frontend", "slideshow"), True),
        "ui_zoom": read_config(("frontend", "ui_zoom"), 100),
        "iocs_number" : get_iocs_number()
    })

@misc_bp.route("/battery", methods=["GET"])
def battery_level():
    """
        Return the battery level
    """
    return jsonify({
        "battery_level" : get_battery_level()
    })


@misc_bp.route("/whitelist/<path:host>", methods=["GET"])
def whitelist_host(host):
    """Add a host/ip/cidr to the local whitelist DB (used by analysis)."""
    try:
        element = (host or "").strip().lower()
        element = element.rstrip(".")
        if not element:
            return jsonify({"status": False, "message": "Empty element", "element": ""})

        # Infer type (minimal, matches analysis whitelist types).
        elem_type = "domain"
        if "/" in element:
            elem_type = "cidr"
        elif re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", element):
            # basic ipv4 sanity
            parts = element.split(".")
            if all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
                elem_type = "ip4addr"
        elif ":" in element and re.match(r"^[0-9a-f:]+$", element):
            elem_type = "ip6addr"
        elif re.match(r"^(?:as)?[0-9]{1,10}$", element):
            s = element[2:] if element.startswith("as") else element
            if s.isdigit():
                nz = s.lstrip("0") or "0"
                element = nz
                elem_type = "asn"

        with sqlite3.connect("/usr/share/spyguard/database.sqlite3") as c:
            cur = c.cursor()
            # ensure table exists (older installs should already have it).
            cur.execute(
                "CREATE TABLE IF NOT EXISTS whitelist (id INTEGER PRIMARY KEY AUTOINCREMENT, element TEXT, type TEXT, source TEXT, added_on INTEGER)"
            )
            cur.execute("SELECT 1 FROM whitelist WHERE element = ? LIMIT 1", (element,))
            if cur.fetchone():
                return jsonify({"status": False, "message": "Element already whitelisted", "element": element, "type": elem_type})
            cur.execute(
                "INSERT INTO whitelist (element, type, source, added_on) VALUES (?, ?, ?, strftime('%s','now'))",
                (element, elem_type, "frontend"),
            )
            c.commit()
        return jsonify({"status": True, "message": "Element whitelisted", "element": element, "type": elem_type})
    except Exception as e:
        return jsonify({"status": False, "message": f"Whitelist failed: {str(e)}"})
