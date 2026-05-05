#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import yaml
import sys
import io
import os
import re
import hashlib
import subprocess as sp
from functools import reduce
from flask import send_file
from typing import Any, Dict, Iterable, Tuple


class Config(object):
    def __init__(self):
        self.dir = "/".join(sys.path[0].split("/")[:-2])
        return None

    def _config_path(self) -> str:
        return os.path.join(self.dir, "config.yaml")

    def _load_config(self) -> Dict[str, Any]:
        """Load config.yaml; return {} if missing/empty/invalid."""
        try:
            with open(self._config_path(), "r", encoding="utf-8") as f:
                data = yaml.load(f, Loader=yaml.SafeLoader)
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    def _atomic_write_config(self, config: Dict[str, Any]) -> None:
        """Write config.yaml atomically to avoid empty/truncated files."""
        path = self._config_path()
        tmp_path = f"{path}.tmp"
        with open(tmp_path, "w", encoding="utf-8") as yaml_file:
            yaml_file.write(yaml.dump(config, default_flow_style=False))
            yaml_file.flush()
            os.fsync(yaml_file.fileno())
        os.replace(tmp_path, path)

    def read_config(self, path):
        """
            Read a single value from the configuration
            :return: value (it can be any type)
        """
        config = self._load_config()
        try:
            return reduce(dict.get, path, config)
        except Exception:
            return None

    def export_config(self):
        """
            Export the configuration
            :return: dict (configuration content)
        """
        config = self._load_config()
        fe = config.setdefault("frontend", {})
        if fe.get("capture_export") not in ("usb", "browser", "server"):
            if "download_links" in fe:
                fe["capture_export"] = "browser" if fe.get("download_links") else "usb"
            else:
                fe["capture_export"] = "server"
        fe.setdefault("spyguard_server", "http://localhost:5000")
        fe.setdefault("slideshow", True)
        fe.setdefault("ui_zoom", 100)
        config["ifaces_in"] = self.get_ifaces_in()
        config["ifaces_out"] = self.get_ifaces_out()
        # Keep legacy behavior: ensure indicators_types exists and is list-like.
        config.setdefault("analysis", {})
        indicators = config["analysis"].get("indicators_types")
        config["analysis"]["indicators_types"] = indicators if indicators else []
        return config

    def ioc_type_add(self, tag):
        """Add an IOC type to the config file

        Args:
            tag (str): IOC type.
        """
        config = self._load_config()
        config.setdefault("analysis", {})
        config["analysis"].setdefault("indicators_types", [])
        if tag not in config["analysis"]["indicators_types"]:
            config["analysis"]["indicators_types"].append(tag)
        self._atomic_write_config(config)
        return {"status": True, "message": "Configuration updated"}

    def ioc_type_delete(self, tag):
        """Delete an IOC type to the config file

        Args:
            tag (str): IOC type.
        """
        config = self._load_config()
        config.setdefault("analysis", {})
        config["analysis"].setdefault("indicators_types", [])
        try:
            config["analysis"]["indicators_types"].remove(tag)
        except ValueError:
            pass
        self._atomic_write_config(config)
        return {"status": True, "message": "Configuration updated"}

    def write_config(self, cat, key, value) -> dict:
        """Write a value in the configuration

        Args:
            cat (str): category
            key (str): key 
            value (str): value to write

        Returns:
            dict: status of the operation.
        """

        config = self._load_config()

        # Some checks prior configuration changes.
        if cat not in config:
            return {"status": False,
                    "message": "Wrong category specified"}

        if key not in config[cat]:
            if cat == "frontend" and key in ("capture_export", "spyguard_server", "slideshow", "ui_zoom"):
                pass
            else:
                return {"status": False,
                        "message": "Wrong key specified"}

        # Changes for network interfaces.
        if cat == "network" and key in ["in", "out"]:
            if re.match("^(wlan[0-9]|wl[a-z0-9]{2,20})$", value):
                if key == "in":
                    config[cat][key] = value
                if key == "out":
                    config[cat][key] = value
            elif re.match("^(eth[0-9]|en[a-z0-9]{2,20}|ww[a-z0-9]{2,20}|lo)$", value) and key == "out":
                config[cat][key] = value
            else:
                return {"status": False,
                        "message": "Wrong value specified"}

        # Changes for network SSIDs.
        elif cat == "network" and key == "ssids":
            ssids = list(set(value.split("|"))) if "|" in value else [value]
            if len(ssids):
                config[cat][key] = ssids

        # Changes for backend password.
        elif cat == "backend" and key == "password":
            config[cat][key] = self.make_password(value)

        # Capture export mode (mutually exclusive in the admin UI).
        elif cat == "frontend" and key == "capture_export":
            if value in ("usb", "browser", "server"):
                config[cat][key] = value
            else:
                return {"status": False,
                        "message": "Wrong value for capture_export"}

        # Remote upload base URL (encrypted ZIP POST).
        elif cat == "frontend" and key == "spyguard_server":
            v = (value or "").strip().rstrip("/")
            if not v:
                return {"status": False,
                        "message": "spyguard_server URL cannot be empty"}
            if not (v.startswith("http://") or v.startswith("https://")):
                return {"status": False,
                        "message": "URL must start with http:// or https://"}
            config[cat][key] = v

        # UI zoom (Chromium CSS zoom): 100%..150% step 10
        elif cat == "frontend" and key == "ui_zoom":
            try:
                n = int(str(value).strip())
            except Exception:
                return {"status": False, "message": "ui_zoom must be an integer"}
            if n < 100 or n > 150 or (n % 10) != 0:
                return {"status": False, "message": "ui_zoom must be between 100 and 150 by step 10"}
            config[cat][key] = n

        # Changes for anything not specified.
        # Warning: can break your config if you play with it (eg. arrays, ints & bools).
        else:
            if isinstance(value, bool):
                config[cat][key] = value
            elif len(value):
                config[cat][key] = value

        try:
            self._atomic_write_config(config)
        except Exception:
            return {"status": False, "message": "Error while writing config file"}

        sp.Popen(["systemctl", "restart", "spyguard-frontend"]).wait()
        return {"status": True, "message": "Configuration updated"}

    def make_password(self, clear_text):
        """Make a simple sha256 password hash without salt.

        Args:
            clear_text (str): clear text password

        Returns:
            string: hexdigest of the password sha256 hash.
        """
        return hashlib.sha256(clear_text.encode()).hexdigest()

    def export_db(self):
        """Propose the database to download.

        Returns:
            Response: Flask Response.
        """
        with open(os.path.join(self.dir, "database.sqlite3"), "rb") as f:
            return send_file(
                io.BytesIO(f.read()),
                mimetype="application/octet-stream",
                as_attachment=True,
                attachment_filename='spyguard-export-db.sqlite')

    def get_ifaces_in(self) -> list:
        """ List the wireless interfaces which can be 
        used for the access point

        Returns:
            list: List of available network interfaces
        """
        try:
            return [i for i in os.listdir("/sys/class/net/") if i.startswith("wl")]
        except:
            return ["No wireless interface"]

    def get_ifaces_out(self) -> list:
        """ List the network interfaces which can be 
        used to access to Internet.

        Returns:
            list: List of available network interfaces
        """
        try:
            ifaces = ("wl", "et", "en", "ww", "lo")
            return [i for i in os.listdir("/sys/class/net/") if i.startswith(ifaces)]
        except:
            return ["No network interfaces"]

