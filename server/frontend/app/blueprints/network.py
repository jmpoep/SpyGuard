#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from flask import Blueprint, jsonify, request
from app.classes.network import Network

network = Network()
network_bp = Blueprint("network", __name__)


@network_bp.route("/status", methods=["GET"])
def api_network_status():
    """ Get the network status of eth0, wlan0 """
    return jsonify(network.check_status())


@network_bp.route("/wifi/list", methods=["GET"])
def api_get_wifi_list():
    """ List available WIFI networks """
    return jsonify(network.wifi_list_networks())


@network_bp.route("/wifi/setup", methods=["POST", "OPTIONS"])
def api_set_wifi():
    """ Set an access point and a password """
    if request.method == "POST":
        data = request.get_json()
        res = network.wifi_setup(data["ssid"], data["password"])
        return jsonify(res)
    else:
        return ""

@network_bp.route("/ap/start", methods=["GET"])
def api_start_ap():
    """ Start an access point """
    return jsonify(network.start_hotspot())


@network_bp.route("/ap/stop", methods=["GET"])
def api_stop_ap():
    """ Stop (delete) the current access point connection """
    ok = network.delete_hotspot()
    return jsonify({"status": bool(ok), "message": "AP stopped" if ok else "No active hotspot"})
