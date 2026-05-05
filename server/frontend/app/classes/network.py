#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import subprocess as sp
import netifaces as ni
import requests
import re
import qrcode
import base64
import random
import requests
from app.utils import read_config

from io import BytesIO
from app.spyguard_logging import get_logger


class Network(object):

    def __init__(self):
        self.log = get_logger()
        self.AP_SSID = False
        self.AP_PASS = False
        # Avoid crashing the whole service if config.yaml is empty/missing.
        # Missing iface values will make some actions fail gracefully, but the UI/API can still start.
        self.iface_out = read_config(("network", "out"), "") or ""
        self.iface_in = read_config(("network", "in"), "") or ""
        self.random_choice_alphabet = "abcdef1234567890"


    def check_status(self) -> dict:
        """The method check_status check the IP addressing of the connected interface
        and return its associated IP.

        Returns:
            dict: contains the network context.
        """

        ctx = { "internet": self.check_internet() }

        for iface in ni.interfaces():
            if iface != self.iface_in and iface.startswith(("wl", "en", "et", "ww")):
                addrs = ni.ifaddresses(iface)
                try:
                    ctx["ip_out"] = addrs[ni.AF_INET][0]["addr"]
                except:
                    ctx["ip_out"] = "Not connected"
        return ctx


    def wifi_list_networks(self) -> dict:
        """List the available wifi networks by using nmcli

        Returns:
            dict: list of available networks.
        """

        networks = []
        if self.iface_out.startswith("wl"):
            self.log.info("wifi_list_networks iface_out=%s", self.iface_out)
            sh = sp.Popen(["nmcli", "-f", "SSID,SIGNAL", "dev", "wifi", "list", "ifname", self.iface_out], stdout=sp.PIPE, stderr=sp.PIPE)
            sh = sh.communicate()
        
            for network in [n.decode("utf8") for n in sh[0].splitlines()][1:]:
                name = network.strip()[:-3].strip()
                signal = network.strip()[-3:].strip()
                if name not in [n["name"] for n in networks] and name != "--":
                    networks.append({"name" : name, "signal" : int(signal) })
        return { "networks": networks }
 

    def wifi_setup(self, ssid, password) -> dict:
        """Connect to a WiFi network by using nmcli

        Args:
            ssid (str): Network SSID
            password (str): Network password

        Returns:
            dict: operation status
        """

        if len(password) >= 8 and len(ssid):
            self.log.info("wifi_setup connect requested ssid=%s iface_out=%s", ssid, self.iface_out)
            sh = sp.Popen(["nmcli", "dev", "wifi", "connect", ssid, "password", password, "ifname", self.iface_out], stdout=sp.PIPE, stderr=sp.PIPE)
            sh = sh.communicate()

            if re.match(".*[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}.*", sh[0].decode('utf8')):
                self.log.info("wifi_setup connected ssid=%s", ssid)
                return {"status": True,
                        "message": "Wifi connected"}
            else:
                self.log.warning("wifi_setup failed ssid=%s stdout=%s stderr=%s", ssid, sh[0].decode("utf8", errors="ignore"), sh[1].decode("utf8", errors="ignore"))
                return {"status": False,
                        "message": "Wifi not connected"}
        else:
            self.log.warning("wifi_setup invalid inputs ssid_len=%s pass_len=%s", len(ssid or ""), len(password or ""))
            return {"status": False,
                    "message": "Empty SSID or/and password length less than 8 chars."}

    def start_hotspot(self) -> dict:
        """Generates an Access Point by using nmcli and provide to 
        the GUI the associated ssid, password and qrcode.

        Returns:
            dict: hostpost description
        """

        self.log.info("ap start requested iface_in=%s", self.iface_in)
        self.delete_hotspot()
        
        try:
            if read_config(("network", "tokenized_ssids")):
                token = "".join([random.choice(self.random_choice_alphabet) for i in range(4)])
                self.AP_SSID = random.choice(read_config(("network", "ssids"))) + "-" + token
            else:
                self.AP_SSID = random.choice(read_config(("network", "ssids")))
        except Exception:
            self.log.exception("ap ssid selection failed, using fallback")
            token = "".join([random.choice(self.random_choice_alphabet) for i in range(4)])
            self.AP_SSID = "wifi-" + token

        self.AP_PASS = "".join([random.choice(self.random_choice_alphabet) for i in range(8)])
        self.log.info("ap config ssid=%s", self.AP_SSID)

        try:
            sp.Popen(["nmcli", "con", "add", "type", "wifi", "ifname", self.iface_in, "con-name", self.AP_SSID, "autoconnect", "yes", "ssid", self.AP_SSID]).wait()
            sp.Popen(["nmcli", "con", "modify", self.AP_SSID, "802-11-wireless.mode", "ap", "802-11-wireless.band", "bg", "ipv4.method", "shared"]).wait()
            sp.Popen(["nmcli", "con", "modify", self.AP_SSID, "wifi-sec.key-mgmt", "wpa-psk", "wifi-sec.psk", self.AP_PASS]).wait()
        except Exception:
            self.log.exception("ap nmcli configuration failed ssid=%s iface_in=%s", self.AP_SSID, self.iface_in)
            return {"status": False, "message": "Error while creating AP."}

        if self.launch_hotstop():
            self.log.info("ap started ssid=%s", self.AP_SSID)
            return {"status": True,
                    "message": "AP started",
                    "ssid": self.AP_SSID,
                    "password": self.AP_PASS,
                    "qrcode": self.generate_qr_code()}
        else:
            self.log.warning("ap launch failed ssid=%s", self.AP_SSID)
            return {"status": False,
                    "message": "Error while creating AP."}

    def generate_qr_code(self) -> str:
        """Returns a QRCode based on the SSID and the password.

        Returns:
            str: String representing the QRcode as data scheme.
        """
        qrc = qrcode.make("WIFI:S:{};T:WPA;P:{};;".format(self.AP_SSID, self.AP_PASS))
        buffered = BytesIO()
        qrc.save(buffered, format="PNG")
        return "data:image/png;base64,{}".format(base64.b64encode(buffered.getvalue()).decode("utf8"))

    def launch_hotstop(self) -> bool:
        """This method enables the hotspot by asking nmcli to activate it, 
        then the result is checked against a regex in order to know if everything is good.

        Returns:
            bool: true if hotspot created.
        """
        sh = sp.Popen(["nmcli", "con", "up", self.AP_SSID], stdout=sp.PIPE, stderr=sp.PIPE)
        sh = sh.communicate()
        ok = re.match(".*/ActiveConnection/[0-9]+.*", sh[0].decode("utf8", errors="ignore"))
        if not ok:
            self.log.warning("ap nmcli up failed ssid=%s stdout=%s stderr=%s", self.AP_SSID, sh[0].decode("utf8", errors="ignore"), sh[1].decode("utf8", errors="ignore"))
        return ok

    def check_internet(self) -> bool:
        """Check the internet link just with a small http request
        to an URL present in the configuration

        Returns:
            bool: True if everything works.
        """
        url = read_config(("network", "internet_check"))
        try:
            requests.get(url, timeout=10)
            return True
        except requests.RequestException as exc:
            # Network failures are expected when offline; don't spam stacktraces.
            self.log.warning("internet check failed url=%s error=%s", url, str(exc))
            return False
        except Exception:
            self.log.exception("internet check failed url=%s", url)
            return False

    def delete_hotspot(self) -> bool:
        """
            Delete the previously created hotspot. 
        """
        # Use terse output to reliably match the connection bound to iface_in.
        # We delete *all* matching connections (best-effort) and return True if
        # at least one deletion succeeded.
        try:
            sh = sp.Popen(
                ["nmcli", "-t", "-f", "NAME,DEVICE", "con", "show"],
                stdout=sp.PIPE,
                stderr=sp.PIPE,
            )
            out, _err = sh.communicate()
        except Exception:
            self.log.exception("ap delete: nmcli con show failed")
            return False

        deleted_any = False
        for raw in out.splitlines():
            try:
                line = raw.decode("utf8", errors="ignore").strip()
                if not line:
                    continue
                # Format: NAME:DEVICE
                parts = line.split(":", 1)
                if len(parts) != 2:
                    continue
                name, dev = parts[0].strip(), parts[1].strip()
                if dev != self.iface_in:
                    continue

                # Delete the connection profile by name.
                sh_del = sp.Popen(
                    ["nmcli", "con", "delete", name],
                    stdout=sp.PIPE,
                    stderr=sp.PIPE,
                )
                del_out, _del_err = sh_del.communicate()
                # nmcli prints a UUID when deletion succeeds.
                if re.search(r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}", del_out.decode("utf8", errors="ignore")):
                    deleted_any = True
            except Exception:
                self.log.exception("ap delete loop failed")
                continue

        if deleted_any:
            self.log.info("ap deleted on iface_in=%s", self.iface_in)
        return deleted_any