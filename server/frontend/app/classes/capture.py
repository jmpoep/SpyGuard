#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import subprocess as sp
from app.utils import stop_monitoring, read_config, get_iocs, get_device_uuid
from app.classes.network import Network

from os import mkdir, path, chmod
import sys
import re
import json
import random

from app.spyguard_logging import get_logger, reset_log

class Capture(object):

    def __init__(self):
        self.random_choice_alphabet = "ABCDEF1234567890"
        self.rules_file = "/tmp/rules"
        self.log = get_logger()
        self.generate_rule_file()
        
    def start_capture(self) -> dict:
        """Start a dumpcap capture on the created AP interface and save
        the generated pcap in a temporary directory under /tmp/.

        Returns:
            dict: Capture token and operation status. 
        """
        # New session: truncate debug log.
        reset_log()

        # Few context variable assignment
        self.capture_token = "".join([random.choice(self.random_choice_alphabet) for i in range(8)])
        self.capture_dir = "/tmp/{}/".format(self.capture_token)
        self.assets_dir = "/tmp/{}/assets/".format(self.capture_token)
        self.iface = read_config(("network", "in"))
        self.pcap = self.capture_dir + "capture.pcap"
        self.rules_file = "/tmp/rules"
        self.log.info("capture start requested token=%s iface_in=%s dir=%s", self.capture_token, self.iface, self.capture_dir)

        # For packets monitoring
        self.list_pkts = []
        self.last_pkts = 0

        try:
            # Make the capture and the assets directory
            mkdir(self.capture_dir)
            chmod(self.capture_dir, 0o777)
            mkdir(self.assets_dir)
            chmod(self.assets_dir, 0o777)
            self.log.info("capture dirs created capture_dir=%s assets_dir=%s", self.capture_dir, self.assets_dir)

            # Kill possible potential process
            stop_monitoring()

            # Writing the instance UUID for reporting.
            with open("/tmp/{}/assets/instance.json".format(self.capture_token), "w") as f:
                f.write(json.dumps({ "instance_uuid" : get_device_uuid().strip() }))
            self.log.info("instance.json written token=%s", self.capture_token)

            sp.Popen(["dumpcap",  "-n", "-i", self.iface, "-w", self.pcap])
            sp.Popen(["suricata", "-c", "/etc/suricata/suricata.yaml", "-i", self.iface, "-l", self.assets_dir, "-S", self.rules_file])
            self.log.info("capture processes started token=%s pcap=%s", self.capture_token, self.pcap)
            return { "status": True,
                     "message": "Capture started",
                     "capture_token": self.capture_token }
        except Exception:
            self.log.exception("capture start failed token=%s", self.capture_token)
            return { "status": False,
                     "message": f"Unexpected error: {sys.exc_info()[0]}"}

    def get_capture_stats(self) -> dict:
        """ Get some dirty capture statistics in order to have a sparkline 
            in the background of capture view.

        Returns:
            dict: dict containing stats associated to the capture
        """
        with open("/sys/class/net/{}/statistics/tx_packets".format(self.iface)) as f:
            tx_pkts = int(f.read())
        with open("/sys/class/net/{}/statistics/rx_packets".format(self.iface)) as f:
            rx_pkts = int(f.read())

        if self.last_pkts == 0:
            self.last_pkts = tx_pkts + rx_pkts
            return {"status": True,
                    # Return a stable series immediately to avoid an initial “max bar” artifact.
                    "packets": [0] * 400}
        else:
            curr_pkts = (tx_pkts + rx_pkts) - self.last_pkts
            self.last_pkts = tx_pkts + rx_pkts
            self.list_pkts.append(curr_pkts)
            return {"status": True,
                    "packets": self.beautify_stats(self.list_pkts)}

    @staticmethod
    def beautify_stats(data) -> list:
        """Add 0 at the end of the array if the len of the array is less 
           than max_len. Else, get the last 100 stats. This allows to 
           show a kind of "progressive chart" in the background for 
           the first packets.

        Args:
            data (list): list of integers

        Returns:
            list: list of integers
        """
        max_len = 400
        if len(data) >= max_len:
            return data[-max_len:]
        else:
            # Pad with zeros so the sparkline starts flat.
            return data + [0] * (max_len - len(data))

    def stop_capture(self) -> dict:
        """Stop dumpcap & suricata if any instance present & ask create_capinfos.

        Returns:
            dict: operation status
        """
        network = Network()

        # We stop the monitoring and the associated hotspot. 
        if stop_monitoring(): 
            if network.delete_hotspot():
                self.create_capinfos()
                self.log.info("capture stopped token=%s", getattr(self, "capture_token", None))
                return {"status": True,
                        "message": "Capture stopped"}
            else:
                self.log.warning("capture stop requested but no active hotspot token=%s", getattr(self, "capture_token", None))
                return {"status": False,
                        "message": "No active hotspot"}     
        else:
            self.log.warning("capture stop requested but no active capture token=%s", getattr(self, "capture_token", None))
            return {"status": False,
                    "message": "No active capture"}


    def create_capinfos(self) -> bool:
        """Creates a capinfo json file.

        Returns:
            bool: True if everything worked well.
        """
        self.pcap = self.capture_dir + "capture.pcap"
        infos = sp.Popen(["capinfos", self.pcap], stdout=sp.PIPE, stderr=sp.PIPE)
        infos = infos.communicate()[0]
        data = {}
        for l in infos.decode().splitlines():
            try:
                l = l.split(": ") if ": " in l else l.split("= ")
                if len(l[0]) and len(l[1]):
                    data[l[0].strip()] = l[1].strip()
            except:
                continue

        try:
            with open("{}capinfos.json".format(self.assets_dir), 'w') as f:
                json.dump(data, f)
            self.log.info("capinfos.json written token=%s", getattr(self, "capture_token", None))
            return True
        except Exception:
            self.log.exception("capinfos.json write failed token=%s", getattr(self, "capture_token", None))
            return False

    def generate_rule_file(self) -> bool:
        """Generate a suricata rules files.

        Returns:
            bool: operation status.
        """
        sid = 1000000
        rules = []
        
        for rule in get_iocs("snort"):
            sid = sid + 1
            rule = re.sub("sid:[0-9a-zA-Z]+", f"sid:{sid}", rule[0] )
            rules.append(rule)

        try:
            with open(self.rules_file, "w+") as f:
                f.write("\n".join(rules))
            self.log.info("suricata rules file generated path=%s rules=%s", self.rules_file, len(rules))
            return True
        except Exception:
            self.log.exception("suricata rules file generation failed path=%s", self.rules_file)
            return False

