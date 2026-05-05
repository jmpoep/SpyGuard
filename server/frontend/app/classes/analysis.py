#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import subprocess as sp
import json
import sys
import re
import os

from app.spyguard_logging import get_logger


class Analysis(object):

    def __init__(self, token):
        self.token = token if re.match(r"[A-F0-9]{8}", token) else None
        self.log = get_logger()

    def start(self) -> dict:
        """Start the analysis of the captured communication by lauching
        analysis.py with the capture token as a paramater.

        Returns:
            dict: operation status
        """

        if self.token is not None:
            parent = "/".join(sys.path[0].split("/")[:-2])
            cmd = [sys.executable, "{}/analysis/analysis.py".format(parent), "/tmp/{}".format(self.token)]
            self.log.info("analysis start token=%s cmd=%s", self.token, cmd)
            try:
                sp.Popen(cmd)
            except Exception:
                self.log.exception("analysis start failed token=%s", self.token)
                return {"status": False, "message": "Analysis failed to start", "token": self.token}
            return {"status": True,
                    "message": "Analysis started",
                    "token": self.token}
        else:
            self.log.warning("analysis start with bad token=%s", token)
            return {"status": False,
                    "message": "Bad token provided",
                    "token": "null"}

    def get_report(self) -> dict:
        """Generate a small json report of the analysis
        containing the alerts and the device properties.

        Returns:
            dict: alerts, pcap and device info.
        """

        device, alerts, pcap = {}, {}, {}
        methods = {}
        records = []

        # Getting device configuration.
        if os.path.isfile("/tmp/{}/assets/device.json".format(self.token)):
            with open("/tmp/{}/assets/device.json".format(self.token), "r") as f:
                device = json.load(f)

        # Getting pcap infos.
        if os.path.isfile("/tmp/{}/assets/capinfos.json".format(self.token)):
            with open("/tmp/{}/assets/capinfos.json".format(self.token), "r") as f:
                pcap = json.load(f)

        # Getting alerts configuration.
        if os.path.isfile("/tmp/{}/assets/alerts.json".format(self.token)):
            with open("/tmp/{}/assets/alerts.json".format(self.token), "r") as f:
                alerts = json.load(f)

        # Getting detection methods.
        if os.path.isfile("/tmp/{}/assets/detection_methods.json".format(self.token)):
            with open("/tmp/{}/assets/detection_methods.json".format(self.token), "r") as f:
                methods = json.load(f)

        # Getting records.
        if os.path.isfile("/tmp/{}/assets/records.json".format(self.token)):
            with open("/tmp/{}/assets/records.json".format(self.token), "r") as f:
                records = json.load(f)

        analysis_meta = {}
        if os.path.isfile("/tmp/{}/assets/analysis_meta.json".format(self.token)):
            with open("/tmp/{}/assets/analysis_meta.json".format(self.token), "r") as f:
                analysis_meta = json.load(f)

        if device != {} and alerts != {}:
            self.log.info("analysis report ready token=%s alerts=%s records=%s", self.token, {k: len(v) for k, v in (alerts or {}).items() if isinstance(v, list)}, len(records or []))
            return {"alerts": alerts,
                    "device": device,
                    "methods": methods,
                    "pcap": pcap, 
                    "records": records,
                    "analysis_meta": analysis_meta}
        else:
            return {"message": "No report yet"}
