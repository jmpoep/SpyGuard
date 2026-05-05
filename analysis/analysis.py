#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from classes.engine import Engine
from classes.report import Report
import sys
import json
import os
import traceback
import sys as _sys
_sys.path.insert(0, "/usr/share/spyguard/server/frontend")
from app.spyguard_logging import get_logger

"""
    This file is called by the frontend to do the analysis.
"""

log = get_logger()

def analyze(capture_folder):
    """This method analyse a pcap. It:
        1. Launches the detection engine which uses suricata;
        2. Save the results inside the "assets" subfolder of the capture folder;
        3. Generates the PDF report and save it in the capture folder. 

    Args:
        capture_folder (str): The capture folder (eg. /tmp/45FB392D/)
    """
    if os.path.isdir(capture_folder):

        alerts = {}
        log.info("analysis.py start folder=%s", capture_folder)
        
        # Create the assets folder.
        if not os.path.isdir(os.path.join(capture_folder, "assets")):
            try:
                os.mkdir(os.path.join(capture_folder, "assets"))
                log.info("analysis.py assets dir created folder=%s", os.path.join(capture_folder, "assets"))
            except Exception:
                log.exception("analysis.py assets dir create failed")
        
        try:
            # Starts the engine and get alerts
            engine = Engine(capture_folder)
            engine.start_engine()
            alerts = engine.get_alerts()
            analysis_duration = (engine.analysis_end-engine.analysis_start).seconds
            log.info("analysis.py engine done duration_s=%s alerts=%s errors=%s", analysis_duration, len(alerts or []), len(getattr(engine, "errors", []) or []))
        except Exception:
            log.exception("analysis.py engine failed")
            # When run manually, ensure the error is visible on stderr.
            traceback.print_exc()
            # Best-effort: persist an errors.json so the UI can surface it.
            try:
                assets = os.path.join(capture_folder, "assets")
                os.makedirs(assets, exist_ok=True)
                with open(os.path.join(assets, "errors.json"), "w") as f:
                    f.write(json.dumps(["analysis engine failed (see logs)"], indent=4, separators=(',', ': ')))
            except Exception:
                pass
            raise
        
        # alerts.json writing.
        try:
            with open(os.path.join(capture_folder, "assets/alerts.json"), "w") as f:
                report = {"high": [], "moderate": [], "low": []}
                for alert in alerts:
                    level_raw = alert.get("level", "")
                    level_norm = str(level_raw).strip().lower()
                    bucket_by_level = {
                        "high": "high",
                        "moderate": "moderate",
                        "low": "low",
                    }
                    bucket = bucket_by_level.get(level_norm)
                    if bucket:
                        report[bucket].append(alert)
                f.write(json.dumps(report, indent=4, separators=(',', ': ')))
            log.info("analysis.py wrote alerts.json")
        except Exception:
            log.exception("analysis.py failed writing alerts.json")

        # records.json writing.
        try:
            with open(os.path.join(capture_folder, "assets/records.json"), "w") as f:
                f.write(json.dumps(engine.records, indent=4, separators=(',', ': ')))
            log.info("analysis.py wrote records.json records=%s", len(getattr(engine, "records", []) or []))
        except Exception:
            log.exception("analysis.py failed writing records.json")

        # detection_methods.json writing.
        try:
            with open(os.path.join(capture_folder, "assets/detection_methods.json"), "w") as f:
                f.write(json.dumps(engine.detection_methods, indent=4, separators=(',', ': ')))
            log.info("analysis.py wrote detection_methods.json")
        except Exception:
            log.exception("analysis.py failed writing detection_methods.json")

        # errors.json writing.
        try:
            with open(os.path.join(capture_folder, "assets/errors.json"), "w") as f:
                f.write(json.dumps(engine.errors, indent=4, separators=(',', ': ')))
            log.info("analysis.py wrote errors.json")
        except Exception:
            log.exception("analysis.py failed writing errors.json")

        # analysis_meta.json writing (health of external services, effectiveness estimate)
        try:
            meta = engine.get_analysis_health() if hasattr(engine, "get_analysis_health") else {}
            with open(os.path.join(capture_folder, "assets/analysis_meta.json"), "w") as f:
                f.write(json.dumps(meta, indent=4, separators=(',', ': ')))
            log.info("analysis.py wrote analysis_meta.json")
        except Exception:
            log.exception("analysis.py failed writing analysis_meta.json")

        # Generate the PDF report
        try:
            report = Report(capture_folder, analysis_duration)
            report.generate_report()
            log.info("analysis.py report generated")
        except Exception:
            log.exception("analysis.py report generation failed")

    else:
        log.warning("analysis.py folder does not exist folder=%s", capture_folder)

def usage():
    """Shows the usage output."""
    print(""" Usage: python analysis.py [capture_folder] where [capture_folder] is a folder containing a capture.pcap file """)

if __name__ == "__main__":
    if len(sys.argv) == 2:
        try:
            analyze(sys.argv[1])
        except Exception:
            sys.exit(1)
    else:
        usage()



