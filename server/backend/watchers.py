#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Parse watchers from config and pull IOCs / whitelist / MISP; refresh Umbrella top-1M."""

from app.utils import get_watchers
from app.classes.iocs import IOCs
from app.classes.whitelist import WhiteList
from app.classes.misp import MISP

import io
import json
import os
import requests
import urllib3
import zipfile
import time
from datetime import datetime, timezone
from multiprocessing import Process


UMBRELLA_TOP1M_ZIP_URL = "https://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip"
UMBRELLA_JSON_PATH = "/usr/share/spyguard/assets/umbrella-top-1m.json"

IP2ASN_V4_TSV_GZ_URL = "https://iptoasn.com/data/ip2asn-v4.tsv.gz"
IP2ASN_V4_TSV_GZ_PATH = "/usr/share/spyguard/assets/ip2asn-v4.tsv.gz"


def download_umbrella_top1m_json():
    """Fetch Cisco Umbrella Top 1M (CSV in zip), write domains as JSON for analysis."""
    r = requests.get(UMBRELLA_TOP1M_ZIP_URL, timeout=180)
    r.raise_for_status()
    zf = zipfile.ZipFile(io.BytesIO(r.content))
    csv_names = [n for n in zf.namelist() if n.lower().endswith(".csv")]
    if not csv_names:
        raise ValueError("No CSV found in Umbrella zip")
    domains = []
    with zf.open(csv_names[0]) as raw:
        for i, line in enumerate(raw):
            if i >= 1_000_000:
                break
            try:
                s = line.decode("utf-8", errors="replace").strip()
            except Exception:
                continue
            if not s or "," not in s:
                continue
            _, dom = s.split(",", 1)
            dom = dom.strip().lower().rstrip(".")
            if dom:
                domains.append(dom)
    payload = {
        "source": UMBRELLA_TOP1M_ZIP_URL,
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "format": "rank,domain",
        "count": len(domains),
        "domains": domains,
    }
    os.makedirs(os.path.dirname(UMBRELLA_JSON_PATH), exist_ok=True)
    with open(UMBRELLA_JSON_PATH, "w", encoding="utf-8") as out:
        json.dump(payload, out, ensure_ascii=False)


def download_ip2asn_v4_tsv_gz():
    """Fetch ip2asn IPv4 TSV (gzip) for offline ASN lookups during analysis."""
    r = requests.get(IP2ASN_V4_TSV_GZ_URL, timeout=600, stream=True)
    r.raise_for_status()
    os.makedirs(os.path.dirname(IP2ASN_V4_TSV_GZ_PATH), exist_ok=True)
    tmp = IP2ASN_V4_TSV_GZ_PATH + ".part"
    with open(tmp, "wb") as out:
        for chunk in r.iter_content(chunk_size=1024 * 1024):
            if chunk:
                out.write(chunk)
    os.replace(tmp, IP2ASN_V4_TSV_GZ_PATH)


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def watch_iocs():
    """
        Retrieve IOCs from the remote URLs defined in config/watchers.
        For each IOC, add it to the DB.
    """

    watchers = [{"url": w["url"], "status": False} for w in get_watchers("iocs")]

    while True:
        for w in watchers:
            if w["status"] == False:
                iocs = IOCs()
                iocs_list = []
                to_delete = []
                try:
                    res = requests.get(w["url"], verify=False)
                    if res.status_code == 200:
                        content = json.loads(res.content)
                        iocs_list = content["iocs"] if "iocs" in content else []
                        to_delete = content["to_delete"] if "to_delete" in content else []
                    else:
                        w["status"] = False
                except:
                    w["status"] = False

                for ioc in iocs_list:
                    try:
                        iocs.add(ioc["type"], ioc["tag"],
                                 ioc["tlp"], ioc["value"], "watcher")
                        w["status"] = True
                    except:
                        continue

                for ioc in to_delete:
                    try:
                        iocs.delete_by_value(ioc["value"])
                        w["status"] = True
                    except:
                        continue

        # If at least one URL haven't be parsed, let's retry in 1min.
        if False in [w["status"] for w in watchers]:
            time.sleep(60)
        else:
            break


def watch_whitelists():
    """
        Retrieve whitelist elements from the remote URLs
        defined in config/watchers. For each (new ?) element,
        add it to the DB.
    """

    watchers = [{"url": w["url"], "status": False} for w in get_watchers("whitelist")]

    while True:
        for w in watchers:
            if w["status"] == False:
                whitelist = WhiteList()
                elements = []
                to_delete = []
                try:
                    res = requests.get(w["url"], verify=False)
                    if res.status_code == 200:
                        content = json.loads(res.content)
                        elements = content["elements"] if "elements" in content else []
                        to_delete = content["to_delete"] if "to_delete" in content else []
                    else:
                        w["status"] = False
                except:
                    w["status"] = False

                for elem in elements:
                    try:
                        whitelist.add(elem["type"], elem["element"], "watcher")
                        w["status"] = True
                    except:
                        continue

                for elem in to_delete:
                    try:
                        whitelist.delete_by_value(elem["element"])
                        w["status"] = True
                    except:
                        continue

        if False in [w["status"] for w in watchers]:
            time.sleep(60)
        else:
            break


def watch_misp():
    """
        Retrieve IOCs from misp instances. Each new element is
        tested and then added to the database.
    """
    iocs, misp = IOCs(), MISP()
    instances = [i for i in misp.get_instances()]

    while instances:
        for i, ist in enumerate(instances):
            status = misp.test_instance(ist["url"],
                                        ist["apikey"],
                                        ist["verifycert"])
            if status:
                for ioc in misp.get_iocs(ist["id"]):
                    iocs.add(ioc["type"], ioc["tag"], ioc["tlp"],
                             ioc["value"], "misp-{}".format(ist["id"]))
                misp.update_sync(ist["id"])
                instances.pop(i)
        if instances: time.sleep(60)


try:
    download_umbrella_top1m_json()
except Exception as exc:
    print("[watchers] Cisco Umbrella top-1m download failed: {}".format(exc))

try:
    download_ip2asn_v4_tsv_gz()
except Exception as exc:
    print("[watchers] ip2asn-v4.tsv.gz download failed: {}".format(exc))

p1 = Process(target=watch_iocs)
p2 = Process(target=watch_whitelists)
p3 = Process(target=watch_misp)

p1.start()
p2.start()
p3.start()
