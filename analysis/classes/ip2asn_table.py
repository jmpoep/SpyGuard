#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Local IPv4 → ASN lookup using iptoasn.com TSV (no external API per IP)."""

from __future__ import annotations

import gzip
import ipaddress
import os
from array import array
from bisect import bisect_right
from typing import Optional

# Same source as https://iptoasn.com/ — tab-separated: range_start range_end AS_number country_code AS_description
IP2ASN_V4_GZ_URL = "https://iptoasn.com/data/ip2asn-v4.tsv.gz"
IP2ASN_V4_GZ_PATH = "/usr/share/spyguard/assets/ip2asn-v4.tsv.gz"


class Ip2AsnV4Table:
    """Immutable IPv4 routing table: sorted range starts, bisect lookup O(log n)."""

    __slots__ = ("_starts", "_ends", "_asns", "_orgs", "n")

    def __init__(
        self,
        starts: array,
        ends: array,
        asns: array,
        orgs: list[str],
    ) -> None:
        self._starts = starts
        self._ends = ends
        self._asns = asns
        self._orgs = orgs
        self.n = len(starts)

    @classmethod
    def load(cls, path: str) -> Optional[Ip2AsnV4Table]:
        if not path or not os.path.isfile(path):
            return None
        try:
            return cls._parse_gz(path)
        except Exception:
            return None

    @classmethod
    def _parse_gz(cls, path: str) -> Ip2AsnV4Table:
        starts_list: list[int] = []
        ends_list: list[int] = []
        asns_list: list[int] = []
        orgs_list: list[str] = []
        v4 = ipaddress.IPv4Address
        with gzip.open(path, "rt", encoding="utf-8", errors="replace", newline="") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split("\t", 4)
                if len(parts) < 5:
                    continue
                try:
                    su = int(v4(parts[0].strip()))
                    eu = int(v4(parts[1].strip()))
                    asn = int(parts[2].strip())
                except (ValueError, ipaddress.AddressValueError):
                    continue
                if su > eu:
                    continue
                org = (parts[4] or "").strip()
                starts_list.append(su)
                ends_list.append(eu)
                asns_list.append(asn)
                orgs_list.append(org)
        n = len(starts_list)
        if n == 0:
            raise ValueError("empty ip2asn table")
        if n > 1:
            bad = False
            for i in range(1, n):
                if starts_list[i] < starts_list[i - 1]:
                    bad = True
                    break
            if bad:
                order = sorted(range(n), key=lambda i: starts_list[i])
                starts_list = [starts_list[i] for i in order]
                ends_list = [ends_list[i] for i in order]
                asns_list = [asns_list[i] for i in order]
                orgs_list = [orgs_list[i] for i in order]
        return cls(
            array("I", starts_list),
            array("I", ends_list),
            array("I", asns_list),
            orgs_list,
        )

    def lookup_u32(self, u: int) -> tuple[Optional[int], str]:
        """Return (asn, org) or (None, '') if unrouted / unknown. ASN <= 0 → (None, org_note)."""
        if u < 0 or u > 0xFFFFFFFF or self.n == 0:
            return (None, "")
        i = bisect_right(self._starts, u) - 1
        if i < 0:
            return (None, "")
        if int(self._ends[i]) < u:
            return (None, "")
        asn = int(self._asns[i])
        org = self._orgs[i] or ""
        if asn <= 0:
            return (None, org)
        return (asn, org)

    def lookup_ip_string(self, ip: str) -> tuple[Optional[int], str]:
        try:
            a = ipaddress.ip_address((ip or "").strip())
        except ValueError:
            return (None, "")
        if a.version != 4:
            return (None, "")
        return self.lookup_u32(int(a))


_MODULE_TABLE: Optional[Ip2AsnV4Table] = None
_MODULE_PATH_MT: Optional[tuple[str, float]] = None


def load_ip2asn_v4_table(path: str = IP2ASN_V4_GZ_PATH) -> Optional[Ip2AsnV4Table]:
    """Load table once per process; reload if file path or mtime changes."""
    global _MODULE_TABLE, _MODULE_PATH_MT
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        _MODULE_TABLE = None
        _MODULE_PATH_MT = None
        return None
    key = (path, mtime)
    if _MODULE_TABLE is not None and _MODULE_PATH_MT == key:
        return _MODULE_TABLE
    t = Ip2AsnV4Table.load(path)
    if t is None:
        _MODULE_TABLE = None
        _MODULE_PATH_MT = None
        return None
    _MODULE_TABLE = t
    _MODULE_PATH_MT = key
    return t
