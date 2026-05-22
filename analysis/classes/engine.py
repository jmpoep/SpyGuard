#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import json
import os
import re
import subprocess as sp
import sys
import time
from datetime import datetime
from ipaddress import IPv4Address, IPv6Address, IPv6Network, ip_address
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Iterator, Optional, cast

import ssl
import socket
import OpenSSL
import requests
import ipaddress

import pydig
import whois
from publicsuffix2 import get_sld
from netaddr import IPAddress, IPNetwork
from classes.jarm import get_jarm
from classes.ip2asn_table import load_ip2asn_v4_table
from utils import get_config, get_iocs, get_whitelist

UMBRELLA_JSON_PATH = "/usr/share/spyguard/assets/umbrella-top-1m.json"
UMBRELLA_TOP500K = 500_000
IPTHC_LOOKUP_URL = "https://ip.thc.org/api/v1/lookup"
WHOIS_RECENT_REGISTRATION_MAX_DAYS = 548


def _whitelist_asn_elements_to_int_set(elements: list[str]) -> set[int]:
    """ASN whitelist entries are stored as digit strings (see WhiteList.add)."""
    out: set[int] = set()
    for x in elements or []:
        s = str(x).strip()
        if not s.isdigit():
            continue
        try:
            n = int(s)
        except ValueError:
            continue
        if n >= 0:
            out.add(n)
    return out


def _iter_domain_suffixes(name: str) -> Iterator[str]:
    """Yield name and its parent suffixes, normalized.

    Example: a.b.example.com -> a.b.example.com, b.example.com, example.com, com
    """
    if not name:
        return
    n = name.strip().strip(".").lower()
    if not n:
        return
    parts = [p for p in n.split(".") if p]
    for i in range(len(parts)):
        yield ".".join(parts[i:])


def _normalize_dn(dn: str) -> str:
    """Normalize a DN string for stable matching."""
    if not dn:
        return ""
    dn = dn.strip().strip(".")
    if not dn:
        return ""
    parts: list[str] = []
    for raw in dn.split(","):
        raw = raw.strip()
        if not raw:
            continue
        if "=" in raw:
            k, v = raw.split("=", 1)
            k = k.strip().lower()
            v = v.strip().lower()
            parts.append(f"{k}={v}")
        else:
            parts.append(raw.strip().lower())
    parts.sort()
    return ",".join(parts)


@dataclass(frozen=True)
class EngineConfig:
    heuristics_analysis: bool
    iocs_analysis: bool
    whitelist_analysis: bool
    active_analysis: bool
    userlang: str
    max_ports: int
    http_default_ports: list[int]
    tls_default_ports: list[int]
    indicators_types: list[str]

    @classmethod
    def load(cls, get_cfg: Callable[[tuple[str, str]], Any]) -> "EngineConfig":
        def _as_int_list(value: Any) -> list[int]:
            if value is None:
                return []
            if isinstance(value, list):
                out: list[int] = []
                for v in value:
                    try:
                        out.append(int(v))
                    except (TypeError, ValueError):
                        continue
                return out
            return []

        heuristics = bool(get_cfg(("analysis", "heuristics")))
        iocs = bool(get_cfg(("analysis", "iocs")))
        whitelist = bool(get_cfg(("analysis", "whitelist")))
        active = bool(get_cfg(("analysis", "active")))
        userlang = str(get_cfg(("frontend", "user_lang")) or "en")
        max_ports_raw = get_cfg(("analysis", "max_ports"))
        try:
            max_ports = int(max_ports_raw)
        except (TypeError, ValueError):
            max_ports = 1024

        http_default_ports = _as_int_list(get_cfg(("analysis", "http_default_ports")))
        tls_default_ports = _as_int_list(get_cfg(("analysis", "tls_default_ports")))
        indicators_types_raw = get_cfg(("analysis", "indicators_types")) or []
        indicators_types = [str(x) for x in indicators_types_raw] if isinstance(indicators_types_raw, list) else []

        return cls(
            heuristics_analysis=heuristics,
            iocs_analysis=iocs,
            whitelist_analysis=whitelist,
            active_analysis=active,
            userlang=userlang,
            max_ports=max_ports,
            http_default_ports=http_default_ports,
            tls_default_ports=tls_default_ports,
            indicators_types=indicators_types,
        )


class WhitelistIndex:
    def __init__(self, cidrs: list[IPNetwork], hosts: list[str], domains: list[str]) -> None:
        self.cidrs = cidrs
        self.hosts = hosts
        self.domains = domains
        self._hosts_set = set(hosts or [])
        self._domains_set = set(d.strip(".").lower() for d in (domains or []) if d)

    def is_domain_whitelisted(self, dnsname: str) -> bool:
        if not dnsname or not self._domains_set:
            return False
        for suffix in _iter_domain_suffixes(dnsname):
            if suffix in self._domains_set:
                return True
        return False

    def mark_record_if_whitelisted(self, record: dict[str, Any], *, ipv6_ula: IPv6Network) -> bool:
        """Mutates record['whitelisted'] exactly like the legacy code."""
        ip_dst = record.get("ip_dst")
        if not isinstance(ip_dst, str) or not ip_dst:
            return False

        # IPv4 checks
        try:
            IPv4Address(ip_dst)
            if IPv4Address("224.0.0.0") <= IPv4Address(ip_dst) <= IPv4Address("239.255.255.255"):
                record["whitelisted"] = True
                return True

            for cidr in self.cidrs:
                if IPAddress(ip_dst) in cidr:
                    record["whitelisted"] = True
                    return True

            if ip_dst in self._hosts_set:
                record["whitelisted"] = True
                return True
        except Exception:
            pass

        # IPv6 checks
        try:
            ip6 = IPv6Address(ip_dst)
            if ip6.is_link_local or ip6.is_multicast or ip6 in ipv6_ula:
                record["whitelisted"] = True
                return True

            for cidr in self.cidrs:
                if IPAddress(ip_dst) in cidr:
                    record["whitelisted"] = True
                    return True

            if ip_dst in self._hosts_set:
                record["whitelisted"] = True
                return True
        except Exception:
            pass

        # Domain suffix checks
        domains = record.get("domains") or []
        if isinstance(domains, list):
            for domain in domains:
                if isinstance(domain, str) and self.is_domain_whitelisted(domain):
                    record["whitelisted"] = True
                    return True
        return False


class IOCIndex:
    """Pre-index IOCs for fast lookups.

    Engine keeps legacy attributes (self.bl_* and self._bl_*_map) sourced from this object.
    """

    def __init__(
        self,
        *,
        bl_cidrs: list[list[Any]],
        bl_hosts: list[list[Any]],
        bl_asns: list[list[Any]],
        tor_nodes: list[str],
        bl_domains: list[list[Any]],
        bl_freedns: list[list[Any]],
        bl_certs: list[list[Any]],
        bl_jarms: list[list[Any]],
        bl_nameservers: list[list[Any]],
        bl_tlds: list[list[Any]],
        bl_issuers: list[list[Any]],
        enabled_indicator_types: set[str],
    ) -> None:
        self.bl_cidrs = bl_cidrs
        self.bl_hosts = bl_hosts
        self.bl_asns = bl_asns
        self.tor_nodes = tor_nodes
        self.bl_domains = bl_domains
        self.bl_freedns = bl_freedns
        self.bl_certs = bl_certs
        self.bl_jarms = bl_jarms
        self.bl_nameservers = bl_nameservers
        self.bl_tlds = bl_tlds
        self.bl_issuers = bl_issuers
        self.enabled_indicator_types = enabled_indicator_types

        self.tor_nodes_set = set(self.tor_nodes or [])

        self.bl_hosts_map: dict[str, str] = {}
        for value, tag in (self.bl_hosts or []):
            self.bl_hosts_map[value] = tag

        self.bl_asns_map: dict[int, str] = {}
        for value, tag in (self.bl_asns or []):
            if value is None:
                continue
            s = str(value).strip()
            if not s:
                continue
            m = re.match(r"^(?:AS|as)?\s*(\d+)$", s)
            if not m:
                continue
            try:
                n = int(m.group(1))
            except Exception:
                continue
            if n > 0:
                self.bl_asns_map[n] = str(tag or "asn")

        def _index_iocs_as_tagmap(items: list[list[Any]] | None) -> dict[str, set[str]]:
            m: dict[str, set[str]] = {}
            for value, tag in (items or []):
                if not value:
                    continue
                key = str(value).strip(".").lower()
                m.setdefault(key, set()).add(str(tag))
            return m

        self.bl_domains_map = _index_iocs_as_tagmap(self.bl_domains)
        self.bl_freedns_map = _index_iocs_as_tagmap(self.bl_freedns)
        self.bl_tlds_map = _index_iocs_as_tagmap(self.bl_tlds)
        self.bl_nameservers_map = _index_iocs_as_tagmap(self.bl_nameservers)

        self.bl_certs_map = {value: tag for value, tag in (self.bl_certs or []) if value}
        self.bl_jarms_map = {value: tag for value, tag in (self.bl_jarms or []) if value}

        self.bl_issuers_map: dict[str, set[str]] = {}
        for value, tag in (self.bl_issuers or []):
            if not value:
                continue
            key = _normalize_dn(str(value))
            self.bl_issuers_map.setdefault(key, set()).add(str(tag))

    def indicator_type_enabled(self, tag: str) -> bool:
        return (tag in self.enabled_indicator_types) or ("all" in self.enabled_indicator_types)


class Engine():

    def __init__(self, capture_directory):

        # Set some vars.
        self.analysis_start = datetime.now()
        self.connected = self.check_internet()
        self.working_dir = capture_directory
        self.assets_dir = f"{capture_directory}/assets/"
        self.rules_file = "/tmp/rules.rules"
        self.pcap_path = os.path.join(self.working_dir, "capture.pcap")
        self.records = []
        self.alerts = []
        self.dns = []
        self.files = []
        self.whitelist = []
        self.uncategorized = []
        self.analysed = []
        self.dns_failed = []
        self.dns_checked = set()
        self.cert_checked = set()
        self.errors = []
        self.analysis_end = None
        self._enabled_indicator_types = None
        self._active_ssl_cache = {}
        self._active_ssl_lock = threading.Lock()
        self._active_ssl_workers = 4
        # Hostname extracted from peer TLS certificate (CN/SAN), keyed by (host_or_ip, port).
        self._tls_cert_hostname_cache: dict[tuple[str, int], Optional[str]] = {}
        # Unique local IPv6 (fc00::/7); used instead of a broken list-comprehension test.
        self._ipv6_ula = IPv6Network("fc00::/7")
        self._umbrella_top500k_set: Optional[set[str]] = None
        self._umbrella_top500k_rank_map: Optional[dict[str, int]] = None
        self._ipthc_cache: dict[str, tuple[Optional[str], int]] = {}
        # Domain enrichment caches (filled via prefetch to avoid sequential network latency).
        self._domain_ns_cache: dict[str, list[str]] = {}
        self._domain_ns_err: dict[str, str] = {}
        self._domain_whois_creation_cache: dict[str, Optional[datetime]] = {}
        self._domain_whois_err: dict[str, str] = {}
        self._domain_enrich_lock = threading.Lock()
        self._enrich_workers = 4

        # Get configuration (centralized/typed)
        self.config = EngineConfig.load(get_config)
        self.heuristics_analysis = self.config.heuristics_analysis
        self.iocs_analysis = self.config.iocs_analysis
        self.whitelist_analysis = self.config.whitelist_analysis
        self.active_analysis = self.config.active_analysis
        self.userlang = self.config.userlang
        self.max_ports = self.config.max_ports
        self.http_default_ports = self.config.http_default_ports
        self.tls_default_ports = self.config.tls_default_ports
        self.indicators_types = self.config.indicators_types

        # Save detection methods used.
        self.detection_methods = {
            "iocs": self.iocs_analysis,
            "heuristics": self.heuristics_analysis,
            "active": self.active_analysis,
        }

        # Pre-index indicator types for fast lookups.
        self._enabled_indicator_types = set(self.indicators_types or [])

        # Retrieve and index IOCs.
        if self.iocs_analysis:
            bl_cidrs = [[IPNetwork(cidr[0]), cidr[1]] for cidr in get_iocs("cidr")]
            bl_hosts = get_iocs("ip4addr") + get_iocs("ip6addr")
            bl_asns = get_iocs("asn")
            tor_nodes = self.get_tor_nodes()
            bl_domains = get_iocs("domain")
            bl_freedns = get_iocs("freedns")
            bl_certs = get_iocs("sha1cert")
            bl_jarms = get_iocs("jarm")
            bl_nameservers = get_iocs("ns")
            bl_tlds = get_iocs("tld")
            bl_issuers = get_iocs("issuerdn")
        else:
            bl_cidrs = []
            bl_hosts = []
            bl_asns = []
            tor_nodes = []
            bl_domains = []
            bl_freedns = []
            bl_certs = []
            bl_jarms = []
            bl_nameservers = []
            bl_tlds = []
            bl_issuers = []

        self.ioc_index = IOCIndex(
            bl_cidrs=bl_cidrs,
            bl_hosts=bl_hosts,
            bl_asns=bl_asns,
            tor_nodes=tor_nodes,
            bl_domains=bl_domains,
            bl_freedns=bl_freedns,
            bl_certs=bl_certs,
            bl_jarms=bl_jarms,
            bl_nameservers=bl_nameservers,
            bl_tlds=bl_tlds,
            bl_issuers=bl_issuers,
            enabled_indicator_types=self._enabled_indicator_types,
        )

        # Keep legacy attributes (minimize churn across the rest of the class).
        self.bl_cidrs = self.ioc_index.bl_cidrs
        self.bl_hosts = self.ioc_index.bl_hosts
        self.bl_asns = self.ioc_index.bl_asns
        self.tor_nodes = self.ioc_index.tor_nodes
        self.bl_domains = self.ioc_index.bl_domains
        self.bl_freedns = self.ioc_index.bl_freedns
        self.bl_certs = self.ioc_index.bl_certs
        self.bl_jarms = self.ioc_index.bl_jarms
        self.bl_nameservers = self.ioc_index.bl_nameservers
        self.bl_tlds = self.ioc_index.bl_tlds
        self.bl_issuers = self.ioc_index.bl_issuers

        self._tor_nodes_set = self.ioc_index.tor_nodes_set
        self._bl_hosts_map = self.ioc_index.bl_hosts_map
        self._bl_asns_map = self.ioc_index.bl_asns_map
        self._bl_domains_map = self.ioc_index.bl_domains_map
        self._bl_freedns_map = self.ioc_index.bl_freedns_map
        self._bl_tlds_map = self.ioc_index.bl_tlds_map
        self._bl_certs_map = self.ioc_index.bl_certs_map
        self._bl_jarms_map = self.ioc_index.bl_jarms_map
        self._bl_nameservers_map = self.ioc_index.bl_nameservers_map
        self._bl_issuers_map = self.ioc_index.bl_issuers_map

        # Retrieve and index whitelist.
        if self.whitelist_analysis:
            wl_cidrs = [IPNetwork(cidr) for cidr in get_whitelist("cidr")]
            wl_hosts = get_whitelist("ip4addr") + get_whitelist("ip6addr") + self.get_public_ip()
            wl_domains = get_whitelist("domain")
            wl_asn_elems = get_whitelist("asn")
        else:
            wl_cidrs = []
            wl_hosts = []
            wl_domains = []
            wl_asn_elems = []

        self.whitelist_index = WhitelistIndex(wl_cidrs, wl_hosts, wl_domains)

        # Keep legacy attributes.
        self.wl_cidrs = self.whitelist_index.cidrs
        self.wl_hosts = self.whitelist_index.hosts
        self.wl_domains = self.whitelist_index.domains
        self._wl_hosts_set = set(self.wl_hosts)
        self._wl_domains_set = set(d.strip(".").lower() for d in (self.wl_domains or []) if d)
        # AS whitelist: checked last in check_whitelist (local ip2asn DB) when IP/CIDR/domain do not match.
        self._wl_asns_int = _whitelist_asn_elements_to_int_set(wl_asn_elems)

        # Load template language
        if not re.match("^[a-z]{2,3}$", self.userlang):
            self.userlang = "en"
        with open(os.path.join(os.path.dirname(os.path.realpath(sys.argv[0])), "locales/{}.json".format(self.userlang))) as f:
            self.template = json.load(f)["alerts"]

        # Health report for external services (shown in UI).
        self.analysis_health = {
            "internet": bool(self.connected),
            "checks": {},  # name -> {attempted:int, ok:int, fail:int, last_error:str}
        }

        self._asn_ip_cache: dict[str, tuple[Optional[int], str]] = {}
        self._ip2asn_table = load_ip2asn_v4_table()
        if self._ip2asn_table:
            self._health_event("ip2asn", True, "")
        else:
            self._health_event("ip2asn", False, "missing_or_unreadable")

    def _health_event(self, name: str, ok: bool, detail: str = "") -> None:
        """Record the health of an external dependency / enrichment step."""
        try:
            c = self.analysis_health.setdefault("checks", {}).setdefault(
                name, {"attempted": 0, "ok": 0, "fail": 0, "last_error": ""}
            )
            c["attempted"] += 1
            if ok:
                c["ok"] += 1
            else:
                c["fail"] += 1
                if detail:
                    c["last_error"] = str(detail)[:500]
        except Exception:
            pass

    def _call_with_timeout(self, fn: Callable[[], Any], timeout_s: float) -> tuple[bool, Any, str]:
        """Run fn() with a wall-clock timeout. Returns (ok, result, error_str)."""
        try:
            with ThreadPoolExecutor(max_workers=1) as pool:
                fut = pool.submit(fn)
                return (True, fut.result(timeout=timeout_s), "")
        except Exception as exc:
            return (False, None, str(exc))

    def get_analysis_health(self) -> dict:
        """Return a structured health report + a rough effectiveness estimate."""
        checks = (self.analysis_health or {}).get("checks") or {}
        internet = bool((self.analysis_health or {}).get("internet"))

        # Weighted, best-effort estimate of how much analysis capability was lost.
        # These weights are heuristic and intended only for user-facing guidance.
        weights = {
            "ipthc": 10,
            "umbrella": 10,
            "ip2asn": 10,
            "dns_ns": 10,
            "whois": 10,
            "tor_nodes": 5,
            "active_ssl": 20,
        }
        enabled = {k: True for k in weights.keys()}
        need_asn = bool(self._bl_asns_map) or bool(self._wl_asns_int)
        enabled["ip2asn"] = need_asn
        if not self.active_analysis:
            enabled["active_ssl"] = False
            enabled["ipthc"] = False
            enabled["dns_ns"] = False
            enabled["whois"] = False

        total = sum(w for k, w in weights.items() if enabled.get(k))
        lost = 0

        # Offline = hard loss for internet-dependent checks (local ip2asn is unaffected).
        if not internet:
            for k in ("ipthc", "dns_ns", "whois", "tor_nodes"):
                if enabled.get(k):
                    lost += weights[k]

        # Umbrella list is local, but if missing, it's a loss.
        umb = checks.get("umbrella") or {}
        if enabled.get("umbrella") and umb.get("fail", 0) > 0 and umb.get("ok", 0) == 0:
            lost += weights["umbrella"]

        # ip2asn TSV is local; loss only if load failed when ASN rules are enabled.
        ip2 = checks.get("ip2asn") or {}
        if enabled.get("ip2asn") and ip2.get("fail", 0) > 0 and ip2.get("ok", 0) == 0:
            lost += weights["ip2asn"]

        # Active SSL failures: consider it degraded if most attempts fail.
        if enabled.get("active_ssl"):
            a = checks.get("active_ssl") or {}
            att = int(a.get("attempted", 0) or 0)
            fail = int(a.get("fail", 0) or 0)
            if att > 0 and fail / max(att, 1) >= 0.5:
                lost += weights["active_ssl"]

        # Generic service failures when online (ipthc/whois/ns/tor)
        for k in ("ipthc", "dns_ns", "whois", "tor_nodes"):
            if not enabled.get(k) or not internet:
                continue
            a = checks.get(k) or {}
            att = int(a.get("attempted", 0) or 0)
            fail = int(a.get("fail", 0) or 0)
            if att > 0 and fail / max(att, 1) >= 0.5:
                lost += weights[k]

        if total <= 0:
            effectiveness = 100
            lost_pct = 0
        else:
            lost = min(lost, total)
            lost_pct = int(round(100 * (lost / total)))
            effectiveness = max(0, 100 - lost_pct)

        degraded = (not internet) or any((v or {}).get("fail", 0) for v in checks.values())
        return {
            "internet": internet,
            "degraded": bool(degraded),
            "effectiveness_pct": int(effectiveness),
            "lost_pct": int(lost_pct),
            "checks": checks,
        }

    def _indicator_type_enabled(self, tag: str) -> bool:
        # Keep the semantics: IOC tag itself, or "all".
        return self.ioc_index.indicator_type_enabled(tag)

    def _iter_domain_suffixes(self, name: str):
        # Backward-compatible wrapper.
        yield from _iter_domain_suffixes(name)

    def _is_domain_whitelisted(self, dnsname: str) -> bool:
        """True if dnsname matches a whitelisted domain suffix (same rules as check_whitelist)."""
        return self.whitelist_index.is_domain_whitelisted(dnsname)

    def _dns_rr_is_a_or_aaaa(self, rrtype) -> bool:
        """Suricata EVE may use rrtype as name (A/AAAA) or numeric RFC code (1 / 28)."""
        if rrtype in ("A", "AAAA"):
            return True
        if isinstance(rrtype, int):
            return rrtype in (1, 28)
        if isinstance(rrtype, str):
            s = rrtype.strip().upper()
            if s in ("A", "AAAA"):
                return True
            if s.isdigit():
                return int(s) in (1, 28)
        return False

    def _format_x509_name(self, components: dict) -> str:
        """Format an X509Name components dict to a stable DN string."""
        if not components:
            return ""
        preferred = ["C", "ST", "L", "O", "OU", "CN"]
        ordered_keys = [k for k in preferred if k.encode() in components] + sorted(
            [k.decode("utf8") for k in components.keys() if k.decode("utf8") not in preferred]
        )
        parts = []
        for k in ordered_keys:
            kb = k.encode("utf8")
            if kb not in components:
                continue
            vb = components[kb]
            parts.append(f"{k}={vb.decode('utf8')}")
        return ", ".join(parts)

    def _normalize_dn(self, dn: str) -> str:
        # Backward-compatible wrapper.
        return _normalize_dn(dn)

    def _tls_version_number(self, version: str):
        """Extract numeric TLS version from strings like 'TLS 1.3'."""
        if not version:
            return None
        m = re.search(r"([0-9]+(?:\.[0-9]+)?)", str(version))
        if not m:
            return None
        try:
            return float(m.group(1))
        except Exception:
            return None

    def _coerce_tls_port(self, certificate: dict) -> int:
        """Suricata sometimes omits dest_port on tls events; default to 443."""
        p = certificate.get("port")
        if p is None or p == "":
            return 443
        try:
            n = int(p)
        except (TypeError, ValueError):
            return 443
        if n < 1 or n > 65535:
            return 443
        return n

    def _cert_issuerdn_str(self, certificate: dict) -> str:
        for key in ("issuerdn", "issuer"):
            v = certificate.get(key)
            if isinstance(v, str) and v.strip():
                return v.strip()
        return ""

    def check_internet(self) -> bool:
        """Check the internet link just with a small http request
        to an URL present in the configuration. If the link is down,
        retry 3 times.

        Returns:
            bool: True if everything works.
        """
        attempts = 3

        while True:
            try:
                url = get_config(("network", "internet_check"))
                requests.get(url, timeout=3)
                return True
            except:
                if attempts == 0:
                    return False
                else:
                    time.sleep(5)
                    attempts -= 1

    def get_public_ip(self) -> list:
        """Get the public IP address

        Returns:
            list: list containing the public IP address.
        """
        if self.connected:
            try:
                return [requests.get("https://api.ipify.org", timeout=3).text]
            except:
                return []
        else:
            return []

    def start_engine(self):
        """ This method starts suricata and then launch the 
            parsers to analyse the output logs. 
        """

        # Parse the eve.json file.
        self.parse_eve_file()

        # Whitelist before any other work so parallel SSL probes skip allowlisted flows.
        if self.whitelist_analysis:
            for record in self.records:
                self.check_whitelist(record)

        # Cheap: merge SNI / HTTP Host into domains once so later steps skip useless work.
        for record in self.records:
            self._merge_observed_hostnames_into_domains(record)

        # Prefetch internet enrichments in parallel to avoid per-domain sequential waits.
        if self.active_analysis and self.connected:
            try:
                self._prefetch_domain_enrichments()
            except Exception:
                # Best-effort; never break the analysis.
                pass

        # Warm local ASN cache (O(log n) each; dedupe by IP for repeated destinations).
        if self._ip2asn_table and (self._bl_asns_map or self._wl_asns_int):
            try:
                self._prefetch_asn_lookups()
            except Exception:
                pass

        # Pre-run active SSL checks in parallel (TLS 1.3+ certificates are not in EVE).
        # This is the most expensive part of the analysis and is independent per host.
        # Active SSL probing requires network reachability; when offline it can hang on DNS/connect.
        if self.active_analysis and self.connected:
            self._precheck_active_ssl()

        # Parallel cert CN/SAN fetch for empty-domain + :443 flows (replaces sequential probes in check_domains).
        if self.active_analysis and self.connected:
            self._precheck_tls_cert_hostnames_for_report()

        # For each type of records, check it against heuristics.
        for record in self.records:
            self.check_domains(record)
            self.check_flow(record)
            self.check_tls(record)
            self.check_http(record)

        # Check for failed DNS answers (if spyguard not connected)
        for dnsname in list(set(self.dns_failed)):
            if self._is_domain_whitelisted(dnsname):
                continue
            self.check_dnsname(dnsname)

        self._check_umbrella_popularity()
        self._attach_umbrella_ranks_to_records()
        self._strip_parse_eve_internal_state()

    def _strip_parse_eve_internal_state(self) -> None:
        """Remove non-JSON-serializable parse helpers before records.json export."""
        for rec in self.records or []:
            rec.pop("_proto_keys", None)
            rec.pop("_cert_snis_seen", None)

    def _iter_domains_for_enrichment(self) -> set[str]:
        """Unique apex domains to enrich (NS + WHOIS), from DNS/SNI/HTTP hostnames."""
        out: set[str] = set()
        for record in (self.records or []):
            if record.get("whitelisted"):
                continue
            for h in self._iter_record_hostnames(record):
                if not isinstance(h, str) or not h.strip():
                    continue
                hn = h.strip().lower().rstrip(".")
                if not hn or hn == "--":
                    continue
                # Skip IP literals.
                try:
                    ip_address(hn)
                    continue
                except ValueError:
                    pass
                try:
                    d = get_sld(hn) or hn
                except Exception:
                    d = hn
                d = str(d).strip().lower().rstrip(".")
                if d:
                    out.add(d)
        return out

    def _prefetch_domain_enrichments(self) -> None:
        """Run DNS NS + WHOIS for all unique domains, in parallel with bounded workers."""
        domains = sorted(self._iter_domains_for_enrichment())
        if not domains:
            return

        def do_ns(domain: str) -> None:
            with self._domain_enrich_lock:
                if domain in self._domain_ns_cache or domain in self._domain_ns_err:
                    return
            try:
                ok_ns, name_servers, err_ns = self._call_with_timeout(
                    lambda: pydig.query(domain, "NS"), 5
                )
                if not ok_ns:
                    raise RuntimeError(err_ns or "timeout")
                ns = [str(x).strip().strip(".") for x in (name_servers or []) if str(x).strip()]
                with self._domain_enrich_lock:
                    self._domain_ns_cache[domain] = ns
                self._health_event("dns_ns", True, "" if ns else "empty")
            except Exception as e:
                with self._domain_enrich_lock:
                    self._domain_ns_err[domain] = str(e)
                self._health_event("dns_ns", False, str(e))

        def do_whois(domain: str) -> None:
            with self._domain_enrich_lock:
                if domain in self._domain_whois_creation_cache or domain in self._domain_whois_err:
                    return
            try:
                ok_w, whois_record, err_w = self._call_with_timeout(lambda: whois.whois(domain), 14)
                if not ok_w:
                    raise RuntimeError(err_w or "timeout")
                cd = None
                try:
                    cd = whois_record.creation_date
                    cd = cd if type(cd) is not list else cd[0]
                except Exception:
                    cd = None
                with self._domain_enrich_lock:
                    self._domain_whois_creation_cache[domain] = cd
                # Consider the WHOIS request successful even if creation date is missing/redacted.
                self._health_event("whois", True, "" if cd is not None else "no_creation_date")
            except Exception as e:
                with self._domain_enrich_lock:
                    self._domain_whois_err[domain] = str(e)
                self._health_event("whois", False, str(e))

        workers = min(self._enrich_workers, max(1, len(domains)))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            # Launch both enrichments per domain; still bounded by pool size.
            futs = []
            for d in domains:
                futs.append(pool.submit(do_ns, d))
                futs.append(pool.submit(do_whois, d))
            # Ensure completion (best-effort); we don't want to hang forever.
            for fut in as_completed(futs, timeout=max(20, 2 * len(domains))):
                try:
                    fut.result()
                except Exception:
                    pass

    def _prefetch_asn_lookups(self) -> None:
        """Resolve each unique destination IP once into _asn_ip_cache (local ip2asn table)."""
        if not self._ip2asn_table:
            return
        seen: set[str] = set()
        for record in self.records or []:
            if record.get("whitelisted"):
                continue
            ip = record.get("ip_dst")
            if not isinstance(ip, str) or not ip.strip():
                continue
            ip = ip.strip()
            if ip in seen:
                continue
            seen.add(ip)
            self._resolve_asn_for_ip(ip)

    def _resolve_asn_for_ip(self, ip: str) -> tuple[Optional[int], str]:
        """IPv4 ASN from local ip2asn TSV (iptoasn.com). IPv6: (None, '')."""
        if not ip or not isinstance(ip, str):
            return (None, "")
        ip = ip.strip()
        if not ip or ip == "--":
            return (None, "")
        if ip in self._asn_ip_cache:
            return self._asn_ip_cache[ip]
        if not self._ip2asn_table:
            self._asn_ip_cache[ip] = (None, "")
            return (None, "")
        r = self._ip2asn_table.lookup_ip_string(ip)
        self._asn_ip_cache[ip] = r
        return r

    def _ensure_umbrella_top500k_loaded(self) -> None:
        """Single read of Umbrella JSON; fills both set and rank map (or empty on failure)."""
        if self._umbrella_top500k_set is not None:
            return
        self._umbrella_top500k_set = set()
        self._umbrella_top500k_rank_map = {}
        try:
            with open(UMBRELLA_JSON_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            domains = (data.get("domains") or [])[:UMBRELLA_TOP500K]
            for i, d in enumerate(domains, start=1):
                if not d:
                    continue
                key = str(d).strip().lower().rstrip(".")
                if not key:
                    continue
                self._umbrella_top500k_set.add(key)
                if key not in self._umbrella_top500k_rank_map:
                    self._umbrella_top500k_rank_map[key] = i
            self._health_event("umbrella", True, "")
        except FileNotFoundError:
            self._health_event("umbrella", False, "file_missing")
            self.errors.append(
                "Cisco Umbrella popularity list missing at {}; run watchers.py to download it.".format(
                    UMBRELLA_JSON_PATH
                )
            )
        except Exception as e:
            self._health_event("umbrella", False, str(e))
            self.errors.append("Could not load Umbrella popularity list: {}".format(str(e)))

    def _load_umbrella_top500k_set(self) -> set[str]:
        """Load first 500K FQDNs from Cisco Umbrella JSON (written by watchers.py)."""
        self._ensure_umbrella_top500k_loaded()
        return cast(set[str], self._umbrella_top500k_set)

    def _load_umbrella_top500k_rank_map(self) -> dict[str, int]:
        """Load first 500K FQDNs and map each to its 1-based rank."""
        self._ensure_umbrella_top500k_loaded()
        return cast(dict[str, int], self._umbrella_top500k_rank_map)

    def _attach_umbrella_ranks_to_records(self) -> None:
        """Attach Umbrella Top 500K rank per domain for display purposes."""
        ranks = self._load_umbrella_top500k_rank_map()
        if not ranks:
            return
        for record in self.records:
            doms = record.get("domains") or []
            if not isinstance(doms, list) or not doms:
                continue
            out = {}
            for d in doms:
                if not isinstance(d, str):
                    continue
                k = d.strip().lower().rstrip(".")
                if not k:
                    continue
                r = ranks.get(k)
                if r:
                    out[d] = int(r)
            if out:
                record["domains_umbrella_rank"] = out

    def _iter_record_hostnames(self, record: dict):
        """DNS names, TLS SNI, and HTTP hostnames seen for this destination."""
        for d in record.get("domains") or []:
            if isinstance(d, str) and d.strip():
                yield d
        for c in record.get("certificates") or []:
            sni = c.get("sni")
            if isinstance(sni, str) and sni.strip():
                yield sni
        for h in record.get("http") or []:
            if isinstance(h, dict):
                hn = h.get("hostname")
                if isinstance(hn, str) and hn.strip():
                    yield hn

    def _merge_observed_hostnames_into_domains(self, record: dict) -> None:
        """Copy TLS SNI and HTTP hostnames into record['domains'] for reporting.

        Suricata stores these separately; the UI only lists record['domains']. Whitelisted
        flows skip check_tls/check_http, so without this merge the Domain column stays empty
        even when SNI/Host was observed in the capture.

        If _dns_domains is non-empty (names from captured DNS A/AAAA answers), those take
        precedence: we do not add SNI/Host so certificate placeholders (e.g. invalid2.invalid)
        do not mask real resolver data.
        """
        doms = record.get("domains")
        if not isinstance(doms, list):
            return
        dns_only = record.get("_dns_domains")
        if isinstance(dns_only, list) and len(dns_only) > 0:
            return

        seen = {d.strip().lower().rstrip(".") for d in doms if isinstance(d, str) and d.strip()}

        def _append(name: str) -> None:
            raw = name.strip()
            if not raw:
                return
            try:
                ip_address(raw)
                return
            except ValueError:
                pass
            if self._normalize_cert_hostname_candidate(raw) is None:
                return
            k = raw.lower().rstrip(".")
            if not k or k in seen:
                return
            doms.append(raw)
            seen.add(k)

        for c in record.get("certificates") or []:
            if not isinstance(c, dict):
                continue
            sni = c.get("sni")
            if isinstance(sni, str):
                _append(sni)

        for h in record.get("http") or []:
            if not isinstance(h, dict):
                continue
            hn = h.get("hostname")
            if isinstance(hn, str):
                _append(hn)

    def _check_umbrella_popularity(self):
        """Alert (moderate) if a non-whitelisted flow's domain is absent from Umbrella top 500K."""
        umbrella = self._load_umbrella_top500k_set()
        if not umbrella:
            return
        if "UMBRELLA-01" not in self.template:
            return
        seen = set()
        for record in self.records:
            if record.get("whitelisted"):
                continue
            for domain in self._iter_record_hostnames(record):
                if not domain or not isinstance(domain, str):
                    continue
                d = domain.strip().lower().rstrip(".")
                if not d or d == "--":
                    continue
                try:
                    ip_address(d)
                    continue
                except ValueError:
                    pass
                if self._is_domain_whitelisted(domain):
                    continue
                candidates = {d}
                try:
                    sld = get_sld(d)
                    if sld:
                        candidates.add(str(sld).strip().lower().rstrip("."))
                except Exception:
                    pass
                try:
                    canon = get_sld(d) or d
                    canon = str(canon).strip().lower().rstrip(".")
                except Exception:
                    canon = d
                if canon in seen:
                    continue
                if candidates & umbrella:
                    continue
                seen.add(canon)
                self.alerts.append(
                    {
                        "title": self.template["UMBRELLA-01"]["title"].format(domain),
                        "description": self.template["UMBRELLA-01"]["description"].format(domain),
                        "host": domain,
                        "level": "Moderate",
                        "id": "UMBRELLA-01",
                    }
                )

    def _get_host_for_ssl(self, record: dict, certificate: dict) -> str:
        """Pick best hostname for an active TLS connection."""
        if certificate.get("sni"):
            return certificate["sni"]
        if record.get("domains"):
            return record["domains"][0]
        if record.get("http") and isinstance(record["http"], list) and record["http"]:
            return record["http"][0].get("hostname") or ""
        return record.get("ip_dst", "")

    def _record_observed_dest_port(self, record: dict, port: int) -> bool:
        """True if any flow protocol row matches destination port (e.g. 443 for HTTPS)."""
        try:
            want = int(port)
        except Exception:
            return False
        for p in record.get("protocols") or []:
            if not isinstance(p, dict):
                continue
            try:
                if int(p.get("port", -1)) == want:
                    return True
            except Exception:
                continue
        return False

    def _should_skip_active_tls_probe_to_ip(self, ip: str) -> bool:
        """Avoid TLS handshakes to addresses that will not yield useful cert hostnames."""
        if not ip or not isinstance(ip, str):
            return True
        try:
            a = ipaddress.ip_address(ip.strip())
        except ValueError:
            return True
        if a.is_multicast or a.is_link_local or a.is_loopback or a.is_unspecified:
            return True
        return False

    def _normalize_cert_hostname_candidate(self, raw: str) -> Optional[str]:
        """Turn a CN/SAN value into a usable DNS name, or None if not suitable."""
        if not raw or not isinstance(raw, str):
            return None
        s = raw.strip().lower().rstrip(".")
        if not s:
            return None
        if s.startswith("*."):
            s = s[2:]
        if not s:
            return None
        try:
            ipaddress.ip_address(s)
            return None
        except ValueError:
            pass
        if ".." in s or s.startswith(".") or s.endswith("."):
            return None
        # RFC 6761 + common QUIC/TLS placeholders (e.g. invalid2.invalid); never prefer over real DNS.
        if s == "invalid" or s.endswith(".invalid"):
            return None
        if not re.match(r"^[a-z0-9._-]+$", s):
            return None
        if "." not in s:
            return s if re.match(r"^[a-z][a-z0-9-]*$", s) else None
        return s

    def _hostname_from_x509(self, x509: Any) -> Optional[str]:
        """Prefer subject CN, then subjectAltName dNSName entries."""
        if x509 is None:
            return None
        candidates: list[str] = []
        try:
            for k, v in x509.get_subject().get_components():
                if k == b"CN":
                    candidates.append(v.decode("utf-8", errors="replace"))
                    break
        except Exception:
            pass
        try:
            for i in range(x509.get_extension_count()):
                ext = x509.get_extension(i)
                if ext.get_short_name() != b"subjectAltName":
                    continue
                for piece in str(ext).split(","):
                    piece = piece.strip()
                    if piece.upper().startswith("DNS:"):
                        candidates.append(piece[4:].strip())
        except Exception:
            pass
        for raw in candidates:
            norm = self._normalize_cert_hostname_candidate(raw)
            if norm:
                return norm
        return None

    def _tls_handshake_get_peer_x509(self, host: str, port: int) -> Any:
        """Perform TLS handshake and return peer cert as OpenSSL X509 (or raise)."""
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        conn = socket.create_connection((host, port), timeout=5)
        sock = context.wrap_socket(conn, server_hostname=host)
        sock.settimeout(5)
        try:
            der_cert = sock.getpeercert(True)
        finally:
            sock.close()
        if not der_cert:
            raise ValueError("no peer certificate")
        pem = ssl.DER_cert_to_PEM_cert(der_cert)
        return OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, pem)

    def _cache_tls_hostname(self, host: str, port: int, x509: Any) -> None:
        hn = self._hostname_from_x509(x509)
        key = (str(host).strip(), int(port))
        with self._active_ssl_lock:
            self._tls_cert_hostname_cache[key] = hn

    def _get_tls_cert_hostname_for_ip(self, ip: str, port: int = 443) -> Optional[str]:
        """Active probe: certificate CN/SAN for TLS on ip:port (cached). Used before passive DNS."""
        if not ip or not isinstance(ip, str):
            return None
        ip = ip.strip()
        if not ip or ip == "--":
            return None
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return None
        key = (ip, int(port))
        with self._active_ssl_lock:
            if key in self._tls_cert_hostname_cache:
                return self._tls_cert_hostname_cache[key]
        try:
            x509 = self._tls_handshake_get_peer_x509(ip, port)
        except Exception:
            with self._active_ssl_lock:
                self._tls_cert_hostname_cache[key] = None
            return None
        hn = self._hostname_from_x509(x509)
        with self._active_ssl_lock:
            self._tls_cert_hostname_cache[key] = hn
        return hn

    def _precheck_tls_cert_hostnames_for_report(self) -> None:
        """Parallel TLS cert probes for (ip, 443) when domains are still empty.

        check_domains used to call _get_tls_cert_hostname_for_ip sequentially per record;
        this batches unique targets and reuses _tls_cert_hostname_cache.
        """
        if not (self.active_analysis and self.connected and self.heuristics_analysis):
            return

        targets: list[tuple[str, int]] = []
        seen: set[tuple[str, int]] = set()
        for record in self.records:
            dns_only = record.get("_dns_domains")
            if isinstance(dns_only, list) and len(dns_only) > 0:
                continue
            if record.get("domains"):
                continue
            if not self._record_observed_dest_port(record, 443):
                continue
            ip = (record.get("ip_dst") or "").strip()
            if not ip or ip == "--" or self._should_skip_active_tls_probe_to_ip(ip):
                continue
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                continue
            key = (ip, 443)
            if key in seen:
                continue
            seen.add(key)
            with self._active_ssl_lock:
                if key in self._tls_cert_hostname_cache:
                    continue
            targets.append(key)

        if not targets:
            return

        workers = min(self._active_ssl_workers, len(targets))

        def probe_one(key: tuple[str, int]) -> None:
            ip, port = key
            try:
                x509 = self._tls_handshake_get_peer_x509(ip, port)
                hn = self._hostname_from_x509(x509)
            except Exception:
                hn = None
            with self._active_ssl_lock:
                self._tls_cert_hostname_cache[key] = hn

        with ThreadPoolExecutor(max_workers=workers) as pool:
            future_by_key = {pool.submit(probe_one, k): k for k in targets}
            total_timeout_s = max(25, 5 * len(future_by_key))
            try:
                for fut in as_completed(future_by_key, timeout=total_timeout_s):
                    try:
                        fut.result()
                    except Exception:
                        k = future_by_key[fut]
                        with self._active_ssl_lock:
                            self._tls_cert_hostname_cache.setdefault(k, None)
            except Exception:
                with self._active_ssl_lock:
                    for k in targets:
                        self._tls_cert_hostname_cache.setdefault(k, None)

    def _precheck_active_ssl(self):
        """Run active SSL checks concurrently and cache results."""
        targets = []
        seen = set()
        for record in self.records:
            if record.get("whitelisted"):
                continue
            for cert in record.get("certificates", []):
                port = self._coerce_tls_port(cert)
                host = self._get_host_for_ssl(record, cert)
                if not host:
                    continue
                key = (host, port)
                if key in seen:
                    continue
                seen.add(key)
                with self._active_ssl_lock:
                    if key in self._active_ssl_cache:
                        continue
                targets.append(key)

        if not targets:
            return

        workers = min(self._active_ssl_workers, len(targets))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            future_by_key = {pool.submit(self.active_check_ssl, host, port): (host, port) for host, port in targets}
            # Hard cap to avoid rare hangs (DNS resolver / socket edge cases).
            total_timeout_s = max(30, 8 * len(future_by_key))
            try:
                it = as_completed(future_by_key, timeout=total_timeout_s)
                for fut in it:
                    host, port = future_by_key[fut]
                    try:
                        res = bool(fut.result())
                    except Exception:
                        res = False
                    with self._active_ssl_lock:
                        self._active_ssl_cache[(host, port)] = res
            except Exception as exc:
                self._health_event("active_ssl", False, f"timeout_or_error:{exc}")
                # Best-effort: mark remaining tasks as failed in cache so callers don't block.
                with self._active_ssl_lock:
                    for host, port in targets:
                        self._active_ssl_cache.setdefault((host, port), False)
        
    def parse_eve_file(self):
        """This method parses the eve.json file produced by suricata.
           For each record, it look at the record type and then append the self.record
           dictionnary which contains valuable data to look at suspicious stuff.
        """
        eve_path = f"{self.assets_dir}eve.json"

        # Build records efficiently: one pass, plus an index for O(1) lookups.
        records_by_ip = {}

        def get_or_create_record(ip_dst: str):
            rec = records_by_ip.get(ip_dst)
            if rec is None:
                rec = {
                    "ip_dst": ip_dst,
                    "whitelisted": False,
                    "suspicious": False,
                    "protocols": [],
                    "_proto_keys": set(),
                    "domains": [],
                    "_dns_domains": [],
                    "certificates": [],
                    "_cert_snis_seen": set(),
                }
                self.records.append(rec)
                records_by_ip[ip_dst] = rec
            return rec

        dns_queries = set()
        resolved_domains = set()
        # IP -> names from DNS answers (filled before flow rows may exist; merged after the file pass).
        dns_ip_to_domains = {}

        with open(eve_path, "r") as f:
            for line in f:
                try:
                    record = json.loads(line)
                except Exception:
                    # Ignore malformed JSON lines but keep the behavior robust.
                    continue

                # FLOW: create/update per-destination records and protocols.
                if "flow" in record:
                    try:
                        app_proto = record.get("app_proto", "failed")
                        proto = {
                            "name": (app_proto.upper() if app_proto != "failed" else record["proto"].upper()),
                            "port": record.get("dest_port", -1),
                        }
                        rec = get_or_create_record(record["dest_ip"])
                        pkey = (proto["name"], proto["port"])
                        pk = rec.setdefault("_proto_keys", set())
                        if pkey not in pk:
                            pk.add(pkey)
                            rec["protocols"].append(proto)
                    except Exception:
                        self.errors.append(
                            f"Issue when processing the following eve record (flow): {json.dumps(record)}"
                        )
                    continue

                # TLS: attach TLS metadata to the right destination record.
                if "tls" in record:
                    try:
                        dest_ip = record.get("dest_ip")
                        if not dest_ip:
                            continue
                        rec = records_by_ip.get(dest_ip)
                        if rec is None:
                            # Some Suricata configurations don't emit flow records.
                            # Create a destination record so TLS metadata isn't lost.
                            rec = get_or_create_record(dest_ip)

                        tls = record["tls"]
                        if "issuer" in tls and "issuerdn" not in tls:
                            tls["issuerdn"] = tls["issuer"]
                        if "version" in tls:
                            tls_ver = self._tls_version_number(tls.get("version"))
                            snis = rec.setdefault("_cert_snis_seen", set())
                            if tls_ver is not None and tls_ver < 1.3 and "session_resumed" not in tls:
                                if tls not in rec["certificates"]:
                                    tls["port"] = record.get("dest_port")
                                    rec["certificates"].append(tls)
                                    sni0 = tls.get("sni")
                                    if isinstance(sni0, str) and sni0:
                                        snis.add(sni0)
                            else:
                                sni = tls.get("sni")
                                if isinstance(sni, str) and sni and sni not in snis:
                                    rec["certificates"].append(
                                        {"sni": sni, "version": tls["version"], "port": record.get("dest_port")}
                                    )
                                    snis.add(sni)
                                else:
                                    rec["certificates"].append({"version": tls["version"], "port": record.get("dest_port")})
                    except Exception:
                        self.errors.append(
                            f"Issue when processing the following eve record (tls): {json.dumps(record)}"
                        )
                    continue

                # HTTP: attach HTTP host / UA to the right destination record.
                if "http" in record:
                    try:
                        dest_ip = record.get("dest_ip")
                        if not dest_ip:
                            continue
                        rec = records_by_ip.get(dest_ip)
                        if rec is None:
                            # Some Suricata configurations don't emit flow records.
                            rec = get_or_create_record(dest_ip)

                        http = record["http"]
                        d = {"hostname": http["hostname"]}
                        if "http_user_agent" in http:
                            d["user-agent"] = http["http_user_agent"]
                        if "http" in rec:
                            if d not in rec["http"]:
                                rec["http"].append(d)
                        else:
                            rec["http"] = [d]
                    except Exception:
                        self.errors.append(
                            f"Issue when processing the following eve record (http): {json.dumps(record)}"
                        )
                    continue

                # DNS: link rrname to destination IPs when possible; keep queries for later.
                if "dns" in record:
                    try:
                        dns = record["dns"]
                        if dns.get("type") == "answer":
                            rrname = (
                                dns.get("rrname")
                                or dns.get("qry_name")
                                or dns.get("query", {}).get("rrname")
                                or dns.get("query", {}).get("qry_name")
                            )

                            if dns.get("rcode") == "NOERROR":
                                resolved_ips = []

                                # Legacy Suricata EVE format.
                                grouped = dns.get("grouped")
                                if isinstance(grouped, dict):
                                    resolved_ips.extend(grouped.get("A", []) or [])
                                    resolved_ips.extend(grouped.get("AAAA", []) or [])

                                # Modern Suricata EVE format: answers array.
                                answers = dns.get("answers")
                                if isinstance(answers, list):
                                    for ans in answers:
                                        if not isinstance(ans, dict):
                                            continue
                                        rrtype = ans.get("rrtype")
                                        rdata = ans.get("rdata")
                                        if self._dns_rr_is_a_or_aaaa(rrtype) and rdata:
                                            resolved_ips.append(rdata)

                                # Some formats still expose rrtype/rdata at top level.
                                rrtype = dns.get("rrtype")
                                rdata = dns.get("rdata")
                                if self._dns_rr_is_a_or_aaaa(rrtype) and rdata:
                                    resolved_ips.append(rdata)

                                if resolved_ips and rrname:
                                    resolved_domains.add(rrname)
                                for ip in set(resolved_ips):
                                    if rrname:
                                        dns_ip_to_domains.setdefault(ip, set()).add(rrname)

                            elif dns.get("rcode") == "SERVFAIL":
                                if rrname:
                                    self.dns_failed.append(rrname)
                        elif dns.get("type") == "query":
                            qname = (
                                dns.get("rrname")
                                or dns.get("qry_name")
                                or dns.get("query", {}).get("rrname")
                                or dns.get("query", {}).get("qry_name")
                            )
                            if qname:
                                dns_queries.add(qname)
                    except Exception:
                        self.errors.append(
                            f"Issue when processing the following eve record (dns answer): {json.dumps(record)}"
                        )
                    continue

                # ALERT: mark record suspicious and add corresponding alert.
                if "alert" in record and record.get("event_type") == "alert":
                    try:
                        dest_ip = record.get("dest_ip")
                        if not dest_ip:
                            continue
                        rec = records_by_ip.get(dest_ip)
                        if rec is None:
                            rec = get_or_create_record(dest_ip)
                        rec["suspicious"] = True
                        self.alerts.append(
                            {
                                "title": self.template["SNORT-01"]["title"].format(record["alert"]["signature"]),
                                "description": self.template["SNORT-01"]["description"].format(rec["ip_dst"]),
                                "host": rec["ip_dst"],
                                "level": "High",
                                "id": "SNORT-01",
                            }
                        )
                    except Exception:
                        self.errors.append(
                            f"Issue when processing the following eve record (dns answer): {json.dumps(record)}"
                        )

        # Attach DNS names to flows seen to any IP, regardless of eve.json line order.
        for ip, names in dns_ip_to_domains.items():
            rec = records_by_ip.get(ip)
            if rec is None:
                continue
            dd = rec.setdefault("_dns_domains", [])
            for name in sorted(names):
                if name not in rec["domains"]:
                    rec["domains"].append(name)
                if name not in dd:
                    dd.append(name)

        # This pass is if SpyGuard is not connected to Internet.
        # We still analyze the unanswered DNS queries.
        for rrname in dns_queries:
            if rrname not in resolved_domains:
                self.records.append(
                    {
                        "ip_dst": "--",
                        "whitelisted": False,
                        "suspicious": False,
                        "protocols": [{"name": "DNS", "port": "53"}],
                        "domains": [rrname],
                        "_dns_domains": [rrname],
                        "certificates": [],
                    }
                )


    def check_whitelist(self, record):
        """ This method is asked on each record. It:

            1. Check if the associated IP(v4/6) Address can be whitelisted
            2. Check if one of the associated domain names can be whitelisted
            3. Last: if still not whitelisted and ASN whitelist entries exist, resolve ASN
               via local ip2asn-v4.tsv.gz — deferred to avoid lookups when (1–2) already match.

            If its the case, the "whitelisted" key of the record is set to True.
            Therefore, the record will be ignored for the rest of the analysis.
        Args:
            record (dict): record to be processed.
        """

        self.whitelist_index.mark_record_if_whitelisted(record, ipv6_ula=self._ipv6_ula)
        if record.get("whitelisted"):
            return
        self._try_whitelist_by_asn(record)

    def _try_whitelist_by_asn(self, record: dict) -> None:
        """Mark record whitelisted when destination IP's ASN is in the ASN whitelist."""
        if not self._wl_asns_int:
            return
        ip = record.get("ip_dst")
        if not isinstance(ip, str) or not ip.strip() or ip.strip() == "--":
            return
        ip = ip.strip()
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return
        asn, _org = self._resolve_asn_for_ip(ip)
        if asn is not None and asn in self._wl_asns_int:
            record["whitelisted"] = True

    def check_domains(self, record):
        """Check the domains associated to each record.
           First this method checks if the record is whitelisted. If not:
              1. Leverage a low alert if the record don't have any associated DNSName
              2. Check each domain associated to the record by calling check_dnsname.
        Args:
            record (dict): record to be processed.
        """
        # Populate record['domains'] for the report (SNI, HTTP Host), including whitelisted flows.
        self._merge_observed_hostnames_into_domains(record)

        # TLS 1.3 / no cleartext cert in EVE: hostname from cache — only if no DNS names for this IP.
        dns_only = record.get("_dns_domains")
        has_dns = isinstance(dns_only, list) and len(dns_only) > 0
        if (
            not has_dns
            and self.heuristics_analysis
            and record["domains"] == []
            and self.active_analysis
            and self.connected
            and self._record_observed_dest_port(record, 443)
        ):
            ip_dst = (record.get("ip_dst") or "").strip()
            if ip_dst and not self._should_skip_active_tls_probe_to_ip(ip_dst):
                cert_name = self._get_tls_cert_hostname_for_ip(ip_dst, 443)
                if (
                    cert_name
                    and cert_name not in record["domains"]
                    and self._normalize_cert_hostname_candidate(cert_name) is not None
                ):
                    record["domains"].append(cert_name)

        if record["whitelisted"]:
            return

        if self.heuristics_analysis:
            # Otherwise, we alert the user that an IP haven't been resolved by
            # a DNS answer during the session...
            if record["domains"] == []:
                record["suspicious"] = True
                ip_dst = record.get("ip_dst", "")
                title = self.template["PROTO-05"]["title"].format(ip_dst)
                description = self.template["PROTO-05"]["description"].format(ip_dst)
                # Best-effort: attach observed service (port/proto) from flows.
                # This is derived from Suricata EVE flow metadata, not DNS.
                alert_proto = None
                alert_port = None
                try:
                    protocols = record.get("protocols") or []
                    for p in protocols:
                        if not isinstance(p, dict):
                            continue
                        name = p.get("name")
                        port = p.get("port")
                        if not name:
                            continue
                        try:
                            port_i = int(port)
                        except Exception:
                            continue
                        if port_i > 0:
                            alert_proto = str(name).strip().upper()
                            alert_port = port_i
                            break
                except Exception:
                    pass

                # Optional enrichment only (do not add to record["domains"]): passive DNS can
                # list many unrelated names for shared IPs (e.g. CDNs) and must not look like
                # a DNS query observed during capture.
                if self.active_analysis and self.connected:
                    domain, matching_records = self._ipthc_first_domain(ip_dst)
                    if domain:
                        title_t = self.template["PROTO-05"].get("title_pdns")
                        desc_t = self.template["PROTO-05"].get("description_pdns")
                        desc_single_t = self.template["PROTO-05"].get("description_pdns_single")
                        other = max(int(matching_records) - 1, 0)

                        if isinstance(title_t, str) and title_t:
                            title = title_t.format(ip_dst, domain)
                        else:
                            title = f"{title} ({domain})"

                        if other == 0 and isinstance(desc_single_t, str) and desc_single_t:
                            description = desc_single_t.format(ip_dst, domain)
                        elif isinstance(desc_t, str) and desc_t:
                            description = desc_t.format(ip_dst, domain, other)

                        umbrella_note = self.template["PROTO-05"].get("umbrella_top500k_note")
                        if isinstance(umbrella_note, str) and umbrella_note:
                            umbrella = self._load_umbrella_top500k_set()
                            d_norm = str(domain).strip().lower().rstrip(".")
                            present = False
                            if umbrella and d_norm:
                                if d_norm in umbrella:
                                    present = True
                                else:
                                    try:
                                        sld = get_sld(d_norm)
                                        if sld and str(sld).strip().lower().rstrip(".") in umbrella:
                                            present = True
                                    except Exception:
                                        pass
                            if present:
                                description = f"{description} {umbrella_note}"
                    else:
                        no_pdns_note = self.template["PROTO-05"].get("description_pdns_none")
                        if isinstance(no_pdns_note, str) and no_pdns_note:
                            description = f"{description} {no_pdns_note}".strip()
                        else:
                            description = (
                                f"{description} Passive DNS (ip.thc.org) did not return any associated domain for this IP address.".strip()
                            )

                self.alerts.append(
                    {
                        "title": title,
                        "description": description,
                        "host": ip_dst,
                        "proto": alert_proto,
                        "port": alert_port,
                        "level": "Low",
                        "id": "PROTO-05",
                    }
                )

        # Check each associated domain.
        for domain in record["domains"]:
            if self.check_dnsname(domain): 
                record["suspicious"] = True

    def _ipthc_first_domain(self, ip: str) -> tuple[Optional[str], int]:
        """Best-effort passive DNS lookup for an IP address using ip.thc.org.

        Returns (first_domain, matching_records_count). Both are cached per IP for the analysis run.
        """
        if not ip or not isinstance(ip, str):
            return (None, 0)
        if ip in self._ipthc_cache:
            return self._ipthc_cache[ip]

        # Only try for IP literals (skip "--" and hostnames).
        try:
            ip_address(ip)
        except ValueError:
            self._ipthc_cache[ip] = (None, 0)
            return (None, 0)

        payload = {
            "ip_address": ip,
            "tld": [],
            "apex_domain": "",
            "page_state": "",
            "limit": 10,
        }
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        try:
            r = requests.post(IPTHC_LOOKUP_URL, headers=headers, json=payload, timeout=5)
            if r.status_code != 200:
                self._health_event("ipthc", False, f"http_{r.status_code}")
                self._ipthc_cache[ip] = (None, 0)
                return (None, 0)
            data = r.json()
            self._health_event("ipthc", True, "")
            domains = data.get("domains") or []
            first = None
            if isinstance(domains, list) and domains:
                d0 = domains[0]
                if isinstance(d0, dict):
                    first = d0.get("domain") or d0.get("apex_domain")
            matching = int(data.get("matching_records") or (len(domains) if isinstance(domains, list) else 0))
            if isinstance(first, str):
                first = first.strip().strip(".").lower()
            if not first:
                first = None
            res = (first, matching)
            self._ipthc_cache[ip] = res
            return res
        except Exception:
            self._health_event("ipthc", False, "exception")
            self._ipthc_cache[ip] = (None, 0)
            return (None, 0)

    def check_dnsname(self, dnsname):
        """Check a domain name against a set of IOCs / heuristics.
              1. Check if the parent domain is blacklisted. 
              2. Check if the parent domain is a Free DNS.
              3. Check if the domain extension is a suspicious TLD.
              4. Check if the name servers associated to the domain are suspicious.
              5. Check if the domain have been registered recently - less than one year.
        Args:
            record (dict): record to be processed.
        Returns:
            supicious (bool) : if an alert has been leveraged. 
        """
        suspicious = False
        
        if self.iocs_analysis:
            # Domain & FreeDNS IOCs: match by walking suffixes once.
            for suffix in self._iter_domain_suffixes(dnsname):
                tags = self._bl_domains_map.get(suffix)
                if tags:
                    for tag in tags:
                        if not self._indicator_type_enabled(tag):
                            continue
                        if tag == "dual":
                            suspicious = True
                            self.alerts.append(
                                {
                                    "title": self.template["IOC-12"]["title"],
                                    "description": self.template["IOC-12"]["description"].format(suffix),
                                    "host": suffix,
                                    "level": "Low",
                                    "id": "IOC-12",
                                }
                            )
                        elif tag == "tracker":
                            suspicious = True
                            self.alerts.append(
                                {
                                    "title": self.template["IOC-04"]["title"].format(suffix, "tracker"),
                                    "description": self.template["IOC-04"]["description"].format(suffix, "tracker"),
                                    "host": suffix,
                                    "level": "Low",
                                    "id": "IOC-04",
                                }
                            )
                        elif tag == "doh":
                            suspicious = True
                            self.alerts.append(
                                {
                                    "title": self.template["IOC-13"]["title"].format(f"{dnsname}"),
                                    "description": self.template["IOC-13"]["description"].format(f"{dnsname}"),
                                    "host": dnsname,
                                    "level": "Low",
                                    "id": "IOC-13",
                                }
                            )
                        else:
                            suspicious = True
                            self.alerts.append(
                                {
                                    "title": self.template["IOC-03"]["title"].format(dnsname, tag.upper()),
                                    "description": self.template["IOC-03"]["description"].format(dnsname),
                                    "host": dnsname,
                                    "level": "High",
                                    "id": "IOC-03",
                                }
                            )

                freedns_tags = self._bl_freedns_map.get(suffix)
                if freedns_tags:
                    for tag in freedns_tags:
                        if not self._indicator_type_enabled(tag):
                            continue
                        suspicious = True
                        self.alerts.append(
                            {
                                "title": self.template["IOC-05"]["title"].format(dnsname),
                                "description": self.template["IOC-05"]["description"].format(dnsname),
                                "host": dnsname,
                                "level": "Moderate",
                                "id": "IOC-05",
                            }
                        )
                        break
                    
        if self.heuristics_analysis:        
            # TLD IOCs: check the last label.
            tld = dnsname.strip().strip(".").lower().split(".")[-1] if dnsname else ""
            if tld:
                tags = self._bl_tlds_map.get(tld)
                if tags:
                    for tag in tags:
                        if not self._indicator_type_enabled(tag):
                            continue
                        suspicious = True
                        self.alerts.append(
                            {
                                "title": self.template["IOC-06"]["title"].format(dnsname),
                                "description": self.template["IOC-06"]["description"].format(dnsname, tld),
                                "host": dnsname,
                                "level": "Low",
                                "id": "IOC-06",
                            }
                        )
                        break
                    
        if self.active_analysis and self.connected:
            domain = get_sld(dnsname)
            if domain not in self.dns_checked:
                self.dns_checked.add(domain)

                # DNS NS results (prefer prefetch cache).
                name_servers = None
                ns_err = ""
                with self._domain_enrich_lock:
                    if domain in self._domain_ns_cache:
                        name_servers = self._domain_ns_cache.get(domain) or []
                    elif domain in self._domain_ns_err:
                        ns_err = self._domain_ns_err.get(domain) or ""
                if name_servers is None:
                    # Fallback: should be rare (prefetch best-effort).
                    try:
                        ok_ns, ns_res, err_ns = self._call_with_timeout(
                            lambda: pydig.query(domain, "NS"), 5
                        )
                        if not ok_ns:
                            raise RuntimeError(err_ns or "timeout")
                        name_servers = ns_res or []
                    except Exception as e:
                        name_servers = []
                        ns_err = str(e)

                if name_servers:
                    ns0 = str(name_servers[0]).strip().strip(".").lower()
                    for suffix in self._iter_domain_suffixes(ns0):
                        tags = self._bl_nameservers_map.get(suffix)
                        if not tags:
                            continue
                        if any(self._indicator_type_enabled(tag) for tag in tags):
                            suspicious = True
                            self.alerts.append(
                                {
                                    "title": self.template["ACT-01"]["title"].format(dnsname, name_servers[0]),
                                    "description": self.template["ACT-01"]["description"].format(dnsname),
                                    "host": dnsname,
                                    "level": "Moderate",
                                    "id": "ACT-01",
                                }
                            )
                            break
                elif ns_err:
                    self.errors.append(f"Issue when doing a dig NS query to {domain}: {ns_err}")

                # WHOIS creation_date (prefer prefetch cache).
                creation_date = None
                whois_err = ""
                with self._domain_enrich_lock:
                    if domain in self._domain_whois_creation_cache:
                        creation_date = self._domain_whois_creation_cache.get(domain)
                    elif domain in self._domain_whois_err:
                        whois_err = self._domain_whois_err.get(domain) or ""
                if creation_date is None and not whois_err:
                    # Fallback: should be rare (prefetch best-effort).
                    try:
                        ok_w, whois_record, err_w = self._call_with_timeout(lambda: whois.whois(domain), 14)
                        if not ok_w:
                            raise RuntimeError(err_w or "timeout")
                        cd = whois_record.creation_date
                        creation_date = cd if type(cd) is not list else cd[0]
                    except Exception as e:
                        whois_err = str(e)

                if creation_date is None:
                    if whois_err:
                        if "timeout" in whois_err.lower():
                            self.errors.append(
                                f"WHOIS for {domain} timed out after 14s (registry slow, rate-limited, or unreachable). {whois_err}"
                            )
                        else:
                            self.errors.append(f"WHOIS query for {domain} failed: {whois_err}")
                    else:
                        self.errors.append(
                            f"WHOIS for {domain} returned no creation date (redacted or unparsed response)."
                        )
                else:
                    try:
                        creation_days = abs((datetime.now() - creation_date).days)
                        if creation_days < WHOIS_RECENT_REGISTRATION_MAX_DAYS:
                            suspicious = True
                            self.alerts.append(
                                {"title": self.template["ACT-02"]["title"].format(dnsname, creation_days),
                                 "description": self.template["ACT-02"]["description"].format(dnsname),
                                 "host": dnsname,
                                 "level": "Moderate",
                                 "id": "ACT-02"}
                            )
                    except Exception:
                        # Don't fail the whole check on weird creation_date types.
                        self.errors.append(
                            f"WHOIS for {domain} returned an unparseable creation date."
                        )
        
        return suspicious
        

    def check_flow(self, record):
        """Check a network flow against a set of IOCs / heuristics.
              1. Check if the IP Address is blacklisted 
              2. Check if the IP Address is inside a blacklisted CIDR
              3. Check if the UDP or ICMP protocol is going outside of the local network. 
              4. Check if the HTTP protocol is not using default HTTP ports.
              5. Check if the network flow is using a port > 1024.
        Args:
            record (dict): record to be processed.
        Returns:
            supicious (bool) : if an alert has been leveraged. 
        """
        if record["whitelisted"]: return 

        resolved_host = record["domains"][0] if len(record["domains"]) else record["ip_dst"]

        if self.iocs_analysis:
            host_tag = self._bl_hosts_map.get(record["ip_dst"])
            if host_tag and self._indicator_type_enabled(host_tag):
                if host_tag == "dual": 
                    record["suspicious"] = True
                    self.alerts.append({"title": self.template["IOC-12"]["title"],
                                        "description": self.template["IOC-12"]["description"].format(resolved_host),
                                        "host": resolved_host,
                                        "level": "Low",
                                        "id": "IOC-12"})
                if host_tag == "tracker": 
                    record["suspicious"] = True
                    self.alerts.append({"title": self.template["IOC-04"]["title"].format(resolved_host, "tracker"),
                                        "description": self.template["IOC-04"]["description"].format(resolved_host, "tracker"),
                                        "host": resolved_host,
                                        "level": "Low",
                                        "id": "IOC-04"})
                elif host_tag == "doh":
                    if 443 in [p["port"] for p in record["protocols"]]:
                        record["suspicious"] = True
                        self.alerts.append({"title": self.template["IOC-13"]["title"].format(f"{resolved_host}"),
                                            "description": self.template["IOC-13"]["description"].format(f"{resolved_host}"),
                                            "host": resolved_host,
                                            "level": "Low",
                                            "id": "IOC-13"})
                else:
                    record["suspicious"] = True
                    self.alerts.append({"title": self.template["IOC-01"]["title"].format(resolved_host, record["ip_dst"], host_tag.upper()),
                                        "description": self.template["IOC-01"]["description"].format(f"{resolved_host} ({record['ip_dst']})"),
                                        "host": resolved_host,
                                        "level": "High",
                                        "id": "IOC-01"})

            # ASN IOC: lookup ASN via local ip2asn table and match against IOC list.
            try:
                if self._bl_asns_map and record.get("ip_dst"):
                    asn_num, asn_org = self._resolve_asn_for_ip(record["ip_dst"])
                    if asn_num:
                        asn_tag = self._bl_asns_map.get(asn_num)
                        if asn_tag and self._indicator_type_enabled(asn_tag):
                            record["suspicious"] = True
                            # Best-effort proto/port for display
                            a_proto = None
                            a_port = None
                            try:
                                if record.get("protocols") and isinstance(record["protocols"], list) and record["protocols"]:
                                    p0 = record["protocols"][0]
                                    a_proto = p0.get("name")
                                    a_port = p0.get("port")
                            except Exception:
                                pass
                            self.alerts.append(
                                {
                                    "title": self.template["IOC-14"]["title"].format(asn_num, asn_org or ""),
                                    "description": self.template["IOC-14"]["description"].format(
                                        resolved_host, record["ip_dst"], asn_num, asn_org or ""
                                    ),
                                    "host": resolved_host,
                                    "proto": a_proto,
                                    "port": a_port,
                                    "level": "Moderate",
                                    "id": "IOC-14",
                                }
                            )
            except Exception:
                pass
            
            if record["ip_dst"] in self._tor_nodes_set:
                record["suspicious"] = True
                self.alerts.append({"title": self.template["IOC-11"]["title"].format(resolved_host, record["ip_dst"]),
                                    "description": self.template["IOC-11"]["description"].format(f"{resolved_host} ({record['ip_dst']})"),
                                    "host": resolved_host,
                                    "level": "High",
                                    "id": "IOC-11"})

            for cidr in self.bl_cidrs:
                try:
                    if IPAddress(record["ip_dst"]) in cidr[0] and self._indicator_type_enabled(cidr[1]):
                        record["suspicious"] = True
                        self.alerts.append({"title": self.template["IOC-02"]["title"].format(resolved_host, cidr[0], cidr[1].upper()),
                                            "description": self.template["IOC-02"]["description"].format(record["ip_dst"]),
                                            "host": resolved_host,
                                            "level": "Moderate",
                                            "id": "IOC-02"})
                except:
                    continue

        if self.heuristics_analysis:
            for protocol in record["protocols"]:
                if protocol["name"] in ["UDP", "ICMP", "IPV6-ICMP"]:
                    record["suspicious"] = True
                    self.alerts.append({"title": self.template["PROTO-01"]["title"].format(protocol["name"], resolved_host),
                                        "description": self.template["PROTO-01"]["description"].format(protocol["name"], resolved_host),
                                        "host": resolved_host,
                                        "proto": protocol.get("name"),
                                        "port": protocol.get("port"),
                                        "level": "Low",
                                        "id": "PROTO-01"})
                try:
                    if protocol["port"] >= int(self.max_ports):
                        record["suspicious"] = True
                        self.alerts.append({"title": self.template["PROTO-02"]["title"].format("", resolved_host,  self.max_ports),
                                            "description": self.template["PROTO-02"]["description"].format("", resolved_host, protocol["port"]),
                                            "host": resolved_host,
                                            "proto": protocol.get("name"),
                                            "port": protocol.get("port"),
                                            "level": "Low",
                                            "id": "PROTO-02"})
                except:
                    pass
                
                if protocol["name"] == "HTTP":
                    record["suspicious"] = True
                    self.alerts.append({"title": self.template["PROTO-03"]["title"].format(resolved_host),
                                        "description": self.template["PROTO-03"]["description"].format(resolved_host),
                                        "host":  resolved_host,
                                        "proto": protocol.get("name"),
                                        "port": protocol.get("port"),
                                        "level": "Low",
                                        "id": "PROTO-03"})

                if protocol["name"] == "HTTP" and protocol["port"] not in self.http_default_ports:
                    record["suspicious"] = True
                    self.alerts.append({"title": self.template["PROTO-04"]["title"].format(resolved_host, protocol["port"]),
                                        "description": self.template["PROTO-04"]["description"].format(resolved_host, protocol["port"]),
                                        "host":  resolved_host,
                                        "proto": protocol.get("name"),
                                        "port": protocol.get("port"),
                                        "level": "Moderate",
                                        "id": "PROTO-04"})

    def check_tls(self, record):
        """Check a TLS protocol and certificates against a set of IOCs / heuristics.
        Note since TLS 1.3, the certificate is not exchanged in clear text, therefore 
        we need to check it "actively" via the method active_check_ssl. 

              1. Check if the TLS record is not using default TLS ports.
              2. Check if one of the certificates is a free one, like Let's Encrypt.
              3. Check if the certificate is auto-signed. 
              4. If the certificate has an SNI, check the domain by calling check_dnsname.
        Args:
            record (dict): record to be processed.
        Returns:
            supicious (bool) : if an alert has been leveraged. 
        """
        if record["whitelisted"]: return

        resolved_host = record["domains"][0] if len(record["domains"]) else record["ip_dst"]
                
        for certificate in record["certificates"]:

            try:
                tls_port = self._coerce_tls_port(certificate)
                certificate["port"] = tls_port

                if "sni" in certificate and certificate["sni"] not in record["domains"]:
                    if certificate["sni"]:
                        if self.check_dnsname(certificate["sni"]):
                            record["suspicious"] = True

                default_ports = [int(p) for p in self.tls_default_ports]
                if tls_port not in default_ports:
                    record["suspicious"] = True
                    self.alerts.append({"title": self.template["SSL-01"]["title"].format(tls_port, resolved_host),
                                        "description": self.template["SSL-01"]["description"].format(resolved_host),
                                        "host": resolved_host,
                                        "proto": "TLS",
                                        "port": tls_port,
                                        "level": "Moderate",
                                        "id": "SSL-01"})

                cert_tls_ver = self._tls_version_number(certificate.get("version"))
                issuerdn = self._cert_issuerdn_str(certificate)
                subject = (certificate.get("subject") or "").strip() if isinstance(certificate.get("subject"), str) else ""

                if cert_tls_ver is not None and cert_tls_ver < 1.3 and issuerdn:

                    tags = self._bl_issuers_map.get(self._normalize_dn(issuerdn))
                    if tags and any(self._indicator_type_enabled(t) for t in tags):
                        record["suspicious"] = True
                        self.alerts.append({"title": self.template["SSL-02"]["title"].format(resolved_host),
                                            "description": self.template["SSL-02"]["description"],
                                            "host": resolved_host,
                                            "proto": "TLS",
                                            "port": tls_port,
                                            "level": "Moderate",
                                            "id": "SSL-02"})

                    elif subject and self._normalize_dn(issuerdn) == self._normalize_dn(subject):
                        record["suspicious"] = True
                        self.alerts.append({"title": self.template["SSL-03"]["title"].format(resolved_host),
                                            "description": self.template["SSL-03"]["description"].format(resolved_host),
                                            "host": resolved_host,
                                            "proto": "TLS",
                                            "port": tls_port,
                                            "level": "Moderate",
                                            "id": "SSL-03"})
                else:
                    # Even if the generic internet check fails, the target host
                    # may still be reachable. Try the active SSL check anyway.
                    # When offline, active checks can block on name resolution/connect; skip.
                    if self.active_analysis and self.connected:
                        host_for_ssl = self._get_host_for_ssl(record, certificate) or resolved_host
                        port = tls_port
                        cache_key = (host_for_ssl, port)

                        if host_for_ssl not in self.cert_checked:
                            self.cert_checked.add(host_for_ssl)

                            with self._active_ssl_lock:
                                cached = self._active_ssl_cache.get(cache_key)

                            if cached is None:
                                cached = self.active_check_ssl(host_for_ssl, port)
                                with self._active_ssl_lock:
                                    self._active_ssl_cache[cache_key] = bool(cached)

                            if cached:
                                record["suspicious"] = True
                                break
            except Exception as e:
                self.errors.append(f"Issue when processing the following certificate (check_tls): {json.dumps(certificate)}")
    
    def get_tor_nodes(self) -> list:
        """Get a list of TOR nodes from dan.me.uk.

        Returns:
            list: list of TOR nodes
        """

        nodes = []
        if os.path.exists("/tmp/tor_nodes.lst"):
            with open("/tmp/tor_nodes.lst", "r") as f:
                for l in f.readlines():
                    nodes.append(l.strip())
        else:
            if self.connected:
                try:
                    nodes_list = requests.get("https://www.dan.me.uk/torlist/", timeout=10).text
                    with open("/tmp/tor_nodes.lst", "w+") as f:
                        f.write(nodes_list)
                    for l in nodes_list.splitlines():
                        nodes.append(l.strip())
                    self._health_event("tor_nodes", True, "")
                except:
                    self._health_event("tor_nodes", False, "exception")
                    self.errors.append(f"Issue when trying to get TOR nodes from dan.me.uk")
        return nodes


    def check_http(self, record):
        """Check the HTTP hostname against a set of IOCs / heuristics.
        Args:
            record (dict): record to be processed.
        Returns:
            supicious (bool) : if an alert has been leveraged. 
        """
        if record["whitelisted"]: return

        if "http" in record:
            for http in record["http"]:
                if http["hostname"] not in record["domains"]:
                    if re.match(r"^[a-z\.0-9\-]+\.[a-z\-]{2,}$", http["hostname"]):
                        if http["hostname"]:
                            if self.check_dnsname(http["hostname"]):
                                record["suspicious"] = True

    def active_check_ssl(self, host, port):
        """This method:
        
        1. Check the issuer and subject of a certificate directly by connecting
        to the remote server in order to bypass TLS 1.3+ restrictions. 
        Most of this method was been taken from: https://tinyurl.com/3vsvhu79

        2. Get the JARM of the remote server by using the standard poc library
        from sales force. 

        Args:
            host (str): Host to connect to
            port (int): Port to connect to
        """
        try:
            suspect = False
            try:
                x509 = self._tls_handshake_get_peer_x509(host, port)
            except Exception as conn_err:
                self._health_event("active_ssl", False, str(conn_err))
                with self._active_ssl_lock:
                    self.errors.append(
                        f"Issue when trying to grab the SSL certificate located at {host}:{port} ({str(conn_err)})"
                    )
                return False

            self._cache_tls_hostname(host, port, x509)

            issuer = dict(x509.get_issuer().get_components())
            subject = dict(x509.get_subject().get_components())
            certhash = x509.digest("sha1").decode("utf8").replace(":", "").lower()
            issuer = self._format_x509_name(issuer)
            subject = self._format_x509_name(subject)

            issuer_tags = self._bl_issuers_map.get(self._normalize_dn(issuer))
            if issuer_tags and any(self._indicator_type_enabled(t) for t in issuer_tags):
                with self._active_ssl_lock:
                    self.alerts.append(
                        {
                            "title": self.template["SSL-02"]["title"].format(host),
                            "description": self.template["SSL-02"]["description"],
                            "host": host,
                            "proto": "TLS",
                            "port": port,
                            "level": "Moderate",
                            "id": "SSL-02",
                        }
                    )
                suspect = True

            if issuer == subject:
                with self._active_ssl_lock:
                    self.alerts.append({"title": self.template["SSL-03"]["title"].format(host),
                                        "description": self.template["SSL-03"]["description"].format(host),
                                        "host": host,
                                        "proto": "TLS",
                                        "port": port,
                                        "level": "Moderate",
                                        "id": "SSL-03"})
                suspect = True

            if self.iocs_analysis:
                cert_tag = self._bl_certs_map.get(certhash)
                if cert_tag and self._indicator_type_enabled(cert_tag):
                    with self._active_ssl_lock:
                        self.alerts.append({"title": self.template["SSL-04"]["title"].format(host, cert_tag.upper()),
                                            "description": self.template["SSL-04"]["description"].format(host),
                                            "host": host,
                                            "level": "High",
                                            "id": "SSL-04"})
                    suspect = True

                if self._bl_jarms_map:
                    host_jarm = get_jarm(host, port)
                    jarm_tag = self._bl_jarms_map.get(host_jarm)
                    if jarm_tag and self._indicator_type_enabled(jarm_tag):
                        with self._active_ssl_lock:
                            self.alerts.append({"title": self.template["SSL-05"]["title"].format(host, jarm_tag.upper()),
                                                "description": self.template["SSL-05"]["description"].format(host),
                                                "host": host,
                                                "level": "High",
                                                "id": "SSL-05"})
                        suspect = True

            self._health_event("active_ssl", True, "")
            return suspect
        except Exception as e:
            self._health_event("active_ssl", False, str(e))
            with self._active_ssl_lock:
                self.errors.append(f"Issue when trying to grab the SSL certificate located at {host}:{port} ({str(e)})")
            return False

    def get_alerts(self):
        """Retrieves the alerts triggered during the analysis

        Returns:
            list: list of the alerts.
        """
        self.analysis_end = datetime.now()
        return [dict(t) for t in {tuple(d.items()) for d in self.alerts}]
