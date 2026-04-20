#!/usr/bin/env python3
"""
Ray-Axis SIEM — Enrichissement des événements
GeoIP (MaxMind GeoLite2) + Threat Intelligence (blocklists publiques)
"""

import time
import logging
import ipaddress
import threading
import urllib.request
from typing import Optional

logger = logging.getLogger("enricher")

# IPs privées — jamais enrichies
PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
]


def is_private(ip: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
        return any(ip_obj in net for net in PRIVATE_NETWORKS) or ip_obj.is_loopback
    except ValueError:
        return True


class Enricher:
    def __init__(self, config: dict):
        self.cfg           = config.get("enricher", {})
        self._geoip_reader = None
        self._blocklist    = set()
        self._cache        = {}     # {ip: (ts, result)}
        self._lock         = threading.Lock()
        self._stats        = {"geoip_hits": 0, "threat_hits": 0, "cache_hits": 0}

        self._init_geoip()
        self._init_threat_intel()

    # ── GeoIP ─────────────────────────────────────────────────

    def _init_geoip(self):
        gcfg = self.cfg.get("geoip", {})
        if not gcfg.get("enabled", False):
            return
        db_path = gcfg.get("db_path", "/usr/share/GeoIP/GeoLite2-City.mmdb")
        try:
            import geoip2.database
            self._geoip_reader = geoip2.database.Reader(db_path)
            logger.info(f"GeoIP initialisé : {db_path}")
        except ImportError:
            logger.warning("geoip2 non installé — pip install geoip2")
        except FileNotFoundError:
            logger.warning(f"Base GeoIP introuvable : {db_path}")
        except Exception as e:
            logger.warning(f"GeoIP erreur : {e}")

    def _geoip_lookup(self, ip: str) -> Optional[dict]:
        if not self._geoip_reader:
            return None
        try:
            r = self._geoip_reader.city(ip)
            self._stats["geoip_hits"] += 1
            return {
                "country_code": r.country.iso_code,
                "country_name": r.country.name,
                "city":         r.city.name,
                "latitude":     r.location.latitude,
                "longitude":    r.location.longitude,
                "asn":          None,
            }
        except Exception:
            return None

    # ── Threat Intelligence ───────────────────────────────────

    def _init_threat_intel(self):
        tcfg = self.cfg.get("threat_intel", {})
        if not tcfg.get("enabled", False):
            return
        t = threading.Thread(target=self._load_blocklists, daemon=True, name="threat-intel-loader")
        t.start()

    def _load_blocklists(self):
        tcfg  = self.cfg.get("threat_intel", {})
        urls  = tcfg.get("blocklists", [])
        total = 0
        for url in urls:
            try:
                req = urllib.request.Request(
                    url, headers={"User-Agent": "Ray-Axis-SIEM/1.0"}
                )
                with urllib.request.urlopen(req, timeout=15) as r:
                    for line in r.read().decode("utf-8", errors="ignore").splitlines():
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        ip = line.split()[0]
                        try:
                            ipaddress.ip_address(ip)
                            self._blocklist.add(ip)
                            total += 1
                        except ValueError:
                            pass
            except Exception as e:
                logger.debug(f"Blocklist {url}: {e}")
        logger.info(f"Threat Intel : {total} IPs malveillantes chargées")

    # ── Enrich ────────────────────────────────────────────────

    def enrich(self, event: dict) -> dict:
        ip = event.get("remote_ip")
        if not ip or is_private(ip):
            return event

        ttl = self.cfg.get("threat_intel", {}).get("cache_ttl_seconds", 3600)

        with self._lock:
            cached = self._cache.get(ip)
            if cached and time.time() - cached[0] < ttl:
                self._stats["cache_hits"] += 1
                event["geo"]          = cached[1].get("geo")
                event["threat_intel"] = cached[1].get("threat_intel")
                return event

        geo    = self._geoip_lookup(ip)
        threat = None
        if self._blocklist:
            is_threat = ip in self._blocklist
            if is_threat:
                self._stats["threat_hits"] += 1
            threat = {"known_malicious": is_threat}

        with self._lock:
            self._cache[ip] = (time.time(), {"geo": geo, "threat_intel": threat})

        event["geo"]          = geo
        event["threat_intel"] = threat
        return event

    def get_stats(self) -> dict:
        return dict(self._stats)
