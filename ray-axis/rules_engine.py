#!/usr/bin/env python3
"""
Ray-Axis SIEM — Moteur de règles
Détection par regex + seuils + fenêtres temporelles + MITRE ATT&CK
"""

import re
import time
import logging
from collections import defaultdict
from datetime import datetime

logger = logging.getLogger("rules")


class RulesEngine:
    def __init__(self, config, alerter, storage, enricher, responder, correlation_engine):
        self.config     = config
        self.alerter    = alerter
        self.storage    = storage
        self.enricher   = enricher
        self.responder  = responder
        self.corr       = correlation_engine
        self.rules      = self._compile_rules(config.get("rules", []))
        # {rule_id: [(timestamp, event), ...]}
        self._counters  = defaultdict(list)
        # Stats de performance
        self._stats     = defaultdict(int)

    def _compile_rules(self, raw_rules: list) -> list:
        compiled = []
        for rule in raw_rules:
            try:
                r = dict(rule)
                r["_pattern"] = re.compile(rule["pattern"], re.IGNORECASE)
                compiled.append(r)
            except re.error as e:
                logger.error(f"Règle invalide '{rule.get('id')}': {e}")
        logger.info(f"{len(compiled)} règles chargées.")
        return compiled

    def evaluate(self, event: dict):
        source_type = event.get("source_type", "")
        message     = event.get("message", "") or event.get("raw", "")

        for rule in self.rules:
            allowed = rule.get("source_types", [])
            if allowed and source_type not in allowed:
                continue

            if not rule["_pattern"].search(message):
                continue

            # Enrichissement (GeoIP, threat intel)
            event = self.enricher.enrich(event)

            # Stocker l'événement brut
            self.storage.store_event(event, rule)
            self._stats[rule["id"]] += 1

            threshold = rule.get("threshold", 1)
            window    = rule.get("window_seconds", 1)

            if threshold <= 1:
                self._trigger(rule, event, count=1)
            else:
                self._count_and_check(rule, event, threshold, window)

    def _count_and_check(self, rule: dict, event: dict, threshold: int, window: int):
        rule_id = rule["id"]
        now = time.time()

        # Clé de regroupement : par IP si disponible, sinon global
        group_key = event.get("remote_ip") or "global"
        counter_key = f"{rule_id}:{group_key}"

        self._counters[counter_key].append((now, event))
        self._counters[counter_key] = [
            (ts, ev) for ts, ev in self._counters[counter_key]
            if now - ts <= window
        ]
        count = len(self._counters[counter_key])

        if count >= threshold:
            self._trigger(rule, event, count=count)
            self._counters[counter_key] = []

    def _trigger(self, rule: dict, event: dict, count: int = 1):
        alert = {
            "rule_id":         rule["id"],
            "rule_name":       rule["name"],
            "description":     rule.get("description", ""),
            "severity":        rule.get("severity", "medium"),
            "mitre_tactic":    rule.get("mitre_tactic", ""),
            "mitre_technique": rule.get("mitre_technique", ""),
            "source_type":     event.get("source_type"),
            "source_path":     event.get("source_path"),
            "timestamp":       event.get("parsed_at", datetime.now().isoformat()),
            "event_timestamp": event.get("timestamp"),
            "message":         event.get("message", ""),
            "raw":             event.get("raw", ""),
            "remote_ip":       event.get("remote_ip"),
            "username":        event.get("username"),
            "hostname":        event.get("hostname"),
            "beats_host":      event.get("beats_host"),
            "http_status":     event.get("http_status"),
            "http_path":       event.get("http_path"),
            "geo":             event.get("geo"),
            "threat_intel":    event.get("threat_intel"),
            "count":           count,
        }

        self.storage.store_alert(alert)
        self.alerter.send(alert)
        self.responder.handle(alert)
        self.corr.feed(alert)

    def get_stats(self) -> dict:
        return dict(self._stats)
