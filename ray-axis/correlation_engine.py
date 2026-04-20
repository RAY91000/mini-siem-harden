#!/usr/bin/env python3
"""
Ray-Axis SIEM — Moteur de corrélation multi-sources
Détecte des séquences d'alertes sur une timeline partagée.
"""

import time
import logging
from collections import defaultdict
from datetime import datetime

logger = logging.getLogger("correlation")


class CorrelationEngine:
    def __init__(self, config: dict, alerter, storage):
        self.alerter = alerter
        self.storage = storage
        self.rules   = config.get("correlation_rules", [])
        # {corr_id: {field_value: [(ts, alert)]}}
        self._state  = defaultdict(lambda: defaultdict(list))
        logger.info(f"{len(self.rules)} règles de corrélation chargées.")

    def feed(self, alert: dict):
        triggered_id = alert.get("rule_id")
        if not triggered_id:
            return

        for rule in self.rules:
            sequence = rule.get("sequence", [])
            if triggered_id not in sequence:
                continue

            field     = rule.get("same_field", "remote_ip")
            field_val = alert.get(field)
            if not field_val:
                continue

            window   = rule.get("window_seconds", 300)
            corr_id  = rule["id"]
            now      = time.time()

            # Nettoyer les entrées expirées
            self._state[corr_id][field_val] = [
                (ts, a) for ts, a in self._state[corr_id][field_val]
                if now - ts <= window
            ]

            # Éviter les doublons immédiats
            if self._state[corr_id][field_val]:
                last_rule = self._state[corr_id][field_val][-1][1].get("rule_id")
                if last_rule == triggered_id:
                    # Mettre à jour plutôt que dupliquer
                    self._state[corr_id][field_val][-1] = (now, alert)
                else:
                    self._state[corr_id][field_val].append((now, alert))
            else:
                self._state[corr_id][field_val].append((now, alert))

            # Vérifier si toute la séquence est présente dans l'ordre
            seen = [a.get("rule_id") for _, a in self._state[corr_id][field_val]]
            if self._sequence_present(sequence, seen):
                history = list(self._state[corr_id][field_val])
                self._trigger(rule, field_val, field, history)
                self._state[corr_id][field_val] = []

    def _sequence_present(self, sequence: list, seen: list) -> bool:
        """Vérifie que toutes les étapes de la séquence sont présentes dans l'ordre."""
        it = iter(seen)
        return all(step in it for step in sequence)

    def _trigger(self, rule: dict, field_val: str, field: str, history: list):
        first = history[0][1]
        last  = history[-1][1]

        # Résumé de la séquence
        seq_str = " → ".join(a.get("rule_id", "?") for _, a in history)

        # Collecter toutes les IPs et usernames impliqués
        ips   = list({a.get("remote_ip") for _, a in history if a.get("remote_ip")})
        users = list({a.get("username")  for _, a in history if a.get("username")})

        corr_alert = {
            "rule_id":         rule["id"],
            "rule_name":       rule["name"],
            "description":     rule.get("description", ""),
            "severity":        rule.get("severity", "critical"),
            "mitre_tactic":    rule.get("mitre_tactic", ""),
            "mitre_technique": rule.get("mitre_technique", ""),
            "source_type":     "correlation",
            "source_path":     "multi-source",
            "timestamp":       datetime.now().isoformat(),
            "remote_ip":       ips[0]   if ips   else first.get("remote_ip"),
            "username":        users[0] if users else last.get("username"),
            "hostname":        last.get("hostname"),
            "beats_host":      last.get("beats_host"),
            "geo":             first.get("geo"),
            "threat_intel":    first.get("threat_intel"),
            "count":           len(history),
            "message":         f"Séquence : {seq_str} | {field}={field_val}",
            "correlated_alerts": [
                {
                    "rule_id":   a.get("rule_id"),
                    "rule_name": a.get("rule_name"),
                    "ts":        ts,
                    "ip":        a.get("remote_ip"),
                }
                for ts, a in history
            ],
        }

        logger.warning(
            f"CORRÉLATION [{rule['id']}] {rule['name']} "
            f"| {field}={field_val} | {len(history)} étapes"
        )
        self.storage.store_alert(corr_alert)
        self.alerter.send(corr_alert)
