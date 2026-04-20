#!/usr/bin/env python3
"""
Ray-Axis SIEM — Répondeur automatisé
Blocage IP iptables + notifications webhook Slack/Discord
"""

import json
import logging
import ipaddress
import subprocess
import threading
import urllib.request
from datetime import datetime

logger = logging.getLogger("responder")

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]

WEBHOOK_COLORS = {
    "critical": 0xFF2D55,
    "high":     0xFF6B2B,
    "medium":   0xFFD166,
    "low":      0x00E5A0,
    "info":     0x4DABF7,
}


class Responder:
    def __init__(self, config: dict):
        self.cfg          = config.get("responder", {})
        self._blocked_ips = set()
        self._lock        = threading.Lock()
        self._stats       = {"ips_blocked": 0, "webhooks_sent": 0, "webhook_errors": 0}

    def handle(self, alert: dict):
        sev = alert.get("severity", "info")

        # Blocage IP automatique
        block_cfg = self.cfg.get("auto_block_ip", {})
        if block_cfg.get("enabled", False):
            if sev in block_cfg.get("severities", ["critical"]):
                ip = alert.get("remote_ip")
                if ip:
                    threading.Thread(
                        target=self._block_ip,
                        args=(ip, alert, block_cfg),
                        daemon=True,
                    ).start()

        # Webhook
        wh_cfg = self.cfg.get("webhook", {})
        if wh_cfg.get("enabled", False) and wh_cfg.get("url"):
            min_sev = wh_cfg.get("min_severity", "high")
            if SEVERITY_ORDER.index(sev) >= SEVERITY_ORDER.index(min_sev):
                threading.Thread(
                    target=self._send_webhook,
                    args=(alert, wh_cfg),
                    daemon=True,
                ).start()

    # ── Blocage IP ────────────────────────────────────────────

    def _block_ip(self, ip: str, alert: dict, cfg: dict):
        with self._lock:
            if ip in self._blocked_ips:
                return

        # Vérifier whitelist
        whitelist = cfg.get("whitelist", [])
        try:
            ip_obj = ipaddress.ip_address(ip)
            for entry in whitelist:
                try:
                    if ip_obj in ipaddress.ip_network(entry, strict=False):
                        logger.debug(f"IP {ip} whitelistée — pas de blocage")
                        return
                except ValueError:
                    if ip == entry:
                        return
        except ValueError:
            return

        try:
            # Vérifier si déjà bloquée
            check = subprocess.run(
                ["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
                capture_output=True
            )
            if check.returncode == 0:
                with self._lock:
                    self._blocked_ips.add(ip)
                return

            subprocess.run(
                ["iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP",
                 "-m", "comment", "--comment", f"ray-axis:{alert.get('rule_id','')}"],
                check=True, capture_output=True
            )
            with self._lock:
                self._blocked_ips.add(ip)
                self._stats["ips_blocked"] += 1

            logger.warning(
                f"[BLOCK] IP bloquée : {ip} "
                f"(règle: {alert.get('rule_id')}, sévérité: {alert.get('severity')})"
            )
        except subprocess.CalledProcessError as e:
            logger.error(f"Échec blocage iptables {ip}: {e}")
        except FileNotFoundError:
            logger.warning("iptables non disponible — blocage IP désactivé")

    # ── Webhook ───────────────────────────────────────────────

    def _send_webhook(self, alert: dict, cfg: dict):
        url   = cfg.get("url", "")
        sev   = alert.get("severity", "info")
        color = WEBHOOK_COLORS.get(sev, 0x888888)
        ts    = alert.get("timestamp", datetime.now().isoformat())[:19].replace("T", " ")

        is_corr = alert.get("source_type") == "correlation"
        title   = f"{'⚡ ' if is_corr else ''}[{sev.upper()}] {alert.get('rule_name','')}"

        # Construire le détail
        details = []
        if alert.get("remote_ip"):
            geo = alert.get("geo") or {}
            loc = f" ({geo.get('country_code','?')})" if geo else ""
            ti  = alert.get("threat_intel") or {}
            flag = " ⚠ MALVEILLANTE" if ti.get("known_malicious") else ""
            details.append(f"**IP** : `{alert['remote_ip']}`{loc}{flag}")
        if alert.get("username"):
            details.append(f"**Utilisateur** : `{alert['username']}`")
        if alert.get("beats_host"):
            details.append(f"**Hôte** : `{alert['beats_host']}`")
        if alert.get("mitre_technique"):
            details.append(f"**MITRE** : {alert.get('mitre_tactic','')} [{alert['mitre_technique']}]")
        if alert.get("count", 1) > 1:
            details.append(f"**Occurrences** : {alert['count']}")

        details_str = "\n".join(details)
        msg_str     = (alert.get("message") or "")[:300]
        desc        = alert.get("description", "")

        is_discord = "discord.com" in url or "discordapp.com" in url

        if is_discord:
            payload = {
                "embeds": [{
                    "title":       title,
                    "description": f"{desc}\n\n{details_str}\n```{msg_str}```" if details_str else f"{desc}\n```{msg_str}```",
                    "color":       color,
                    "footer":      {"text": f"Ray-Axis SIEM • {ts}"},
                }]
            }
        else:
            # Slack
            payload = {
                "text": f"*{title}*",
                "attachments": [{
                    "color":  f"#{color:06X}",
                    "fields": [
                        {"title": "Description", "value": desc,        "short": False},
                        {"title": "Détails",     "value": details_str, "short": False},
                        {"title": "Message",     "value": f"`{msg_str}`", "short": False},
                    ],
                    "footer": f"Ray-Axis SIEM | {ts}",
                }]
            }

        try:
            data = json.dumps(payload).encode("utf-8")
            req  = urllib.request.Request(
                url, data=data,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent":   "Ray-Axis-SIEM/1.0",
                }
            )
            with urllib.request.urlopen(req, timeout=5) as r:
                self._stats["webhooks_sent"] += 1
                logger.debug(f"Webhook envoyé : {r.status}")
        except Exception as e:
            self._stats["webhook_errors"] += 1
            logger.error(f"Webhook erreur : {e}")

    def get_stats(self) -> dict:
        return dict(self._stats)
