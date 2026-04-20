#!/usr/bin/env python3
"""
Ray-Axis SIEM — Système d'alertes
Sorties : terminal coloré, fichier, email SMTP, webhook Slack/Discord
"""

import os
import json
import logging
import smtplib
import threading
import urllib.request
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

logger = logging.getLogger("alerter")

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]

# ── Couleurs ANSI ─────────────────────────────────────────────
C = {
    "critical": "\033[1;31m",
    "high":     "\033[0;31m",
    "medium":   "\033[0;33m",
    "low":      "\033[0;34m",
    "info":     "\033[0;32m",
    "corr":     "\033[0;35m",
    "reset":    "\033[0m",
    "bold":     "\033[1m",
    "dim":      "\033[2m",
    "cyan":     "\033[0;36m",
}

ICONS = {
    "critical":    "🔴 CRITIQUE",
    "high":        "🟠 ÉLEVÉ",
    "medium":      "🟡 MOYEN",
    "low":         "🔵 FAIBLE",
    "info":        "🟢 INFO",
    "correlation": "⚡ CORRÉLATION",
}

WEBHOOK_COLORS = {
    "critical": 0xFF2D55,
    "high":     0xFF6B2B,
    "medium":   0xFFD166,
    "low":      0x00E5A0,
    "info":     0x4DABF7,
}


class Alerter:
    def __init__(self, config: dict):
        self.cfg   = config.get("alerter", {})
        self._lock = threading.Lock()
        self._setup_file()

    def _setup_file(self):
        fcfg = self.cfg.get("file", {})
        if fcfg.get("enabled", False):
            path = fcfg.get("path", "/var/log/ray-axis/alerts.log")
            try:
                os.makedirs(os.path.dirname(path), exist_ok=True)
            except Exception:
                pass

    def send(self, alert: dict):
        if self.cfg.get("terminal", {}).get("enabled", True):
            self._terminal(alert)

        fcfg = self.cfg.get("file", {})
        if fcfg.get("enabled", True):
            self._file(alert, fcfg.get("path", "/var/log/ray-axis/alerts.log"))

        ecfg = self.cfg.get("email", {})
        if ecfg.get("enabled", False):
            min_sev = ecfg.get("min_severity", "high")
            sev     = alert.get("severity", "info")
            if SEVERITY_ORDER.index(sev) >= SEVERITY_ORDER.index(min_sev):
                t = threading.Thread(target=self._email, args=(alert, ecfg), daemon=True)
                t.start()

    # ── Terminal ──────────────────────────────────────────────

    def _terminal(self, alert: dict):
        sev     = alert.get("severity", "info")
        is_corr = alert.get("source_type") == "correlation"
        col     = C.get("corr" if is_corr else sev, "")
        reset   = C["reset"]
        bold    = C["bold"]
        dim     = C["dim"]
        cyan    = C["cyan"]
        icon    = ICONS.get("correlation" if is_corr else sev, sev.upper())
        ts      = alert.get("timestamp", "")[:19].replace("T", " ")
        sep     = ("═" if is_corr else "─") * 66

        lines = [
            f"\n{col}{sep}{reset}",
            f"{col}{bold}[{icon}]{reset}  {bold}{alert.get('rule_name','')}{reset}",
            f"{dim}{ts}  │  {alert.get('source_type','?')}  │  {alert.get('source_path','')}{reset}",
        ]

        if alert.get("description"):
            lines.append(f"  {alert['description']}")

        if alert.get("mitre_technique"):
            lines.append(
                f"  {cyan}MITRE{reset} {alert.get('mitre_tactic','')} "
                f"[{alert.get('mitre_technique','')}]"
            )

        details = []
        if alert.get("remote_ip"):
            geo  = alert.get("geo") or {}
            loc  = f" ({geo.get('country_code','?')} — {geo.get('city','?')})" if geo else ""
            ti   = alert.get("threat_intel") or {}
            flag = f"  {col}⚠ IP CONNUE MALVEILLANTE{reset}" if ti.get("known_malicious") else ""
            details.append(f"IP: {col}{alert['remote_ip']}{reset}{loc}{flag}")
        if alert.get("username"):
            details.append(f"User: {col}{alert['username']}{reset}")
        if alert.get("beats_host"):
            details.append(f"Hôte: {cyan}{alert['beats_host']}{reset}")
        if alert.get("http_path"):
            details.append(f"Path: {dim}{alert['http_path'][:80]}{reset}")
        if alert.get("count", 1) > 1:
            details.append(f"N: {col}{alert['count']}{reset}")
        if details:
            lines.append("  " + "  │  ".join(details))

        if alert.get("message"):
            lines.append(f"  {dim}↳{reset} {alert['message'][:280]}")

        if is_corr and alert.get("correlated_alerts"):
            seq = " → ".join(a.get("rule_id", "?") for a in alert["correlated_alerts"])
            lines.append(f"  {cyan}Séquence:{reset} {seq}")

        lines.append(f"{col}{sep}{reset}\n")
        with self._lock:
            print("\n".join(lines), flush=True)

    # ── Fichier ───────────────────────────────────────────────

    def _file(self, alert: dict, path: str):
        try:
            ts  = alert.get("timestamp", datetime.now().isoformat())[:19].replace("T", " ")
            sev = alert.get("severity", "?").upper()
            geo = alert.get("geo") or {}
            loc = f"[{geo.get('country_code','?')}]" if geo else ""
            ti  = alert.get("threat_intel") or {}
            threat_flag = " THREAT" if ti.get("known_malicious") else ""
            line = (
                f"[{ts}] [{sev}] {alert.get('rule_id','')} "
                f"| {alert.get('rule_name','')} "
                f"| src={alert.get('source_type','')} "
                f"ip={alert.get('remote_ip','N/A')}{loc}{threat_flag} "
                f"user={alert.get('username','N/A')} "
                f"host={alert.get('beats_host','N/A')} "
                f"count={alert.get('count',1)} "
                f"mitre={alert.get('mitre_technique','N/A')} "
                f"| {alert.get('message','')[:300]}\n"
            )
            with self._lock:
                with open(path, "a", encoding="utf-8") as f:
                    f.write(line)
        except Exception as e:
            logger.error(f"Écriture alerte fichier : {e}")

    # ── Email ─────────────────────────────────────────────────

    def _email(self, alert: dict, cfg: dict):
        try:
            sev    = alert.get("severity", "?").upper()
            subj   = f"[Ray-Axis] [{sev}] {alert.get('rule_name','')}"
            geo    = alert.get("geo") or {}
            geo_s  = f"{geo.get('country_name','?')} / {geo.get('city','?')}" if geo else "N/A"
            ti     = alert.get("threat_intel") or {}
            ti_s   = "OUI ⚠" if ti.get("known_malicious") else "non"

            body = f"""
Ray-Axis SIEM — Alerte de sécurité
====================================

Règle        : {alert.get('rule_id','')} — {alert.get('rule_name','')}
Sévérité     : {sev}
Horodatage   : {alert.get('timestamp','N/A')}
Source       : {alert.get('source_type','N/A')} ({alert.get('source_path','N/A')})
Hôte Beats   : {alert.get('beats_host','N/A')}

MITRE ATT&CK : {alert.get('mitre_tactic','N/A')} [{alert.get('mitre_technique','N/A')}]
Description  : {alert.get('description','N/A')}

IP source    : {alert.get('remote_ip','N/A')}
Géoloc.      : {geo_s}
Threat Intel : {ti_s}
Utilisateur  : {alert.get('username','N/A')}
Occurrences  : {alert.get('count',1)}

Message      :
{alert.get('message','N/A')[:800]}
"""
            msg = MIMEMultipart()
            msg["From"]    = cfg["from"]
            msg["To"]      = ", ".join(cfg["to"])
            msg["Subject"] = subj
            msg.attach(MIMEText(body, "plain", "utf-8"))

            with smtplib.SMTP(cfg["smtp_host"], cfg["smtp_port"]) as srv:
                srv.starttls()
                srv.login(cfg["smtp_user"], cfg["smtp_password"])
                srv.sendmail(cfg["from"], cfg["to"], msg.as_string())
            logger.info(f"Email envoyé : {alert.get('rule_id')}")
        except Exception as e:
            logger.error(f"Email erreur : {e}")
