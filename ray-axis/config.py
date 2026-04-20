#!/usr/bin/env python3
"""
Ray-Axis SIEM — Chargement et validation de la configuration
"""

import os
import yaml
import logging

logger = logging.getLogger("config")

DEFAULT_CONFIG = {
    "log_sources": [
        {"path": "/var/log/auth.log",          "type": "auth",   "enabled": True},
        {"path": "/var/log/syslog",             "type": "syslog", "enabled": True},
        {"path": "/var/log/nginx/access.log",   "type": "nginx",  "enabled": False},
        {"path": "/var/log/apache2/access.log", "type": "apache", "enabled": False},
    ],
    "journald": {
        "enabled": True,
        "units": ["sshd", "sudo", "cron", "systemd"]
    },
    "beats_input": {
        "enabled": False,
        "host": "0.0.0.0",
        "port": 5044,
        "tls_cert": "",
        "tls_key": "",
        "tls_ca": "",
        "mtls": False,
    },
    "rules": [
        {
            "id": "SSH_BRUTE_FORCE",
            "name": "Brute force SSH",
            "description": "Trop de tentatives SSH échouées depuis la même IP",
            "source_types": ["auth", "journald"],
            "pattern": "Failed password",
            "threshold": 5,
            "window_seconds": 60,
            "severity": "high",
            "mitre_tactic": "Credential Access",
            "mitre_technique": "T1110.001",
        },
        {
            "id": "SSH_ROOT_LOGIN",
            "name": "Connexion root SSH",
            "description": "Tentative de connexion SSH directe en root",
            "source_types": ["auth", "journald"],
            "pattern": "Failed password for root",
            "threshold": 1,
            "window_seconds": 3600,
            "severity": "critical",
            "mitre_tactic": "Privilege Escalation",
            "mitre_technique": "T1078.003",
        },
        {
            "id": "SSH_ACCEPTED",
            "name": "Connexion SSH réussie",
            "description": "Authentification SSH acceptée",
            "source_types": ["auth", "journald"],
            "pattern": r"Accepted (password|publickey)",
            "threshold": 1,
            "window_seconds": 1,
            "severity": "info",
            "mitre_tactic": "Initial Access",
            "mitre_technique": "T1078",
        },
        {
            "id": "SUDO_FAILURE",
            "name": "Échec sudo répété",
            "description": "Commandes sudo refusées de façon répétée",
            "source_types": ["auth", "journald"],
            "pattern": "incorrect password attempts",
            "threshold": 3,
            "window_seconds": 300,
            "severity": "medium",
            "mitre_tactic": "Privilege Escalation",
            "mitre_technique": "T1548.003",
        },
        {
            "id": "SUDO_SUCCESS",
            "name": "Escalade sudo réussie",
            "description": "Commande sudo exécutée avec succès",
            "source_types": ["auth", "journald"],
            "pattern": r"sudo:.*COMMAND=",
            "threshold": 1,
            "window_seconds": 1,
            "severity": "low",
            "mitre_tactic": "Privilege Escalation",
            "mitre_technique": "T1548.003",
        },
        {
            "id": "NEW_USER_CREATED",
            "name": "Nouvel utilisateur créé",
            "description": "Création d'un compte utilisateur système",
            "source_types": ["auth", "syslog"],
            "pattern": r"new user|useradd",
            "threshold": 1,
            "window_seconds": 1,
            "severity": "medium",
            "mitre_tactic": "Persistence",
            "mitre_technique": "T1136.001",
        },
        {
            "id": "OOM_KILLER",
            "name": "OOM Killer déclenché",
            "description": "Le kernel a tué un processus par manque de mémoire",
            "source_types": ["syslog", "journald"],
            "pattern": r"Out of memory|oom-killer",
            "threshold": 1,
            "window_seconds": 1,
            "severity": "high",
            "mitre_tactic": "Impact",
            "mitre_technique": "T1499",
        },
        {
            "id": "KERNEL_PANIC",
            "name": "Kernel panic",
            "description": "Panique du noyau Linux",
            "source_types": ["syslog", "journald"],
            "pattern": "Kernel panic",
            "threshold": 1,
            "window_seconds": 1,
            "severity": "critical",
            "mitre_tactic": "Impact",
            "mitre_technique": "T1499",
        },
        {
            "id": "NGINX_4XX_FLOOD",
            "name": "Scan HTTP (flood 4xx)",
            "description": "Trop de requêtes 4xx en peu de temps — scan probable",
            "source_types": ["nginx", "apache"],
            "pattern": r'" 4[0-9]{2} ',
            "threshold": 20,
            "window_seconds": 60,
            "severity": "medium",
            "mitre_tactic": "Discovery",
            "mitre_technique": "T1595.002",
        },
        {
            "id": "NGINX_SQL_INJECTION",
            "name": "Injection SQL",
            "description": "Pattern SQL injection détecté dans les requêtes web",
            "source_types": ["nginx", "apache"],
            "pattern": r"(?i)(union.*select|drop.*table|insert.*into|'\s*or\s*'1'\s*=\s*'1)",
            "threshold": 1,
            "window_seconds": 1,
            "severity": "critical",
            "mitre_tactic": "Initial Access",
            "mitre_technique": "T1190",
        },
        {
            "id": "NGINX_XSS",
            "name": "Tentative XSS",
            "description": "Pattern XSS détecté dans les requêtes web",
            "source_types": ["nginx", "apache"],
            "pattern": r"(?i)(<script|javascript:|onerror=|onload=|alert\()",
            "threshold": 1,
            "window_seconds": 1,
            "severity": "high",
            "mitre_tactic": "Initial Access",
            "mitre_technique": "T1190",
        },
        {
            "id": "NGINX_PATH_TRAVERSAL",
            "name": "Path traversal",
            "description": "Tentative de traversée de répertoire",
            "source_types": ["nginx", "apache"],
            "pattern": r"(\.\./|%2e%2e%2f|%252e%252e)",
            "threshold": 1,
            "window_seconds": 1,
            "severity": "high",
            "mitre_tactic": "Discovery",
            "mitre_technique": "T1083",
        },
        {
            "id": "NGINX_SCANNER",
            "name": "Outil de scan détecté",
            "description": "User-agent d'outil de scan ou d'attaque reconnu",
            "source_types": ["nginx", "apache"],
            "pattern": r"(?i)(sqlmap|nikto|nmap|masscan|dirbuster|gobuster|wfuzz|hydra|burpsuite|zgrab)",
            "threshold": 1,
            "window_seconds": 1,
            "severity": "high",
            "mitre_tactic": "Discovery",
            "mitre_technique": "T1595",
        },
        {
            "id": "CRON_MODIFICATION",
            "name": "Cron modifié",
            "description": "Modification d'une tâche cron détectée",
            "source_types": ["syslog", "auth"],
            "pattern": r"CRON.*CMD|crontab",
            "threshold": 5,
            "window_seconds": 300,
            "severity": "low",
            "mitre_tactic": "Persistence",
            "mitre_technique": "T1053.003",
        },
        {
            "id": "SYSTEMD_SERVICE_ADDED",
            "name": "Nouveau service systemd",
            "description": "Un nouveau service systemd a été installé",
            "source_types": ["syslog", "journald"],
            "pattern": r"systemd.*Created symlink|systemd.*Installed",
            "threshold": 1,
            "window_seconds": 1,
            "severity": "low",
            "mitre_tactic": "Persistence",
            "mitre_technique": "T1543.002",
        },
        {
            "id": "SSH_PORT_SCAN",
            "name": "Scan de port SSH",
            "description": "Multiples connexions SSH depuis la même IP sans authentification",
            "source_types": ["auth", "journald"],
            "pattern": r"Connection closed by|Did not receive identification string",
            "threshold": 10,
            "window_seconds": 30,
            "severity": "medium",
            "mitre_tactic": "Discovery",
            "mitre_technique": "T1046",
        },
    ],
    "correlation_rules": [
        {
            "id": "BRUTE_FORCE_SUCCESS",
            "name": "Brute force SSH réussi",
            "description": "Brute force suivi d'une connexion SSH réussie depuis la même IP",
            "sequence": ["SSH_BRUTE_FORCE", "SSH_ACCEPTED"],
            "window_seconds": 300,
            "same_field": "remote_ip",
            "severity": "critical",
            "mitre_tactic": "Initial Access",
            "mitre_technique": "T1110.001",
        },
        {
            "id": "RECON_THEN_EXPLOIT",
            "name": "Reconnaissance puis exploitation web",
            "description": "Scan 4xx suivi d'une injection SQL depuis la même IP",
            "sequence": ["NGINX_4XX_FLOOD", "NGINX_SQL_INJECTION"],
            "window_seconds": 600,
            "same_field": "remote_ip",
            "severity": "critical",
            "mitre_tactic": "Initial Access",
            "mitre_technique": "T1595",
        },
        {
            "id": "SCAN_THEN_BRUTE",
            "name": "Scan puis brute force",
            "description": "Scan de port SSH suivi d'un brute force depuis la même IP",
            "sequence": ["SSH_PORT_SCAN", "SSH_BRUTE_FORCE"],
            "window_seconds": 300,
            "same_field": "remote_ip",
            "severity": "high",
            "mitre_tactic": "Credential Access",
            "mitre_technique": "T1110",
        },
        {
            "id": "PRIVESC_AFTER_LOGIN",
            "name": "Escalade après connexion",
            "description": "Connexion SSH réussie suivie d'une élévation sudo",
            "sequence": ["SSH_ACCEPTED", "SUDO_SUCCESS"],
            "window_seconds": 600,
            "same_field": "username",
            "severity": "high",
            "mitre_tactic": "Privilege Escalation",
            "mitre_technique": "T1548",
        },
    ],
    "enricher": {
        "geoip": {
            "enabled": False,
            "db_path": "/usr/share/GeoIP/GeoLite2-City.mmdb",
        },
        "threat_intel": {
            "enabled": False,
            "cache_ttl_seconds": 3600,
            "blocklists": [
                "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",
                "https://lists.blocklist.de/lists/ssh.txt",
            ],
        },
    },
    "responder": {
        "auto_block_ip": {
            "enabled": False,
            "severities": ["critical"],
            "whitelist": [
                "127.0.0.1",
                "10.0.0.0/8",
                "192.168.0.0/16",
                "172.16.0.0/12",
            ],
        },
        "webhook": {
            "enabled": False,
            "url": "",
            "min_severity": "high",
        },
    },
    "alerter": {
        "terminal": {"enabled": True, "colors": True},
        "file": {
            "enabled": True,
            "path": "/var/log/ray-axis/alerts.log",
        },
        "email": {
            "enabled": False,
            "smtp_host": "smtp.gmail.com",
            "smtp_port": 587,
            "smtp_user": "",
            "smtp_password": "",
            "from": "",
            "to": [],
            "min_severity": "high",
        },
    },
    "storage": {
        "db_path": "/var/lib/ray-axis/events.db",
        "max_events": 200000,
        "max_alerts": 100000,
    },
    "dashboard": {
        "enabled": True,
        "host": "0.0.0.0",
        "port": 5000,
        "secret_key": "change-me-in-production",
        "auth": False,
    },
}

# Niveaux de sévérité ordonnés
SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]


def load_config(path: str = "config.yaml") -> dict:
    if not os.path.exists(path):
        logger.warning(f"Config '{path}' introuvable — valeurs par défaut utilisées.")
        return DEFAULT_CONFIG

    with open(path, "r", encoding="utf-8") as f:
        user = yaml.safe_load(f) or {}

    # Fusion profonde sur les dicts de premier niveau
    merged = dict(DEFAULT_CONFIG)
    for key, default_val in DEFAULT_CONFIG.items():
        if key not in user:
            continue
        if isinstance(default_val, dict) and isinstance(user[key], dict):
            merged[key] = {**default_val, **user[key]}
        else:
            merged[key] = user[key]

    # Les listes de rules/correlation_rules remplacent entièrement les défauts
    for list_key in ("rules", "correlation_rules", "log_sources"):
        if list_key in user:
            merged[list_key] = user[list_key]

    logger.debug(f"Config chargée depuis {path}")
    return merged
