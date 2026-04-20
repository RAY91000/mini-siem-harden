#!/usr/bin/env python3
"""
Ray-Axis SIEM — Parseur de logs
Normalise les entrées de toutes les sources vers un format commun (inspiré ECS).
"""

import re
import logging
from datetime import datetime
from typing import Optional

logger = logging.getLogger("parser")

# ── Patterns par type de source ───────────────────────────────

PATTERNS = {
    "auth": re.compile(
        r"^(?P<timestamp>\w{3}\s+\d+\s+\d+:\d+:\d+)\s+"
        r"(?P<hostname>\S+)\s+"
        r"(?P<program>\S+?)(?:\[(?P<pid>\d+)\])?:\s+"
        r"(?P<message>.+)$"
    ),
    "syslog": re.compile(
        r"^(?P<timestamp>\w{3}\s+\d+\s+\d+:\d+:\d+)\s+"
        r"(?P<hostname>\S+)\s+"
        r"(?P<program>\S+?)(?:\[(?P<pid>\d+)\])?:\s+"
        r"(?P<message>.+)$"
    ),
    "nginx": re.compile(
        r'^(?P<remote_addr>\S+)\s+-\s+(?P<remote_user>\S+)\s+'
        r'\[(?P<timestamp>[^\]]+)\]\s+'
        r'"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<protocol>[^"]+)"\s+'
        r'(?P<status>\d+)\s+(?P<body_bytes>\d+)\s+'
        r'"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)"'
        r'(?:\s+(?P<request_time>[\d.]+))?'
    ),
    "apache": re.compile(
        r'^(?P<remote_addr>\S+)\s+\S+\s+(?P<remote_user>\S+)\s+'
        r'\[(?P<timestamp>[^\]]+)\]\s+'
        r'"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<protocol>[^"]+)"\s+'
        r'(?P<status>\d+)\s+(?P<body_bytes>\S+)'
    ),
    "journald": re.compile(
        r"^(?P<timestamp>\S+)\s+"
        r"(?P<hostname>\S+)\s+"
        r"(?P<program>\S+?)(?:\[(?P<pid>\d+)\])?:\s+"
        r"(?P<message>.+)$"
    ),
    # Logs JSON structurés (ex: app Node.js)
    "app": re.compile(
        r'^(?P<json_data>\{.+\})$'
    ),
}

IP_RE      = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
USER_RE    = re.compile(r'(?:for(?:\sinvalid\suser)?|user)\s+(\S+)', re.IGNORECASE)
PORT_RE    = re.compile(r'\bport\s+(\d+)', re.IGNORECASE)
PROCESS_RE = re.compile(r'\bprocess\s+(\d+)', re.IGNORECASE)


class LogParser:

    def parse(self, raw_line: str, source_type: str, source_path: str) -> Optional[dict]:
        if not raw_line.strip():
            return None

        pattern = PATTERNS.get(source_type)

        # Essayer le pattern spécifique
        if pattern:
            m = pattern.match(raw_line)
            if m:
                return self._build_event(m, raw_line, source_type, source_path)

        # Fallback : event générique
        return self._generic(raw_line, source_type, source_path)

    def _build_event(self, m: re.Match, raw_line: str, source_type: str, source_path: str) -> dict:
        event = {
            "raw":         raw_line,
            "source_type": source_type,
            "source_path": source_path,
            "parsed_at":   datetime.now().isoformat(),
        }
        event.update({k: v for k, v in m.groupdict().items() if v is not None})

        if source_type in ("auth", "syslog", "journald"):
            event["timestamp"] = self._normalize_ts(event.get("timestamp", ""))
            msg = event.get("message", raw_line)
            ips   = IP_RE.findall(msg)
            users = USER_RE.findall(msg)
            ports = PORT_RE.findall(msg)
            procs = PROCESS_RE.findall(msg)
            event["remote_ip"] = ips[0]   if ips   else None
            event["username"]  = users[0] if users else None
            event["src_port"]  = ports[0] if ports else None
            event["process_id"]= procs[0] if procs else event.get("pid")
            event["message"]   = msg

        elif source_type in ("nginx", "apache"):
            event["timestamp"]   = datetime.now().isoformat()
            event["remote_ip"]   = event.get("remote_addr")
            event["http_status"] = int(event.get("status", 0) or 0)
            event["http_method"] = event.get("method", "")
            event["http_path"]   = event.get("path", "")
            event["username"]    = None
            event["message"]     = (
                f"{event.get('method','')} {event.get('path','')} "
                f"[{event.get('status','')}] "
                f'"{event.get("user_agent","")}"'
            )

        elif source_type == "app":
            import json as _json
            try:
                data = _json.loads(event.get("json_data", "{}"))
                event.update(data)
                event["message"]   = data.get("message", raw_line)
                event["remote_ip"] = data.get("ip", data.get("remote_ip"))
                event["username"]  = data.get("username", data.get("user"))
                event["timestamp"] = data.get("timestamp", datetime.now().isoformat())
            except Exception:
                pass

        return event

    def _generic(self, raw_line: str, source_type: str, source_path: str) -> dict:
        ips   = IP_RE.findall(raw_line)
        users = USER_RE.findall(raw_line)
        return {
            "raw":         raw_line,
            "source_type": source_type,
            "source_path": source_path,
            "message":     raw_line,
            "parsed_at":   datetime.now().isoformat(),
            "timestamp":   datetime.now().isoformat(),
            "remote_ip":   ips[0]   if ips   else None,
            "username":    users[0] if users else None,
            "hostname":    None,
            "program":     None,
            "pid":         None,
        }

    def _normalize_ts(self, ts: str) -> str:
        if not ts:
            return datetime.now().isoformat()
        # Syslog : "Jan  5 14:30:00"
        for fmt in ("%b %d %H:%M:%S", "%b  %d %H:%M:%S"):
            try:
                dt = datetime.strptime(ts.strip(), fmt).replace(year=datetime.now().year)
                return dt.isoformat()
            except ValueError:
                pass
        # ISO 8601 (journald) : "2026-04-18T15:30:00+0200"
        try:
            return datetime.fromisoformat(ts.split("+")[0].split("Z")[0]).isoformat()
        except Exception:
            pass
        return datetime.now().isoformat()
