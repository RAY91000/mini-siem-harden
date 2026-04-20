#!/usr/bin/env python3
"""
Ray-Axis SIEM — Stockage SQLite
Tables : events, alerts + FTS5 pour la recherche full-text
"""

import os
import json
import sqlite3
import logging
import threading
from datetime import datetime

logger = logging.getLogger("storage")


class Storage:
    def __init__(self, config: dict):
        self.cfg     = config.get("storage", {})
        db_path      = self.cfg.get("db_path", "/var/lib/ray-axis/events.db")
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.db_path = db_path
        self._lock   = threading.Lock()
        self._init_db()

    def _conn(self) -> sqlite3.Connection:
        c = sqlite3.connect(self.db_path, check_same_thread=False, timeout=10)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA journal_mode=WAL")   # Meilleure concurrence
        c.execute("PRAGMA synchronous=NORMAL") # Bon compromis perf/sécurité
        c.execute("PRAGMA foreign_keys=ON")
        return c

    def _init_db(self):
        with self._lock, self._conn() as c:
            c.executescript("""
                CREATE TABLE IF NOT EXISTS events (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp   TEXT NOT NULL,
                    source_type TEXT,
                    source_path TEXT,
                    rule_id     TEXT,
                    message     TEXT,
                    raw         TEXT,
                    remote_ip   TEXT,
                    username    TEXT,
                    hostname    TEXT,
                    beats_host  TEXT,
                    extra       TEXT
                );

                CREATE TABLE IF NOT EXISTS alerts (
                    id               INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp        TEXT NOT NULL,
                    rule_id          TEXT NOT NULL,
                    rule_name        TEXT,
                    severity         TEXT,
                    source_type      TEXT,
                    source_path      TEXT,
                    message          TEXT,
                    remote_ip        TEXT,
                    username         TEXT,
                    hostname         TEXT,
                    beats_host       TEXT,
                    count            INTEGER DEFAULT 1,
                    description      TEXT,
                    mitre_tactic     TEXT,
                    mitre_technique  TEXT,
                    http_status      INTEGER,
                    http_path        TEXT,
                    geo_country      TEXT,
                    geo_city         TEXT,
                    geo_lat          REAL,
                    geo_lon          REAL,
                    threat_known     INTEGER DEFAULT 0,
                    is_correlation   INTEGER DEFAULT 0,
                    corr_sequence    TEXT,
                    acknowledged     INTEGER DEFAULT 0,
                    ack_by           TEXT,
                    ack_notes        TEXT,
                    ack_at           TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_alerts_ts      ON alerts(timestamp DESC);
                CREATE INDEX IF NOT EXISTS idx_alerts_sev     ON alerts(severity);
                CREATE INDEX IF NOT EXISTS idx_alerts_ip      ON alerts(remote_ip);
                CREATE INDEX IF NOT EXISTS idx_alerts_rule    ON alerts(rule_id);
                CREATE INDEX IF NOT EXISTS idx_alerts_src     ON alerts(source_type);
                CREATE INDEX IF NOT EXISTS idx_alerts_ack     ON alerts(acknowledged);
                CREATE INDEX IF NOT EXISTS idx_alerts_threat  ON alerts(threat_known);
                CREATE INDEX IF NOT EXISTS idx_events_ts      ON events(timestamp DESC);
                CREATE INDEX IF NOT EXISTS idx_events_ip      ON events(remote_ip);
                CREATE INDEX IF NOT EXISTS idx_events_rule    ON events(rule_id);

                CREATE VIRTUAL TABLE IF NOT EXISTS alerts_fts
                USING fts5(
                    rule_name, message, remote_ip, username,
                    beats_host, description,
                    content='alerts',
                    content_rowid='id'
                );

                CREATE TRIGGER IF NOT EXISTS alerts_fts_insert
                AFTER INSERT ON alerts BEGIN
                    INSERT INTO alerts_fts(rowid, rule_name, message, remote_ip,
                        username, beats_host, description)
                    VALUES (new.id, new.rule_name, new.message, new.remote_ip,
                        new.username, new.beats_host, new.description);
                END;

                CREATE TRIGGER IF NOT EXISTS alerts_fts_delete
                AFTER DELETE ON alerts BEGIN
                    INSERT INTO alerts_fts(alerts_fts, rowid, rule_name, message,
                        remote_ip, username, beats_host, description)
                    VALUES ('delete', old.id, old.rule_name, old.message, old.remote_ip,
                        old.username, old.beats_host, old.description);
                END;
            """)
        logger.info(f"Base de données : {self.db_path}")

    # ── Écriture ──────────────────────────────────────────────

    def store_event(self, event: dict, rule: dict):
        extra = {k: v for k, v in event.items()
                 if k not in ("raw", "message", "source_type", "source_path",
                              "timestamp", "remote_ip", "username", "hostname",
                              "beats_host", "geo", "threat_intel", "parsed_at")}
        with self._lock, self._conn() as c:
            c.execute(
                """INSERT INTO events
                   (timestamp, source_type, source_path, rule_id, message,
                    raw, remote_ip, username, hostname, beats_host, extra)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    event.get("parsed_at", datetime.now().isoformat()),
                    event.get("source_type"), event.get("source_path"),
                    rule.get("id"),
                    (event.get("message") or "")[:1000],
                    (event.get("raw") or "")[:2000],
                    event.get("remote_ip"), event.get("username"),
                    event.get("hostname"),  event.get("beats_host"),
                    json.dumps(extra, default=str),
                )
            )
        self._prune_events()

    def store_alert(self, alert: dict):
        geo  = alert.get("geo") or {}
        ti   = alert.get("threat_intel") or {}
        corr = alert.get("correlated_alerts")
        with self._lock, self._conn() as c:
            c.execute(
                """INSERT INTO alerts
                   (timestamp, rule_id, rule_name, severity, source_type,
                    source_path, message, remote_ip, username, hostname,
                    beats_host, count, description, mitre_tactic, mitre_technique,
                    http_status, http_path,
                    geo_country, geo_city, geo_lat, geo_lon,
                    threat_known, is_correlation, corr_sequence)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    alert.get("timestamp", datetime.now().isoformat()),
                    alert.get("rule_id"),   alert.get("rule_name"),
                    alert.get("severity"),  alert.get("source_type"),
                    alert.get("source_path"),
                    (alert.get("message") or "")[:1000],
                    alert.get("remote_ip"), alert.get("username"),
                    alert.get("hostname"),  alert.get("beats_host"),
                    alert.get("count", 1),  alert.get("description"),
                    alert.get("mitre_tactic"), alert.get("mitre_technique"),
                    alert.get("http_status"), alert.get("http_path"),
                    geo.get("country_code"), geo.get("city"),
                    geo.get("latitude"),     geo.get("longitude"),
                    1 if ti.get("known_malicious") else 0,
                    1 if alert.get("source_type") == "correlation" else 0,
                    json.dumps(corr) if corr else None,
                )
            )

    # ── Lecture ───────────────────────────────────────────────

    def get_recent_alerts(
        self,
        limit: int = 200,
        severity: str = None,
        source_type: str = None,
        search: str = None,
        only_threats: bool = False,
        only_unacked: bool = False,
        rule_id: str = None,
    ) -> list:
        # Recherche FTS si terme de recherche fourni
        if search:
            return self._search_alerts(search, limit)

        q, p = "SELECT * FROM alerts WHERE 1=1", []
        if severity:
            q += " AND severity=?"; p.append(severity)
        if source_type == "correlation":
            q += " AND is_correlation=1"
        elif source_type:
            q += " AND source_type=?"; p.append(source_type)
        if only_threats:
            q += " AND threat_known=1"
        if only_unacked:
            q += " AND acknowledged=0"
        if rule_id:
            q += " AND rule_id=?"; p.append(rule_id)
        q += " ORDER BY timestamp DESC LIMIT ?"; p.append(limit)

        with self._lock, self._conn() as c:
            rows = c.execute(q, p).fetchall()
        return [dict(r) for r in rows]

    def _search_alerts(self, search: str, limit: int) -> list:
        with self._lock, self._conn() as c:
            rows = c.execute(
                """SELECT a.* FROM alerts a
                   INNER JOIN alerts_fts f ON a.id = f.rowid
                   WHERE alerts_fts MATCH ?
                   ORDER BY a.timestamp DESC LIMIT ?""",
                (search, limit)
            ).fetchall()
        return [dict(r) for r in rows]

    def get_stats(self) -> dict:
        with self._lock, self._conn() as c:
            total_alerts  = c.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
            total_events  = c.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            total_corr    = c.execute("SELECT COUNT(*) FROM alerts WHERE is_correlation=1").fetchone()[0]
            total_threats = c.execute("SELECT COUNT(*) FROM alerts WHERE threat_known=1").fetchone()[0]
            total_unacked = c.execute("SELECT COUNT(*) FROM alerts WHERE acknowledged=0").fetchone()[0]

            by_severity = {
                r["severity"]: r["c"]
                for r in c.execute(
                    "SELECT severity, COUNT(*) as c FROM alerts GROUP BY severity"
                ).fetchall()
            }

            by_rule = [dict(r) for r in c.execute(
                """SELECT rule_id, rule_name, severity, mitre_tactic,
                          mitre_technique, COUNT(*) as c
                   FROM alerts GROUP BY rule_id ORDER BY c DESC LIMIT 10"""
            ).fetchall()]

            top_ips = [dict(r) for r in c.execute(
                """SELECT remote_ip, geo_country, geo_city,
                          COUNT(*) as c, MAX(threat_known) as is_threat
                   FROM alerts WHERE remote_ip IS NOT NULL
                   GROUP BY remote_ip ORDER BY c DESC LIMIT 10"""
            ).fetchall()]

            top_hosts = [dict(r) for r in c.execute(
                """SELECT beats_host, COUNT(*) as c
                   FROM alerts WHERE beats_host IS NOT NULL
                   GROUP BY beats_host ORDER BY c DESC LIMIT 10"""
            ).fetchall()]

            hourly = [dict(r) for r in c.execute(
                """SELECT strftime('%H', timestamp) as hour, COUNT(*) as c
                   FROM alerts
                   WHERE timestamp >= datetime('now', '-24 hours')
                   GROUP BY hour ORDER BY hour"""
            ).fetchall()]

            daily = [dict(r) for r in c.execute(
                """SELECT strftime('%Y-%m-%d', timestamp) as day, COUNT(*) as c
                   FROM alerts
                   WHERE timestamp >= datetime('now', '-30 days')
                   GROUP BY day ORDER BY day"""
            ).fetchall()]

            mitre = [dict(r) for r in c.execute(
                """SELECT mitre_tactic, mitre_technique, rule_name,
                          COUNT(*) as c
                   FROM alerts
                   WHERE mitre_technique IS NOT NULL AND mitre_technique != ''
                   GROUP BY mitre_technique ORDER BY c DESC LIMIT 15"""
            ).fetchall()]

            recent_threats = [dict(r) for r in c.execute(
                """SELECT remote_ip, geo_country, rule_name, timestamp
                   FROM alerts WHERE threat_known=1
                   ORDER BY timestamp DESC LIMIT 5"""
            ).fetchall()]

        return {
            "total_alerts":     total_alerts,
            "total_events":     total_events,
            "total_corr":       total_corr,
            "total_threats":    total_threats,
            "total_unacked":    total_unacked,
            "by_severity":      by_severity,
            "by_rule":          by_rule,
            "top_ips":          top_ips,
            "top_hosts":        top_hosts,
            "hourly":           hourly,
            "daily":            daily,
            "mitre":            mitre,
            "recent_threats":   recent_threats,
        }

    def acknowledge_alert(self, alert_id: int, notes: str = "", ack_by: str = "analyst"):
        with self._lock, self._conn() as c:
            c.execute(
                "UPDATE alerts SET acknowledged=1, ack_notes=?, ack_by=?, ack_at=? WHERE id=?",
                (notes, ack_by, datetime.now().isoformat(), alert_id)
            )

    def get_alert_by_id(self, alert_id: int) -> dict:
        with self._lock, self._conn() as c:
            row = c.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
        return dict(row) if row else {}

    def _prune_events(self):
        max_e = self.cfg.get("max_events", 200000)
        with self._lock, self._conn() as c:
            count = c.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            if count > max_e:
                c.execute(
                    "DELETE FROM events WHERE id IN "
                    "(SELECT id FROM events ORDER BY timestamp ASC LIMIT ?)",
                    (count - max_e,)
                )
