#!/usr/bin/env python3
"""
Ray-Axis SIEM — Collecteur de logs
Sources : fichiers locaux, journald, serveur Beats TCP (Filebeat)
"""

import os
import re
import time
import json
import ssl
import socket
import struct
import zlib
import threading
import subprocess
import logging
from typing import Callable

logger = logging.getLogger("collector")


class LogCollector:
    def __init__(self, config: dict, log_parser, rules_engine):
        self.config       = config
        self.log_parser   = log_parser
        self.rules_engine = rules_engine
        self._threads     = []
        self._stop_event  = threading.Event()

    # ── Démarrage ─────────────────────────────────────────────

    def start(self):
        for source in self.config.get("log_sources", []):
            if not source.get("enabled", True):
                continue
            path = source["path"]
            if not os.path.exists(path):
                logger.warning(f"Fichier introuvable, ignoré : {path}")
                continue
            t = threading.Thread(
                target=self._tail_file,
                args=(path, source["type"]),
                daemon=True,
                name=f"tail-{source['type']}",
            )
            t.start()
            self._threads.append(t)
            logger.info(f"Surveillance fichier : {path}")

        jcfg = self.config.get("journald", {})
        if jcfg.get("enabled", False):
            t = threading.Thread(
                target=self._watch_journald,
                args=(jcfg.get("units", []),),
                daemon=True,
                name="journald",
            )
            t.start()
            self._threads.append(t)
            logger.info("Surveillance journald activée")

        bcfg = self.config.get("beats_input", {})
        if bcfg.get("enabled", False):
            t = threading.Thread(
                target=self._beats_server,
                args=(bcfg,),
                daemon=True,
                name="beats-server",
            )
            t.start()
            self._threads.append(t)
            logger.info(
                f"Beats input sur {bcfg.get('host','0.0.0.0')}:{bcfg.get('port',5044)}"
                + (" (mTLS)" if bcfg.get("mtls") else " (non chiffré)")
            )

    def stop(self):
        self._stop_event.set()

    # ── Tail fichier ──────────────────────────────────────────

    def _tail_file(self, path: str, source_type: str):
        retry_delay = 2
        while not self._stop_event.is_set():
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    f.seek(0, 2)  # Aller à la fin
                    inode = os.fstat(f.fileno()).st_ino
                    while not self._stop_event.is_set():
                        line = f.readline()
                        if line:
                            self._process_line(line.rstrip(), source_type, path)
                        else:
                            time.sleep(0.1)
                            # Détecter rotation (nouveau fichier = nouvel inode)
                            try:
                                if os.stat(path).st_ino != inode:
                                    logger.debug(f"Rotation détectée : {path}")
                                    break
                                # Détecter truncation
                                if f.tell() > os.path.getsize(path):
                                    f.seek(0)
                            except OSError:
                                break
                retry_delay = 2
            except PermissionError:
                logger.error(f"Permission refusée : {path} — lancez en root")
                return
            except FileNotFoundError:
                time.sleep(retry_delay)
                retry_delay = min(retry_delay * 2, 30)
            except Exception as e:
                logger.error(f"Erreur tail {path}: {e}")
                time.sleep(retry_delay)

    # ── Journald ──────────────────────────────────────────────

    def _watch_journald(self, units: list):
        cmd = ["journalctl", "-f", "-o", "short-iso", "--no-pager"]
        for unit in units:
            cmd += ["-u", unit]
        retry_delay = 2
        while not self._stop_event.is_set():
            try:
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    text=True,
                    bufsize=1,
                )
                while not self._stop_event.is_set():
                    line = proc.stdout.readline()
                    if line:
                        self._process_line(line.rstrip(), "journald", "journald")
                    else:
                        if proc.poll() is not None:
                            break
                        time.sleep(0.1)
                proc.terminate()
                retry_delay = 2
            except FileNotFoundError:
                logger.warning("journalctl non disponible")
                return
            except Exception as e:
                logger.error(f"Erreur journald : {e}")
                time.sleep(retry_delay)
                retry_delay = min(retry_delay * 2, 30)

    # ── Beats server ──────────────────────────────────────────

    def _beats_server(self, bcfg: dict):
        host = bcfg.get("host", "0.0.0.0")
        port = bcfg.get("port", 5044)
        use_tls = bcfg.get("mtls", False) or (
            bcfg.get("tls_cert") and bcfg.get("tls_key")
        )

        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # Configurer TLS si activé
        if use_tls:
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ctx.load_cert_chain(bcfg["tls_cert"], bcfg["tls_key"])
                if bcfg.get("tls_ca"):
                    ctx.load_verify_locations(bcfg["tls_ca"])
                    if bcfg.get("mtls"):
                        ctx.verify_mode = ssl.CERT_REQUIRED
                srv = ctx.wrap_socket(srv, server_side=True)
                logger.info("Beats input TLS configuré")
            except Exception as e:
                logger.error(f"Erreur TLS Beats : {e} — démarrage sans TLS")

        try:
            srv.bind((host, port))
            srv.listen(20)
            srv.settimeout(1.0)
            while not self._stop_event.is_set():
                try:
                    conn, addr = srv.accept()
                    t = threading.Thread(
                        target=self._handle_beats_client,
                        args=(conn, addr),
                        daemon=True,
                    )
                    t.start()
                except socket.timeout:
                    continue
                except ssl.SSLError as e:
                    logger.warning(f"Connexion Beats rejetée (TLS) : {e}")
        except Exception as e:
            logger.error(f"Beats server erreur : {e}")
        finally:
            srv.close()

    def _handle_beats_client(self, conn: socket.socket, addr):
        """
        Gère une connexion Filebeat.
        Supporte deux modes :
          - JSON lines (mode simple, un objet JSON par ligne)
          - Lumberjack v2 frames (protocole natif Filebeat)
        """
        logger.debug(f"Connexion Beats depuis {addr[0]}")
        try:
            conn.settimeout(60.0)
            buf = b""
            while not self._stop_event.is_set():
                try:
                    chunk = conn.recv(8192)
                    if not chunk:
                        break
                    buf += chunk

                    # Tenter de parser comme Lumberjack v2
                    consumed, events = self._parse_lumberjack(buf)
                    if consumed > 0:
                        buf = buf[consumed:]
                        for ev in events:
                            self._process_beats_event(ev, addr[0])
                        # Envoyer ACK
                        try:
                            conn.sendall(struct.pack(">ccI", b"2", b"A", len(events)))
                        except Exception:
                            pass
                        continue

                    # Fallback : JSON lines
                    while b"\n" in buf:
                        line, buf = buf.split(b"\n", 1)
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            data = json.loads(line.decode("utf-8", errors="replace"))
                            self._process_beats_event(data, addr[0])
                        except json.JSONDecodeError:
                            raw = line.decode("utf-8", errors="replace")
                            self._process_line(raw, "beats", f"beats://{addr[0]}")

                except socket.timeout:
                    break
        except Exception as e:
            logger.debug(f"Beats client {addr[0]} : {e}")
        finally:
            conn.close()

    def _parse_lumberjack(self, buf: bytes):
        """
        Parse les frames Lumberjack v2 de Filebeat.
        Retourne (bytes_consommés, liste_d_événements).
        """
        events = []
        pos = 0

        while pos + 2 <= len(buf):
            version = buf[pos:pos+1]
            frame_type = buf[pos+1:pos+2]

            if version != b"2":
                break

            # Frame de fenêtre (W) — ignorer
            if frame_type == b"W":
                if pos + 6 > len(buf):
                    break
                pos += 6
                continue

            # Frame compressée (C)
            if frame_type == b"C":
                if pos + 6 > len(buf):
                    break
                size = struct.unpack(">I", buf[pos+2:pos+6])[0]
                if pos + 6 + size > len(buf):
                    break
                try:
                    decompressed = zlib.decompress(buf[pos+6:pos+6+size])
                    _, sub_events = self._parse_lumberjack(decompressed)
                    events.extend(sub_events)
                except Exception:
                    pass
                pos += 6 + size
                continue

            # Frame JSON (J)
            if frame_type == b"J":
                if pos + 10 > len(buf):
                    break
                _seq = struct.unpack(">I", buf[pos+2:pos+6])[0]
                jsize = struct.unpack(">I", buf[pos+6:pos+10])[0]
                if pos + 10 + jsize > len(buf):
                    break
                try:
                    data = json.loads(buf[pos+10:pos+10+jsize].decode("utf-8", errors="replace"))
                    events.append(data)
                except Exception:
                    pass
                pos += 10 + jsize
                continue

            break

        return pos, events

    def _process_beats_event(self, data: dict, remote_ip: str):
        message  = data.get("message", "")
        log_path = data.get("log", {}).get("file", {}).get("path", f"beats://{remote_ip}")
        src_type = self._infer_source_type(log_path, data)

        event = self.log_parser.parse(message, src_type, log_path)
        if event:
            if not event.get("remote_ip"):
                event["remote_ip"] = remote_ip
            event["beats_host"] = data.get("host", {}).get("name", remote_ip)
            self.rules_engine.evaluate(event)

    def _infer_source_type(self, path: str, data: dict) -> str:
        tags = data.get("tags", [])
        fields = data.get("fields", {})
        src = fields.get("source_type", "")
        if src:
            return src
        for tag in tags:
            if tag in ("nginx", "apache", "auth", "syslog"):
                return tag
        if "nginx" in path:
            return "nginx"
        if "apache" in path:
            return "apache"
        if "auth" in path:
            return "auth"
        if "syslog" in path or "messages" in path:
            return "syslog"
        return "beats"

    # ── Pipeline commun ───────────────────────────────────────

    def _process_line(self, line: str, source_type: str, source_path: str):
        if not line.strip():
            return
        event = self.log_parser.parse(line, source_type, source_path)
        if event:
            self.rules_engine.evaluate(event)
