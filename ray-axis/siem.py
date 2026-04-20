#!/usr/bin/env python3
"""
Ray-Axis SIEM — Point d'entrée principal
"""

import threading
import argparse
import logging
import signal
import sys
import time

from log_collector      import LogCollector
from log_parser         import LogParser
from rules_engine       import RulesEngine
from correlation_engine import CorrelationEngine
from alerter            import Alerter
from storage            import Storage
from enricher           import Enricher
from responder          import Responder
from config             import load_config

# ── Logging ───────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("RAY-AXIS")


def banner():
    print("""
\033[0;36m  ██████╗  █████╗ ██╗   ██╗      █████╗ ██╗  ██╗██╗███████╗
  ██╔══██╗██╔══██╗╚██╗ ██╔╝     ██╔══██╗╚██╗██╔╝██║██╔════╝
  ██████╔╝███████║ ╚████╔╝      ███████║ ╚███╔╝ ██║███████╗
  ██╔══██╗██╔══██║  ╚██╔╝       ██╔══██║ ██╔██╗ ██║╚════██║
  ██║  ██║██║  ██║   ██║        ██║  ██║██╔╝ ██╗██║███████║
  ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝        ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚══════╝\033[0m
  \033[2mSecurity Information and Event Management\033[0m
    """)


def main():
    parser = argparse.ArgumentParser(description="Ray-Axis SIEM")
    parser.add_argument("--config",    default="config.yaml",  help="Fichier de configuration")
    parser.add_argument("--dashboard", action="store_true",    help="Activer le dashboard web")
    parser.add_argument("--port",      type=int, default=5000, help="Port du dashboard")
    parser.add_argument("--debug",     action="store_true",    help="Mode debug (verbose)")
    parser.add_argument("--no-banner", action="store_true",    help="Pas de bannière ASCII")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    if not args.no_banner:
        banner()

    # ── Initialisation des modules ────────────────────────────
    config    = load_config(args.config)
    storage   = Storage(config)
    enricher  = Enricher(config)
    alerter   = Alerter(config)
    responder = Responder(config)
    corr      = CorrelationEngine(config, alerter, storage)
    rules     = RulesEngine(config, alerter, storage, enricher, responder, corr)
    log_parser= LogParser()
    collector = LogCollector(config, log_parser, rules)

    stop_event = threading.Event()

    def handle_signal(sig, frame):
        logger.info("Signal reçu — arrêt de Ray-Axis...")
        stop_event.set()
        collector.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT,  handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    # ── Dashboard Flask ───────────────────────────────────────
    dash_enabled = args.dashboard or config.get("dashboard", {}).get("enabled", False)
    if dash_enabled:
        from dashboard import create_app
        app  = create_app(storage, config)
        port = args.port or config.get("dashboard", {}).get("port", 5000)
        host = config.get("dashboard", {}).get("host", "0.0.0.0")
        dash_thread = threading.Thread(
            target=lambda: app.run(
                host=host, port=port,
                debug=False, use_reloader=False,
            ),
            daemon=True,
            name="dashboard",
        )
        dash_thread.start()
        logger.info(f"Dashboard : http://{host}:{port}")

    # ── Démarrage du collecteur ───────────────────────────────
    logger.info("Démarrage de la surveillance...")
    collector.start()
    logger.info("Ray-Axis actif — Ctrl+C pour arrêter")

    # ── Boucle principale ─────────────────────────────────────
    try:
        tick = 0
        while not stop_event.is_set():
            time.sleep(1)
            tick += 1
            # Log de statut toutes les 5 minutes
            if tick % 300 == 0:
                stats = storage.get_stats()
                logger.info(
                    f"Statut — alertes: {stats['total_alerts']} "
                    f"| événements: {stats['total_events']} "
                    f"| corrélations: {stats['total_corr']}"
                )
    except KeyboardInterrupt:
        pass
    finally:
        collector.stop()
        logger.info("Ray-Axis arrêté.")


if __name__ == "__main__":
    main()
