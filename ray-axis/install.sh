#!/bin/bash
# ================================================================
# Ray-Axis SIEM — Script d'installation
# Usage : sudo bash install.sh
# ================================================================
set -e

RED='\033[0;31m';GREEN='\033[0;32m';YELLOW='\033[0;33m'
BLUE='\033[0;34m';NC='\033[0m'
info(){ echo -e "${BLUE}[INFO]${NC}  $1"; }
ok(){   echo -e "${GREEN}[OK]${NC}    $1"; }
warn(){ echo -e "${YELLOW}[WARN]${NC}  $1"; }
err(){  echo -e "${RED}[ERR]${NC}   $1"; exit 1; }

echo -e "\n${BLUE}══════════════════════════════════════${NC}"
echo -e "${BLUE}   Ray-Axis SIEM — Installation        ${NC}"
echo -e "${BLUE}══════════════════════════════════════${NC}\n"

[[ "$EUID" -ne 0 ]] && err "Lancez en root : sudo bash install.sh"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/opt/ray-axis"
SVC_USER="ray-axis"

# ── Python ────────────────────────────────────────────────────
info "Vérification Python 3..."
command -v python3 &>/dev/null || apt-get install -y python3 python3-pip python3-venv -qq
ok "$(python3 --version)"

# ── Copie des fichiers ────────────────────────────────────────
info "Installation dans $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"
cp -r "$SCRIPT_DIR"/*.py "$INSTALL_DIR/"
[ -f "$SCRIPT_DIR/config.yaml" ] && cp "$SCRIPT_DIR/config.yaml" "$INSTALL_DIR/config.yaml"
[ -f "$SCRIPT_DIR/test_attacks.sh" ] && cp "$SCRIPT_DIR/test_attacks.sh" "$INSTALL_DIR/"
ok "Fichiers copiés"

# ── Virtualenv ────────────────────────────────────────────────
info "Création du virtualenv..."
python3 -m venv "$INSTALL_DIR/venv"
source "$INSTALL_DIR/venv/bin/activate"
pip install --quiet --upgrade pip
pip install --quiet flask pyyaml
ok "flask, pyyaml installés"

# Optionnel : GeoIP
pip install --quiet geoip2 2>/dev/null && ok "geoip2 installé" \
    || warn "geoip2 non installé (GeoIP désactivé — pip install geoip2)"

# ── Répertoires de données ────────────────────────────────────
info "Répertoires de données..."
mkdir -p /var/log/ray-axis /var/lib/ray-axis
ok "Créés"

# ── Utilisateur système ───────────────────────────────────────
info "Utilisateur système '$SVC_USER'..."
id "$SVC_USER" &>/dev/null \
    || useradd --system --no-create-home --shell /usr/sbin/nologin "$SVC_USER"
chown -R "$SVC_USER:$SVC_USER" /var/log/ray-axis /var/lib/ray-axis "$INSTALL_DIR"
usermod -aG adm              "$SVC_USER" 2>/dev/null || true
usermod -aG systemd-journal  "$SVC_USER" 2>/dev/null || true
ok "Utilisateur configuré"

# ── Service systemd ───────────────────────────────────────────
info "Service systemd..."
cat > /etc/systemd/system/ray-axis.service << EOF
[Unit]
Description=Ray-Axis SIEM
After=network.target
Wants=network.target

[Service]
Type=simple
User=${SVC_USER}
Group=${SVC_USER}
WorkingDirectory=${INSTALL_DIR}
ExecStart=${INSTALL_DIR}/venv/bin/python3 ${INSTALL_DIR}/siem.py \\
    --config ${INSTALL_DIR}/config.yaml \\
    --dashboard \\
    --no-banner
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=ray-axis
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/var/log/ray-axis /var/lib/ray-axis
ReadOnlyPaths=/var/log
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
ok "Service systemd créé"

# ── Commande ray-axis ─────────────────────────────────────────
cat > /usr/local/bin/ray-axis << 'EOF'
#!/bin/bash
case "$1" in
  start)   systemctl start ray-axis ;;
  stop)    systemctl stop ray-axis ;;
  restart) systemctl restart ray-axis ;;
  status)  systemctl status ray-axis ;;
  logs)    journalctl -u ray-axis -f ;;
  alerts)  tail -f /var/log/ray-axis/alerts.log ;;
  test)    sudo bash /opt/ray-axis/test_attacks.sh ;;
  *)
    echo "Usage: ray-axis {start|stop|restart|status|logs|alerts|test}"
    echo ""
    echo "  start    Démarrer le service"
    echo "  stop     Arrêter le service"
    echo "  restart  Redémarrer"
    echo "  status   État systemd"
    echo "  logs     Logs en direct (journald)"
    echo "  alerts   Alertes en direct (fichier)"
    echo "  test     Lancer le script de simulation d'attaques"
    ;;
esac
EOF
chmod +x /usr/local/bin/ray-axis
ok "Commande ray-axis disponible"

# ── Résumé ────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}══════════════════════════════════════${NC}"
echo -e "${GREEN}   Ray-Axis installé !                 ${NC}"
echo -e "${GREEN}══════════════════════════════════════${NC}\n"
echo -e "  ${YELLOW}Démarrage :${NC}"
echo "  ray-axis start"
echo ""
echo -e "  ${YELLOW}Démarrage automatique :${NC}"
echo "  sudo systemctl enable ray-axis"
echo ""
echo -e "  ${YELLOW}Dashboard :${NC}  http://localhost:5000"
echo -e "  ${YELLOW}Config    :${NC}  $INSTALL_DIR/config.yaml"
echo ""
