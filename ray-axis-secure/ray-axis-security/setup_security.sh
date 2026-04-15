#!/bin/bash
# ================================================================
# Ray-Axis — Setup sécurité complet
# Intègre auth.py dans le dashboard, configure Nginx HTTPS,
# active les certificats TLS pour Beats input
#
# Usage : sudo bash setup_security.sh <IP-VM-KALI>
# Exemple : sudo bash setup_security.sh 10.1.0.152
# ================================================================
set -e

SIEM_IP="${1:-$(hostname -I | awk '{print $1}')}"
RAY_DIR="/opt/ray-axis"
CERTS_DIR="$RAY_DIR/certs"
# Résoudre le chemin absolu du script AVANT tout cd
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

GREEN='\033[0;32m'; BLUE='\033[0;34m'; YELLOW='\033[0;33m'; NC='\033[0m'
info(){ echo -e "${BLUE}[SETUP]${NC} $1"; }
ok(){   echo -e "${GREEN}[OK]${NC}    $1"; }
warn(){ echo -e "${YELLOW}[WARN]${NC}  $1"; }

[[ "$EUID" -ne 0 ]] && echo "Lancez en root : sudo bash setup_security.sh" && exit 1

echo -e "\n${BLUE}══════════════════════════════════════════${NC}"
echo -e "${BLUE}   Ray-Axis — Configuration sécurité       ${NC}"
echo -e "${BLUE}══════════════════════════════════════════${NC}\n"

# ── 1. Nginx pour Ray-Axis ────────────────────────────────────
info "Installation Nginx..."
apt-get install -y -qq nginx
mkdir -p /etc/nginx/ssl

# ── 2. Génération des certificats ────────────────────────────
info "Génération des certificats TLS (IP: $SIEM_IP)..."
mkdir -p "$CERTS_DIR"
cd "$CERTS_DIR"

# CA
if [ ! -f ca.crt ]; then
    openssl genrsa -out ca.key 4096
    openssl req -new -x509 -days 3650 -key ca.key -out ca.crt \
        -subj "/C=FR/O=Ray-Axis/CN=Ray-Axis-CA" 2>/dev/null
    ok "CA générée"
fi

# Certificat SIEM (pour Nginx + Beats)
if [ ! -f siem.crt ]; then
    cat > /tmp/siem-ext.cnf << EOF
[req]
req_extensions = v3_req
distinguished_name = req_distinguished_name
[req_distinguished_name]
[v3_req]
subjectAltName = @alt_names
[alt_names]
IP.1 = $SIEM_IP
IP.2 = 127.0.0.1
DNS.1 = localhost
DNS.2 = ray-axis
EOF
    openssl genrsa -out siem.key 2048
    openssl req -new -key siem.key -out siem.csr \
        -subj "/C=FR/O=Ray-Axis/CN=ray-axis-siem" 2>/dev/null
    openssl x509 -req -days 3650 -in siem.csr -CA ca.crt -CAkey ca.key \
        -CAcreateserial -out siem.crt -extensions v3_req \
        -extfile /tmp/siem-ext.cnf 2>/dev/null
    ok "Certificat SIEM généré"
fi

# Certificat Filebeat client
if [ ! -f filebeat.crt ]; then
    openssl genrsa -out filebeat.key 2048
    openssl req -new -key filebeat.key -out filebeat.csr \
        -subj "/C=FR/O=Ray-Axis/CN=filebeat-client" 2>/dev/null
    openssl x509 -req -days 3650 -in filebeat.csr -CA ca.crt -CAkey ca.key \
        -CAcreateserial -out filebeat.crt 2>/dev/null
    ok "Certificat Filebeat généré"
fi

chmod 600 "$CERTS_DIR"/*.key
chmod 644 "$CERTS_DIR"/*.crt
cp "$CERTS_DIR/siem.crt" /etc/nginx/ssl/
cp "$CERTS_DIR/siem.key" /etc/nginx/ssl/

# ── 3. Nginx reverse proxy HTTPS ─────────────────────────────
info "Configuration Nginx HTTPS pour Ray-Axis..."
cp "$SCRIPT_DIR/nginx-siem.conf" /etc/nginx/sites-available/ray-axis
ln -sf /etc/nginx/sites-available/ray-axis /etc/nginx/sites-enabled/ray-axis
rm -f /etc/nginx/sites-enabled/default
nginx -t && systemctl enable nginx && systemctl restart nginx
ok "Nginx HTTPS actif sur :443"

# ── 4. Copier auth.py dans Ray-Axis ──────────────────────────
info "Intégration auth.py dans Ray-Axis..."
cp "$SCRIPT_DIR/auth.py" "$RAY_DIR/"
chown ray-axis:ray-axis "$RAY_DIR/auth.py" 2>/dev/null || true

# ── 5. Activer TLS dans config.yaml ──────────────────────────
info "Mise à jour config.yaml pour TLS..."
python3 - << PYEOF
import yaml, os

cfg_path = "$RAY_DIR/config.yaml"
if not os.path.exists(cfg_path):
    print("config.yaml introuvable — configuration manuelle requise")
    exit(0)

with open(cfg_path) as f:
    cfg = yaml.safe_load(f) or {}

cfg.setdefault("beats_input", {})
cfg["beats_input"]["enabled"]  = True
cfg["beats_input"]["tls_cert"] = "$CERTS_DIR/siem.crt"
cfg["beats_input"]["tls_key"]  = "$CERTS_DIR/siem.key"
cfg["beats_input"]["tls_ca"]   = "$CERTS_DIR/ca.crt"
cfg["beats_input"]["mtls"]     = True

cfg.setdefault("dashboard", {})
cfg["dashboard"]["https"]    = False   # Nginx gère le HTTPS
cfg["dashboard"]["auth"]     = True    # Activer l'auth JWT

with open(cfg_path, "w") as f:
    yaml.dump(cfg, f, default_flow_style=False, allow_unicode=True)

print("config.yaml mis à jour")
PYEOF
ok "config.yaml mis à jour"

# ── 6. Résumé ─────────────────────────────────────────────────
echo ""
echo -e "${GREEN}══════════════════════════════════════════${NC}"
echo -e "${GREEN}   Sécurité Ray-Axis configurée !          ${NC}"
echo -e "${GREEN}══════════════════════════════════════════${NC}\n"

echo -e "  ${YELLOW}Dashboard sécurisé :${NC}"
echo "  https://$SIEM_IP (via Nginx)"
echo "  Login : admin / RayAxis@2024!  ← CHANGER IMMÉDIATEMENT"
echo ""
echo -e "  ${YELLOW}Certificats à copier sur Windows (Docker) :${NC}"
echo "  $CERTS_DIR/ca.crt       → dans client-infra/certs/"
echo "  $CERTS_DIR/filebeat.crt → dans client-infra/certs/"
echo "  $CERTS_DIR/filebeat.key → dans client-infra/certs/"
echo ""
echo -e "  ${YELLOW}Commandes de vérification :${NC}"
echo "  nginx -t"
echo "  openssl verify -CAfile $CERTS_DIR/ca.crt $CERTS_DIR/siem.crt"
echo "  curl -k https://$SIEM_IP/api/stats"
echo ""
