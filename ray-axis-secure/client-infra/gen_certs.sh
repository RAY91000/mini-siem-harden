#!/bin/bash
# ================================================================
# Ray-Axis — Génération des certificats TLS/mTLS
#
# Génère :
#   - CA (Certificate Authority) auto-signée
#   - Certificat serveur Ray-Axis (SIEM)
#   - Certificat client Filebeat (mTLS)
#   - Certificat Nginx (HTTPS)
#
# Usage : bash gen_certs.sh <IP-VM-KALI>
# Exemple : bash gen_certs.sh 10.1.0.152
# ================================================================

set -e
SIEM_IP="${1:-10.1.0.152}"
CERTS_DIR="$(dirname "$0")/certs"
DAYS=3650   # 10 ans pour le homelab

GREEN='\033[0;32m'; BLUE='\033[0;34m'; NC='\033[0m'
info(){ echo -e "${BLUE}[CERT]${NC} $1"; }
ok(){   echo -e "${GREEN}[OK]${NC}   $1"; }

mkdir -p "$CERTS_DIR"
cd "$CERTS_DIR"

info "Génération de la CA Ray-Axis..."
openssl genrsa -out ca.key 4096
openssl req -new -x509 -days $DAYS -key ca.key -out ca.crt \
    -subj "/C=FR/O=Ray-Axis/CN=Ray-Axis-CA"
ok "CA générée : ca.crt"

# ── Certificat serveur SIEM (Beats input) ─────────────────────
info "Certificat serveur SIEM (IP: $SIEM_IP)..."
cat > siem-ext.cnf << EOF
[req]
req_extensions = v3_req
distinguished_name = req_distinguished_name
[req_distinguished_name]
[v3_req]
subjectAltName = @alt_names
[alt_names]
IP.1 = $SIEM_IP
IP.2 = 127.0.0.1
DNS.1 = ray-axis
DNS.2 = localhost
EOF

openssl genrsa -out siem.key 2048
openssl req -new -key siem.key -out siem.csr \
    -subj "/C=FR/O=Ray-Axis/CN=ray-axis-siem"
openssl x509 -req -days $DAYS -in siem.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out siem.crt -extensions v3_req -extfile siem-ext.cnf
ok "Certificat SIEM : siem.crt"

# ── Certificat client Filebeat (mTLS) ─────────────────────────
info "Certificat client Filebeat (mTLS)..."
openssl genrsa -out filebeat.key 2048
openssl req -new -key filebeat.key -out filebeat.csr \
    -subj "/C=FR/O=Ray-Axis/CN=filebeat-client"
openssl x509 -req -days $DAYS -in filebeat.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out filebeat.crt
ok "Certificat Filebeat : filebeat.crt"

# ── Certificat Nginx HTTPS ────────────────────────────────────
info "Certificat Nginx HTTPS..."
cat > nginx-ext.cnf << EOF
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
EOF

openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr \
    -subj "/C=FR/O=Ray-Axis/CN=client-web"
openssl x509 -req -days $DAYS -in server.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out server.crt -extensions v3_req -extfile nginx-ext.cnf
ok "Certificat Nginx : server.crt"

# ── Copier les certificats Nginx dans le bon dossier ──────────
mkdir -p ../nginx/ssl
cp server.crt ../nginx/ssl/
cp server.key ../nginx/ssl/
ok "Certificats Nginx copiés dans nginx/ssl/"

# ── Permissions ───────────────────────────────────────────────
chmod 600 *.key ca.key
chmod 644 *.crt

# ── Résumé ────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}══════════════════════════════════════${NC}"
echo -e "${GREEN}   Certificats générés !               ${NC}"
echo -e "${GREEN}══════════════════════════════════════${NC}"
echo ""
echo "  Dossier : $CERTS_DIR"
echo ""
echo "  Fichiers :"
ls -la "$CERTS_DIR"/*.crt "$CERTS_DIR"/*.key 2>/dev/null
echo ""
echo "  Sur la VM Kali (Ray-Axis), copier :"
echo "    scp certs/ca.crt certs/siem.crt certs/siem.key kali@$SIEM_IP:~/ray-axis/certs/"
echo ""
echo "  Puis activer beats_input dans config.yaml :"
echo "    beats_input:"
echo "      enabled: true"
echo "      tls_cert: /home/kali/ray-axis/certs/siem.crt"
echo "      tls_key:  /home/kali/ray-axis/certs/siem.key"
echo "      tls_ca:   /home/kali/ray-axis/certs/ca.crt"
