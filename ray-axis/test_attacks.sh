#!/bin/bash
# ================================================================
# Ray-Axis SIEM — Simulation d'attaques
# Injecte des entrées dans les fichiers de logs pour tester
# la détection, les corrélations et les alertes.
#
# Usage : sudo bash test_attacks.sh
# ATTENTION : à utiliser uniquement sur votre propre système
# ================================================================

RED='\033[0;31m';GREEN='\033[0;32m';YELLOW='\033[0;33m'
BLUE='\033[0;34m';CYAN='\033[0;36m';BOLD='\033[1m';NC='\033[0m'

AUTHLOG="/var/log/auth.log"
SYSLOG="/var/log/syslog"
NGINXLOG="/var/log/nginx/access.log"
DELAY=0.8

banner(){ echo -e "\n${BOLD}${CYAN}╔══════════════════════════════════════════╗${NC}
${BOLD}${CYAN}║   Ray-Axis — Simulation d'attaques       ║${NC}
${BOLD}${CYAN}╚══════════════════════════════════════════╝${NC}\n"; }
section(){ echo -e "\n${BOLD}${BLUE}━━━ $1 ━━━${NC}\n"; }
ok(){   echo -e "  ${GREEN}✓${NC} $1"; }
info(){ echo -e "  ${CYAN}→${NC} $1"; }
warn(){ echo -e "  ${YELLOW}!${NC} $1"; }
ts(){   date "+%b %d %H:%M:%S"; }

ia(){ echo "$1" >> "$AUTHLOG"; }
is(){ echo "$1" >> "$SYSLOG"; }
in(){ [ -f "$NGINXLOG" ] && echo "$1" >> "$NGINXLOG" || warn "Nginx log introuvable, ignoré"; }

# ── Scénario 1 : Brute force SSH ─────────────────────────────
test_brute(){
    section "SCÉNARIO 1 — Brute force SSH (règle: SSH_BRUTE_FORCE)"
    info "8 tentatives depuis 192.168.100.5"
    local USERS=("admin" "root" "ubuntu" "pi" "user" "deploy" "git" "test")
    for i in $(seq 0 7); do
        local u="${USERS[$i]}"
        local p=$((10000 + RANDOM % 55000))
        ia "$(ts) $(hostname) sshd[$$]: Failed password for $u from 192.168.100.5 port $p ssh2"
        ok "Tentative $((i+1))/8 → user='$u'"
        sleep "$DELAY"
    done
    warn "Attendu : SSH_BRUTE_FORCE (HIGH) après 5 occurrences"
}

# ── Scénario 2 : Connexion root SSH ──────────────────────────
test_root(){
    section "SCÉNARIO 2 — Connexion root SSH (règle: SSH_ROOT_LOGIN)"
    ia "$(ts) $(hostname) sshd[$$]: Failed password for root from 10.0.0.99 port 55443 ssh2"
    ok "Tentative root depuis 10.0.0.99"
    warn "Attendu : SSH_ROOT_LOGIN (CRITICAL) immédiat"
}

# ── Scénario 3 : Connexion SSH réussie ───────────────────────
test_accepted(){
    section "SCÉNARIO 3 — Connexion SSH réussie (règle: SSH_ACCEPTED)"
    ia "$(ts) $(hostname) sshd[$$]: Accepted publickey for deploy from 192.168.1.50 port 22 ssh2: RSA SHA256:abc123"
    ok "Connexion SSH réussie pour 'deploy'"
    warn "Attendu : SSH_ACCEPTED (INFO)"
}

# ── Scénario 4 : Corrélation brute force réussi ──────────────
test_corr_brute(){
    section "SCÉNARIO 4 — CORRÉLATION : Brute force → login réussi (même IP)"
    info "Cette simulation déclenche BRUTE_FORCE_SUCCESS"
    local IP="172.16.0.200"
    for i in $(seq 1 6); do
        ia "$(ts) $(hostname) sshd[$$]: Failed password for admin from $IP port $((20000+i)) ssh2"
        ok "Échec SSH $i/6 depuis $IP"
        sleep 0.5
    done
    sleep 1
    ia "$(ts) $(hostname) sshd[$$]: Accepted password for admin from $IP port 22345 ssh2"
    ok "Login SSH réussi depuis $IP"
    warn "Attendu : SSH_BRUTE_FORCE (HIGH) + BRUTE_FORCE_SUCCESS (CRITICAL)"
}

# ── Scénario 5 : Échecs sudo ─────────────────────────────────
test_sudo(){
    section "SCÉNARIO 5 — Échecs sudo répétés (règle: SUDO_FAILURE)"
    for i in $(seq 1 4); do
        ia "$(ts) $(hostname) sudo[$$]: hacker : 3 incorrect password attempts ; TTY=pts/1 ; USER=root ; COMMAND=/bin/bash"
        ok "Refus sudo $i/4"
        sleep "$DELAY"
    done
    warn "Attendu : SUDO_FAILURE (MEDIUM) après 3 occurrences"
}

# ── Scénario 6 : OOM Killer ───────────────────────────────────
test_oom(){
    section "SCÉNARIO 6 — OOM Killer (règle: OOM_KILLER)"
    is "$(ts) $(hostname) kernel: [123456.789] Out of memory: Kill process 9999 (stress) score 950 or sacrifice child"
    is "$(ts) $(hostname) kernel: [123456.790] Killed process 9999 (stress) total-vm:2048000kB, anon-rss:1900000kB"
    ok "OOM Killer injecté (PID 9999)"
    warn "Attendu : OOM_KILLER (HIGH)"
}

# ── Scénario 7 : Kernel panic ────────────────────────────────
test_panic(){
    section "SCÉNARIO 7 — Kernel Panic (règle: KERNEL_PANIC)"
    is "$(ts) $(hostname) kernel: [999999.001] Kernel panic - not syncing: Fatal exception in interrupt"
    ok "Kernel panic injecté"
    warn "Attendu : KERNEL_PANIC (CRITICAL)"
}

# ── Scénario 8 : Scan HTTP 4xx ────────────────────────────────
test_scan(){
    section "SCÉNARIO 8 — Scan HTTP (règle: NGINX_4XX_FLOOD)"
    local IP="172.16.100.55"
    local PATHS=("/admin" "/.env" "/wp-admin" "/phpmyadmin" "/.git/config"
                 "/backup.zip" "/config.php" "/shell.php" "/uploads/cmd.php"
                 "/.htaccess" "/etc/passwd" "/proc/self/environ" "/server-status"
                 "/api/v1/users" "/api/v1/admin" "/.DS_Store" "/Thumbs.db"
                 "/robots.txt" "/sitemap.xml" "/.well-known/security.txt"
                 "/xmlrpc.php" "/wp-login.php" "/manager/html" "/console" "/actuator")
    for path in "${PATHS[@]}"; do
        in "$IP - - [$(date '+%d/%b/%Y:%H:%M:%S %z')] \"GET $path HTTP/1.1\" 404 162 \"-\" \"Mozilla/5.0 (dirbuster)\""
        ok "GET $path → 404"
        sleep 0.15
    done
    warn "Attendu : NGINX_4XX_FLOOD (MEDIUM) après 20 occurrences"
}

# ── Scénario 9 : Injection SQL ───────────────────────────────
test_sqli(){
    section "SCÉNARIO 9 — Injection SQL (règle: NGINX_SQL_INJECTION)"
    local IP="10.10.10.200"
    local PAYLOADS=(
        "GET /search?q=' OR '1'='1 HTTP/1.1"
        "GET /user?id=1 UNION SELECT username,password FROM users-- HTTP/1.1"
        "GET /api/items?filter=1; DROP TABLE users;-- HTTP/1.1"
        "GET /login?user=admin'-- HTTP/1.1"
    )
    for payload in "${PAYLOADS[@]}"; do
        in "$IP - - [$(date '+%d/%b/%Y:%H:%M:%S %z')] \"$payload\" 200 512 \"-\" \"sqlmap/1.7\""
        ok "Payload injecté : ${payload:0:50}..."
        sleep "$DELAY"
    done
    warn "Attendu : NGINX_SQL_INJECTION (CRITICAL) + NGINX_SCANNER (HIGH)"
}

# ── Scénario 10 : XSS ────────────────────────────────────────
test_xss(){
    section "SCÉNARIO 10 — Tentative XSS (règle: NGINX_XSS)"
    local IP="10.10.10.201"
    in "$IP - - [$(date '+%d/%b/%Y:%H:%M:%S %z')] \"GET /search?q=<script>alert('xss')</script> HTTP/1.1\" 200 256 \"-\" \"Mozilla/5.0\""
    ok "Payload XSS injecté"
    warn "Attendu : NGINX_XSS (HIGH)"
}

# ── Scénario 11 : Path traversal ─────────────────────────────
test_traversal(){
    section "SCÉNARIO 11 — Path Traversal (règle: NGINX_PATH_TRAVERSAL)"
    local IP="10.10.10.202"
    in "$IP - - [$(date '+%d/%b/%Y:%H:%M:%S %z')] \"GET /download?file=../../../etc/passwd HTTP/1.1\" 200 1024 \"-\" \"curl/7.88\""
    ok "Path traversal injecté"
    warn "Attendu : NGINX_PATH_TRAVERSAL (HIGH)"
}

# ── Scénario 12 : Corrélation recon + exploit ─────────────────
test_corr_web(){
    section "SCÉNARIO 12 — CORRÉLATION : Scan puis injection SQL (même IP)"
    local IP="10.10.10.203"
    info "Scan HTTP 4xx d'abord..."
    for path in "/admin" "/.env" "/wp-admin" "/phpmyadmin" "/.git" \
                "/backup" "/config" "/shell" "/uploads" "/htaccess" \
                "/passwd" "/environ" "/status" "/api/users" "/api/admin" \
                "/DS_Store" "/Thumbs" "/robots" "/sitemap" "/well-known" "/xmlrpc"; do
        in "$IP - - [$(date '+%d/%b/%Y:%H:%M:%S %z')] \"GET $path HTTP/1.1\" 404 162 \"-\" \"gobuster/3.0\""
        sleep 0.1
    done
    ok "Scan de 21 chemins depuis $IP"
    sleep 2
    info "Puis injection SQL depuis la même IP..."
    in "$IP - - [$(date '+%d/%b/%Y:%H:%M:%S %z')] \"GET /api/items?id=1 UNION SELECT username,password FROM users-- HTTP/1.1\" 200 512 \"-\" \"sqlmap/1.7\""
    ok "Injection SQL depuis $IP"
    warn "Attendu : NGINX_4XX_FLOOD + NGINX_SQL_INJECTION + RECON_THEN_EXPLOIT (CRITICAL)"
}

# ── Scénario 13 : SSH réel (optionnel) ───────────────────────
test_real_ssh(){
    section "SCÉNARIO 13 — Test SSH réel (optionnel)"
    if ! command -v sshpass &>/dev/null; then
        warn "sshpass non installé — sudo apt install sshpass"
        info "Test manuel : for i in \$(seq 1 6); do sshpass -p wrong ssh fakeuser@localhost; done"
        return
    fi
    info "6 tentatives SSH réelles sur localhost..."
    for i in $(seq 1 6); do
        sshpass -p "wrong_$i" ssh -o StrictHostKeyChecking=no \
            -o ConnectTimeout=2 fakeuser_$i@127.0.0.1 2>/dev/null || true
        ok "Tentative réelle $i/6"
        sleep 1
    done
    warn "Attendu : SSH_BRUTE_FORCE dans les vrais logs auth.log"
}

# ── Menu ──────────────────────────────────────────────────────
main(){
    banner
    [[ "$EUID" -ne 0 ]] && echo -e "${RED}Lancez en root : sudo bash test_attacks.sh${NC}" && exit 1
    echo -e "  ${YELLOW}Modes disponibles :${NC}"
    echo "  1) Tous les scénarios (recommandé)"
    echo "  2) SSH uniquement (scénarios 1-4)"
    echo "  3) Web / Nginx (scénarios 8-12)"
    echo "  4) Système (scénarios 6-7)"
    echo "  5) Corrélations uniquement (scénarios 4, 12)"
    echo "  6) Choisir manuellement"
    echo "  7) Test SSH réel (nécessite sshpass)"
    echo ""
    read -rp "  Votre choix [1-7] : " choice
    case "$choice" in
        1) test_brute; test_root; test_accepted; test_corr_brute; test_sudo
           test_oom; test_panic; test_scan; test_sqli; test_xss; test_traversal; test_corr_web ;;
        2) test_brute; test_root; test_accepted; test_corr_brute; test_sudo ;;
        3) test_scan; test_sqli; test_xss; test_traversal; test_corr_web ;;
        4) test_oom; test_panic ;;
        5) test_corr_brute; test_corr_web ;;
        6)
            echo ""
            echo "  a) Brute force SSH        g) Scan HTTP 4xx"
            echo "  b) Login root SSH         h) Injection SQL"
            echo "  c) Login SSH réussi       i) XSS"
            echo "  d) Corrélation brute+OK   j) Path traversal"
            echo "  e) Échecs sudo            k) Corrélation scan+SQL"
            echo "  f) OOM Killer / Panic"
            read -rp "  Lettres (ex: abde) : " letters
            [[ "$letters" == *a* ]] && test_brute
            [[ "$letters" == *b* ]] && test_root
            [[ "$letters" == *c* ]] && test_accepted
            [[ "$letters" == *d* ]] && test_corr_brute
            [[ "$letters" == *e* ]] && test_sudo
            [[ "$letters" == *f* ]] && test_oom && test_panic
            [[ "$letters" == *g* ]] && test_scan
            [[ "$letters" == *h* ]] && test_sqli
            [[ "$letters" == *i* ]] && test_xss
            [[ "$letters" == *j* ]] && test_traversal
            [[ "$letters" == *k* ]] && test_corr_web
            ;;
        7) test_real_ssh ;;
        *) echo -e "\n  ${RED}Choix invalide.${NC}" ; exit 1 ;;
    esac

    echo -e "\n${GREEN}${BOLD}═══════════════════════════════════════════${NC}"
    echo -e "${GREEN}${BOLD}   Simulation terminée !${NC}"
    echo -e "${GREEN}${BOLD}═══════════════════════════════════════════${NC}\n"
    echo -e "  ${CYAN}Vérifier :${NC}"
    echo "  → Dashboard : http://localhost:5000"
    echo "  → Alertes   : ray-axis alerts"
    echo "  → Logs SIEM : ray-axis logs"
    echo ""
}

main
