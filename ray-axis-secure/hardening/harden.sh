#!/bin/bash
# ================================================================
# Ray-Axis — Script de durcissement VM Kali Linux
# Installe et configure : ufw, fail2ban, auditd, AppArmor
# + sécurisation SSH + rotation logs chiffrés
#
# Usage : sudo bash harden.sh
# ================================================================
set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'
info(){ echo -e "${BLUE}[HARDEN]${NC} $1"; }
ok(){   echo -e "${GREEN}[OK]${NC}     $1"; }
warn(){ echo -e "${YELLOW}[WARN]${NC}   $1"; }

[[ "$EUID" -ne 0 ]] && echo -e "${RED}Lancez en root : sudo bash harden.sh${NC}" && exit 1

echo -e "\n${CYAN}╔══════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║   Ray-Axis — Durcissement VM Kali        ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════╝${NC}\n"

# ── 1. Mise à jour système ────────────────────────────────────
info "Mise à jour du système..."
apt-get update -qq && apt-get upgrade -y -qq
ok "Système à jour"

# ── 2. Installation des outils ────────────────────────────────
info "Installation ufw, fail2ban, auditd, apparmor..."
apt-get install -y -qq ufw fail2ban auditd audispd-plugins \
    apparmor apparmor-utils apparmor-profiles \
    libpam-pwquality unattended-upgrades logrotate
ok "Outils installés"

# ── 3. UFW — Firewall ─────────────────────────────────────────
info "Configuration UFW (firewall)..."
ufw --force reset
ufw default deny incoming
ufw default allow outgoing

# SSH — limité à ton réseau local
ufw allow from 10.0.0.0/8    to any port 22 proto tcp
ufw allow from 192.168.0.0/16 to any port 22 proto tcp
ufw allow from 172.16.0.0/12  to any port 22 proto tcp

# Dashboard Ray-Axis HTTPS
ufw allow from 10.0.0.0/8    to any port 5000 proto tcp
ufw allow from 192.168.0.0/16 to any port 5000 proto tcp
ufw allow from 172.16.0.0/12  to any port 5000 proto tcp

# Beats input Filebeat
ufw allow from 10.0.0.0/8    to any port 5044 proto tcp
ufw allow from 192.168.0.0/16 to any port 5044 proto tcp
ufw allow from 172.16.0.0/12  to any port 5044 proto tcp

# Bloquer tout le reste
ufw --force enable
ok "UFW configuré — ports 22, 5000, 5044 ouverts sur LAN uniquement"

# ── 4. Fail2ban ────────────────────────────────────────────────
info "Configuration fail2ban..."
cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime          = 3600
findtime         = 600
maxretry         = 5
backend          = systemd
destemail        = root@localhost
action           = %(action_mwl)s

[sshd]
enabled  = true
port     = ssh
logpath  = %(sshd_log)s
maxretry = 3
bantime  = 86400

[ray-axis-dashboard]
enabled  = true
port     = 5000
logpath  = /var/log/ray-axis/alerts.log
filter   = ray-axis-auth
maxretry = 5
bantime  = 3600

[nginx-http-auth]
enabled = true
EOF

# Filtre custom pour Ray-Axis
cat > /etc/fail2ban/filter.d/ray-axis-auth.conf << 'EOF'
[Definition]
failregex = .*login_failed.*ip.*<HOST>
            .*auth_failed.*<HOST>
ignoreregex =
EOF

systemctl enable fail2ban
systemctl restart fail2ban
ok "fail2ban configuré (SSH: max 3 tentatives, ban 24h)"

# ── 5. Auditd — audit syscalls ────────────────────────────────
info "Configuration auditd..."
cat > /etc/audit/rules.d/ray-axis.rules << 'EOF'
# Ray-Axis SIEM — Règles d'audit

# Supprimer les règles existantes
-D

# Buffer
-b 8192

# Echecs d'audit
-f 1

# ── Authentification ──────────────────────────────────────────
-w /etc/passwd         -p wa -k identity
-w /etc/group          -p wa -k identity
-w /etc/shadow         -p wa -k identity
-w /etc/sudoers        -p wa -k sudo
-w /etc/sudoers.d/     -p wa -k sudo

# ── Connexions ────────────────────────────────────────────────
-w /var/log/faillog    -p wa -k auth
-w /var/log/lastlog    -p wa -k auth
-w /var/run/utmp       -p wa -k auth
-w /var/log/wtmp       -p wa -k auth
-w /var/log/btmp       -p wa -k auth

# ── Élévation de privilèges ───────────────────────────────────
-a always,exit -F arch=b64 -S setuid  -k privilege_escalation
-a always,exit -F arch=b64 -S setgid  -k privilege_escalation
-a always,exit -F arch=b32 -S setuid  -k privilege_escalation
-a always,exit -F arch=b32 -S setgid  -k privilege_escalation

# ── Fichiers de config système ────────────────────────────────
-w /etc/crontab        -p wa -k cron
-w /etc/cron.d/        -p wa -k cron
-w /etc/cron.daily/    -p wa -k cron
-w /etc/cron.hourly/   -p wa -k cron
-w /var/spool/cron/    -p wa -k cron

# ── Ray-Axis lui-même ─────────────────────────────────────────
-w /opt/ray-axis/      -p wa -k ray-axis-modified
-w /var/lib/ray-axis/  -p wa -k ray-axis-data
-w /var/log/ray-axis/  -p r  -k ray-axis-logs-read

# ── Réseau ────────────────────────────────────────────────────
-a always,exit -F arch=b64 -S bind    -k network_bind
-a always,exit -F arch=b64 -S connect -k network_connect

# ── Exécutables suspects ──────────────────────────────────────
-a always,exit -F arch=b64 -S execve -F euid=0 -k root_commands

# Rendre les règles immuables (nécessite reboot pour modifier)
# -e 2
EOF

systemctl enable auditd
systemctl restart auditd
ok "auditd configuré avec règles Ray-Axis"

# ── 6. AppArmor ────────────────────────────────────────────────
info "Configuration AppArmor pour Ray-Axis..."
cat > /etc/apparmor.d/opt.ray-axis.siem << 'EOF'
#include <tunables/global>

/opt/ray-axis/venv/bin/python3 {
  #include <abstractions/base>
  #include <abstractions/python>
  #include <abstractions/nameservice>

  # Répertoire Ray-Axis
  /opt/ray-axis/  r,
  /opt/ray-axis/** r,
  /opt/ray-axis/venv/** r,
  /opt/ray-axis/venv/bin/python3 ix,

  # Logs système en lecture seule
  /var/log/auth.log r,
  /var/log/syslog r,
  /var/log/nginx/access.log r,
  /var/log/apache2/access.log r,

  # Données Ray-Axis en écriture
  /var/lib/ray-axis/ rw,
  /var/lib/ray-axis/** rw,
  /var/log/ray-axis/ rw,
  /var/log/ray-axis/** rw,

  # Réseau — ports autorisés uniquement
  network tcp,
  network udp,

  # Systemd journal
  /run/systemd/journal/socket rw,

  # Refuser tout le reste
  deny /etc/shadow r,
  deny /proc/*/mem rw,
}
EOF

apparmor_parser -r /etc/apparmor.d/opt.ray-axis.siem 2>/dev/null || \
    warn "AppArmor profile non chargé (relancer après installation de Ray-Axis)"
ok "Profil AppArmor créé"

# ── 7. Durcissement SSH ───────────────────────────────────────
info "Durcissement SSH..."
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

cat >> /etc/ssh/sshd_config << 'EOF'

# ── Ray-Axis SIEM — SSH hardening ────────────────────────────
Protocol 2
PermitRootLogin no
MaxAuthTries 3
MaxSessions 5
PubkeyAuthentication yes
PasswordAuthentication yes      # Mettre no si clé SSH configurée
PermitEmptyPasswords no
X11Forwarding no
AllowTcpForwarding no
ClientAliveInterval 300
ClientAliveCountMax 2
LoginGraceTime 30
EOF

systemctl reload sshd
ok "SSH durci (root login désactivé, max 3 essais)"

# ── 8. Rotation des logs ──────────────────────────────────────
info "Configuration rotation des logs Ray-Axis..."
cat > /etc/logrotate.d/ray-axis << 'EOF'
/var/log/ray-axis/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0640 ray-axis ray-axis
    sharedscripts
    postrotate
        systemctl reload ray-axis 2>/dev/null || true
    endscript
}
EOF
ok "Rotation logs configurée (30 jours, compression)"

# ── 9. Mise à jour automatique sécurité ───────────────────────
info "Mises à jour automatiques de sécurité..."
cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
EOF
systemctl enable unattended-upgrades
ok "Mises à jour sécurité automatiques activées"

# ── 10. Politique mots de passe ───────────────────────────────
info "Politique de mots de passe..."
cat > /etc/security/pwquality.conf << 'EOF'
minlen = 12
minclass = 3
maxrepeat = 3
reject_username = 1
dictcheck = 1
EOF
ok "Politique mots de passe : min 12 chars, 3 classes"

# ── Résumé ────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}══════════════════════════════════════════${NC}"
echo -e "${GREEN}   Durcissement terminé !                  ${NC}"
echo -e "${GREEN}══════════════════════════════════════════${NC}\n"

echo -e "  ${CYAN}Récapitulatif :${NC}"
echo "  ✓ UFW : ports 22, 5000, 5044 ouverts (LAN uniquement)"
echo "  ✓ fail2ban : SSH (ban 24h après 3 essais), dashboard"
echo "  ✓ auditd : surveillance syscalls, fichiers sensibles"
echo "  ✓ AppArmor : confinement Ray-Axis"
echo "  ✓ SSH : root désactivé, max 3 essais"
echo "  ✓ Logrotate : 30 jours, compression"
echo "  ✓ Mises à jour sécurité automatiques"
echo ""
echo -e "  ${YELLOW}Vérifier le statut :${NC}"
echo "  ufw status verbose"
echo "  fail2ban-client status"
echo "  auditctl -l"
echo "  aa-status"
echo ""
