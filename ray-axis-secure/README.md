# Ray-Axis — Architecture sécurisée complète

Intégration sécurisée de Ray-Axis avec une infrastructure client (Nginx + Node.js + MySQL)
via Docker Desktop sur Windows, avec durcissement complet de la VM Kali.

---

## Structure

```
ray-axis-secure/
├── client-infra/              <- Infrastructure cliente à surveiller (Windows/Docker)
│   ├── docker-compose.yml     <- Stack complète avec 3 réseaux isolés
│   ├── nginx/
│   │   └── nginx.conf         <- Nginx durci (rate limit, headers sécurité, TLS)
│   ├── app/
│   │   ├── server.js          <- Application Node.js avec logs structurés
│   │   ├── Dockerfile         <- Image non-root, healthcheck
│   │   └── package.json
│   ├── mysql/
│   │   ├── init.sql           <- DB init + permissions minimales
│   │   └── mysql-audit.cnf    <- Audit MySQL activé
│   ├── filebeat/
│   │   └── filebeat.yml       <- Config Filebeat avec mTLS vers Ray-Axis
│   ├── certs/                 <- Certificats générés par gen_certs.sh
│   └── gen_certs.sh           <- Génération CA + certificats TLS/mTLS
│
├── ray-axis-security/         <- Sécurisation de Ray-Axis (VM Kali)
│   ├── auth.py                <- Authentification JWT (intégrer dans dashboard.py)
│   ├── nginx-siem.conf        <- Reverse proxy HTTPS pour le dashboard
│   └── setup_security.sh     <- Script d'installation tout-en-un
│
└── hardening/
    └── harden.sh              <- Durcissement OS Kali (ufw, fail2ban, auditd, AppArmor)
```

---

## Déploiement — Ordre des étapes

### Étape 1 — Durcir la VM Kali

```bash
sudo bash hardening/harden.sh
```

Installe et configure : ufw, fail2ban, auditd, AppArmor, SSH hardening,
rotation des logs, mises à jour automatiques de sécurité.

### Étape 2 — Configurer la sécurité Ray-Axis

```bash
sudo bash ray-axis-security/setup_security.sh <IP-VM-KALI>
# Exemple : sudo bash ray-axis-security/setup_security.sh 10.1.0.152
```

Génère les certificats TLS, configure Nginx HTTPS, active l'auth JWT,
active le Beats input avec mTLS.

### Étape 3 — Générer les certificats pour Filebeat (sur Windows)

```bash
# Dans client-infra/
bash gen_certs.sh <IP-VM-KALI>
```

Génère tous les certificats dans `client-infra/certs/`.

### Étape 4 — Lancer l'infrastructure client (Windows/Docker)

```bash
# Dans client-infra/
# Créer le fichier .env avec les mots de passe
echo "DB_PASSWORD=MonMotDePasse123!" > .env
echo "MYSQL_ROOT_PASSWORD=RootPass456!" >> .env
echo "SIEM_HOST=<IP-VM-KALI>" >> .env

# Lancer la stack
docker-compose up -d

# Vérifier
docker-compose ps
docker-compose logs filebeat
```

### Étape 5 — Démarrer Ray-Axis

```bash
sudo ray-axis start
# ou
sudo python3 /opt/ray-axis/siem.py --dashboard
```

Dashboard : **https://<IP-KALI>** (login : admin / RayAxis@2024! — à changer !)

---

## Architecture réseau Docker

```
net-frontend (172.20.1.0/24)
  nginx ← accès internet (ports 80/443)
  app   ← reçoit les requêtes de nginx

net-backend (172.20.2.0/24) — internal, pas d'internet
  app ← parle à la DB
  db  ← uniquement joignable par app

net-monitoring (172.20.3.0/24)
  filebeat → envoie logs vers Ray-Axis (port 5044)

Attaquant (profil attack) :
  uniquement net-frontend → ne voit pas la DB, ne voit pas le monitoring
```

---

## Sécurité en couches

| Couche | Mécanisme | Outil |
|--------|-----------|-------|
| Réseau OS | Firewall strict | ufw |
| Brute force | Bannissement auto | fail2ban |
| Syscalls | Audit kernel | auditd |
| Processus | Confinement | AppArmor |
| Transport | Chiffrement | TLS 1.3 / mTLS |
| Dashboard | Authentification | JWT + Nginx |
| Docker | Isolation réseau | 3 réseaux séparés |
| App | Requêtes paramétrées | mysql2 + bcrypt |
| Nginx | Headers + rate limit | nginx.conf durci |
| Logs | Rotation + compression | logrotate |

---

## Tester la sécurité

### Vérifier l'isolation réseau Docker

```bash
# L'attaquant ne doit PAS pouvoir joindre la DB
docker-compose --profile attack up -d attacker
docker exec client-attacker ping db           # Doit échouer
docker exec client-attacker ping nginx        # Doit réussir
docker exec client-attacker ping filebeat     # Doit échouer
```

### Vérifier le mTLS Filebeat

```bash
# Depuis la VM Kali — vérifier que Filebeat se connecte avec certificat
openssl s_client -connect localhost:5044 \
    -cert certs/filebeat.crt \
    -key certs/filebeat.key \
    -CAfile certs/ca.crt
```

### Tester fail2ban

```bash
# 4 tentatives SSH → bannissement
for i in $(seq 1 4); do
    ssh wronguser@localhost 2>/dev/null || true
done
fail2ban-client status sshd
```

### Vérifier les règles UFW

```bash
ufw status verbose
```

---

## Note sur les mots de passe

Changer impérativement avant tout usage réel :

- Dashboard Ray-Axis : modifier `DEFAULT_USERS` dans `auth.py`
- MySQL root : variable `MYSQL_ROOT_PASSWORD` dans `.env`
- MySQL appuser : variable `DB_PASSWORD` dans `.env`
- JWT secret : variable `RAY_AXIS_SECRET` dans l'environnement
- Nginx SSL : régénérer les certificats avec `setup_security.sh`
