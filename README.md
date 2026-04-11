# Ray-Axis — SIEM personnel open source

> Projet personnel de cybersécurité — développement d'un système SIEM from scratch,
> de la VM locale vers une infrastructure cloud privée sécurisée.

**Auteur :** Ray Dotrop  
**Début du projet :** Février 2026  
**État actuel :** En développement actif (avril 2026)  
**Stack :** Python 3 · Flask · SQLite · Docker · Filebeat · Nginx · Kali Linux

---

## Pourquoi ce projet ?

J'ai commencé ce projet parce que je voulais comprendre vraiment comment fonctionne
un SIEM — pas juste lire la doc de Splunk ou regarder des tutos, mais construire quelque
chose qui tourne sur ma propre machine et qui détecte de vraies attaques.

L'idée de départ était simple : surveiller les logs de ma VM Kali et me prévenir quand
quelque chose de suspect se passe. En pratique, ça s'est transformé en un projet beaucoup
plus ambitieux que prévu, avec une infrastructure Docker, des certificats TLS, un moteur
de corrélation, et un dashboard web.

Je suis encore loin d'un Splunk ou d'un ELK Stack, mais ce qui est là fonctionne,
j'ai appris une quantité de choses que je n'aurais jamais vues en cours, et je continue
à l'améliorer.

---

## Table des matières

1. [Vue d'ensemble](#1-vue-densemble)
2. [Architecture](#2-architecture)
3. [Structure du projet](#3-structure-du-projet)
4. [Installation et lancement](#4-installation-et-lancement)
5. [Ce que ça détecte](#5-ce-que-ça-détecte)
6. [Infrastructure client simulée](#6-infrastructure-client-simulée)
7. [Sécurité](#7-sécurité)
8. [Ce sur quoi j'ai galéré](#8-ce-sur-quoi-jai-galéré)
9. [Ce qui manque encore / pistes d'amélioration](#9-ce-qui-manque-encore--pistes-damélioration)
10. [Journal de bord](#10-journal-de-bord)

---

## 1. Vue d'ensemble

Ray-Axis est un SIEM (Security Information and Event Management) développé entièrement
en Python. Il surveille les logs système en temps réel, applique des règles de détection,
corrèle les événements entre plusieurs sources, et envoie des alertes.

**Ce que fait Ray-Axis aujourd'hui :**

- Surveillance en temps réel de `/var/log/auth.log`, `/var/log/syslog`,
  journald, Nginx, Apache
- Réception de logs réseau depuis des agents Filebeat distants (port 5044, mTLS)
- Parsing et normalisation des logs par type de source
- Moteur de règles : regex + seuils + fenêtres temporelles
- Moteur de corrélation multi-sources (ex : brute force suivi d'un login réussi)
- Enrichissement GeoIP (MaxMind GeoLite2) et Threat Intelligence (blocklists)
- Alertes : terminal coloré, fichier de log, email SMTP, webhook Slack/Discord
- Réponse automatisée : blocage IP via iptables
- Stockage SQLite avec pruning automatique
- Dashboard web Flask avec stats temps réel, MITRE ATT&CK, top IPs, corrélations
- Infrastructure client Docker complète (Nginx + Node.js + MySQL + Filebeat)
- Durcissement OS complet (ufw, fail2ban, auditd, AppArmor)

**Ce que Ray-Axis ne fait pas encore** (voir section 9) :

- Interface de recherche full-text dans les événements bruts
- Détection par anomalie (baseline statistique)
- Support natif Elasticsearch pour les gros volumes
- Multi-tenant (plusieurs clients isolés)

---

## 2. Architecture

### Vue globale

```
┌─────────────────────────────────────────────────────────────────┐
│  Windows 10 (PC hôte) — Docker Desktop                          │
│                                                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐           │
│  │  Nginx       │  │  Node.js app │  │  MySQL       │           │
│  │  net-frontend│  │  net-frontend│  │  net-backend │           │
│  │              │  │  net-backend │  │  (interne)   │           │
│  └──────────────┘  └──────────────┘  └──────────────┘           │
│          │                │                                      │
│  ┌──────────────────────────────────────┐                        │
│  │  Filebeat — net-monitoring           │                        │
│  │  mTLS → Ray-Axis port 5044           │                        │
│  └──────────────────────────────────────┘                        │
└────────────────────────────┬────────────────────────────────────┘
                             │ TCP 5044 (mTLS)
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│  VM Kali Linux — Ray-Axis SIEM                                   │
│                                                                  │
│  log_collector.py  ──► log_parser.py  ──► rules_engine.py       │
│        │                                        │                │
│        │ (fichiers locaux + Beats réseau)        │                │
│        │                                  ┌─────┴──────┐        │
│        │                                  │            │        │
│                                    correlation   alerter.py     │
│                                    _engine.py    (terminal      │
│                                           │       fichier       │
│                                    enricher.py   email          │
│                                    responder.py  webhook)       │
│                                           │                     │
│                                    storage.py (SQLite)         │
│                                           │                     │
│                                    dashboard.py (Flask)         │
│                                           │                     │
│                              Nginx reverse proxy HTTPS :443      │
└─────────────────────────────────────────────────────────────────┘
```

### Isolation réseau Docker

L'infrastructure client utilise 3 réseaux Docker séparés pour limiter
la propagation en cas de compromission :

```
net-frontend  (172.20.1.0/24) — Nginx exposé internet
net-backend   (172.20.2.0/24) — App ↔ DB, pas d'accès internet
net-monitoring (172.20.3.0/24) — Filebeat → SIEM uniquement

Un attaquant qui compromet Nginx reste dans net-frontend.
Il ne peut pas voir la base de données (net-backend seulement).
```

---

## 3. Structure du projet

```
ray-axis/                          ← SIEM principal (VM Kali)
├── siem.py                        # Point d'entrée
├── config.py                      # Chargement config + valeurs par défaut
├── log_collector.py               # tail -f + journald + serveur Beats TCP
├── log_parser.py                  # Parsing regex par type de source
├── rules_engine.py                # Règles regex + seuils + MITRE ATT&CK
├── correlation_engine.py          # Corrélation multi-sources, séquences
├── enricher.py                    # GeoIP MaxMind + blocklists threat intel
├── alerter.py                     # Terminal / fichier / email / webhook
├── responder.py                   # Blocage iptables + webhook Slack/Discord
├── storage.py                     # SQLite : events + alerts
├── dashboard.py                   # Flask API REST + interface SOC
├── config.yaml                    # Configuration utilisateur
├── install.sh                     # Installation service systemd
└── test_attacks.sh                # Simulation d'attaques

ray-axis-secure/                   ← Sécurisation et infrastructure client
├── client-infra/
│   ├── docker-compose.yml         # Stack Nginx + Node.js + MySQL + Filebeat
│   ├── nginx/nginx.conf           # Nginx durci (headers, rate limit, TLS)
│   ├── app/
│   │   ├── server.js              # App Node.js avec logs structurés
│   │   ├── Dockerfile             # Image non-root, healthcheck
│   │   └── package.json
│   ├── mysql/
│   │   ├── init.sql               # Init DB + permissions minimales
│   │   └── mysql-audit.cnf        # Audit MySQL
│   ├── filebeat/filebeat.yml      # Config Filebeat mTLS
│   └── gen_certs.sh               # Génération CA + certificats TLS/mTLS
├── ray-axis-security/
│   ├── auth.py                    # Auth JWT pour le dashboard
│   ├── nginx-siem.conf            # Reverse proxy HTTPS Ray-Axis
│   └── setup_security.sh         # Setup sécurité tout-en-un
└── hardening/
    └── harden.sh                  # Durcissement OS Kali
```

---

## 4. Installation et lancement

### Prérequis

- VM Kali Linux (testé sur Kali 2024.x)
- Python 3.10+
- pip : `flask pyyaml` (obligatoires), `geoip2` (optionnel pour GeoIP)
- Sur Windows : Docker Desktop avec WSL2

### Lancement rapide (test/dev)

```bash
# Cloner / extraire le projet
cd ray-axis/

# Installer les dépendances
pip install flask pyyaml

# Lancer avec le dashboard
sudo python3 siem.py --dashboard --port 5000

# Dashboard : http://localhost:5000
```

### Installation complète (production)

```bash
# 1. Installer Ray-Axis comme service systemd
sudo bash install.sh

# 2. Durcir la VM
sudo bash ../ray-axis-secure/hardening/harden.sh

# 3. Configurer la sécurité (TLS + Nginx + JWT)
sudo bash ../ray-axis-secure/ray-axis-security/setup_security.sh <IP-KALI>

# Démarrer
sudo ray-axis start

# Vérifier
sudo ray-axis status
sudo ray-axis logs
```

### Lancer l'infrastructure client Docker (Windows)

```bash
# Dans ray-axis-secure/client-infra/

# 1. Générer les certificats
bash gen_certs.sh <IP-VM-KALI>

# 2. Créer le fichier d'environnement
cat > .env << EOF
SIEM_HOST=<IP-VM-KALI>
DB_PASSWORD=MonMotDePasse123!
MYSQL_ROOT_PASSWORD=RootPass456!
EOF

# 3. Lancer la stack
docker-compose up -d

# 4. Vérifier que Filebeat envoie bien les logs
docker-compose logs filebeat
```

### Commandes utiles

```bash
ray-axis start      # Démarrer le service
ray-axis stop       # Arrêter
ray-axis status     # État systemd
ray-axis logs       # Logs du service en direct
ray-axis alerts     # Fichier d'alertes en temps réel
```

---

## 5. Ce que ça détecte

### Règles de détection (moteur principal)

| ID | Description | Sévérité | MITRE |
|----|-------------|----------|-------|
| `SSH_BRUTE_FORCE` | 5 échecs SSH en 60s | HIGH | T1110.001 |
| `SSH_ROOT_LOGIN` | Connexion root SSH | CRITICAL | T1078.003 |
| `SSH_ACCEPTED` | Connexion SSH réussie | INFO | T1078 |
| `SUDO_FAILURE` | 3 refus sudo en 5min | MEDIUM | T1548.003 |
| `NEW_USER_CREATED` | Création compte système | MEDIUM | T1136.001 |
| `OOM_KILLER` | OOM Killer déclenché | HIGH | T1499 |
| `KERNEL_PANIC` | Kernel panic | CRITICAL | T1499 |
| `NGINX_4XX_FLOOD` | 20 erreurs 4xx en 60s | MEDIUM | T1595.002 |
| `NGINX_SQL_INJECTION` | Pattern SQL injection | CRITICAL | T1190 |
| `NGINX_XSS` | Tentative XSS | HIGH | T1190 |
| `NGINX_PATH_TRAVERSAL` | Traversée de répertoire | HIGH | T1083 |
| `CRON_MODIFICATION` | Cron modifié | LOW | T1053.003 |
| `SYSTEMD_SERVICE_ADDED` | Nouveau service systemd | LOW | T1543.002 |

### Règles de corrélation (moteur multi-sources)

| ID | Séquence détectée | Sévérité |
|----|-------------------|----------|
| `BRUTE_FORCE_SUCCESS` | SSH_BRUTE_FORCE → SSH_ACCEPTED (même IP, 5min) | CRITICAL |
| `RECON_THEN_EXPLOIT` | NGINX_4XX_FLOOD → NGINX_SQL_INJECTION (même IP, 10min) | CRITICAL |

### Tester la détection

**Important : lancer Ray-Axis AVANT le script de test.** Le collecteur se place
à la fin des fichiers au démarrage — il ne lit pas l'historique.

```bash
# Terminal 1
sudo python3 siem.py --dashboard

# Terminal 2 (une fois "Surveillance active" affiché)
sudo bash test_attacks.sh
```

Le script simule 8 scénarios : brute force SSH, login root, échecs sudo,
OOM killer, kernel panic, scan HTTP, injection SQL.

Pour des attaques réelles depuis Kali vers les conteneurs Docker :

```bash
# Brute force SSH
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://IP-CONTENEUR

# Scan de ports
nmap -sV -p- IP-CONTENEUR

# Scan web
nikto -h http://IP-CONTENEUR

# Injection SQL
sqlmap -u "http://IP-CONTENEUR/api/items?id=1" --dbs
```

---

## 6. Infrastructure client simulée

L'infrastructure Docker simule un environnement client réel composé de :

**Nginx** — reverse proxy web avec configuration durcie :
- Headers de sécurité (CSP, HSTS, X-Frame-Options...)
- Rate limiting par zone (global, API, login)
- Blocage des user-agents d'outils d'attaque (sqlmap, nikto, nmap...)
- Redirection HTTPS automatique

**Application Node.js** — API REST avec :
- Authentification JWT
- Requêtes SQL paramétrées (protection injection)
- Logs structurés JSON (parsables par Filebeat)
- Rate limiting par endpoint
- Tournant en utilisateur non-root

**MySQL** — base de données avec :
- Utilisateur applicatif avec permissions minimales (pas de GRANT ALL)
- Audit log activé
- Aucun port exposé à l'extérieur (uniquement accessible depuis l'app)

**Filebeat** — agent de collecte qui envoie tous les logs vers Ray-Axis
via une connexion mTLS (authentification mutuelle par certificats).

---

## 7. Sécurité

### Sécurité en couches (defence in depth)

| Couche | Mécanisme | Outil |
|--------|-----------|-------|
| Réseau OS | Firewall entrant strict | ufw |
| Brute force | Bannissement automatique | fail2ban |
| Audit kernel | Surveillance syscalls | auditd |
| Confinement | Isolation processus | AppArmor |
| Transport | Chiffrement bout-en-bout | TLS 1.3 / mTLS |
| Dashboard | Authentification | JWT + Nginx HTTPS |
| Docker | Isolation réseau | 3 réseaux séparés |
| App | Requêtes sécurisées | mysql2 + bcrypt |
| Logs | Rotation + compression | logrotate 30j |
| OS | Mises à jour auto | unattended-upgrades |

### Ports ouverts sur la VM Kali

```
22   (SSH)    — LAN uniquement (10.0.0.0/8, 192.168.0.0/16)
443  (HTTPS)  — Dashboard via Nginx, LAN uniquement
5044 (Beats)  — Réception Filebeat, LAN uniquement
```

Tout le reste est bloqué par ufw.

### Certificats TLS

Le projet utilise une CA auto-signée pour le homelab.
En production réelle, il faudrait utiliser Let's Encrypt ou une CA d'entreprise.

```
CA Ray-Axis
├── siem.crt     (serveur — Nginx + Beats input)
├── filebeat.crt (client — authentification mTLS)
└── server.crt   (Nginx client-infra)
```

---

## 8. Ce sur quoi j'ai galéré

Cette section est honnête — voilà les vrais obstacles rencontrés pendant le projet.

### Le tail -f et la rotation des logs

Au début, le collecteur de logs plantait silencieusement quand logrotate faisait
tourner les fichiers. Le fichier était renommé, un nouveau créé, et `log_collector.py`
continuait à lire l'ancien fichier vide. J'ai mis un moment à comprendre pourquoi
les alertes s'arrêtaient à heure fixe la nuit.

La solution a été d'ajouter une vérification de la taille : si la position courante
dans le fichier dépasse sa taille réelle, c'est qu'il a été rotaté — on repart du début.

```python
if f.tell() > os.path.getsize(path):
    f.seek(0)
```

Simple, mais j'ai mis plusieurs heures à trouver.

### Le protocole Beats (Filebeat → Ray-Axis)

Le protocole Lumberjack v2 utilisé par Filebeat est assez complexe avec des frames
binaires, une compression zlib, et des ACKs. J'ai essayé de l'implémenter proprement
au début et c'était un enfer — les frames n'étaient pas bien parsées et Filebeat
se déconnectait en boucle.

J'ai finalement opté pour une approche plus simple : configurer Filebeat en mode
JSON lines sur TCP, ce qui permet de lire des lignes JSON directement sans implémenter
le protocole complet. Ça marche, mais c'est moins robuste que le vrai protocole Beats
(pas d'ACK, pas de garantie de livraison). C'est noté dans la roadmap.

### Les regex et les faux positifs

Construire des regex qui matchent exactement ce qu'on veut sans faire de faux positifs,
c'est beaucoup plus difficile que prévu. La règle `SSH_BRUTE_FORCE` matchait au début
sur ses propres logs d'alerte (Ray-Axis écrit "Failed password" dans son fichier
d'alertes, qui était lu par le collecteur).

Il a fallu soit exclure le fichier d'alertes des sources surveillées, soit rendre les
regex plus spécifiques. J'ai fait les deux.

### L'isolation réseau Docker et les IPs changeantes

Mon IP change entre le réseau de l'école et celui de chez moi. Au début, j'avais
codé l'IP en dur dans `filebeat.yml` et évidemment ça ne marchait plus le lendemain.

La solution : utiliser une variable d'environnement `SIEM_HOST` dans `filebeat.yml`
et un fichier `.env` pour Docker Compose. Maintenant je fais juste :

```bash
SIEM_HOST=$(hostname -I | awk '{print $1}') docker-compose up -d
```

### Le dashboard Flask et les threads

Flask en mode développement n'est pas thread-safe. Le SIEM tourne en plusieurs
threads (un par source de log) et tous écrivent dans SQLite en même temps.
J'ai eu des corruptions de base de données au début.

La solution a été d'ajouter un verrou threading sur toutes les opérations SQLite
et d'utiliser `check_same_thread=False` avec précaution. Ça tient, mais en production
il faudrait passer à une vraie base de données avec un ORM correct.

### Les certificats mTLS

Générer une CA, des certificats serveur et client, les faire signer correctement,
et configurer Filebeat pour utiliser le mTLS — ça paraît simple sur le papier
mais entre les extensions SubjectAltName, les formats PEM/DER, et les erreurs
cryptiques d'OpenSSL, j'ai passé une après-midi entière sur ça.

Le problème principal : oublier l'extension `subjectAltName` dans le certificat
serveur. OpenSSL génère le certificat sans erreur mais les clients modernes
(Filebeat, navigateurs) le rejettent avec une erreur TLS bizarre.

```bash
# L'extension qu'il ne faut pas oublier
[v3_req]
subjectAltName = @alt_names
[alt_names]
IP.1 = 10.1.0.152
IP.2 = 127.0.0.1
DNS.1 = localhost
```

### AppArmor sur Kali

AppArmor n'est pas activé par défaut sur Kali Linux (contrairement à Ubuntu).
Il faut le démarrer manuellement et les profils ne s'appliquent pas automatiquement
au reboot sans configuration supplémentaire. J'ai perdu du temps à me demander
pourquoi mon profil ne faisait rien.

---

## 9. Ce qui manque encore / pistes d'amélioration

### Court terme (dans les prochaines semaines)

**Implémentation correcte du protocole Beats**
La réception Filebeat actuelle fonctionne en JSON lines TCP mais n'implémente
pas le vrai protocole Lumberjack v2. En cas de perte réseau, les événements
peuvent être perdus. Il faudrait soit implémenter le protocole complet, soit
utiliser une bibliothèque existante.

**Recherche full-text dans le dashboard**
Aujourd'hui on peut filtrer par sévérité et faire une recherche basique côté client.
Il manque une vraie recherche dans les événements bruts avec des opérateurs
(AND, OR, champs spécifiques). Quelque chose de proche de la syntaxe Lucene mais
en simple SQLite FTS5.

**Acquittement des alertes avec workflow**
Le bouton d'acquittement existe dans l'API mais n'est pas encore dans l'interface.
Il faudrait aussi un système de notes et d'assignation à un analyste.

### Moyen terme

**Détection par anomalie (baseline)**
C'est probablement l'amélioration qui aurait le plus d'impact opérationnel.
L'idée est de calculer une baseline sur 7 jours (volume de logs par heure,
IPs habituelles, utilisateurs actifs) et d'alerter sur les écarts statistiques.
Ça permettrait de détecter les attaques lentes que les règles à seuil ne voient pas.

**Vrai support multi-clients**
Actuellement Ray-Axis surveille une seule infrastructure. Dans un contexte MSSP
(Managed Security Service Provider), il faudrait isoler les données de plusieurs
clients, avec des règles et des dashboards séparés par tenant.

**Support Elasticsearch**
SQLite tient bien pour le homelab mais il ne passera pas à l'échelle avec des
milliers d'événements par seconde. Abstraire le backend de stockage pour supporter
Elasticsearch permettrait de gérer des volumes réels.

**Carte du monde des attaques**
Une fois le GeoIP en place, il serait intéressant d'afficher une carte temps réel
des IPs sources avec leur géolocalisation dans le dashboard.

### Long terme

**Agent natif Ray-Axis**
Remplacer Filebeat par un agent Python léger développé spécifiquement pour Ray-Axis,
avec un protocole simple et documenté, et une configuration centralisée depuis le SIEM.

**Réponse automatisée avancée (SOAR)**
Aujourd'hui le responder bloque des IPs via iptables. Il faudrait des playbooks
configurables : isoler une VM, capturer un snapshot mémoire, créer un ticket
automatiquement, notifier différentes personnes selon la sévérité.

**Interface de création de règles graphique**
Écrire des règles YAML à la main c'est fonctionnel mais pas accessible.
Une interface web pour créer, tester, et activer des règles serait plus pratique.

---

## 10. Journal de bord

Ce journal retrace les grandes étapes du projet de façon honnête.

### Février 2026 — Début et premiers tâtonnements (3 semaines)

Le projet commence par une question simple : est-ce que je peux détecter
une attaque brute force SSH sur ma VM Kali avec un script Python ?

La première version fait 80 lignes et surveille un seul fichier.
Elle fonctionne — mais plante dès que le fichier est rotaté, ne gère
pas les erreurs de permission, et n'a pas de stockage persistant.

Première vraie difficulté : comprendre les formats de logs. `auth.log`,
`syslog`, nginx — chacun a son propre format, ses propres timestamps,
ses propres champs. Écrire des regex qui parsent tout ça correctement
sans trop de faux positifs prend plus de temps que prévu.

À la fin du mois, j'ai un collecteur multi-fichiers, un parseur qui
normalise les entrées, et un système d'alertes terminal basique.
Pas encore de stockage, pas de dashboard.

### Mars 2026 — Dashboard, SQLite, et moteur de règles (3 semaines)

Je veux voir les alertes dans un dashboard web plutôt que de lire
le terminal. Flask s'impose naturellement.

Problème immédiat : Flask et les threads Python ne font pas bon ménage.
Le SIEM tourne en plusieurs threads et SQLite se corrompt.
Ajout de verrous threading sur toutes les opérations DB.

Le moteur de règles s'enrichit : seuils, fenêtres temporelles, regex.
Premier test avec Hydra depuis Kali vers Kali en local — ça marche,
l'alerte SSH_BRUTE_FORCE se déclenche après 5 tentatives.

Satisfaction d'avoir quelque chose qui fonctionne vraiment.

Fin mars : je commence à réfléchir à comment surveiller plusieurs machines.
C'est là que l'idée du homelab Docker émerge.

### Début avril 2026 — Homelab Docker, mTLS, corrélation (2 semaines)

La partie la plus complexe du projet. Docker Desktop sur Windows,
Filebeat qui envoie des logs vers la VM Kali, certificats TLS mutuels.

**Semaine 1 :** mise en place du docker-compose avec les 3 réseaux isolés.
L'isolation réseau est la chose la plus intéressante que j'ai découverte —
le fait qu'un conteneur compromis ne puisse pas voir la base de données
juste en changeant des paramètres réseau, sans code supplémentaire.

**Semaine 2 :** Filebeat et les certificats. L'après-midi perdue sur le
`subjectAltName` (voir section 8). Une fois le mTLS qui marche, Ray-Axis
reçoit des logs depuis les conteneurs Docker en temps réel — c'est
vraiment satisfaisant à voir.

Ajout du moteur de corrélation : détecter une séquence d'événements
cross-sources. La première corrélation qui fonctionne :
`SSH_BRUTE_FORCE → SSH_ACCEPTED` depuis la même IP = alerte CRITICAL.

**11 avril 2026 — aujourd'hui :**
Le projet est dans un état utilisable. Le dashboard tourne, les alertes
arrivent depuis les conteneurs Docker, la corrélation fonctionne.

Il reste beaucoup à faire (voir section 9) mais la base est solide.

---

## Environnement de développement

| Composant | Détail |
|-----------|--------|
| PC hôte | i5-6200U, 16 Go RAM, 477 Go SSD, Windows 10 |
| VM SIEM | Kali Linux 2024.x (VirtualBox) |
| Réseau | 10.1.0.0/22 (DHCP école/domicile) |
| Docker | Docker Desktop + WSL2 sur Windows |
| Éditeur | VS Code + extension Remote SSH vers la VM |

---

## Dépendances

### Ray-Axis (Python)

```
flask>=3.0       # Dashboard web
pyyaml>=6.0      # Configuration
geoip2>=4.7      # GeoIP (optionnel)
```

### Infrastructure client (Docker)

```
nginx:1.25-alpine
node:20-alpine
mysql:8.0
docker.elastic.co/beats/filebeat:8.11.0
```

---

## Licence

Projet personnel — libre d'utilisation et de modification à des fins éducatives.  
À utiliser uniquement sur ses propres systèmes.

---

*Ray Dotrop — avril 2026*
