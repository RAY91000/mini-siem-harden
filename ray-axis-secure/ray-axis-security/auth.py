#!/usr/bin/env python3
"""
Ray-Axis — Authentification JWT pour le dashboard
Login sécurisé avec tokens JWT, rate limiting, sessions
"""

import os
import time
import hmac
import hashlib
import base64
import json
import logging
import threading
from datetime import datetime, timedelta
from functools import wraps
from flask import request, jsonify, session

logger = logging.getLogger("auth")

# ── Configuration ─────────────────────────────────────────────
SECRET_KEY  = os.environ.get("RAY_AXIS_SECRET", "change-me-in-production-32chars!")
TOKEN_TTL   = 8 * 3600        # 8 heures
MAX_ATTEMPTS = 5
LOCKOUT_TIME = 900             # 15 minutes

# ── Utilisateurs (en production : base de données) ────────────
# Mots de passe hashés avec PBKDF2
# Générer un hash : python3 -c "from auth import hash_password; print(hash_password('monmotdepasse'))"
DEFAULT_USERS = {
    "admin": {
        "password_hash": "",   # Sera généré au premier lancement
        "role": "admin",
        "default_password": "RayAxis@2024!"   # Changer immédiatement
    }
}


def hash_password(password: str) -> str:
    """Hash un mot de passe avec PBKDF2-SHA256."""
    salt = os.urandom(32)
    key  = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310000)
    return base64.b64encode(salt + key).decode()


def verify_password(password: str, stored_hash: str) -> bool:
    """Vérifie un mot de passe contre son hash."""
    try:
        decoded = base64.b64decode(stored_hash.encode())
        salt    = decoded[:32]
        stored  = decoded[32:]
        key     = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310000)
        return hmac.compare_digest(key, stored)
    except Exception:
        return False


def generate_token(username: str, role: str) -> str:
    """Génère un JWT simple sans dépendance externe."""
    header  = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).decode().rstrip("=")
    payload = base64.urlsafe_b64encode(json.dumps({
        "sub":  username,
        "role": role,
        "iat":  int(time.time()),
        "exp":  int(time.time()) + TOKEN_TTL,
    }).encode()).decode().rstrip("=")

    sig_data = f"{header}.{payload}"
    sig = hmac.new(SECRET_KEY.encode(), sig_data.encode(), hashlib.sha256).digest()
    signature = base64.urlsafe_b64encode(sig).decode().rstrip("=")
    return f"{header}.{payload}.{signature}"


def verify_token(token: str) -> dict:
    """Vérifie et décode un JWT. Retourne le payload ou lève ValueError."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("Format token invalide")

        header, payload, signature = parts
        sig_data = f"{header}.{payload}"
        expected_sig = hmac.new(SECRET_KEY.encode(), sig_data.encode(), hashlib.sha256).digest()
        expected = base64.urlsafe_b64encode(expected_sig).decode().rstrip("=")

        if not hmac.compare_digest(signature, expected):
            raise ValueError("Signature invalide")

        # Ajouter le padding manquant
        padding = 4 - len(payload) % 4
        payload_decoded = json.loads(base64.urlsafe_b64decode(payload + "=" * padding))

        if payload_decoded.get("exp", 0) < time.time():
            raise ValueError("Token expiré")

        return payload_decoded
    except (json.JSONDecodeError, Exception) as e:
        raise ValueError(f"Token invalide : {e}")


class AuthManager:
    """Gestion de l'authentification avec rate limiting et lockout."""

    def __init__(self, config: dict):
        self.config      = config
        self._attempts   = {}   # {ip: [timestamps]}
        self._locked     = {}   # {ip: lockout_until}
        self._lock       = threading.Lock()
        self._users      = self._load_users(config)
        logger.info(f"Auth manager initialisé — {len(self._users)} utilisateur(s)")

    def _load_users(self, config: dict) -> dict:
        users_cfg = config.get("dashboard", {}).get("users", {})
        users = dict(DEFAULT_USERS)

        # Initialiser le hash du mot de passe par défaut si vide
        for username, user_data in users.items():
            if not user_data.get("password_hash"):
                user_data["password_hash"] = hash_password(user_data.get("default_password", "admin"))
                logger.warning(f"Mot de passe par défaut pour '{username}' — CHANGER IMMÉDIATEMENT")

        # Ajouter les utilisateurs de la config
        for username, user_data in users_cfg.items():
            users[username] = user_data

        return users

    def is_locked(self, ip: str) -> bool:
        with self._lock:
            if ip in self._locked:
                if time.time() < self._locked[ip]:
                    return True
                del self._locked[ip]
        return False

    def record_attempt(self, ip: str, success: bool):
        with self._lock:
            if success:
                self._attempts.pop(ip, None)
                return

            now = time.time()
            self._attempts.setdefault(ip, [])
            self._attempts[ip] = [t for t in self._attempts[ip] if now - t < LOCKOUT_TIME]
            self._attempts[ip].append(now)

            if len(self._attempts[ip]) >= MAX_ATTEMPTS:
                self._locked[ip] = now + LOCKOUT_TIME
                logger.warning(f"IP {ip} verrouillée pour {LOCKOUT_TIME//60} minutes")

    def authenticate(self, username: str, password: str, ip: str) -> dict:
        """Authentifie un utilisateur. Retourne {"token": ..., "role": ...} ou lève ValueError."""
        if self.is_locked(ip):
            raise ValueError("IP temporairement verrouillée")

        user = self._users.get(username)
        if not user or not verify_password(password, user["password_hash"]):
            self.record_attempt(ip, success=False)
            logger.warning(f"Échec authentification : user={username} ip={ip}")
            raise ValueError("Identifiants incorrects")

        self.record_attempt(ip, success=True)
        token = generate_token(username, user["role"])
        logger.info(f"Authentification réussie : user={username} ip={ip} role={user['role']}")
        return {"token": token, "role": user["role"], "username": username}


def require_auth(f):
    """Décorateur Flask — protège une route par JWT."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        # Token dans le header Authorization
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]

        # Token dans le cookie de session
        if not token:
            token = request.cookies.get("ray_axis_token")

        if not token:
            if request.is_json:
                return jsonify({"error": "Authentification requise"}), 401
            from flask import redirect, url_for
            return redirect("/login")

        try:
            payload = verify_token(token)
            request.current_user = payload
        except ValueError as e:
            if request.is_json:
                return jsonify({"error": str(e)}), 401
            from flask import redirect
            return redirect("/login")

        return f(*args, **kwargs)
    return decorated


def require_admin(f):
    """Décorateur Flask — exige le rôle admin."""
    @wraps(f)
    @require_auth
    def decorated(*args, **kwargs):
        if getattr(request, "current_user", {}).get("role") != "admin":
            return jsonify({"error": "Accès refusé — rôle admin requis"}), 403
        return f(*args, **kwargs)
    return decorated
