// ================================================================
// Ray-Axis — Application web client (Node.js)
// App de démonstration avec authentification, API, logs structurés
// ================================================================

const express    = require("express");
const mysql      = require("mysql2/promise");
const bcrypt     = require("bcryptjs");
const jwt        = require("jsonwebtoken");
const winston    = require("winston");
const helmet     = require("helmet");
const rateLimit  = require("express-rate-limit");
const path       = require("path");
const fs         = require("fs");

const app  = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "change-me-in-production";

// ── Logger structuré (parsable par Ray-Axis) ──────────────────
const logDir = "/app/logs";
fs.mkdirSync(logDir, { recursive: true });

const logger = winston.createLogger({
    level: "info",
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
    ),
    transports: [
        new winston.transports.File({ filename: `${logDir}/app.log` }),
        new winston.transports.File({ filename: `${logDir}/error.log`, level: "error" }),
        new winston.transports.Console({ format: winston.format.simple() }),
    ],
});

// ── Connexion MySQL ───────────────────────────────────────────
let db;
async function getDB() {
    if (!db) {
        db = await mysql.createConnection({
            host:     process.env.DB_HOST     || "db",
            user:     process.env.DB_USER     || "appuser",
            password: process.env.DB_PASSWORD || "changeme",
            database: process.env.DB_NAME     || "appdb",
        });
        logger.info("Connexion MySQL établie");
    }
    return db;
}

// ── Middlewares sécurité ──────────────────────────────────────
app.use(helmet());
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: false, limit: "1mb" }));

// Rate limiting API
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { error: "Trop de requêtes" },
});
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: { error: "Trop de tentatives de connexion" },
});

// ── Logger middleware ─────────────────────────────────────────
app.use((req, res, next) => {
    res.on("finish", () => {
        logger.info("http_request", {
            method:      req.method,
            path:        req.path,
            status:      res.statusCode,
            ip:          req.ip,
            user_agent:  req.get("User-Agent"),
            duration_ms: Date.now() - req._startTime,
        });
    });
    req._startTime = Date.now();
    next();
});

// ── Auth middleware ───────────────────────────────────────────
function authRequired(req, res, next) {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) return res.status(401).json({ error: "Token requis" });
    try {
        req.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch {
        logger.warn("token_invalid", { ip: req.ip, path: req.path });
        res.status(401).json({ error: "Token invalide" });
    }
}

// ── Routes ────────────────────────────────────────────────────

// Page d'accueil
app.get("/", (req, res) => {
    res.json({
        app:     "Ray-Axis Client App",
        version: "1.0.0",
        status:  "running",
    });
});

// Login
app.post("/login", loginLimiter, async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: "Champs manquants" });
    }

    try {
        const conn = await getDB();
        const [rows] = await conn.execute(
            "SELECT id, username, password_hash, role FROM users WHERE username = ?",
            [username]   // Requête paramétrée — protection injection SQL
        );

        if (!rows.length) {
            logger.warn("login_failed", { username, ip: req.ip, reason: "user_not_found" });
            return res.status(401).json({ error: "Identifiants incorrects" });
        }

        const user  = rows[0];
        const valid = await bcrypt.compare(password, user.password_hash);

        if (!valid) {
            logger.warn("login_failed", { username, ip: req.ip, reason: "wrong_password" });
            return res.status(401).json({ error: "Identifiants incorrects" });
        }

        const token = jwt.sign(
            { id: user.id, username: user.username, role: user.role },
            JWT_SECRET,
            { expiresIn: "8h" }
        );

        logger.info("login_success", { username, ip: req.ip, role: user.role });
        res.json({ token, role: user.role });

    } catch (err) {
        logger.error("login_error", { error: err.message });
        res.status(500).json({ error: "Erreur serveur" });
    }
});

// API utilisateurs (protégée)
app.get("/api/users", authRequired, apiLimiter, async (req, res) => {
    if (req.user.role !== "admin") {
        logger.warn("unauthorized_access", { user: req.user.username, ip: req.ip, path: "/api/users" });
        return res.status(403).json({ error: "Accès refusé" });
    }
    try {
        const conn  = await getDB();
        const [rows] = await conn.execute("SELECT id, username, role, created_at FROM users");
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: "Erreur serveur" });
    }
});

// API profil (protégée)
app.get("/api/profile", authRequired, async (req, res) => {
    res.json({ user: req.user });
});

// Health check
app.get("/health", (req, res) => {
    res.json({ status: "ok", uptime: process.uptime() });
});

// ── 404 ───────────────────────────────────────────────────────
app.use((req, res) => {
    logger.warn("not_found", { path: req.path, ip: req.ip, method: req.method });
    res.status(404).json({ error: "Route introuvable" });
});

// ── Démarrage ─────────────────────────────────────────────────
app.listen(PORT, "0.0.0.0", () => {
    logger.info("app_started", { port: PORT, env: process.env.NODE_ENV });
});
