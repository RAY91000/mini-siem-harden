-- ================================================================
-- Ray-Axis — Initialisation base de données client
-- ================================================================

CREATE DATABASE IF NOT EXISTS appdb CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE appdb;

-- Table utilisateurs
CREATE TABLE IF NOT EXISTS users (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    username      VARCHAR(64) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role          ENUM('admin', 'user', 'viewer') DEFAULT 'user',
    created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login    TIMESTAMP NULL,
    failed_logins INT DEFAULT 0,
    locked        BOOLEAN DEFAULT FALSE
);

-- Utilisateurs de test (mots de passe : admin123, user123)
INSERT INTO users (username, password_hash, role) VALUES
('admin', '$2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4J/HS.iK2i', 'admin'),
('alice', '$2a$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW', 'user'),
('bob',   '$2a$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW', 'viewer');

-- Table logs applicatifs
CREATE TABLE IF NOT EXISTS app_logs (
    id         INT AUTO_INCREMENT PRIMARY KEY,
    timestamp  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    level      VARCHAR(16),
    message    TEXT,
    user_id    INT NULL,
    ip_address VARCHAR(45),
    INDEX idx_ts (timestamp),
    INDEX idx_level (level)
);

-- Permissions minimales pour appuser
GRANT SELECT, INSERT, UPDATE ON appdb.users TO 'appuser'@'%';
GRANT INSERT ON appdb.app_logs TO 'appuser'@'%';
FLUSH PRIVILEGES;
