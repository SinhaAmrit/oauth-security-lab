/**
 * SQLite Database Initialization
 * Stores: registered clients, authorization codes, tokens, users, audit logs
 */

const Database = require('better-sqlite3');
const path = require('path');
const { v4: uuidv4 } = require('uuid');

const DB_PATH = process.env.DB_PATH || '/tmp/oauth.db';

let db;

function getDb() {
  if (!db) {
    db = new Database(DB_PATH);
    db.pragma('journal_mode = WAL');
    db.pragma('foreign_keys = ON');
  }
  return db;
}

function initDatabase() {
  const db = getDb();

  // ── Schema ──────────────────────────────────────────────────────────────────
  db.exec(`
    CREATE TABLE IF NOT EXISTS clients (
      client_id       TEXT PRIMARY KEY,
      client_secret   TEXT NOT NULL,
      name            TEXT NOT NULL,
      redirect_uris   TEXT NOT NULL,  -- JSON array of allowed URIs
      scopes          TEXT NOT NULL,  -- JSON array of allowed scopes
      require_pkce    INTEGER DEFAULT 0,
      trusted         INTEGER DEFAULT 0,  -- trusted = no consent screen
      created_at      DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS users (
      id              TEXT PRIMARY KEY,
      username        TEXT UNIQUE NOT NULL,
      password_hash   TEXT NOT NULL,
      email           TEXT,
      roles           TEXT DEFAULT '["user"]',
      created_at      DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS authorization_codes (
      code            TEXT PRIMARY KEY,
      client_id       TEXT NOT NULL,
      user_id         TEXT NOT NULL,
      redirect_uri    TEXT NOT NULL,
      scopes          TEXT NOT NULL,
      code_challenge  TEXT,           -- PKCE: SHA256(code_verifier)
      challenge_method TEXT,          -- S256 or plain
      expires_at      DATETIME NOT NULL,
      used            INTEGER DEFAULT 0,
      created_at      DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS access_tokens (
      token_id        TEXT PRIMARY KEY,
      client_id       TEXT NOT NULL,
      user_id         TEXT NOT NULL,
      scopes          TEXT NOT NULL,
      expires_at      DATETIME NOT NULL,
      revoked         INTEGER DEFAULT 0,
      created_at      DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS refresh_tokens (
      token           TEXT PRIMARY KEY,
      access_token_id TEXT NOT NULL,
      client_id       TEXT NOT NULL,
      user_id         TEXT NOT NULL,
      scopes          TEXT NOT NULL,
      rotated         INTEGER DEFAULT 0,  -- for refresh token rotation
      revoked         INTEGER DEFAULT 0,
      expires_at      DATETIME NOT NULL,
      created_at      DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS audit_log (
      id              INTEGER PRIMARY KEY AUTOINCREMENT,
      event_type      TEXT NOT NULL,
      client_id       TEXT,
      user_id         TEXT,
      ip_address      TEXT,
      details         TEXT,           -- JSON payload
      severity        TEXT DEFAULT 'INFO',
      timestamp       DATETIME DEFAULT CURRENT_TIMESTAMP
    );
  `);

  // ── Seed Data ───────────────────────────────────────────────────────────────
  seedClients(db);
  seedUsers(db);

  console.log('✅ Database initialized');
}

function seedClients(db) {
  // Use env vars so the lab works on any domain (not just localhost)
  const clientBase   = process.env.CLIENT_BASE_URL   || 'http://localhost:3002';
  const attackerBase = process.env.ATTACKER_BASE_URL || 'http://localhost:3004';

  const clients = [
    // Legitimate client app
    {
      client_id: 'legitimate-client',
      client_secret: 'legitimate-secret-abc123',
      name: 'Legitimate Web App',
      redirect_uris: JSON.stringify([`${clientBase}/callback`]),
      scopes: JSON.stringify(['read', 'profile', 'email']),
      require_pkce: 0,
      trusted: 0,
    },
    // Secure client with PKCE required
    {
      client_id: 'secure-client',
      client_secret: 'secure-secret-xyz789',
      name: 'Secure PKCE Client',
      redirect_uris: JSON.stringify([`${clientBase}/secure-callback`]),
      scopes: JSON.stringify(['read', 'profile', 'email']),
      require_pkce: 1,
      trusted: 0,
    },
    // Malicious client registered by attacker
    {
      client_id: 'malicious-client',
      client_secret: 'evil-secret-666',
      name: 'Free Gift Cards App 🎁',  // Social engineering name
      redirect_uris: JSON.stringify([`${attackerBase}/capture`]),
      scopes: JSON.stringify(['read', 'write', 'admin']),  // Requests excessive scopes
      require_pkce: 0,
      trusted: 0,
    },
  ];

  const insert = db.prepare(`
    INSERT OR IGNORE INTO clients
      (client_id, client_secret, name, redirect_uris, scopes, require_pkce, trusted)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `);

  clients.forEach(c => insert.run(
    c.client_id, c.client_secret, c.name,
    c.redirect_uris, c.scopes, c.require_pkce, c.trusted
  ));
}

function seedUsers(db) {
  const crypto = require('crypto');
  const hashPassword = (p) => crypto.createHash('sha256').update(p).digest('hex');

  const users = [
    { id: uuidv4(), username: 'alice', password_hash: hashPassword('password123'), email: 'alice@example.com', roles: '["user"]' },
    { id: uuidv4(), username: 'admin', password_hash: hashPassword('adminpass'), email: 'admin@example.com', roles: '["user","admin"]' },
  ];

  const insert = db.prepare(`
    INSERT OR IGNORE INTO users (id, username, password_hash, email, roles)
    VALUES (?, ?, ?, ?, ?)
  `);

  users.forEach(u => insert.run(u.id, u.username, u.password_hash, u.email, u.roles));
}

module.exports = { getDb, initDatabase };
