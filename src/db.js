/**
 * db.js — builds and seeds the lab database (SQLite, via Node's built-in node:sqlite).
 *
 * The SAME database file is shared by the vulnerable app and the secure app so you can
 * run identical payloads against both and compare the outcome.
 *
 * WEB404 Secure Coding Practices — Practical 5.
 * This data is fictional and exists only to demonstrate SQL injection in a local lab.
 */
'use strict';

const { DatabaseSync } = require('node:sqlite');
const path = require('node:path');
const fs = require('node:fs');

const DB_PATH = path.join(__dirname, '..', 'data', 'lab.db');

function openDatabase() {
  fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
  const db = new DatabaseSync(DB_PATH);

  // Register a user-defined sleep() so time-based blind SQLi can be demonstrated.
  // Real engines ship their own: MySQL SLEEP(), PostgreSQL pg_sleep(), MSSQL WAITFOR DELAY.
  // SQLite has none, so we add one purely for the lab.
  try {
    db.function('sleep', (seconds) => {
      const ms = Math.max(0, Math.min(Number(seconds) || 0, 10)) * 1000; // capped at 10s
      const end = Date.now() + ms;
      while (Date.now() < end) { /* busy-wait, blocking by design for the demo */ }
      return 0;
    });
  } catch (_) { /* already registered on this connection */ }

  return db;
}

function seed() {
  fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
  // Start clean every seed so demos are reproducible.
  if (fs.existsSync(DB_PATH)) fs.rmSync(DB_PATH);

  const db = openDatabase();

  db.exec(`
    CREATE TABLE users (
      id        INTEGER PRIMARY KEY AUTOINCREMENT,
      username  TEXT NOT NULL UNIQUE,
      password  TEXT NOT NULL,          -- plaintext ON PURPOSE, to show what a dump leaks
      role      TEXT NOT NULL,
      email     TEXT NOT NULL,
      api_token TEXT NOT NULL           -- "sensitive" secret an attacker would exfiltrate
    );

    CREATE TABLE products (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      name        TEXT NOT NULL,
      category    TEXT NOT NULL,
      price       REAL NOT NULL,
      description TEXT NOT NULL
    );

    CREATE TABLE app_secrets (
      name  TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );
  `);

  const insertUser = db.prepare(
    `INSERT INTO users (username, password, role, email, api_token)
     VALUES (?, ?, ?, ?, ?)`
  );
  insertUser.run('admin', 'S3cr3t_Adm1n!2024', 'admin',   'admin@lab.local',  'tok_admin_9f8e7d6c5b4a');
  insertUser.run('alice', 'password123',        'manager', 'alice@lab.local',  'tok_alice_1a2b3c4d5e6f');
  insertUser.run('bob',   'qwerty',             'user',    'bob@lab.local',    'tok_bob_0z9y8x7w6v5u');
  insertUser.run('carol', 'Winter!2024',        'user',    'carol@lab.local',  'tok_carol_abcdef012345');

  const insertProduct = db.prepare(
    `INSERT INTO products (name, category, price, description) VALUES (?, ?, ?, ?)`
  );
  insertProduct.run('Mechanical Keyboard', 'peripherals', 89.99,  'Tactile switches, USB-C.');
  insertProduct.run('Wireless Mouse',      'peripherals', 39.50,  'Ergonomic, 2.4GHz.');
  insertProduct.run('27-inch Monitor',     'displays',    245.00, '1440p IPS panel.');
  insertProduct.run('USB-C Hub',           'accessories', 29.95,  '7-in-1 adapter.');
  insertProduct.run('Laptop Stand',        'accessories', 24.00,  'Aluminium, adjustable.');
  insertProduct.run('Webcam 1080p',        'peripherals', 54.75,  'Auto-focus, privacy shutter.');

  const insertSecret = db.prepare(`INSERT INTO app_secrets (name, value) VALUES (?, ?)`);
  insertSecret.run('flag',              'WEB404{sql_injection_union_select_success}');
  insertSecret.run('db_backup_key',     'backup-key-7h3-r3al-0n3');

  db.close();
  return DB_PATH;
}

module.exports = { openDatabase, seed, DB_PATH };

// Allow `node src/db.js` to (re)build the database from the command line.
if (require.main === module) {
  const p = seed();
  console.log('[seed] Lab database created at:', p);
  console.log('[seed] Tables: users(4 rows), products(6 rows), app_secrets(2 rows)');
}
