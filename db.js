import sqlite3 from "sqlite3";

export const db = new sqlite3.Database("./unitv.db");

export function initDb() {
  db.serialize(() => {
    db.run(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        plan TEXT NOT NULL DEFAULT 'FREE',
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      );
    `);
  });
}
