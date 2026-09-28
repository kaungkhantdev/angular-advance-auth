import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { env } from '../config/env.ts';
import { migrations } from './migrations.ts';

function open(path: string): DatabaseSync {
  if (path !== ':memory:') mkdirSync(dirname(path), { recursive: true });
  const db = new DatabaseSync(path);
  db.exec(`
    PRAGMA journal_mode = WAL;
    PRAGMA foreign_keys = ON;
    PRAGMA busy_timeout = 5000;
  `);
  migrate(db);
  return db;
}

function migrate(db: DatabaseSync): void {
  db.exec('CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL)');
  const row = db.prepare('SELECT COALESCE(MAX(version), 0) AS v FROM schema_migrations').get() as { v: number };
  for (let i = row.v; i < migrations.length; i++) {
    transaction(db, () => {
      db.exec(migrations[i]!);
      db.prepare('INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)').run(i + 1, Date.now());
    });
  }
}

function transaction<T>(target: DatabaseSync, fn: () => T): T {
  if (target.isTransaction) return fn(); // flatten nested calls into the outer transaction
  target.exec('BEGIN IMMEDIATE');
  try {
    const result = fn();
    target.exec('COMMIT');
    return result;
  } catch (err) {
    target.exec('ROLLBACK');
    throw err;
  }
}

export const db = open(env.DATABASE_PATH);

/** Runs `fn` atomically. Nested calls join the outer transaction. */
export function tx<T>(fn: () => T): T {
  return transaction(db, fn);
}
