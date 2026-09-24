/**
 * Forja: persistence for PIN lockout state and the attempt log.
 *
 * Kept out of the upstream schema file on purpose (fork mergeability): the two
 * tables are created lazily, idempotently, on first use. The PIN hash itself
 * lives in `users.password_hash`; the username is the Access email.
 */
import { getConnection } from '@/modules/database/index.js';

const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS forja_pin_state (
    user_id INTEGER PRIMARY KEY,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until INTEGER,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS forja_pin_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL,
    outcome TEXT NOT NULL,
    ip TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_forja_pin_attempts_email ON forja_pin_attempts(email, created_at);
`;

let ensuredFor: unknown = null;

function db() {
  const connection = getConnection();
  // Re-run when the singleton connection changes (tests swap databases).
  if (ensuredFor !== connection) {
    connection.exec(SCHEMA_SQL);
    ensuredFor = connection;
  }
  return connection;
}

export type PinUserRow = { id: number; username: string; password_hash: string };
export type PinState = { failedAttempts: number; lockedUntil: number | null };

export const pinRepository = {
  getUserByEmail(email: string): PinUserRow | undefined {
    return db()
      .prepare('SELECT id, username, password_hash FROM users WHERE username = ? AND is_active = 1')
      .get(email) as PinUserRow | undefined;
  },

  createUser(email: string, pinHash: string): PinUserRow {
    const result = db()
      .prepare('INSERT INTO users (username, password_hash) VALUES (?, ?)')
      .run(email, pinHash);
    return { id: Number(result.lastInsertRowid), username: email, password_hash: pinHash };
  },

  getState(userId: number): PinState {
    const row = db()
      .prepare('SELECT failed_attempts, locked_until FROM forja_pin_state WHERE user_id = ?')
      .get(userId) as { failed_attempts: number; locked_until: number | null } | undefined;
    return { failedAttempts: row?.failed_attempts ?? 0, lockedUntil: row?.locked_until ?? null };
  },

  saveState(userId: number, state: PinState): void {
    db()
      .prepare(`INSERT INTO forja_pin_state (user_id, failed_attempts, locked_until) VALUES (?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET failed_attempts = excluded.failed_attempts,
                                                   locked_until = excluded.locked_until`)
      .run(userId, state.failedAttempts, state.lockedUntil);
  },

  logAttempt(email: string, outcome: string, ip: string | null): void {
    db().prepare('INSERT INTO forja_pin_attempts (email, outcome, ip) VALUES (?, ?, ?)').run(email, outcome, ip);
  },

  updateLastLogin(userId: number): void {
    db().prepare('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?').run(userId);
  },
};

export type PinRepository = typeof pinRepository;
