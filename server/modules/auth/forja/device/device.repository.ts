/**
 * Forja device mode: registered devices and pending enrolments.
 *
 * Same approach as pin.repository.ts: tables created lazily and idempotently,
 * outside the upstream schema. At most one ACTIVE device per (email, platform)
 * is enforced by a partial unique index, so a race cannot register two PCs.
 */
import { getConnection } from '@/modules/database/index.js';

const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS forja_devices (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL,
    platform TEXT NOT NULL,
    name TEXT NOT NULL,
    cert_sha256 TEXT NOT NULL UNIQUE,
    cf_cert_id TEXT,
    status TEXT NOT NULL DEFAULT 'active',
    created_at INTEGER NOT NULL,
    last_seen_at INTEGER,
    revoked_at INTEGER
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_forja_devices_slot ON forja_devices(email, platform) WHERE status = 'active';
CREATE TABLE IF NOT EXISTS forja_enrollments (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL,
    platform TEXT NOT NULL,
    name TEXT NOT NULL,
    csr TEXT NOT NULL,
    code_hash TEXT,
    kind TEXT NOT NULL,
    status TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    ip TEXT,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_forja_enrollments_ip ON forja_enrollments(ip, created_at);
CREATE INDEX IF NOT EXISTS idx_forja_enrollments_email ON forja_enrollments(email, created_at);
CREATE TABLE IF NOT EXISTS forja_enroll_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    enrollment_id TEXT,
    outcome TEXT NOT NULL,
    ip TEXT,
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_forja_enroll_attempts_ip ON forja_enroll_attempts(ip, created_at);
`;

let ensuredFor: unknown = null;

function db() {
  const connection = getConnection();
  if (ensuredFor !== connection) {
    connection.exec(SCHEMA_SQL);
    ensuredFor = connection;
  }
  return connection;
}

export type DevicePlatform = 'pc' | 'phone';
export type DeviceStatus = 'active' | 'revoked';

export type DeviceRow = {
  id: string;
  email: string;
  platform: DevicePlatform;
  name: string;
  cert_sha256: string;
  cf_cert_id: string | null;
  status: DeviceStatus;
  created_at: number;
  last_seen_at: number | null;
  revoked_at: number | null;
};

/** `real` = allowed email with a free slot; `decoy` = unknown email; `blocked` = slot taken. */
export type EnrollmentKind = 'real' | 'decoy' | 'blocked';
export type EnrollmentStatus = 'pending' | 'used' | 'failed';

export type EnrollmentRow = {
  id: string;
  email: string;
  platform: DevicePlatform;
  name: string;
  csr: string;
  code_hash: string | null;
  kind: EnrollmentKind;
  status: EnrollmentStatus;
  attempts: number;
  ip: string | null;
  created_at: number;
  expires_at: number;
};

export const deviceRepository = {
  findByFingerprint(sha256Hex: string): DeviceRow | undefined {
    return db().prepare('SELECT * FROM forja_devices WHERE cert_sha256 = ?').get(sha256Hex) as DeviceRow | undefined;
  },

  findById(id: string): DeviceRow | undefined {
    return db().prepare('SELECT * FROM forja_devices WHERE id = ?').get(id) as DeviceRow | undefined;
  },

  findActiveSlot(email: string, platform: DevicePlatform): DeviceRow | undefined {
    return db()
      .prepare("SELECT * FROM forja_devices WHERE email = ? AND platform = ? AND status = 'active'")
      .get(email, platform) as DeviceRow | undefined;
  },

  list(): DeviceRow[] {
    return db().prepare('SELECT * FROM forja_devices ORDER BY created_at').all() as DeviceRow[];
  },

  insert(row: Omit<DeviceRow, 'status' | 'last_seen_at' | 'revoked_at'>): void {
    db()
      .prepare(`INSERT INTO forja_devices (id, email, platform, name, cert_sha256, cf_cert_id, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, 'active', ?)`)
      .run(row.id, row.email, row.platform, row.name, row.cert_sha256, row.cf_cert_id, row.created_at);
  },

  revoke(id: string, at: number): boolean {
    const result = db()
      .prepare("UPDATE forja_devices SET status = 'revoked', revoked_at = ? WHERE id = ? AND status = 'active'")
      .run(at, id);
    return result.changes > 0;
  },

  touch(id: string, at: number): void {
    db().prepare('UPDATE forja_devices SET last_seen_at = ? WHERE id = ?').run(at, id);
  },

  insertEnrollment(row: EnrollmentRow): void {
    db()
      .prepare(`INSERT INTO forja_enrollments
                (id, email, platform, name, csr, code_hash, kind, status, attempts, ip, created_at, expires_at)
                VALUES (@id, @email, @platform, @name, @csr, @code_hash, @kind, @status, @attempts, @ip, @created_at, @expires_at)`)
      .run(row);
  },

  getEnrollment(id: string): EnrollmentRow | undefined {
    return db().prepare('SELECT * FROM forja_enrollments WHERE id = ?').get(id) as EnrollmentRow | undefined;
  },

  /** Counts one code attempt; returns the new count. */
  bumpAttempts(id: string): number {
    db().prepare('UPDATE forja_enrollments SET attempts = attempts + 1 WHERE id = ?').run(id);
    return (db().prepare('SELECT attempts FROM forja_enrollments WHERE id = ?').get(id) as { attempts: number }).attempts;
  },

  /** pending → status, atomically; false if it was no longer pending (single use). */
  closeEnrollment(id: string, status: Exclude<EnrollmentStatus, 'pending'>): boolean {
    const result = db()
      .prepare("UPDATE forja_enrollments SET status = ? WHERE id = ? AND status = 'pending'")
      .run(status, id);
    return result.changes > 0;
  },

  countEnrollmentsByIp(ip: string, since: number): number {
    return (db().prepare('SELECT COUNT(*) AS n FROM forja_enrollments WHERE ip = ? AND created_at >= ?').get(ip, since) as { n: number }).n;
  },

  countEnrollmentsByEmail(email: string, since: number): number {
    return (db().prepare('SELECT COUNT(*) AS n FROM forja_enrollments WHERE email = ? AND created_at >= ?').get(email, since) as { n: number }).n;
  },

  countEnrollments(since: number): number {
    return (db().prepare('SELECT COUNT(*) AS n FROM forja_enrollments WHERE created_at >= ?').get(since) as { n: number }).n;
  },

  logAttempt(enrollmentId: string | null, outcome: string, ip: string | null, at: number): void {
    db()
      .prepare('INSERT INTO forja_enroll_attempts (enrollment_id, outcome, ip, created_at) VALUES (?, ?, ?, ?)')
      .run(enrollmentId, outcome, ip, at);
  },

  countFailedAttemptsByIp(ip: string, since: number): number {
    return (db()
      .prepare("SELECT COUNT(*) AS n FROM forja_enroll_attempts WHERE ip = ? AND created_at >= ? AND outcome LIKE 'fail%'")
      .get(ip, since) as { n: number }).n;
  },
};

export type DeviceRepository = typeof deviceRepository;
