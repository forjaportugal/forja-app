/**
 * Forja device mode: enrolment of a device (1 PC + 1 phone per person).
 *
 *  start   {email, platform, name, csr} → a 6-digit code is emailed to that
 *          address (only allowed emails with a free slot actually get one).
 *          The answer is the same for every email, so the allow-list and the
 *          slot state do not leak.
 *  confirm {enrollmentId, code} → the CSR is signed by the Cloudflare-managed
 *          CA and the device is registered; the certificate goes back to the
 *          device, which pairs it with its non-exportable key.
 *
 * Limits: codes live 10 min, 5 tries per enrolment, single use; per IP
 * 5 starts/hour and 10 failed confirms/15 min; per email 3 starts/hour;
 * 30 starts/day in total. The CSR self-signature is verified (proof of
 * possession) and the returned certificate must carry the CSR's key.
 */
import { X509Certificate, createHmac, randomBytes, randomInt, timingSafeEqual } from 'node:crypto';

import { AppError } from '@/shared/utils.js';

import type { CertificateSigner } from './cf-client-certs.js';
import { parseAndVerifyCsr } from './csr.js';
import type { DevicePlatform, DeviceRepository, EnrollmentKind } from './device.repository.js';
import { buildEnrollmentCodeMail, type Mailer } from './mailer.js';

export const CODE_TTL_MS = 10 * 60 * 1000;
export const MAX_CODE_ATTEMPTS = 5;
export const LIMITS = {
  startsPerIpPerHour: 5,
  startsPerEmailPerHour: 3,
  startsPerDay: 30,
  failedConfirmsPerIpPer15Min: 10,
};
const HOUR = 60 * 60 * 1000;
const PLATFORM_LABEL: Record<DevicePlatform, string> = { pc: 'computador', phone: 'telemóvel' };

export type EnrollmentDependencies = {
  repo: DeviceRepository;
  allowedEmails: string[];
  mailer: Mailer | null;
  signer: CertificateSigner | null;
  /** HMAC key for stored code hashes (the server's JWT secret). */
  secret: string;
  now?: () => number;
  log?: (line: string) => void;
};

function fail(message: string, code: string, statusCode: number, details?: unknown): never {
  throw new AppError(message, { code, statusCode, details });
}

function readEmail(value: unknown): string {
  if (typeof value !== 'string') fail('Email required', 'ENROLL_EMAIL', 400);
  const email = value.trim().toLowerCase();
  if (email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) fail('Email required', 'ENROLL_EMAIL', 400);
  return email;
}

function readPlatform(value: unknown): DevicePlatform {
  if (value !== 'pc' && value !== 'phone') fail('Unknown platform', 'ENROLL_PLATFORM', 400);
  return value;
}

function readName(value: unknown): string {
  const name = typeof value === 'string' ? value.replace(/[^\p{L}\p{N} ._-]/gu, '').trim().slice(0, 64) : '';
  return name || 'aparelho';
}

export function fingerprintOf(certificatePem: string): string {
  return new X509Certificate(certificatePem).fingerprint256.replace(/:/g, '').toLowerCase();
}

export function createEnrollmentService(dependencies: EnrollmentDependencies) {
  const { repo } = dependencies;
  const now = dependencies.now ?? (() => Date.now());
  const log = dependencies.log ?? ((line: string) => console.log(line));
  const allowed = new Set(dependencies.allowedEmails.map((email) => email.toLowerCase()));

  function hashCode(id: string, code: string): string {
    return createHmac('sha256', dependencies.secret).update(`forja-enroll:${id}:${code}`).digest('hex');
  }

  function ready(): { mailer: Mailer; signer: CertificateSigner } {
    if (!dependencies.mailer) fail('Email sending is not configured on the server', 'MAIL_NOT_CONFIGURED', 503);
    if (!dependencies.signer) fail('Device certificates are not configured on the server', 'SIGNER_NOT_CONFIGURED', 503);
    return { mailer: dependencies.mailer, signer: dependencies.signer };
  }

  async function start(body: Record<string, unknown>, ip: string | null) {
    const { mailer } = ready();
    const email = readEmail(body.email);
    const platform = readPlatform(body.platform);
    const name = readName(body.name);
    const csr = body.csr;
    try {
      parseAndVerifyCsr(csr);
    } catch (error) {
      log(`[forja-device] enroll start rejected csr ip=${ip ?? '-'}: ${error instanceof Error ? error.message : String(error)}`);
      fail('Invalid device key request', 'ENROLL_CSR', 400);
    }

    const at = now();
    if (ip && repo.countEnrollmentsByIp(ip, at - HOUR) >= LIMITS.startsPerIpPerHour) {
      repo.logAttempt(null, 'fail-rate-ip', ip, at);
      fail('Too many attempts. Try again later.', 'ENROLL_RATE_LIMITED', 429);
    }
    if (repo.countEnrollments(at - 24 * HOUR) >= LIMITS.startsPerDay) {
      repo.logAttempt(null, 'fail-rate-global', ip, at);
      fail('Too many attempts. Try again later.', 'ENROLL_RATE_LIMITED', 429);
    }

    let kind: EnrollmentKind = 'real';
    if (!allowed.has(email)) kind = 'decoy';
    else if (repo.countEnrollmentsByEmail(email, at - HOUR) >= LIMITS.startsPerEmailPerHour) kind = 'decoy';
    else if (repo.findActiveSlot(email, platform)) kind = 'blocked';

    const id = randomBytes(18).toString('base64url');
    const code = String(randomInt(0, 1_000_000)).padStart(6, '0');
    repo.insertEnrollment({
      id,
      email,
      platform,
      name,
      csr: csr as string,
      code_hash: kind === 'real' ? hashCode(id, code) : null,
      kind,
      status: 'pending',
      attempts: 0,
      ip,
      created_at: at,
      expires_at: at + CODE_TTL_MS,
    });
    log(`[forja-device] enroll start id=${id.slice(0, 6)} kind=${kind} platform=${platform} ip=${ip ?? '-'}`);

    if (kind === 'real') {
      try {
        await mailer.send(buildEnrollmentCodeMail({ to: email, code, deviceLabel: PLATFORM_LABEL[platform], deviceName: name }));
      } catch (error) {
        repo.closeEnrollment(id, 'failed');
        log(`[forja-device] enroll mail failed: ${error instanceof Error ? error.message : String(error)}`);
        fail('Could not send the email. Try again later.', 'MAIL_FAILED', 503);
      }
    } else if (kind === 'blocked') {
      // Tell the real owner, not the requester, that the slot is taken.
      await mailer.send({
        to: email,
        subject: `Forja: já tens um ${PLATFORM_LABEL[platform]} registado`,
        text: `Alguém (talvez tu) tentou registar mais um ${PLATFORM_LABEL[platform]} na Forja.\n`
          + `Só pode haver um ${PLATFORM_LABEL[platform]} por pessoa. Para trocar de aparelho, pede ao Maestro para retirar o antigo.\n`,
      }).catch(() => undefined);
    }
    return { enrollmentId: id, expiresIn: Math.round(CODE_TTL_MS / 1000) };
  }

  async function confirm(body: Record<string, unknown>, ip: string | null) {
    const { signer } = ready();
    const at = now();
    if (ip && repo.countFailedAttemptsByIp(ip, at - 15 * 60 * 1000) >= LIMITS.failedConfirmsPerIpPer15Min) {
      fail('Too many attempts. Try again later.', 'ENROLL_RATE_LIMITED', 429);
    }
    const id = typeof body.enrollmentId === 'string' ? body.enrollmentId : '';
    const code = typeof body.code === 'string' ? body.code.trim() : '';
    const row = id ? repo.getEnrollment(id) : undefined;
    if (!row || row.status !== 'pending' || row.expires_at <= at) {
      repo.logAttempt(id || null, 'fail-invalid', ip, at);
      fail('This registration has expired. Start again.', 'ENROLL_INVALID', 400);
    }
    const attempts = repo.bumpAttempts(row.id);
    if (attempts > MAX_CODE_ATTEMPTS) {
      repo.closeEnrollment(row.id, 'failed');
      repo.logAttempt(row.id, 'fail-locked', ip, at);
      fail('Too many wrong codes. Start again.', 'ENROLL_LOCKED', 400);
    }
    const good = /^\d{6}$/.test(code) && row.code_hash !== null
      && timingSafeEqual(Buffer.from(hashCode(row.id, code), 'hex'), Buffer.from(row.code_hash, 'hex'));
    if (!good) {
      repo.logAttempt(row.id, 'fail-code', ip, at);
      if (attempts >= MAX_CODE_ATTEMPTS) repo.closeEnrollment(row.id, 'failed');
      fail('Wrong code.', 'ENROLL_CODE_INVALID', 400, { attemptsLeft: Math.max(0, MAX_CODE_ATTEMPTS - attempts) });
    }
    // Single use: only one confirm can move it out of "pending".
    if (!repo.closeEnrollment(row.id, 'used')) {
      repo.logAttempt(row.id, 'fail-replay', ip, at);
      fail('This registration has expired. Start again.', 'ENROLL_INVALID', 400);
    }
    if (repo.findActiveSlot(row.email, row.platform)) {
      repo.logAttempt(row.id, 'fail-slot', ip, at);
      fail('A device of this kind is already registered.', 'ENROLL_SLOT_TAKEN', 409);
    }

    const csr = parseAndVerifyCsr(row.csr);
    const issued = await signer.issue(row.csr);
    let fingerprint: string;
    try {
      const certKey = new X509Certificate(issued.certificatePem).publicKey.export({ type: 'spki', format: 'der' });
      if (!Buffer.from(certKey).equals(csr.spki)) throw new Error('certificate key does not match the CSR');
      fingerprint = fingerprintOf(issued.certificatePem);
      repo.insert({
        id: randomBytes(12).toString('base64url'),
        email: row.email,
        platform: row.platform,
        name: row.name,
        cert_sha256: fingerprint,
        cf_cert_id: issued.cfCertId,
        created_at: at,
      });
    } catch (error) {
      await signer.revoke(issued.cfCertId).catch(() => undefined);
      repo.logAttempt(row.id, 'fail-register', ip, at);
      log(`[forja-device] enroll register failed: ${error instanceof Error ? error.message : String(error)}`);
      fail('Could not register this device.', 'ENROLL_REGISTER_FAILED', 409);
    }
    const device = repo.findByFingerprint(fingerprint);
    repo.logAttempt(row.id, 'success', ip, at);
    log(`[forja-device] enrolled device=${device?.id} email=${row.email} platform=${row.platform}`);
    return { deviceId: device?.id, platform: row.platform, certificate: issued.certificatePem, fingerprintSha256: fingerprint };
  }

  /** Revokes a device here and at Cloudflare (used by the device CLI). */
  async function revoke(deviceId: string) {
    const device = repo.findById(deviceId);
    if (!device) fail('Unknown device', 'DEVICE_UNKNOWN', 404);
    const changed = repo.revoke(deviceId, now());
    if (device.cf_cert_id && dependencies.signer) {
      await dependencies.signer.revoke(device.cf_cert_id);
    }
    return { revoked: changed, cloudflare: Boolean(device.cf_cert_id && dependencies.signer) };
  }

  return { start, confirm, revoke };
}

export type EnrollmentService = ReturnType<typeof createEnrollmentService>;
