/**
 * Forja device mode (`FORJA_AUTH=device`): identity = the registered device.
 *
 * Transport proof is mutual TLS at the Cloudflare edge: the device holds a
 * non-exportable key (TPM / Android Keystore / Secure Enclave) and a client
 * certificate issued by the zone's Cloudflare-managed CA at enrolment. A WAF
 * rule refuses every request on the app hostname without a verified,
 * unrevoked client certificate, so unauthenticated traffic never reaches the
 * tunnel. A request header transform rule then sets two headers for the origin:
 *
 *   x-forja-edge-auth          static secret known only to Cloudflare and this server
 *   x-forja-client-cert-sha256 cf.tls_client_auth.cert_fingerprint_sha256
 *
 * Cloudflare overwrites client-sent copies of both. The edge secret stops a
 * local process on the server (which can reach 127.0.0.1:3001 directly) from
 * forging a fingerprint. The origin then requires the fingerprint to belong
 * to an ACTIVE registered device of an allowed email, so a revoked device is
 * refused here even before Cloudflare's revocation propagates.
 */
import { timingSafeEqual, createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import type { IncomingHttpHeaders } from 'node:http';

import { parseEmailList, type AccessResult } from '../cf-access.js';

import type { DeviceRepository } from './device.repository.js';

export const EDGE_AUTH_HEADER = 'x-forja-edge-auth';
export const CLIENT_CERT_SHA256_HEADER = 'x-forja-client-cert-sha256';
const TOUCH_INTERVAL_MS = 5 * 60 * 1000;
export const MIN_EDGE_SECRET_LENGTH = 32;

export type DeviceModeConfig = {
  allowedEmails: string[];
  edgeSecret: string;
};

function readSecret(env: NodeJS.ProcessEnv, name: string): string {
  const file = env[`${name}_FILE`];
  if (file) {
    try {
      return readFileSync(file, 'utf8').trim();
    } catch (error) {
      console.error(`[forja-device] cannot read ${name}_FILE:`, error instanceof Error ? error.message : String(error));
      return '';
    }
  }
  return (env[name] ?? '').trim();
}

export function loadDeviceModeConfig(env: NodeJS.ProcessEnv = process.env): DeviceModeConfig {
  return {
    allowedEmails: parseEmailList(env.FORJA_ALLOWED_EMAILS),
    edgeSecret: readSecret(env, 'FORJA_EDGE_SECRET'),
  };
}

function headerValue(headers: IncomingHttpHeaders, name: string): string | null {
  const raw = headers[name];
  const value = Array.isArray(raw) ? raw[0] : raw;
  return typeof value === 'string' && value.trim() ? value.trim() : null;
}

/** Cloudflare sends lowercase hex; accept colon-separated/uppercase too. */
export function normalizeFingerprint(value: string | null): string | null {
  if (!value) return null;
  const hex = value.replace(/:/g, '').toLowerCase();
  return /^[0-9a-f]{64}$/.test(hex) ? hex : null;
}

function sameSecret(given: string, expected: string): boolean {
  // Compare fixed-length digests so the length of the secret does not leak.
  const a = createHash('sha256').update(given).digest();
  const b = createHash('sha256').update(expected).digest();
  return timingSafeEqual(a, b);
}

export type DeviceVerifierOptions = DeviceModeConfig & {
  repo: Pick<DeviceRepository, 'findByFingerprint' | 'touch'>;
  now?: () => number;
};

export function createDeviceVerifier(options: DeviceVerifierOptions) {
  const allowed = new Set(options.allowedEmails.map((email) => email.toLowerCase()));
  const now = options.now ?? (() => Date.now());
  const lastTouch = new Map<string, number>();

  /** The request came through the Cloudflare edge (enrolment paths need only this). */
  function verifyEdge(headers: IncomingHttpHeaders): { ok: true } | { ok: false; reason: 'misconfigured' | 'missing' | 'invalid' } {
    if (options.edgeSecret.length < MIN_EDGE_SECRET_LENGTH || allowed.size === 0) {
      return { ok: false, reason: 'misconfigured' };
    }
    const edge = headerValue(headers, EDGE_AUTH_HEADER);
    if (!edge) return { ok: false, reason: 'missing' };
    if (!sameSecret(edge, options.edgeSecret)) return { ok: false, reason: 'invalid' };
    return { ok: true };
  }

  function verifySync(headers: IncomingHttpHeaders): AccessResult {
    const edge = verifyEdge(headers);
    if (!edge.ok) return edge;

    const fingerprint = normalizeFingerprint(headerValue(headers, CLIENT_CERT_SHA256_HEADER));
    if (!fingerprint) return { ok: false, reason: 'missing' };
    const device = options.repo.findByFingerprint(fingerprint);
    if (!device) return { ok: false, reason: 'not-registered' };
    if (device.status !== 'active') return { ok: false, reason: 'revoked' };
    if (!allowed.has(device.email.toLowerCase())) return { ok: false, reason: 'not-allowed' };

    const at = now();
    if (at - (lastTouch.get(device.id) ?? 0) > TOUCH_INTERVAL_MS) {
      lastTouch.set(device.id, at);
      try {
        options.repo.touch(device.id, at);
      } catch { /* best effort */ }
    }
    return { ok: true, identity: { email: device.email.toLowerCase(), via: 'device', deviceId: device.id } };
  }

  return {
    verifyEdge,
    verifySync,
    async verify(headers: IncomingHttpHeaders): Promise<AccessResult> {
      return verifySync(headers);
    },
  };
}

export type DeviceVerifier = ReturnType<typeof createDeviceVerifier>;
