/**
 * Forja device mode: issue/revoke device client certificates with the
 * zone's Cloudflare-managed CA (API Shield / SSL "Client certificates").
 *
 * The device's key never leaves the device: only its CSR is sent. Needs an
 * API token limited to the Forja zone with "SSL and Certificates: Edit",
 * read from FORJA_CF_CERT_TOKEN_FILE (never from git or the environment).
 */
import { readFileSync } from 'node:fs';

import { certIssueViaSecretd, certRevokeViaSecretd, secretdEnabled } from './secretd-client.js';

export type IssuedCertificate = { cfCertId: string; certificatePem: string };

export type CertificateSigner = {
  issue(csrPem: string): Promise<IssuedCertificate>;
  revoke(cfCertId: string): Promise<void>;
};

type FetchLike = (url: string, init: { method: string; headers: Record<string, string>; body?: string; signal?: AbortSignal }) =>
  Promise<{ ok: boolean; status: number; json(): Promise<unknown> }>;

export type CloudflareSignerOptions = {
  zoneId: string;
  token: string;
  validityDays: number;
  fetch?: FetchLike;
  apiBase?: string;
};

type CfEnvelope = { success?: boolean; errors?: Array<{ code?: number; message?: string }>; result?: Record<string, unknown> };

export function createCloudflareSigner(options: CloudflareSignerOptions): CertificateSigner {
  const doFetch: FetchLike = options.fetch ?? ((url, init) => fetch(url, init));
  const base = `${options.apiBase ?? 'https://api.cloudflare.com/client/v4'}/zones/${encodeURIComponent(options.zoneId)}/client_certificates`;
  const headers = { Authorization: `Bearer ${options.token}`, 'Content-Type': 'application/json' };

  async function call(url: string, method: string, body?: unknown): Promise<Record<string, unknown>> {
    const response = await doFetch(url, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(15_000),
    });
    const payload = (await response.json().catch(() => ({}))) as CfEnvelope;
    if (!response.ok || !payload.success || !payload.result) {
      const detail = (payload.errors ?? []).map((e) => `${e.code ?? '?'} ${e.message ?? ''}`.trim()).join('; ');
      throw new Error(`Cloudflare client_certificates ${method} failed: HTTP ${response.status} ${detail}`.trim());
    }
    return payload.result;
  }

  return {
    async issue(csrPem) {
      const result = await call(base, 'POST', { csr: csrPem, validity_days: options.validityDays });
      const cfCertId = result.id;
      const certificatePem = result.certificate;
      if (typeof cfCertId !== 'string' || typeof certificatePem !== 'string') {
        throw new Error('Cloudflare returned no certificate');
      }
      return { cfCertId, certificatePem };
    },
    async revoke(cfCertId) {
      await call(`${base}/${encodeURIComponent(cfCertId)}`, 'DELETE');
    },
  };
}

/** forja-secretd (system-state-migration.md §7 override 1, 2026-09-30): the daemon holds
 * cloudflare-cert-token and makes the Cloudflare API calls itself -- this app process never reads
 * that token, on disk or in memory, at any point; it only ever sends a CSR (issue) or a cert id
 * (revoke) and gets back the same result shape as the direct signer above. */
function loadSecretdSigner(env: NodeJS.ProcessEnv): CertificateSigner {
  return {
    issue: (csrPem) => certIssueViaSecretd(csrPem, env),
    revoke: (cfCertId) => certRevokeViaSecretd(cfCertId, env),
  };
}

/** Signer from the environment, or null when not configured (enrolment then answers 503). */
export function loadCloudflareSigner(env: NodeJS.ProcessEnv = process.env): CertificateSigner | null {
  if (secretdEnabled(env)) return loadSecretdSigner(env);
  const zoneId = (env.FORJA_CF_ZONE_ID ?? '').trim();
  const tokenFile = (env.FORJA_CF_CERT_TOKEN_FILE ?? '').trim();
  if (!zoneId || !tokenFile) return null;
  let token = '';
  try {
    token = readFileSync(tokenFile, 'utf8').trim();
  } catch (error) {
    console.error('[forja-device] cannot read FORJA_CF_CERT_TOKEN_FILE:', error instanceof Error ? error.message : String(error));
    return null;
  }
  if (!token) return null;
  const days = Number(env.FORJA_DEVICE_CERT_DAYS ?? 1095);
  return createCloudflareSigner({ zoneId, token, validityDays: Number.isFinite(days) && days >= 30 ? Math.min(days, 3650) : 1095 });
}
