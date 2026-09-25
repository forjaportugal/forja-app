/**
 * Forja: Cloudflare Access identity.
 *
 * Every request that reaches the app through the tunnel carries the
 * `Cf-Access-Jwt-Assertion` header, a JWT signed by the team's Access keys.
 * The plain `Cf-Access-Authenticated-User-Email` header is NOT trusted on its
 * own: the email is taken from the verified JWT and must be on the allow-list.
 */
import { createPublicKey, type KeyObject } from 'node:crypto';
import type { IncomingHttpHeaders } from 'node:http';

import jwt from 'jsonwebtoken';

export const CF_ACCESS_JWT_HEADER = 'cf-access-jwt-assertion';
export const CF_ACCESS_EMAIL_HEADER = 'cf-access-authenticated-user-email';

/** `deviceId` is set only in device mode (FORJA_AUTH=device): the registered device the request came from. */
export type AccessIdentity = { email: string; via: 'jwt' | 'dev-bypass' | 'device'; deviceId?: string };

export type AccessFailure = {
  ok: false;
  reason: 'missing' | 'invalid' | 'not-allowed' | 'misconfigured' | 'keys-unavailable' | 'not-registered' | 'revoked';
};

export type AccessResult = { ok: true; identity: AccessIdentity } | AccessFailure;

export type CfAccessConfig = {
  teamDomain: string;
  audience: string;
  allowedEmails: string[];
  devBypass: boolean;
};

type Jwk = { kid?: string; kty?: string; [key: string]: unknown };

export type CfAccessVerifierOptions = CfAccessConfig & {
  fetchCerts?: () => Promise<{ keys?: Jwk[] }>;
  now?: () => number;
  /** How long fetched keys are trusted before a background refresh. */
  keyTtlMs?: number;
};

const DEFAULT_TEAM_DOMAIN = 'wild-tree-51af.cloudflareaccess.com';
const MIN_REFETCH_INTERVAL_MS = 30_000;

export function parseEmailList(value: string | undefined): string[] {
  return (value ?? '')
    .split(',')
    .map((entry) => entry.trim().toLowerCase())
    .filter(Boolean);
}

/** Reads the Access settings from the environment. */
export function loadCfAccessConfig(env: NodeJS.ProcessEnv = process.env): CfAccessConfig {
  const bypassRequested = env.FORJA_ACCESS_DEV_BYPASS === '1';
  const devBypass = bypassRequested && env.NODE_ENV !== 'production';
  if (bypassRequested && !devBypass) {
    console.error('[forja-access] FORJA_ACCESS_DEV_BYPASS ignored: NODE_ENV=production');
  }
  return {
    teamDomain: (env.CF_ACCESS_TEAM_DOMAIN || DEFAULT_TEAM_DOMAIN).replace(/^https?:\/\//, '').replace(/\/+$/, ''),
    audience: (env.CF_ACCESS_AUD ?? '').trim(),
    allowedEmails: parseEmailList(env.FORJA_ALLOWED_EMAILS),
    devBypass,
  };
}

function headerValue(headers: IncomingHttpHeaders, name: string): string | null {
  const raw = headers[name];
  const value = Array.isArray(raw) ? raw[0] : raw;
  return typeof value === 'string' && value.trim() ? value.trim() : null;
}

export function createCfAccessVerifier(options: CfAccessVerifierOptions) {
  const issuer = `https://${options.teamDomain}`;
  const certsUrl = `${issuer}/cdn-cgi/access/certs`;
  const now = options.now ?? (() => Date.now());
  const keyTtlMs = options.keyTtlMs ?? 60 * 60 * 1000;
  const allowed = new Set(options.allowedEmails.map((email) => email.toLowerCase()));
  const fetchCerts = options.fetchCerts ?? (async () => {
    const response = await fetch(certsUrl, { signal: AbortSignal.timeout(5_000) });
    if (!response.ok) {
      throw new Error(`certs fetch failed: HTTP ${response.status}`);
    }
    return (await response.json()) as { keys?: Jwk[] };
  });

  let keys = new Map<string, KeyObject>();
  let fetchedAt = 0;
  let lastAttemptAt = 0;
  let inflight: Promise<void> | null = null;

  async function refreshKeys(force = false): Promise<void> {
    if (!force && now() - lastAttemptAt < MIN_REFETCH_INTERVAL_MS) {
      return inflight ?? undefined;
    }
    if (inflight) {
      return inflight;
    }
    lastAttemptAt = now();
    inflight = (async () => {
      try {
        const body = await fetchCerts();
        const next = new Map<string, KeyObject>();
        for (const jwk of body.keys ?? []) {
          if (!jwk.kid || jwk.kty !== 'RSA') continue;
          next.set(jwk.kid, createPublicKey({ key: jwk as never, format: 'jwk' }));
        }
        if (next.size > 0) {
          keys = next;
          fetchedAt = now();
        }
      } catch (error) {
        console.error('[forja-access] could not fetch Access certs:', error instanceof Error ? error.message : String(error));
      } finally {
        inflight = null;
      }
    })();
    return inflight;
  }

  function checkEmail(email: unknown, via: AccessIdentity['via']): AccessResult {
    if (typeof email !== 'string' || !email.includes('@')) {
      return { ok: false, reason: 'invalid' };
    }
    const normalized = email.trim().toLowerCase();
    if (!allowed.has(normalized)) {
      return { ok: false, reason: 'not-allowed' };
    }
    return { ok: true, identity: { email: normalized, via } };
  }

  function verifyWithKey(token: string, key: KeyObject, headers: IncomingHttpHeaders): AccessResult {
    try {
      const claims = jwt.verify(token, key, {
        algorithms: ['RS256'],
        audience: options.audience,
        issuer,
        clockTimestamp: Math.floor(now() / 1000),
      }) as jwt.JwtPayload;
      const result = checkEmail(claims.email, 'jwt');
      // Defence in depth: if Cloudflare also sent the plain email header it
      // must agree with the signed claim.
      const plainEmail = headerValue(headers, CF_ACCESS_EMAIL_HEADER);
      if (result.ok && plainEmail && plainEmail.toLowerCase() !== result.identity.email) {
        return { ok: false, reason: 'invalid' };
      }
      return result;
    } catch {
      return { ok: false, reason: 'invalid' };
    }
  }

  function preflight(headers: IncomingHttpHeaders): AccessResult | { ok: 'token'; token: string; kid: string } {
    if (options.devBypass) {
      const email = headerValue(headers, CF_ACCESS_EMAIL_HEADER);
      return email ? checkEmail(email, 'dev-bypass') : { ok: false, reason: 'missing' };
    }
    if (!options.audience || allowed.size === 0) {
      return { ok: false, reason: 'misconfigured' };
    }
    const token = headerValue(headers, CF_ACCESS_JWT_HEADER);
    if (!token) {
      return { ok: false, reason: 'missing' };
    }
    const decoded = jwt.decode(token, { complete: true }) as jwt.Jwt | null;
    const kid = decoded && typeof decoded === 'object' ? decoded.header?.kid : undefined;
    if (!kid) {
      return { ok: false, reason: 'invalid' };
    }
    return { ok: 'token', token, kid };
  }

  return {
    certsUrl,
    issuer,
    refreshKeys,

    /** Full verification; fetches the team keys when needed. */
    async verify(headers: IncomingHttpHeaders): Promise<AccessResult> {
      const pre = preflight(headers);
      if (pre.ok !== 'token') return pre;
      if (!keys.has(pre.kid) || now() - fetchedAt > keyTtlMs) {
        await refreshKeys();
      }
      const key = keys.get(pre.kid);
      if (!key) {
        return { ok: false, reason: keys.size === 0 ? 'keys-unavailable' : 'invalid' };
      }
      return verifyWithKey(pre.token, key, headers);
    },

    /**
     * Synchronous verification with the cached keys only (WebSocket upgrade
     * hook is synchronous). An unknown key id triggers a background refresh.
     */
    verifySync(headers: IncomingHttpHeaders): AccessResult {
      const pre = preflight(headers);
      if (pre.ok !== 'token') return pre;
      const key = keys.get(pre.kid);
      if (!key || now() - fetchedAt > keyTtlMs) {
        void refreshKeys();
      }
      if (!key) {
        return { ok: false, reason: keys.size === 0 ? 'keys-unavailable' : 'invalid' };
      }
      return verifyWithKey(pre.token, key, headers);
    },
  };
}

export type CfAccessVerifier = ReturnType<typeof createCfAccessVerifier>;
