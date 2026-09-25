/**
 * Forja auth modes, both "identity + 6-digit PIN":
 *   FORJA_AUTH=pin    identity = Cloudflare Access JWT (current production).
 *   FORJA_AUTH=device identity = registered device (edge mTLS client
 *                     certificate, see ./device/device-verifier.ts); session
 *                     tokens are also bound to that device.
 *
 * - Identity is the email in the verified Access JWT; no usernames, no passwords.
 * - One app user per allowed Access email; the PIN is the only in-app secret.
 * - App session tokens are bound to that email, last at most 12 h and are never
 *   slid forward: when they expire the PIN is asked again.
 * - Every authenticated request (HTTP and WebSocket) re-checks the Access JWT,
 *   so a leaked app token is useless without the enrolled device's Access session.
 *
 * Upstream code only calls into this module behind `isForjaPinMode()`.
 */
import { AsyncLocalStorage } from 'node:async_hooks';
import type { IncomingHttpHeaders } from 'node:http';
import { createRequire } from 'node:module';

import express from 'express';
import type { NextFunction, Request, RequestHandler, Response } from 'express';
import jwt from 'jsonwebtoken';

import { appConfigDb, userDb } from '@/modules/database/index.js';
import { AppError } from '@/shared/utils.js';

import {
  createCfAccessVerifier,
  loadCfAccessConfig,
  type AccessFailure,
  type AccessIdentity,
  type CfAccessVerifier,
} from './cf-access.js';
import { loadCloudflareSigner } from './device/cf-client-certs.js';
import { createDeviceVerifier, loadDeviceModeConfig, MIN_EDGE_SECRET_LENGTH } from './device/device-verifier.js';
import { deviceRepository } from './device/device.repository.js';
import { createEnrollmentService, type EnrollmentService } from './device/enrollment.service.js';
import { loadMailer } from './device/mailer.js';
import { createDeviceGate, installUpgradeGate, type GateVerifier } from './device/device-gate.js';
import { pinRepository } from './pin.repository.js';
import { createPinService, type PinService } from './pin.service.js';

export const FORJA_TOKEN_AMR = 'forja-pin';
/** Single-purpose ticket for EventSource URLs (cannot send headers). */
export const FORJA_SSE_AMR = 'forja-sse';
export const SSE_TICKET_TTL_SECONDS = 60;
const MAX_SESSION_HOURS = 12;

export type ForjaAuthMode = 'pin' | 'device';

export function forjaAuthMode(env: NodeJS.ProcessEnv = process.env): ForjaAuthMode | null {
  return env.FORJA_AUTH === 'pin' || env.FORJA_AUTH === 'device' ? env.FORJA_AUTH : null;
}

/** True in both Forja modes: the PIN screen and PIN sessions replace upstream login. */
export function isForjaPinMode(env: NodeJS.ProcessEnv = process.env): boolean {
  return forjaAuthMode(env) !== null;
}

export function isForjaDeviceMode(env: NodeJS.ProcessEnv = process.env): boolean {
  return forjaAuthMode(env) === 'device';
}

/** Enrolment endpoints: the only tunnel paths served without a registered device. */
export const ENROLL_PATHS = new Set(['/api/auth/device/enroll/start', '/api/auth/device/enroll/confirm']);

export function sessionTtlSeconds(env: NodeJS.ProcessEnv = process.env): number {
  const hours = Number(env.FORJA_SESSION_HOURS ?? MAX_SESSION_HOURS);
  const bounded = Number.isFinite(hours) && hours > 0 ? Math.min(hours, MAX_SESSION_HOURS) : MAX_SESSION_HOURS;
  return Math.round(bounded * 3600);
}

type SessionUser = { id: number; username: string; [key: string]: unknown };

type ForjaRequest = Request & { user?: SessionUser; forjaToken?: string; forjaEmail?: string; forjaDeviceId?: string };
type Identity = Pick<AccessIdentity, 'email' | 'deviceId'>;

export type ForjaAuthDependencies = {
  verifier: Pick<CfAccessVerifier, 'verify' | 'verifySync'> & Partial<Pick<GateVerifier, 'verifyEdge'>>;
  pinService?: PinService;
  secret: string;
  ttlSeconds: number;
  getUserById(userId: number): { id: number; username: string } | undefined;
  /** Only needed when pinService is not injected. */
  hashPin?: (pin: string) => Promise<string>;
  comparePin?: (pin: string, hash: string) => Promise<boolean>;
  /** Device mode only: enrolment endpoints. */
  enrollment?: EnrollmentService;
};

const ACCESS_STATUS: Record<AccessFailure['reason'], number> = {
  missing: 401,
  invalid: 401,
  'not-allowed': 403,
  misconfigured: 503,
  'keys-unavailable': 503,
  'not-registered': 403,
  revoked: 403,
};

function clientIp(req: Request): string | null {
  const header = req.headers['cf-connecting-ip'];
  const value = Array.isArray(header) ? header[0] : header;
  return value || req.ip || null;
}

/**
 * The session token only travels in the Authorization header. EventSource
 * cannot set headers, so GET requests may carry a 60 s SSE ticket in
 * `?token=` instead (never the 12 h session token: URLs end up in logs).
 */
function readCredential(req: Request): { token: string; kind: 'session' | 'sse' } | null {
  const header = req.headers.authorization;
  const fromHeader = header?.startsWith('Bearer ') ? header.slice(7).trim() : '';
  if (fromHeader) return { token: fromHeader, kind: 'session' };
  if (req.method === 'GET' && typeof req.query.token === 'string' && req.query.token) {
    return { token: req.query.token, kind: 'sse' };
  }
  return null;
}

/** True when the request came through Cloudflare (the tunnel), not a direct local call. */
export function isCloudflareRequest(headers: IncomingHttpHeaders): boolean {
  return Boolean(headers['cf-ray'] || headers['cf-connecting-ip'] || headers['cf-access-jwt-assertion']);
}

export function createForjaAuth(dependencies: ForjaAuthDependencies) {
  const { verifier, secret, ttlSeconds } = dependencies;
  // Device the PIN was entered on; carried into issueToken without touching pin.service.
  const tokenBinding = new AsyncLocalStorage<string | undefined>();

  function issueToken(user: { id: number; username: string }): string {
    const dev = tokenBinding.getStore();
    return jwt.sign(
      { userId: user.id, username: user.username, email: user.username, amr: FORJA_TOKEN_AMR, ...(dev ? { dev } : {}) },
      secret,
      { expiresIn: ttlSeconds, algorithm: 'HS256' },
    );
  }

  const pinService = dependencies.pinService ?? createPinService({
    repo: pinRepository,
    hashPin: dependencies.hashPin ?? (() => Promise.reject(new Error('hashPin missing'))),
    comparePin: dependencies.comparePin ?? (() => Promise.reject(new Error('comparePin missing'))),
    issueToken,
  });

  function issueSseTicket(user: { id: number; username: string }, deviceId?: string): string {
    return jwt.sign(
      { userId: user.id, email: user.username, amr: FORJA_SSE_AMR, ...(deviceId ? { dev: deviceId } : {}) },
      secret,
      { expiresIn: SSE_TICKET_TTL_SECONDS, algorithm: 'HS256' },
    );
  }

  /**
   * Verifies an app session token (or SSE ticket): it must belong to the
   * identity's email and, in device mode, to the same registered device.
   */
  function verifySession(
    token: string,
    identity: string | Identity,
    kind: 'session' | 'sse' = 'session',
  ): { user: SessionUser } | { error: 'expired' | 'invalid' } {
    const { email, deviceId } = typeof identity === 'string' ? { email: identity, deviceId: undefined } : identity;
    try {
      const claims = jwt.verify(token, secret, { algorithms: ['HS256'] }) as jwt.JwtPayload;
      const expectedAmr = kind === 'sse' ? FORJA_SSE_AMR : FORJA_TOKEN_AMR;
      if ((claims.dev ?? null) !== (deviceId ?? null)) {
        console.warn(`[forja-auth] token bound to another device presented for ${email}`);
        return { error: 'invalid' };
      }
      if (claims.amr !== expectedAmr || typeof claims.userId !== 'number' || claims.email !== email) {
        if (claims.email && claims.email !== email) {
          console.warn(`[forja-auth] token for ${String(claims.email)} presented by Access identity ${email}`);
        }
        return { error: 'invalid' };
      }
      const user = dependencies.getUserById(claims.userId);
      if (!user || user.username !== email) {
        return { error: 'invalid' };
      }
      return { user: { ...user } };
    } catch (error) {
      return { error: error instanceof jwt.TokenExpiredError ? 'expired' : 'invalid' };
    }
  }

  function denyAccess(res: Response, reason: AccessFailure['reason']) {
    res.setHeader('X-Auth-Error', 'invalid-token');
    return res.status(ACCESS_STATUS[reason]).json({
      authMode: 'pin',
      error: reason === 'not-allowed'
        ? 'This account is not allowed in this app.'
        : reason === 'not-registered' || reason === 'revoked'
          ? 'This device is not registered.'
          : 'Registered device or Cloudflare Access identity required.',
      code: `ACCESS_${reason.toUpperCase().replace('-', '_')}`,
    });
  }

  const authenticateToken: RequestHandler = async (req, res, next) => {
    const access = await verifier.verify(req.headers);
    if (!access.ok) {
      return denyAccess(res, access.reason);
    }
    const credential = readCredential(req);
    if (!credential) {
      res.setHeader('X-Auth-Error', 'invalid-token');
      return res.status(401).json({ error: 'Access denied. No token provided.', code: 'AUTH_TOKEN_INVALID' });
    }
    const { token } = credential;
    const session = verifySession(token, access.identity, credential.kind);
    if ('error' in session) {
      const expired = session.error === 'expired';
      res.setHeader('X-Auth-Error', expired ? 'session-expired' : 'invalid-token');
      return res.status(401).json({
        error: expired ? 'Session expired. Enter your PIN again.' : 'Invalid token',
        code: expired ? 'AUTH_TOKEN_EXPIRED' : 'AUTH_TOKEN_INVALID',
      });
    }
    const forjaReq = req as ForjaRequest;
    forjaReq.user = session.user;
    forjaReq.forjaToken = token;
    forjaReq.forjaEmail = access.identity.email;
    forjaReq.forjaDeviceId = access.identity.deviceId;
    return next();
  };

  /**
   * Gate for routes upstream leaves without a session (`/api/agent`,
   * `/api/browser-use-mcp`): anything that came through Cloudflare needs the
   * Access JWT + PIN session; direct local calls (the Browser MCP bridge on
   * 127.0.0.1, no cf-* headers) keep the route's own token check.
   */
  const gateTunnelRequests: RequestHandler = (req, res, next) => {
    if (!isCloudflareRequest(req.headers)) {
      return next();
    }
    return authenticateToken(req, res, next);
  };

  function authenticateWebSocket(token: string | null, headers: IncomingHttpHeaders | undefined) {
    if (!token || !headers) return null;
    const access = verifier.verifySync(headers);
    if (!access.ok) {
      console.warn(`[forja-auth] WebSocket rejected: access ${access.reason}`);
      return null;
    }
    const session = verifySession(token, access.identity);
    if ('error' in session) return null;
    return { id: session.user.id, userId: session.user.id, username: session.user.username };
  }

  function sendError(res: Response, next: NextFunction, error: unknown) {
    if (error instanceof AppError) {
      return res.status(error.statusCode).json({ error: error.message, code: error.code, details: error.details });
    }
    return next(error);
  }

  function createRouter(): express.Router {
    const router = express.Router();

    const withAccess = (handler: (req: Request, res: Response, email: string) => Promise<unknown> | unknown): RequestHandler =>
      async (req, res, next) => {
        try {
          const access = await verifier.verify(req.headers);
          if (!access.ok) {
            return denyAccess(res, access.reason);
          }
          const { email, deviceId } = access.identity;
          return await tokenBinding.run(deviceId, () => handler(req, res, email));
        } catch (error) {
          return sendError(res, next, error);
        }
      };

    router.get('/status', withAccess((_req, res, email) => {
      res.setHeader('Cache-Control', 'no-store');
      res.json(pinService.status(email));
    }));

    // "register" = choose the PIN on the first visit of this Access email.
    router.post('/register', withAccess(async (req, res, email) => {
      const body = (req.body ?? {}) as { pin?: unknown; pinConfirm?: unknown; password?: unknown };
      res.json(await pinService.setup(email, body.pin ?? body.password, body.pinConfirm, clientIp(req)));
    }));

    // "login" = unlock with the PIN. Any username sent by the client is ignored.
    router.post('/login', withAccess(async (req, res, email) => {
      const body = (req.body ?? {}) as { pin?: unknown; password?: unknown };
      res.json(await pinService.unlock(email, body.pin ?? body.password, clientIp(req)));
    }));

    router.get('/user', authenticateToken, (req, res) => {
      res.json({ user: (req as ForjaRequest).user });
    });

    // No sliding sessions: the token keeps its original expiry.
    router.post('/refresh', authenticateToken, (req, res) => {
      res.json({ token: (req as ForjaRequest).forjaToken });
    });

    // Short-lived ticket for EventSource URLs; needs the header session token.
    router.post('/sse-ticket', authenticateToken, (req, res) => {
      const forjaReq = req as ForjaRequest;
      res.setHeader('Cache-Control', 'no-store');
      res.json({ ticket: issueSseTicket(forjaReq.user as SessionUser, forjaReq.forjaDeviceId), expiresIn: SSE_TICKET_TTL_SECONDS });
    });

    router.post('/logout', authenticateToken, (_req, res) => {
      res.json({ success: true, message: 'Logged out successfully' });
    });

    // Device enrolment (device mode only). Reachable without a device: the
    // edge WAF lets exactly these two paths through without a client cert.
    const { enrollment } = dependencies;
    if (enrollment) {
      const enrollHandler = (run: (body: Record<string, unknown>, ip: string | null) => Promise<unknown>): RequestHandler => async (req, res, next) => {
        try {
          res.setHeader('Cache-Control', 'no-store');
          res.json(await run((req.body ?? {}) as Record<string, unknown>, clientIp(req)));
        } catch (error) {
          sendError(res, next, error);
        }
      };
      router.post('/device/enroll/start', enrollHandler(enrollment.start));
      router.post('/device/enroll/confirm', enrollHandler(enrollment.confirm));
    }

    return router;
  }

  return {
    verifier,
    authenticateToken,
    authenticateWebSocket,
    createRouter,
    gateTunnelRequests,
    issueSseTicket,
    issueToken,
    verifySession,
    pinService,
  };
}

export type ForjaAuth = ReturnType<typeof createForjaAuth>;

let instance: ForjaAuth | null = null;

/** Route gate used by server/index.ts; a no-op unless a Forja mode is on. */
export const forjaRouteGate: RequestHandler = (req, res, next) => {
  if (!isForjaPinMode()) {
    return next();
  }
  return getForjaAuth().gateTunnelRequests(req, res, next);
};

/** The device verifier; fails closed if the process somehow runs a verifier without edge checks. */
function gateVerifier(): GateVerifier {
  const { verifier } = getForjaAuth();
  if (!verifier.verifyEdge) {
    return { verifyEdge: () => ({ ok: false, reason: 'misconfigured' }), verifySync: () => ({ ok: false, reason: 'misconfigured' }) };
  }
  return verifier as GateVerifier;
}

const deviceGate = createDeviceGate(gateVerifier, ENROLL_PATHS);

/**
 * First middleware of the app (server/index.ts): in device mode, refuses every
 * tunnel request without a registered device before any route. No-op otherwise.
 */
export const forjaDeviceGate: RequestHandler = (req, res, next) => {
  if (!isForjaDeviceMode()) {
    return next();
  }
  return deviceGate(req, res, next);
};

/** Same gate for WebSocket/upgrade handshakes; no-op unless FORJA_AUTH=device. */
export function installForjaUpgradeGate(server: import('node:http').Server): void {
  if (!isForjaDeviceMode()) return;
  getForjaAuth();
  installUpgradeGate(server, gateVerifier);
}

/** Process-wide Forja auth, built from the environment on first use. */
export function getForjaAuth(): ForjaAuth {
  if (instance) return instance;

  const require = createRequire(import.meta.url);
  const bcrypt = require('bcrypt') as {
    hash(value: string, rounds: number): Promise<string>;
    compare(value: string, hash: string): Promise<boolean>;
  };

  const secret = process.env.JWT_SECRET || appConfigDb.getOrCreateJwtSecret();
  let verifier: ForjaAuthDependencies['verifier'];
  let enrollment: EnrollmentService | undefined;

  if (isForjaDeviceMode()) {
    const config = loadDeviceModeConfig();
    verifier = createDeviceVerifier({ ...config, repo: deviceRepository });
    const mailer = loadMailer();
    const signer = loadCloudflareSigner();
    enrollment = createEnrollmentService({ repo: deviceRepository, allowedEmails: config.allowedEmails, mailer, signer, secret });
    console.log(
      `[forja-auth] DEVICE mode on. allowed=${config.allowedEmails.length} `
      + `edgeSecret=${config.edgeSecret.length >= MIN_EDGE_SECRET_LENGTH ? 'set' : 'MISSING'} mail=${mailer ? 'set' : 'MISSING'} `
      + `signer=${signer ? 'set' : 'MISSING'} sessionTtl=${sessionTtlSeconds()}s`,
    );
    if (config.edgeSecret.length < MIN_EDGE_SECRET_LENGTH || config.allowedEmails.length === 0) {
      console.error('[forja-auth] FORJA_EDGE_SECRET(_FILE) and FORJA_ALLOWED_EMAILS are required: every tunnel request will be refused.');
    }
  } else {
    const config = loadCfAccessConfig();
    const accessVerifier = createCfAccessVerifier(config);
    verifier = accessVerifier;
    console.log(
      `[forja-auth] PIN mode on. team=${config.teamDomain} aud=${config.audience ? 'set' : 'MISSING'} `
      + `allowed=${config.allowedEmails.length} devBypass=${config.devBypass} sessionTtl=${sessionTtlSeconds()}s`,
    );
    if (!config.devBypass && (!config.audience || config.allowedEmails.length === 0)) {
      console.error('[forja-auth] CF_ACCESS_AUD and FORJA_ALLOWED_EMAILS are required: every request will be refused.');
    }
    if (!config.devBypass) {
      void accessVerifier.refreshKeys(true);
    }
  }

  instance = createForjaAuth({
    verifier,
    enrollment,
    secret,
    ttlSeconds: sessionTtlSeconds(),
    getUserById: (userId) => userDb.getUserById(userId),
    hashPin: (pin) => bcrypt.hash(pin, 12),
    comparePin: (pin, hash) => bcrypt.compare(pin, hash),
  });
  return instance;
}
