/**
 * Forja auth mode (`FORJA_AUTH=pin`): Cloudflare Access identity + 6-digit PIN.
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
import type { IncomingHttpHeaders } from 'node:http';
import { createRequire } from 'node:module';

import express from 'express';
import type { NextFunction, Request, RequestHandler, Response } from 'express';
import jwt from 'jsonwebtoken';

import { appConfigDb, userDb } from '@/modules/database/index.js';
import { AppError } from '@/shared/utils.js';

import { createCfAccessVerifier, loadCfAccessConfig, type AccessFailure, type CfAccessVerifier } from './cf-access.js';
import { pinRepository } from './pin.repository.js';
import { createPinService, type PinService } from './pin.service.js';

export const FORJA_TOKEN_AMR = 'forja-pin';
const MAX_SESSION_HOURS = 12;

export function isForjaPinMode(env: NodeJS.ProcessEnv = process.env): boolean {
  return env.FORJA_AUTH === 'pin';
}

export function sessionTtlSeconds(env: NodeJS.ProcessEnv = process.env): number {
  const hours = Number(env.FORJA_SESSION_HOURS ?? MAX_SESSION_HOURS);
  const bounded = Number.isFinite(hours) && hours > 0 ? Math.min(hours, MAX_SESSION_HOURS) : MAX_SESSION_HOURS;
  return Math.round(bounded * 3600);
}

type SessionUser = { id: number; username: string; [key: string]: unknown };

type ForjaRequest = Request & { user?: SessionUser; forjaToken?: string; forjaEmail?: string };

export type ForjaAuthDependencies = {
  verifier: Pick<CfAccessVerifier, 'verify' | 'verifySync'>;
  pinService?: PinService;
  secret: string;
  ttlSeconds: number;
  getUserById(userId: number): { id: number; username: string } | undefined;
  /** Only needed when pinService is not injected. */
  hashPin?: (pin: string) => Promise<string>;
  comparePin?: (pin: string, hash: string) => Promise<boolean>;
};

const ACCESS_STATUS: Record<AccessFailure['reason'], number> = {
  missing: 401,
  invalid: 401,
  'not-allowed': 403,
  misconfigured: 503,
  'keys-unavailable': 503,
};

function clientIp(req: Request): string | null {
  const header = req.headers['cf-connecting-ip'];
  const value = Array.isArray(header) ? header[0] : header;
  return value || req.ip || null;
}

function bearerToken(req: Request): string | null {
  const header = req.headers.authorization;
  const fromHeader = header?.startsWith('Bearer ') ? header.slice(7).trim() : '';
  if (fromHeader) return fromHeader;
  // SSE endpoints cannot set headers (EventSource), same as upstream.
  return typeof req.query.token === 'string' && req.query.token ? req.query.token : null;
}

export function createForjaAuth(dependencies: ForjaAuthDependencies) {
  const { verifier, secret, ttlSeconds } = dependencies;

  function issueToken(user: { id: number; username: string }): string {
    return jwt.sign(
      { userId: user.id, username: user.username, email: user.username, amr: FORJA_TOKEN_AMR },
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

  /** Verifies an app session token and that it belongs to the Access email. */
  function verifySession(token: string, email: string): { user: SessionUser } | { error: 'expired' | 'invalid' } {
    try {
      const claims = jwt.verify(token, secret, { algorithms: ['HS256'] }) as jwt.JwtPayload;
      if (claims.amr !== FORJA_TOKEN_AMR || typeof claims.userId !== 'number' || claims.email !== email) {
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
        ? 'This Cloudflare Access account is not allowed in this app.'
        : 'Cloudflare Access identity required.',
      code: `ACCESS_${reason.toUpperCase().replace('-', '_')}`,
    });
  }

  const authenticateToken: RequestHandler = async (req, res, next) => {
    const access = await verifier.verify(req.headers);
    if (!access.ok) {
      return denyAccess(res, access.reason);
    }
    const token = bearerToken(req);
    if (!token) {
      res.setHeader('X-Auth-Error', 'invalid-token');
      return res.status(401).json({ error: 'Access denied. No token provided.', code: 'AUTH_TOKEN_INVALID' });
    }
    const session = verifySession(token, access.identity.email);
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
    return next();
  };

  function authenticateWebSocket(token: string | null, headers: IncomingHttpHeaders | undefined) {
    if (!token || !headers) return null;
    const access = verifier.verifySync(headers);
    if (!access.ok) {
      console.warn(`[forja-auth] WebSocket rejected: access ${access.reason}`);
      return null;
    }
    const session = verifySession(token, access.identity.email);
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
          return await handler(req, res, access.identity.email);
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

    router.post('/logout', authenticateToken, (_req, res) => {
      res.json({ success: true, message: 'Logged out successfully' });
    });

    return router;
  }

  return { authenticateToken, authenticateWebSocket, createRouter, issueToken, verifySession, pinService };
}

export type ForjaAuth = ReturnType<typeof createForjaAuth>;

let instance: ForjaAuth | null = null;

/** Process-wide Forja auth, built from the environment on first use. */
export function getForjaAuth(): ForjaAuth {
  if (instance) return instance;

  const config = loadCfAccessConfig();
  const verifier = createCfAccessVerifier(config);
  const require = createRequire(import.meta.url);
  const bcrypt = require('bcrypt') as {
    hash(value: string, rounds: number): Promise<string>;
    compare(value: string, hash: string): Promise<boolean>;
  };

  console.log(
    `[forja-auth] PIN mode on. team=${config.teamDomain} aud=${config.audience ? 'set' : 'MISSING'} `
    + `allowed=${config.allowedEmails.length} devBypass=${config.devBypass} sessionTtl=${sessionTtlSeconds()}s`,
  );
  if (!config.devBypass && (!config.audience || config.allowedEmails.length === 0)) {
    console.error('[forja-auth] CF_ACCESS_AUD and FORJA_ALLOWED_EMAILS are required: every request will be refused.');
  }
  if (!config.devBypass) {
    void verifier.refreshKeys(true);
  }

  instance = createForjaAuth({
    verifier,
    secret: process.env.JWT_SECRET || appConfigDb.getOrCreateJwtSecret(),
    ttlSeconds: sessionTtlSeconds(),
    getUserById: (userId) => userDb.getUserById(userId),
    hashPin: (pin) => bcrypt.hash(pin, 12),
    comparePin: (pin, hash) => bcrypt.compare(pin, hash),
  });
  return instance;
}
