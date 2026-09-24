import assert from 'node:assert/strict';
import type { AddressInfo } from 'node:net';
import { createRequire } from 'node:module';
import test from 'node:test';

import express from 'express';
import jwt from 'jsonwebtoken';

import { userDb } from '@/modules/database/index.js';

import { createCfAccessVerifier } from '../cf-access.js';
import { createForjaAuth, sessionTtlSeconds } from '../forja-auth.js';

import { ALICE, AUD, BOB, TEAM, accessJwt, makeKey, withTempDatabase } from './helpers.js';

const bcrypt = createRequire(import.meta.url)('bcrypt') as {
  hash(value: string, rounds: number): Promise<string>;
  compare(value: string, hash: string): Promise<boolean>;
};

const key = makeKey('kid-routes');

type CallInit = { method?: string; email?: string | null; token?: string; body?: unknown; headers?: Record<string, string> };
const SECRET = 'test-secret';

async function withApp(run: (ctx: {
  call: (path: string, init?: CallInit) => Promise<{ status: number; body: any }>;
  auth: ReturnType<typeof createForjaAuth>;
}) => Promise<void>) {
  await withTempDatabase(async () => {
    const verifier = createCfAccessVerifier({
      teamDomain: TEAM,
      audience: AUD,
      allowedEmails: [ALICE, BOB],
      devBypass: false,
      fetchCerts: async () => ({ keys: [key.jwk] }),
    });
    await verifier.refreshKeys(true);
    const auth = createForjaAuth({
      verifier,
      secret: SECRET,
      ttlSeconds: sessionTtlSeconds({}),
      getUserById: (id) => userDb.getUserById(id),
      hashPin: (pin) => bcrypt.hash(pin, 4),
      comparePin: (pin, hash) => bcrypt.compare(pin, hash),
    });
    const app = express();
    app.use(express.json());
    app.use('/api/auth', auth.createRouter());
    // Stand-ins for upstream routes mounted without a session (/api/agent, /api/browser-use-mcp).
    app.use('/api/agent', auth.gateTunnelRequests, (_req, res) => {
      res.json({ reached: 'agent' });
    });
    app.all('/api/protected', auth.authenticateToken, (req, res) => {
      res.json({ user: (req as express.Request & { user?: unknown }).user });
    });
    const server = app.listen(0, '127.0.0.1');
    await new Promise((resolve) => server.once('listening', resolve));
    const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

    const call = async (path: string, init: CallInit = {}) => {
      const headers: Record<string, string> = { 'Content-Type': 'application/json', ...init.headers };
      if (init.email !== null) headers['Cf-Access-Jwt-Assertion'] = accessJwt(key, { email: init.email ?? ALICE });
      if (init.token) headers.Authorization = `Bearer ${init.token}`;
      const response = await fetch(`${base}${path}`, {
        method: init.method ?? 'GET',
        headers,
        body: init.body === undefined ? undefined : JSON.stringify(init.body),
      });
      return { status: response.status, body: await response.json().catch(() => null) };
    };

    try {
      await run({ call, auth });
    } finally {
      await new Promise((resolve) => server.close(resolve));
    }
  });
}

test('status requires a valid Access JWT and reports first-visit setup', async () => {
  await withApp(async ({ call }) => {
    assert.equal((await call('/api/auth/status', { email: null })).status, 401);
    assert.equal((await call('/api/auth/status', { email: 'mallory@example.com' })).status, 403);
    const status = await call('/api/auth/status');
    assert.equal(status.status, 200);
    assert.deepEqual(
      { authMode: status.body.authMode, email: status.body.email, needsSetup: status.body.needsSetup },
      { authMode: 'pin', email: ALICE, needsSetup: true },
    );
  });
});

test('setup then unlock; the token is 12 h max, bound to the email and not slid forward', async () => {
  await withApp(async ({ call }) => {
    const setup = await call('/api/auth/register', { method: 'POST', body: { pin: '123456', pinConfirm: '123456' } });
    assert.equal(setup.status, 200);
    assert.equal(setup.body.user.username, ALICE);

    const wrong = await call('/api/auth/login', { method: 'POST', body: { pin: '000000' } });
    assert.equal(wrong.status, 401);
    assert.equal(wrong.body.code, 'PIN_INVALID');

    // A username in the body is ignored: identity comes from Access only.
    const login = await call('/api/auth/login', { method: 'POST', body: { username: BOB, pin: '123456' } });
    assert.equal(login.status, 200);
    assert.equal(login.body.user.username, ALICE);

    const claims = jwt.decode(login.body.token) as jwt.JwtPayload;
    assert.ok(claims.exp && claims.iat && claims.exp - claims.iat <= 12 * 3600);

    const me = await call('/api/protected', { token: login.body.token });
    assert.equal(me.status, 200);
    assert.equal(me.body.user.username, ALICE);

    const refreshed = await call('/api/auth/refresh', { method: 'POST', token: login.body.token });
    assert.equal(refreshed.body.token, login.body.token);
  });
});

test('per-user isolation: a token only works with the Access identity it was issued to', async () => {
  await withApp(async ({ call }) => {
    const alice = await call('/api/auth/register', { method: 'POST', body: { pin: '111111', pinConfirm: '111111' } });
    const bob = await call('/api/auth/register', { method: 'POST', email: BOB, body: { pin: '222222', pinConfirm: '222222' } });
    assert.notEqual(alice.body.user.id, bob.body.user.id);

    assert.equal((await call('/api/protected', { token: alice.body.token, email: BOB })).status, 401);
    assert.equal((await call('/api/protected', { token: bob.body.token, email: ALICE })).status, 401);
    assert.equal((await call('/api/protected', { token: bob.body.token, email: BOB })).body.user.username, BOB);
    // Bob's PIN does not unlock Alice.
    assert.equal((await call('/api/auth/login', { method: 'POST', body: { pin: '222222' } })).status, 401);
  });
});

test('protected routes need both the Access JWT and a valid app token', async () => {
  await withApp(async ({ call, auth }) => {
    const { body } = await call('/api/auth/register', { method: 'POST', body: { pin: '123456', pinConfirm: '123456' } });
    assert.equal((await call('/api/protected', { token: body.token, email: null })).status, 401);
    assert.equal((await call('/api/protected')).status, 401);

    const upstreamStyle = jwt.sign({ userId: body.user.id, username: ALICE }, SECRET, { expiresIn: 3600 });
    assert.equal((await call('/api/protected', { token: upstreamStyle })).status, 401);

    const expired = jwt.sign(
      { userId: body.user.id, username: ALICE, email: ALICE, amr: 'forja-pin' },
      SECRET,
      { expiresIn: -10 },
    );
    const expiredResponse = await call('/api/protected', { token: expired });
    assert.equal(expiredResponse.status, 401);
    assert.equal(expiredResponse.body.code, 'AUTH_TOKEN_EXPIRED');

    // WebSocket upgrade: same checks, synchronous path.
    const wsHeaders = { 'cf-access-jwt-assertion': accessJwt(key, { email: ALICE }) };
    assert.equal(auth.authenticateWebSocket(body.token, wsHeaders)?.username, ALICE);
    assert.equal(auth.authenticateWebSocket(body.token, { 'cf-access-jwt-assertion': accessJwt(key, { email: BOB }) }), null);
    assert.equal(auth.authenticateWebSocket(body.token, {}), null);
    assert.equal(auth.authenticateWebSocket(null, wsHeaders), null);
  });
});

test('session lifetime is capped at 12 h', () => {
  assert.equal(sessionTtlSeconds({}), 12 * 3600);
  assert.equal(sessionTtlSeconds({ FORJA_SESSION_HOURS: '48' }), 12 * 3600);
  assert.equal(sessionTtlSeconds({ FORJA_SESSION_HOURS: '2' }), 2 * 3600);
  assert.equal(sessionTtlSeconds({ FORJA_SESSION_HOURS: 'nope' }), 12 * 3600);
});

test('routes upstream leaves open need Access + PIN session when they come through Cloudflare', async () => {
  await withApp(async ({ call }) => {
    const { body } = await call('/api/auth/register', { method: 'POST', body: { pin: '123456', pinConfirm: '123456' } });
    // Through the tunnel without a session: refused.
    assert.equal((await call('/api/agent', { method: 'POST', headers: { 'cf-ray': 'abc' } })).status, 401);
    assert.equal((await call('/api/agent', { method: 'POST', email: null, headers: { 'cf-ray': 'abc' } })).status, 401);
    // Through the tunnel with Access + session: reaches the route (which keeps its own key check).
    assert.equal((await call('/api/agent', { method: 'POST', token: body.token, headers: { 'cf-ray': 'abc' } })).status, 200);
    // Direct local call (Browser MCP bridge on 127.0.0.1, no cf-* headers): the route's own token check applies.
    assert.equal((await call('/api/agent', { method: 'POST', email: null })).status, 200);
  });
});

test('SSE: only a 60 s single-purpose ticket is accepted in the query string', async () => {
  await withApp(async ({ call }) => {
    const { body } = await call('/api/auth/register', { method: 'POST', body: { pin: '123456', pinConfirm: '123456' } });
    const bob = await call('/api/auth/register', { method: 'POST', email: BOB, body: { pin: '222222', pinConfirm: '222222' } });

    // The 12 h session token is refused in the URL.
    assert.equal((await call(`/api/protected?token=${body.token}`)).status, 401);
    assert.equal((await call('/api/auth/sse-ticket', { method: 'POST' })).status, 401);

    const issued = await call('/api/auth/sse-ticket', { method: 'POST', token: body.token });
    assert.equal(issued.status, 200);
    const claims = jwt.decode(issued.body.ticket) as jwt.JwtPayload;
    assert.ok(claims.exp && claims.iat && claims.exp - claims.iat <= 60);

    assert.equal((await call(`/api/protected?token=${issued.body.ticket}`)).status, 200);
    // Not usable as a session token, nor on non-GET, nor by another Access identity.
    assert.equal((await call('/api/protected', { token: issued.body.ticket })).status, 401);
    assert.equal((await call(`/api/protected?token=${issued.body.ticket}`, { method: 'POST' })).status, 401);
    assert.equal((await call(`/api/protected?token=${issued.body.ticket}`, { email: BOB })).status, 401);
    assert.equal((await call('/api/protected', { token: bob.body.token, email: BOB })).status, 200);

    const expired = jwt.sign({ userId: body.user.id, email: ALICE, amr: 'forja-sse' }, SECRET, { expiresIn: -1 });
    assert.equal((await call(`/api/protected?token=${expired}`)).status, 401);
  });
});
