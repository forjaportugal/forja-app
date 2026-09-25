/**
 * Forja device mode: gate (HTTP, SSE, WebSocket), enrolment, limits,
 * replay and revocation — against a real HTTP server and SQLite database.
 */
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import test from 'node:test';

import express from 'express';
import { WebSocket, WebSocketServer } from 'ws';

import { userDb } from '@/modules/database/index.js';

import { createForjaAuth, ENROLL_PATHS, sessionTtlSeconds } from '../../forja-auth.js';
import { ALICE, BOB, withTempDatabase } from '../../tests/helpers.js';
import { createDeviceGate, installUpgradeGate } from '../device-gate.js';
import { createDeviceVerifier } from '../device-verifier.js';
import { deviceRepository } from '../device.repository.js';
import { createEnrollmentService, fingerprintOf, LIMITS, MAX_CODE_ATTEMPTS, CODE_TTL_MS } from '../enrollment.service.js';

import { EDGE_SECRET, makeCsr, makeFakeSigner, makeMailbox } from './device-helpers.js';

const bcrypt = createRequire(import.meta.url)('bcrypt') as {
  hash(value: string, rounds: number): Promise<string>;
  compare(value: string, hash: string): Promise<boolean>;
};

type Ctx = {
  base: string;
  port: number;
  mailbox: ReturnType<typeof makeMailbox>;
  signer: ReturnType<typeof makeFakeSigner>;
  clock: { now: number };
  reached: string[];
  wsOpened: { count: number };
  call(path: string, init?: { method?: string; body?: unknown; token?: string; headers?: Record<string, string | undefined> }): Promise<{ status: number; body: any }>;
  enroll(email: string, platform?: 'pc' | 'phone', ip?: string): Promise<{ fingerprint: string; deviceId: string }>;
  device(fp: string, ip?: string): Record<string, string>;
  enrollment: ReturnType<typeof createEnrollmentService>;
};

async function withDeviceApp(run: (ctx: Ctx) => Promise<void>, options: { mail?: boolean } = {}) {
  await withTempDatabase(async () => {
    const clock = { now: Date.now() };
    const mailbox = makeMailbox();
    const signer = makeFakeSigner();
    const verifier = createDeviceVerifier({ allowedEmails: [ALICE, BOB], edgeSecret: EDGE_SECRET, repo: deviceRepository });
    const enrollment = createEnrollmentService({
      repo: deviceRepository,
      allowedEmails: [ALICE, BOB],
      mailer: options.mail === false ? null : mailbox,
      signer,
      secret: 'test-secret',
      now: () => clock.now,
      log: () => undefined,
    });
    const auth = createForjaAuth({
      verifier,
      enrollment,
      secret: 'test-secret',
      ttlSeconds: sessionTtlSeconds({}),
      getUserById: (id) => userDb.getUserById(id),
      hashPin: (pin) => bcrypt.hash(pin, 4),
      comparePin: (pin, hash) => bcrypt.compare(pin, hash),
    });

    const reached: string[] = [];
    const wsOpened = { count: 0 };
    const app = express();
    const server = http.createServer(app);
    // Same order as server/index.ts: WebSocket server first, then the gates.
    const wss = new WebSocketServer({
      server,
      verifyClient: (info: { req: http.IncomingMessage }) => {
        const url = new URL(info.req.url ?? '/', 'http://x');
        return Boolean(auth.authenticateWebSocket(url.searchParams.get('token'), info.req.headers));
      },
    });
    wss.on('connection', (socket) => {
      wsOpened.count += 1;
      socket.close();
    });
    installUpgradeGate(server, () => verifier);
    app.use(createDeviceGate(() => verifier, ENROLL_PATHS));
    app.use(express.json());
    app.use('/api/auth', auth.createRouter());
    app.all('/api/protected', auth.authenticateToken, (_req, res) => {
      reached.push('protected');
      res.json({ ok: true });
    });
    app.get('/api/stream', auth.authenticateToken, (_req, res) => {
      reached.push('stream');
      res.json({ ok: true });
    });
    app.get('/assets/app.js', (_req, res) => {
      reached.push('static');
      res.send('js');
    });
    server.listen(0, '127.0.0.1');
    await new Promise((resolve) => server.once('listening', resolve));
    const port = (server.address() as AddressInfo).port;
    const base = `http://127.0.0.1:${port}`;

    const device = (fp: string, ip = '203.0.113.7') => ({
      'cf-ray': 'ray-1',
      'cf-connecting-ip': ip,
      'x-forja-edge-auth': EDGE_SECRET,
      'x-forja-client-cert-sha256': fp,
    });

    const call: Ctx['call'] = async (path, init = {}) => {
      const headers: Record<string, string> = { 'content-type': 'application/json' };
      for (const [k, v] of Object.entries(init.headers ?? {})) if (v !== undefined) headers[k] = v;
      if (init.token) headers.authorization = `Bearer ${init.token}`;
      const response = await fetch(`${base}${path}`, {
        method: init.method ?? (init.body ? 'POST' : 'GET'),
        headers,
        body: init.body ? JSON.stringify(init.body) : undefined,
      });
      const text = await response.text();
      let body: any = text;
      try { body = JSON.parse(text); } catch { /* not json */ }
      return { status: response.status, body };
    };

    const edgeOnly = (ip = '203.0.113.7') => ({ 'cf-ray': 'ray-1', 'cf-connecting-ip': ip, 'x-forja-edge-auth': EDGE_SECRET });

    const enroll: Ctx['enroll'] = async (email, platform = 'pc', ip = '203.0.113.7') => {
      const { csr } = makeCsr();
      const start = await call('/api/auth/device/enroll/start', { body: { email, platform, name: 'PC teste', csr }, headers: edgeOnly(ip) });
      assert.equal(start.status, 200, JSON.stringify(start.body));
      const code = mailbox.lastCode();
      assert.ok(code, 'code mailed');
      const confirm = await call('/api/auth/device/enroll/confirm', {
        body: { enrollmentId: start.body.enrollmentId, code },
        headers: edgeOnly(ip),
      });
      assert.equal(confirm.status, 200, JSON.stringify(confirm.body));
      assert.equal(confirm.body.fingerprintSha256, fingerprintOf(confirm.body.certificate));
      return { fingerprint: confirm.body.fingerprintSha256, deviceId: confirm.body.deviceId };
    };

    try {
      await run({ base, port, mailbox, signer, clock, reached, wsOpened, call, enroll, device, enrollment });
    } finally {
      wss.close();
      server.closeAllConnections();
      await new Promise((resolve) => server.close(resolve));
    }
  });
}

function wsStatus(port: number, headers: Record<string, string>, token = 'x'): Promise<number> {
  return new Promise((resolve) => {
    const socket = new WebSocket(`ws://127.0.0.1:${port}/ws?token=${encodeURIComponent(token)}`, { headers });
    socket.on('unexpected-response', (_req, res) => {
      resolve(res.statusCode ?? 0);
      socket.terminate();
    });
    socket.on('open', () => {
      resolve(101);
      socket.close();
    });
    socket.on('error', () => resolve(-1));
  });
}

async function unlockedToken(ctx: Ctx, fp: string): Promise<string> {
  const headers = ctx.device(fp);
  const status = await ctx.call('/api/auth/status', { headers });
  assert.equal(status.status, 200);
  const res = status.body.needsSetup
    ? await ctx.call('/api/auth/register', { body: { pin: '482915', pinConfirm: '482915' }, headers })
    : await ctx.call('/api/auth/login', { body: { pin: '482915' }, headers });
  assert.equal(res.status, 200, JSON.stringify(res.body));
  return res.body.token as string;
}

test('unauthenticated tunnel requests are refused before any route (HTTP, static, SSE, WebSocket)', async () => {
  await withDeviceApp(async (ctx) => {
    const noDevice = { 'cf-ray': 'r', 'cf-connecting-ip': '198.51.100.1' };
    for (const path of ['/api/protected', '/assets/app.js', '/api/stream?token=abc', '/api/auth/status', '/']) {
      const res = await ctx.call(path, { headers: noDevice });
      assert.equal(res.status, 401, path);
    }
    // Wrong edge secret (e.g. a local process forging Cloudflare headers).
    const forged = { ...ctx.device('a'.repeat(64)), 'x-forja-edge-auth': 'guess-guess-guess-guess-guess-guess!!' };
    assert.equal((await ctx.call('/api/protected', { headers: forged })).status, 401);
    // Right edge secret, unknown certificate fingerprint.
    assert.equal((await ctx.call('/assets/app.js', { headers: ctx.device('b'.repeat(64)) })).status, 403);
    // Forja headers alone (no cf-ray) are also treated as tunnel traffic.
    assert.equal((await ctx.call('/assets/app.js', { headers: { 'x-forja-client-cert-sha256': 'c'.repeat(64) } })).status, 401);
    assert.equal(await wsStatus(ctx.port, noDevice), 401);
    assert.equal(await wsStatus(ctx.port, ctx.device('b'.repeat(64))), 403);
    assert.deepEqual(ctx.reached, []);
    assert.equal(ctx.wsOpened.count, 0);

    // Direct local calls (no Cloudflare headers) are left to the route's own session check.
    assert.equal((await ctx.call('/assets/app.js')).status, 200);
    assert.equal((await ctx.call('/api/protected')).status, 401);
  });
});

test('enrolment endpoints pass the gate only with the edge secret', async () => {
  await withDeviceApp(async (ctx) => {
    const { csr } = makeCsr();
    const body = { email: ALICE, platform: 'pc', name: 'x', csr };
    assert.equal((await ctx.call('/api/auth/device/enroll/start', { body, headers: { 'cf-ray': 'r' } })).status, 401);
    assert.equal((await ctx.call('/api/auth/device/enroll/start', { method: 'GET', headers: { 'cf-ray': 'r', 'x-forja-edge-auth': EDGE_SECRET } })).status, 401);
    assert.equal(ctx.mailbox.sent.length, 0);
  });
});

test('enrolled device: PIN, API, SSE ticket and WebSocket work; token is bound to the device', async () => {
  await withDeviceApp(async (ctx) => {
    const pc = await ctx.enroll(ALICE, 'pc');
    const token = await unlockedToken(ctx, pc.fingerprint);
    assert.equal((await ctx.call('/api/protected', { token, headers: ctx.device(pc.fingerprint) })).status, 200);
    // Gate passes but the route still needs the PIN session.
    assert.equal((await ctx.call('/api/protected', { headers: ctx.device(pc.fingerprint) })).status, 401);

    const ticket = await ctx.call('/api/auth/sse-ticket', { method: 'POST', token, headers: ctx.device(pc.fingerprint) });
    assert.equal(ticket.status, 200);
    assert.equal((await ctx.call(`/api/stream?token=${ticket.body.ticket}`, { headers: ctx.device(pc.fingerprint) })).status, 200);
    assert.equal(await wsStatus(ctx.port, ctx.device(pc.fingerprint), token), 101);
    assert.equal(ctx.wsOpened.count, 1);

    // Replay of the session token / SSE ticket from another registered device of the same person: refused.
    const phone = await ctx.enroll(ALICE, 'phone');
    assert.equal((await ctx.call('/api/protected', { token, headers: ctx.device(phone.fingerprint) })).status, 401);
    assert.equal((await ctx.call(`/api/stream?token=${ticket.body.ticket}`, { headers: ctx.device(phone.fingerprint) })).status, 401);
    assert.equal(await wsStatus(ctx.port, ctx.device(phone.fingerprint), token), 401);
  });
});

test('replayed enrolment confirmation is refused (single use)', async () => {
  await withDeviceApp(async (ctx) => {
    const headers = { 'cf-ray': 'r', 'cf-connecting-ip': '203.0.113.9', 'x-forja-edge-auth': EDGE_SECRET };
    const start = await ctx.call('/api/auth/device/enroll/start', { body: { email: ALICE, platform: 'pc', name: 'x', csr: makeCsr().csr }, headers });
    const code = ctx.mailbox.lastCode();
    const body = { enrollmentId: start.body.enrollmentId, code };
    assert.equal((await ctx.call('/api/auth/device/enroll/confirm', { body, headers })).status, 200);
    const replay = await ctx.call('/api/auth/device/enroll/confirm', { body, headers });
    assert.equal(replay.status, 400);
    assert.equal(replay.body.code, 'ENROLL_INVALID');
    assert.equal(ctx.signer.issued, 1);
  });
});

test('revoked device is refused everywhere and its certificate is revoked at the CA', async () => {
  await withDeviceApp(async (ctx) => {
    const pc = await ctx.enroll(BOB, 'pc');
    const token = await unlockedToken(ctx, pc.fingerprint);
    assert.equal((await ctx.call('/api/protected', { token, headers: ctx.device(pc.fingerprint) })).status, 200);

    const result = await ctx.enrollment.revoke(pc.deviceId);
    assert.deepEqual(result, { revoked: true, cloudflare: true });
    assert.deepEqual(ctx.signer.revoked, ['cf-1']);

    const refused = await ctx.call('/api/protected', { token, headers: ctx.device(pc.fingerprint) });
    assert.equal(refused.status, 403);
    assert.equal(refused.body.code, 'DEVICE_REVOKED');
    assert.equal((await ctx.call('/assets/app.js', { headers: ctx.device(pc.fingerprint) })).status, 403);
    assert.equal(await wsStatus(ctx.port, ctx.device(pc.fingerprint), token), 403);
    // The slot is free again: a new PC can be enrolled.
    await ctx.enroll(BOB, 'pc');
  });
});

test('limits: one PC + one phone per person; a second PC never gets a valid code', async () => {
  await withDeviceApp(async (ctx) => {
    await ctx.enroll(ALICE, 'pc');
    const headers = { 'cf-ray': 'r', 'cf-connecting-ip': '203.0.113.20', 'x-forja-edge-auth': EDGE_SECRET };
    const second = await ctx.call('/api/auth/device/enroll/start', { body: { email: ALICE, platform: 'pc', name: 'x', csr: makeCsr().csr }, headers });
    assert.equal(second.status, 200, 'same answer as a real start (no leak)');
    assert.match(ctx.mailbox.sent.at(-1)!.subject, /já tens um computador/);
    for (const code of ['000000', '123456']) {
      const res = await ctx.call('/api/auth/device/enroll/confirm', { body: { enrollmentId: second.body.enrollmentId, code }, headers });
      assert.equal(res.body.code, 'ENROLL_CODE_INVALID');
    }
    assert.equal(deviceRepository.list().filter((d) => d.email === ALICE && d.status === 'active').length, 1);
    await ctx.enroll(ALICE, 'phone');
    assert.equal(deviceRepository.list().filter((d) => d.email === ALICE && d.status === 'active').length, 2);
  });
});

test('limits: unknown email gets no email and the same answer', async () => {
  await withDeviceApp(async (ctx) => {
    const headers = { 'cf-ray': 'r', 'cf-connecting-ip': '203.0.113.30', 'x-forja-edge-auth': EDGE_SECRET };
    const res = await ctx.call('/api/auth/device/enroll/start', { body: { email: 'mallory@example.com', platform: 'pc', name: 'x', csr: makeCsr().csr }, headers });
    assert.equal(res.status, 200);
    assert.ok(res.body.enrollmentId);
    assert.equal(ctx.mailbox.sent.length, 0);
  });
});

test('limits: 5 wrong codes kill the enrolment; codes expire after 10 minutes', async () => {
  await withDeviceApp(async (ctx) => {
    const headers = { 'cf-ray': 'r', 'cf-connecting-ip': '203.0.113.40', 'x-forja-edge-auth': EDGE_SECRET };
    const start = await ctx.call('/api/auth/device/enroll/start', { body: { email: ALICE, platform: 'pc', name: 'x', csr: makeCsr().csr }, headers });
    const good = ctx.mailbox.lastCode()!;
    const wrong = good === '111111' ? '222222' : '111111';
    for (let i = 1; i <= MAX_CODE_ATTEMPTS; i += 1) {
      const res = await ctx.call('/api/auth/device/enroll/confirm', { body: { enrollmentId: start.body.enrollmentId, code: wrong }, headers });
      assert.equal(res.body.code, 'ENROLL_CODE_INVALID');
    }
    const late = await ctx.call('/api/auth/device/enroll/confirm', { body: { enrollmentId: start.body.enrollmentId, code: good }, headers });
    assert.equal(late.status, 400);
    assert.equal(late.body.code, 'ENROLL_INVALID');

    const again = await ctx.call('/api/auth/device/enroll/start', { body: { email: BOB, platform: 'pc', name: 'x', csr: makeCsr().csr }, headers });
    ctx.clock.now += CODE_TTL_MS + 1;
    const expired = await ctx.call('/api/auth/device/enroll/confirm', { body: { enrollmentId: again.body.enrollmentId, code: ctx.mailbox.lastCode() }, headers });
    assert.equal(expired.body.code, 'ENROLL_INVALID');
    assert.equal(ctx.signer.issued, 0);
  });
});

test('limits: per-IP start rate, per-IP failed confirms, per-email starts', async () => {
  await withDeviceApp(async (ctx) => {
    const headers = { 'cf-ray': 'r', 'cf-connecting-ip': '203.0.113.50', 'x-forja-edge-auth': EDGE_SECRET };
    const start = () => ctx.call('/api/auth/device/enroll/start', { body: { email: BOB, platform: 'phone', name: 'x', csr: makeCsr().csr }, headers });
    const ids: string[] = [];
    for (let i = 0; i < LIMITS.startsPerIpPerHour; i += 1) {
      const res = await start();
      assert.equal(res.status, 200);
      ids.push(res.body.enrollmentId);
    }
    assert.equal((await start()).status, 429);
    // Per email: only the first 3 starts in an hour actually send a code.
    assert.equal(ctx.mailbox.sent.length, LIMITS.startsPerEmailPerHour);

    // Failed confirms from one IP across enrolments are capped.
    const other = { ...headers, 'cf-connecting-ip': '203.0.113.51' };
    let status = 0;
    for (let i = 0; i < LIMITS.failedConfirmsPerIpPer15Min + 1; i += 1) {
      status = (await ctx.call('/api/auth/device/enroll/confirm', { body: { enrollmentId: ids[i % ids.length], code: '999999' }, headers: other })).status;
    }
    assert.equal(status, 429);
  });
});

test('bad CSRs are rejected (no proof of possession, weak key)', async () => {
  await withDeviceApp(async (ctx) => {
    const headers = { 'cf-ray': 'r', 'cf-connecting-ip': '203.0.113.60', 'x-forja-edge-auth': EDGE_SECRET };
    const { csr } = makeCsr();
    const der = Buffer.from(csr.replace(/-----[^-]+-----|\s/g, ''), 'base64');
    der[der.length - 5] ^= 0xff; // corrupt the signature
    const tampered = `-----BEGIN CERTIFICATE REQUEST-----\n${der.toString('base64')}\n-----END CERTIFICATE REQUEST-----\n`;
    for (const bad of [tampered, makeCsr('rsa1024').csr, 'not a csr']) {
      const res = await ctx.call('/api/auth/device/enroll/start', { body: { email: ALICE, platform: 'pc', name: 'x', csr: bad }, headers });
      assert.equal(res.status, 400);
      assert.equal(res.body.code, 'ENROLL_CSR');
    }
    const rsa = await ctx.call('/api/auth/device/enroll/start', { body: { email: ALICE, platform: 'pc', name: 'x', csr: makeCsr('rsa2048').csr }, headers });
    assert.equal(rsa.status, 200);
    assert.equal(ctx.mailbox.sent.length, 1);
  });
});

test('a certificate that does not carry the CSR key is not registered', async () => {
  await withDeviceApp(async (ctx) => {
    ctx.signer.swapKey = true;
    const headers = { 'cf-ray': 'r', 'cf-connecting-ip': '203.0.113.70', 'x-forja-edge-auth': EDGE_SECRET };
    const start = await ctx.call('/api/auth/device/enroll/start', { body: { email: ALICE, platform: 'pc', name: 'x', csr: makeCsr().csr }, headers });
    const res = await ctx.call('/api/auth/device/enroll/confirm', { body: { enrollmentId: start.body.enrollmentId, code: ctx.mailbox.lastCode() }, headers });
    assert.equal(res.body.code, 'ENROLL_REGISTER_FAILED');
    assert.deepEqual(ctx.signer.revoked, ['cf-1']);
    assert.equal(deviceRepository.list().length, 0);
  });
});

test('without a mail transport enrolment answers 503 and sends nothing', async () => {
  await withDeviceApp(async (ctx) => {
    const headers = { 'cf-ray': 'r', 'cf-connecting-ip': '203.0.113.80', 'x-forja-edge-auth': EDGE_SECRET };
    const res = await ctx.call('/api/auth/device/enroll/start', { body: { email: ALICE, platform: 'pc', name: 'x', csr: makeCsr().csr }, headers });
    assert.equal(res.status, 503);
    assert.equal(res.body.code, 'MAIL_NOT_CONFIGURED');
  }, { mail: false });
});

test('a misconfigured device verifier refuses everything', () => {
  const verifier = createDeviceVerifier({ allowedEmails: [ALICE], edgeSecret: 'short', repo: deviceRepository });
  const result = verifier.verifySync({ 'x-forja-edge-auth': 'short', 'x-forja-client-cert-sha256': 'a'.repeat(64) });
  assert.deepEqual(result, { ok: false, reason: 'misconfigured' });
});
