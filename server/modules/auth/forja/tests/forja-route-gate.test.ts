import assert from 'node:assert/strict';
import type { AddressInfo } from 'node:net';
import test from 'node:test';

import express from 'express';

import { forjaRouteGate } from '../forja-auth.js';

import { ALICE, withTempDatabase } from './helpers.js';

// The gate server/index.ts puts in front of /api/agent and /api/browser-use-mcp.
async function withGatedApp(run: (call: (headers: Record<string, string>) => Promise<number>) => Promise<void>) {
  const app = express();
  app.use('/api/agent', forjaRouteGate, (_req, res) => {
    res.json({ reached: true });
  });
  app.use('/api/browser-use-mcp', forjaRouteGate, (_req, res) => {
    res.json({ reached: true });
  });
  const server = app.listen(0, '127.0.0.1');
  await new Promise((resolve) => server.once('listening', resolve));
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  try {
    await run(async (headers) => {
      let worst = 0;
      for (const path of ['/api/agent', '/api/browser-use-mcp/tools/x']) {
        const response = await fetch(`${base}${path}`, { method: 'POST', headers });
        worst = Math.max(worst, response.status);
      }
      return worst;
    });
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

test('without FORJA_AUTH the gate is a no-op (upstream behaviour)', async () => {
  delete process.env.FORJA_AUTH;
  await withGatedApp(async (call) => {
    assert.equal(await call({ 'cf-ray': 'abc' }), 200);
  });
});

test('in PIN mode, tunnel requests to /api/agent and /api/browser-use-mcp get 401 without a session', async () => {
  const saved = { ...process.env };
  Object.assign(process.env, {
    FORJA_AUTH: 'pin',
    FORJA_ACCESS_DEV_BYPASS: '1',
    NODE_ENV: 'test',
    FORJA_ALLOWED_EMAILS: ALICE,
  });
  try {
    await withTempDatabase(async () => {
      await withGatedApp(async (call) => {
        assert.equal(await call({ 'cf-ray': 'abc', 'cf-access-authenticated-user-email': ALICE }), 401);
        assert.equal(await call({ 'cf-connecting-ip': '203.0.113.9' }), 401);
        assert.equal(
          await call({ 'cf-ray': 'abc', 'cf-access-authenticated-user-email': ALICE, Authorization: 'Bearer forged' }),
          401,
        );
      });
    });
  } finally {
    process.env = saved;
  }
});
