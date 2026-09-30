/**
 * Forja device mode: forja-secretd client (fake unix-socket daemon, no real secrets, no real
 * daemon). Covers the JSON-over-socket protocol (mail send, cert issue/revoke) and the
 * synchronous edge-secret helper subprocess, plus the mailer.ts / cf-client-certs.ts /
 * device-verifier.ts integration points that switch to forja-secretd when FORJA_SECRETD=1.
 */
import assert from 'node:assert/strict';
import { createServer, type Server } from 'node:net';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync, chmodSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { loadCloudflareSigner } from '../cf-client-certs.js';
import { loadDeviceModeConfig } from '../device-verifier.js';
import { loadMailer } from '../mailer.js';
import {
  certIssueViaSecretd,
  certRevokeViaSecretd,
  getEdgeSecretSync,
  secretdEnabled,
  sendMailViaSecretd,
} from '../secretd-client.js';

type FakeRequest = Record<string, unknown>;

/** A throwaway unix-socket "forja-secretd": one JSON line in, one JSON line back, per connection. */
function fakeSecretd(handler: (req: FakeRequest) => Record<string, unknown>): { socketPath: string; requests: FakeRequest[]; close(): Promise<void> } {
  const dir = mkdtempSync(path.join(tmpdir(), 'forja-secretd-test-'));
  const socketPath = path.join(dir, 'secretd.sock');
  const requests: FakeRequest[] = [];
  const server: Server = createServer((socket) => {
    let buf = '';
    socket.on('data', (chunk) => {
      buf += chunk.toString('utf8');
      const nl = buf.indexOf('\n');
      if (nl === -1) return;
      const req = JSON.parse(buf.slice(0, nl)) as FakeRequest;
      requests.push(req);
      socket.end(`${JSON.stringify(handler(req))}\n`);
    });
  });
  server.listen(socketPath);
  return {
    socketPath,
    requests,
    close: () => new Promise((resolve) => {
      server.close(() => { rmSync(dir, { recursive: true, force: true }); resolve(); });
    }),
  };
}

test('secretdEnabled: only FORJA_SECRETD=1 turns it on', () => {
  assert.equal(secretdEnabled({}), false);
  assert.equal(secretdEnabled({ FORJA_SECRETD: '0' }), false);
  assert.equal(secretdEnabled({ FORJA_SECRETD: 'true' }), false);
  assert.equal(secretdEnabled({ FORJA_SECRETD: '1' }), true);
  assert.equal(secretdEnabled({ FORJA_SECRETD: ' 1 ' }), true);
});

test('sendMailViaSecretd: sends op=send-mail and resolves on ok:true', async () => {
  const fake = fakeSecretd((req) => {
    assert.equal(req.op, 'send-mail');
    return { ok: true };
  });
  try {
    await sendMailViaSecretd('alice@example.com', 'Código Forja: 123456', 'texto do email', { FORJA_SECRETD_SOCKET: fake.socketPath });
    assert.deepEqual(fake.requests, [{ op: 'send-mail', to: 'alice@example.com', subject: 'Código Forja: 123456', text: 'texto do email' }]);
  } finally {
    await fake.close();
  }
});

test('sendMailViaSecretd: rejects with the daemon\'s error on ok:false', async () => {
  const fake = fakeSecretd(() => ({ ok: false, error: 'smtp-auth-failed' }));
  try {
    await assert.rejects(
      sendMailViaSecretd('alice@example.com', 'subj', 'body', { FORJA_SECRETD_SOCKET: fake.socketPath }),
      /secretd send-mail failed: smtp-auth-failed/,
    );
  } finally {
    await fake.close();
  }
});

test('certIssueViaSecretd / certRevokeViaSecretd: round-trip id + PEM, and surface daemon errors', async () => {
  const fake = fakeSecretd((req) => {
    if (req.op === 'cert-issue') return { ok: true, cf_cert_id: 'cert-1', certificate_pem: 'PEM-DATA' };
    if (req.op === 'cert-revoke') return { ok: true };
    return { ok: false, error: 'unknown-op' };
  });
  try {
    const issued = await certIssueViaSecretd('CSR-PEM', { FORJA_SECRETD_SOCKET: fake.socketPath });
    assert.deepEqual(issued, { cfCertId: 'cert-1', certificatePem: 'PEM-DATA' });
    await certRevokeViaSecretd('cert-1', { FORJA_SECRETD_SOCKET: fake.socketPath });
    assert.deepEqual(fake.requests, [
      { op: 'cert-issue', csr_pem: 'CSR-PEM' },
      { op: 'cert-revoke', cf_cert_id: 'cert-1' },
    ]);
  } finally {
    await fake.close();
  }
});

test('certIssueViaSecretd: malformed ok:true response (missing fields) is treated as a failure', async () => {
  const fake = fakeSecretd(() => ({ ok: true }));
  try {
    await assert.rejects(certIssueViaSecretd('CSR', { FORJA_SECRETD_SOCKET: fake.socketPath }), /secretd cert-issue failed/);
  } finally {
    await fake.close();
  }
});

test('no daemon listening on the socket -> the call rejects (never hangs, never falls back silently)', async () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'forja-secretd-nosock-'));
  try {
    await assert.rejects(sendMailViaSecretd('a@b.com', 's', 't', { FORJA_SECRETD_SOCKET: path.join(dir, 'nothing.sock') }));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('getEdgeSecretSync: runs the configured helper and trims its stdout', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'forja-edge-helper-'));
  try {
    const helper = path.join(dir, 'get-edge-secret.py');
    writeFileSync(helper, '#!/usr/bin/env python3\nprint("  edge-secret-value  ")\n');
    chmodSync(helper, 0o755);
    const secret = getEdgeSecretSync({ FORJA_SECRETD_EDGE_HELPER: helper });
    assert.equal(secret, 'edge-secret-value');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('getEdgeSecretSync: runs the helper via /usr/bin/python3 -I, never a bare "python3" resolved through PATH', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'forja-edge-helper-isolated-'));
  try {
    const helper = path.join(dir, 'get-edge-secret.py');
    // No shebang and not executable: if the implementation ever regressed to
    // execFileSync('python3', [helper]) (PATH lookup, ignoring -I), this would still work by
    // accident on some systems -- so the real regression guard is the PATH-poisoning case below.
    writeFileSync(helper, 'import sys; print("value-from-absolute-python3")\n');
    const secret = getEdgeSecretSync({ FORJA_SECRETD_EDGE_HELPER: helper });
    assert.equal(secret, 'value-from-absolute-python3');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('getEdgeSecretSync: a forja-writable PATH with a fake "python3" is never consulted', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'forja-edge-helper-pathpoison-'));
  try {
    const helper = path.join(dir, 'get-edge-secret.py');
    writeFileSync(helper, 'print("real-value")\n');

    // Plant a fake python3 ahead of the real one on PATH -- this is exactly the attack A1 closes
    // (an agent running as forja writing to a forja-writable directory on the app's own PATH).
    const fakeBin = path.join(dir, 'bin');
    mkdirSync(fakeBin);
    const fakePython3 = path.join(fakeBin, 'python3');
    writeFileSync(fakePython3, '#!/bin/sh\necho "PWNED"\n');
    chmodSync(fakePython3, 0o755);

    const secret = getEdgeSecretSync({
      FORJA_SECRETD_EDGE_HELPER: helper,
      PATH: `${fakeBin}:${process.env.PATH ?? ''}`,
    });
    assert.equal(secret, 'real-value');
    assert.notEqual(secret, 'PWNED');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('getEdgeSecretSync: helper failure (missing/non-zero exit) -> empty string, never throws', () => {
  const secret = getEdgeSecretSync({ FORJA_SECRETD_EDGE_HELPER: '/nonexistent/forja-secretd-get-edge-secret' });
  assert.equal(secret, '');

  const dir = mkdtempSync(path.join(tmpdir(), 'forja-edge-helper-fail-'));
  try {
    const helper = path.join(dir, 'fails.py');
    writeFileSync(helper, '#!/usr/bin/env python3\nimport sys\nsys.exit(1)\n');
    chmodSync(helper, 0o755);
    assert.equal(getEdgeSecretSync({ FORJA_SECRETD_EDGE_HELPER: helper }), '');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('loadDeviceModeConfig: FORJA_SECRETD=1 reads the edge secret from the helper, not FORJA_EDGE_SECRET', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'forja-edge-helper-config-'));
  try {
    const helper = path.join(dir, 'get-edge-secret.py');
    writeFileSync(helper, '#!/usr/bin/env python3\nprint("from-secretd")\n');
    chmodSync(helper, 0o755);
    const config = loadDeviceModeConfig({
      FORJA_SECRETD: '1',
      FORJA_SECRETD_EDGE_HELPER: helper,
      FORJA_EDGE_SECRET: 'should-not-be-used',
      FORJA_ALLOWED_EMAILS: 'a@b.com',
    });
    assert.equal(config.edgeSecret, 'from-secretd');

    const legacy = loadDeviceModeConfig({ FORJA_EDGE_SECRET: 'direct-env-value', FORJA_ALLOWED_EMAILS: 'a@b.com' });
    assert.equal(legacy.edgeSecret, 'direct-env-value');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('loadMailer(secretd): sends through the daemon, never touches FORJA_MAIL_PASSWORD_FILE', async () => {
  const fake = fakeSecretd(() => ({ ok: true }));
  try {
    const logs: string[] = [];
    const mailer = loadMailer(
      { FORJA_MAIL: 'secretd', FORJA_SECRETD_SOCKET: fake.socketPath },
      { log: (l) => logs.push(l) },
    );
    assert.ok(mailer);
    await mailer.send({ to: 'alice@example.com', subject: 'Código Forja: 654321', text: 'texto' });
    assert.deepEqual(fake.requests, [{ op: 'send-mail', to: 'alice@example.com', subject: 'Código Forja: 654321', text: 'texto' }]);
    assert.ok(logs.some((line) => /mail transport forja-secretd ready/.test(line)));
    assert.ok(logs.some((line) => /sent to domain=example\.com/.test(line)));
  } finally {
    await fake.close();
  }
});

test('loadCloudflareSigner: FORJA_SECRETD=1 routes issue/revoke through the daemon, never reads FORJA_CF_CERT_TOKEN_FILE', async () => {
  const fake = fakeSecretd((req) => {
    if (req.op === 'cert-issue') return { ok: true, cf_cert_id: 'cert-secretd-1', certificate_pem: 'PEM-VIA-SECRETD' };
    return { ok: true };
  });
  try {
    const signer = loadCloudflareSigner({
      FORJA_SECRETD: '1',
      FORJA_SECRETD_SOCKET: fake.socketPath,
      // deliberately no FORJA_CF_ZONE_ID / FORJA_CF_CERT_TOKEN_FILE: secretd path must not need them
    });
    assert.ok(signer);
    const issued = await signer.issue('CSR-PEM');
    assert.deepEqual(issued, { cfCertId: 'cert-secretd-1', certificatePem: 'PEM-VIA-SECRETD' });
    await signer.revoke('cert-secretd-1');
    assert.deepEqual(fake.requests, [
      { op: 'cert-issue', csr_pem: 'CSR-PEM' },
      { op: 'cert-revoke', cf_cert_id: 'cert-secretd-1' },
    ]);
  } finally {
    await fake.close();
  }
});
