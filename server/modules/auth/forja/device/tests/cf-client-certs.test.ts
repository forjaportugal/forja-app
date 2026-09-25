import assert from 'node:assert/strict';
import test from 'node:test';

import { createCloudflareSigner, loadCloudflareSigner } from '../cf-client-certs.js';

test('issue posts the CSR to the zone client_certificates API and returns id + PEM', async () => {
  const calls: Array<{ url: string; method: string; body?: string; auth?: string }> = [];
  const signer = createCloudflareSigner({
    zoneId: 'zone123',
    token: 'tok',
    validityDays: 1095,
    fetch: async (url, init) => {
      calls.push({ url, method: init.method, body: init.body, auth: init.headers.Authorization });
      return { ok: true, status: 200, json: async () => ({ success: true, result: { id: 'cert-1', certificate: 'PEM' } }) };
    },
  });
  assert.deepEqual(await signer.issue('CSR'), { cfCertId: 'cert-1', certificatePem: 'PEM' });
  await signer.revoke('cert-1');
  assert.equal(calls[0].url, 'https://api.cloudflare.com/client/v4/zones/zone123/client_certificates');
  assert.equal(calls[0].method, 'POST');
  assert.deepEqual(JSON.parse(calls[0].body!), { csr: 'CSR', validity_days: 1095 });
  assert.equal(calls[0].auth, 'Bearer tok');
  assert.equal(calls[1].url, 'https://api.cloudflare.com/client/v4/zones/zone123/client_certificates/cert-1');
  assert.equal(calls[1].method, 'DELETE');
});

test('API errors surface without leaking the token', async () => {
  const signer = createCloudflareSigner({
    zoneId: 'z',
    token: 'secret-token',
    validityDays: 30,
    fetch: async () => ({ ok: false, status: 403, json: async () => ({ success: false, errors: [{ code: 10000, message: 'Authentication error' }] }) }),
  });
  await assert.rejects(signer.issue('CSR'), (error: Error) => {
    assert.match(error.message, /HTTP 403 10000 Authentication error/);
    assert.doesNotMatch(error.message, /secret-token/);
    return true;
  });
});

test('not configured → null (enrolment answers 503)', () => {
  assert.equal(loadCloudflareSigner({}), null);
  assert.equal(loadCloudflareSigner({ FORJA_CF_ZONE_ID: 'z', FORJA_CF_CERT_TOKEN_FILE: '/nonexistent/forja-token' }), null);
});
