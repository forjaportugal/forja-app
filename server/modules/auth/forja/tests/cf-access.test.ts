import assert from 'node:assert/strict';
import test from 'node:test';

import { createCfAccessVerifier, loadCfAccessConfig } from '../cf-access.js';

import { ALICE, AUD, BOB, TEAM, accessJwt, makeKey } from './helpers.js';

const key = makeKey('kid-1');
const otherKey = makeKey('kid-1'); // same kid, different key material

function verifier(overrides: Partial<Parameters<typeof createCfAccessVerifier>[0]> = {}) {
  let fetches = 0;
  const instance = createCfAccessVerifier({
    teamDomain: TEAM,
    audience: AUD,
    allowedEmails: [ALICE, BOB],
    devBypass: false,
    fetchCerts: async () => {
      fetches += 1;
      return { keys: [key.jwk] };
    },
    ...overrides,
  });
  return { instance, fetches: () => fetches };
}

const headers = (token?: string, extra: Record<string, string> = {}) =>
  (token ? { 'cf-access-jwt-assertion': token, ...extra } : { ...extra });

test('accepts a valid Access JWT and returns the email from the signed claim', async () => {
  const { instance } = verifier();
  const result = await instance.verify(headers(accessJwt(key, { email: 'Alice@Example.com' })));
  assert.deepEqual(result, { ok: true, identity: { email: ALICE, via: 'jwt' } });
});

test('rejects a request with no Access JWT, even with the plain email header', async () => {
  const { instance } = verifier();
  assert.deepEqual(await instance.verify(headers(undefined, { 'cf-access-authenticated-user-email': ALICE })), {
    ok: false,
    reason: 'missing',
  });
});

test('rejects garbage and tokens signed by a different key', async () => {
  const { instance } = verifier();
  assert.deepEqual(await instance.verify(headers('not.a.jwt')), { ok: false, reason: 'invalid' });
  assert.deepEqual(await instance.verify(headers(accessJwt(otherKey))), { ok: false, reason: 'invalid' });
});

test('rejects the wrong audience, the wrong issuer and an expired token', async () => {
  const { instance } = verifier();
  assert.deepEqual(await instance.verify(headers(accessJwt(key, {}, { aud: 'other-app-aud' }))), { ok: false, reason: 'invalid' });
  assert.deepEqual(
    await instance.verify(headers(accessJwt(key, {}, { iss: 'https://evil.cloudflareaccess.com' }))),
    { ok: false, reason: 'invalid' },
  );
  assert.deepEqual(await instance.verify(headers(accessJwt(key, {}, { expiresIn: -120 }))), { ok: false, reason: 'invalid' });
});

test('rejects an email that is not on FORJA_ALLOWED_EMAILS and a token without email', async () => {
  const { instance } = verifier();
  assert.deepEqual(await instance.verify(headers(accessJwt(key, { email: 'mallory@example.com' }))), {
    ok: false,
    reason: 'not-allowed',
  });
  assert.deepEqual(await instance.verify(headers(accessJwt(key, { email: undefined }))), { ok: false, reason: 'invalid' });
});

test('rejects when the plain email header disagrees with the signed claim', async () => {
  const { instance } = verifier();
  const result = await instance.verify(headers(accessJwt(key), { 'cf-access-authenticated-user-email': BOB }));
  assert.deepEqual(result, { ok: false, reason: 'invalid' });
});

test('fails closed when the audience or allow-list is not configured', async () => {
  assert.deepEqual(await verifier({ audience: '' }).instance.verify(headers(accessJwt(key))), { ok: false, reason: 'misconfigured' });
  assert.deepEqual(await verifier({ allowedEmails: [] }).instance.verify(headers(accessJwt(key))), {
    ok: false,
    reason: 'misconfigured',
  });
});

test('verifySync uses cached keys only and works once keys are loaded', async () => {
  const { instance, fetches } = verifier();
  const token = accessJwt(key);
  assert.deepEqual(instance.verifySync(headers(token)), { ok: false, reason: 'keys-unavailable' });
  await instance.refreshKeys(true);
  assert.equal(instance.verifySync(headers(token)).ok, true);
  assert.deepEqual(instance.verifySync(headers(accessJwt(key, {}, { aud: 'x' }))), { ok: false, reason: 'invalid' });
  assert.ok(fetches() >= 1);
});

test('keys are cached between requests', async () => {
  const { instance, fetches } = verifier();
  await instance.verify(headers(accessJwt(key)));
  await instance.verify(headers(accessJwt(key)));
  await instance.verify(headers(accessJwt(key)));
  assert.equal(fetches(), 1);
});

test('dev bypass is off by default and ignored in production', () => {
  assert.equal(loadCfAccessConfig({}).devBypass, false);
  assert.equal(loadCfAccessConfig({ FORJA_ACCESS_DEV_BYPASS: '1', NODE_ENV: 'production' }).devBypass, false);
  assert.equal(loadCfAccessConfig({ FORJA_ACCESS_DEV_BYPASS: '1', NODE_ENV: 'development' }).devBypass, true);
  const config = loadCfAccessConfig({ FORJA_ALLOWED_EMAILS: ' A@x.com, b@y.com ,', CF_ACCESS_AUD: ' aud ' });
  assert.deepEqual(config.allowedEmails, ['a@x.com', 'b@y.com']);
  assert.equal(config.audience, 'aud');
  assert.equal(config.teamDomain, 'wild-tree-51af.cloudflareaccess.com');
});

test('dev bypass (explicit) trusts the plain header but still applies the allow-list', async () => {
  const { instance } = verifier({ devBypass: true, audience: '' });
  assert.equal((await instance.verify({ 'cf-access-authenticated-user-email': ALICE })).ok, true);
  assert.deepEqual(await instance.verify({ 'cf-access-authenticated-user-email': 'x@evil.com' }), {
    ok: false,
    reason: 'not-allowed',
  });
});
