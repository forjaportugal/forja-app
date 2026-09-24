import assert from 'node:assert/strict';

import { afterEach, test, vi } from 'vitest';

import { clearAuthToken, storeAuthToken } from '@/shared/authToken';
import { refreshSseTicket, sseQueryToken, startSseTickets } from '@/shared/sseTicket';

const makeToken = (payload: Record<string, unknown>) => {
  const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
  return `${encode({ alg: 'HS256', typ: 'JWT' })}.${encode(payload)}.signature`;
};

afterEach(() => {
  vi.unstubAllGlobals();
  clearAuthToken();
});

test('outside PIN mode the upstream behaviour is kept (session token)', () => {
  const now = Math.floor(Date.now() / 1000);
  const session = makeToken({ iat: now, exp: now + 600 });
  storeAuthToken(session);
  assert.equal(sseQueryToken(), session);
});

test('in PIN mode EventSource URLs get the short ticket, never the session token', async () => {
  const now = Math.floor(Date.now() / 1000);
  const session = makeToken({ iat: now, exp: now + 600 });
  storeAuthToken(session);
  let resolveTicket: (value: Response) => void = () => undefined;
  const fetchMock = vi.fn(
    () => new Promise<Response>((resolve) => {
      resolveTicket = resolve;
    }),
  );
  vi.stubGlobal('fetch', fetchMock);

  const stop = startSseTickets();
  // Ticket not fetched yet: nothing rather than the session token.
  assert.equal(sseQueryToken(), null);

  resolveTicket(new Response(JSON.stringify({ ticket: 'sse-ticket', expiresIn: 60 }), { status: 200 }));
  await vi.waitFor(() => assert.equal(sseQueryToken(), 'sse-ticket'));
  const init = (fetchMock.mock.calls[0] as unknown[])[1] as RequestInit;
  assert.equal((init.headers as Record<string, string>).Authorization, `Bearer ${session}`);

  stop();
  assert.equal(sseQueryToken(), session);
});

test('refresh without a session does nothing', async () => {
  const fetchMock = vi.fn();
  vi.stubGlobal('fetch', fetchMock);
  await refreshSseTicket();
  assert.equal(fetchMock.mock.calls.length, 0);
});
