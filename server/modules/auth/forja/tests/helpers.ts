import { generateKeyPairSync, type KeyObject } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import jwt from 'jsonwebtoken';

import { closeConnection, initializeDatabase } from '@/modules/database/index.js';

export const TEAM = 'forja-test.cloudflareaccess.com';
export const AUD = 'aud-forja-test-0123456789abcdef';
export const ALICE = 'alice@example.com';
export const BOB = 'bob@example.com';

export type TestKey = { kid: string; privateKey: KeyObject; jwk: Record<string, unknown> };

export function makeKey(kid: string): TestKey {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = { ...publicKey.export({ format: 'jwk' }), kid, alg: 'RS256', use: 'sig' } as Record<string, unknown>;
  return { kid, privateKey, jwk };
}

export function accessJwt(
  key: TestKey,
  claims: Record<string, unknown> = {},
  options: { aud?: string; iss?: string; expiresIn?: number } = {},
): string {
  const now = Math.floor(Date.now() / 1000);
  return jwt.sign(
    {
      aud: [options.aud ?? AUD],
      iss: options.iss ?? `https://${TEAM}`,
      email: ALICE,
      sub: 'user-id',
      type: 'app',
      iat: now,
      nbf: now,
      exp: now + (options.expiresIn ?? 3600),
      ...claims,
    },
    key.privateKey,
    { algorithm: 'RS256', keyid: key.kid } as never,
  );
}

export async function withTempDatabase(run: () => Promise<void>): Promise<void> {
  const previous = process.env.DATABASE_PATH;
  const dir = await mkdtemp(path.join(os.tmpdir(), 'forja-pin-db-'));
  const dbPath = path.join(dir, 'auth.db');
  closeConnection();
  process.env.DATABASE_PATH = dbPath;
  await writeFile(dbPath, '');
  await initializeDatabase();
  try {
    await run();
  } finally {
    closeConnection();
    if (previous === undefined) delete process.env.DATABASE_PATH;
    else process.env.DATABASE_PATH = previous;
    await rm(dir, { recursive: true, force: true });
  }
}
