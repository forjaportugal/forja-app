import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import test from 'node:test';

import { getConnection } from '@/modules/database/index.js';
import { AppError } from '@/shared/utils.js';

import { pinRepository } from '../pin.repository.js';
import { LOCK_MS, MAX_FAILED_ATTEMPTS, createPinService } from '../pin.service.js';

import { ALICE, BOB, withTempDatabase } from './helpers.js';

const bcrypt = createRequire(import.meta.url)('bcrypt') as {
  hash(value: string, rounds: number): Promise<string>;
  compare(value: string, hash: string): Promise<boolean>;
};

function service(clock: { now: number }) {
  return createPinService({
    repo: pinRepository,
    hashPin: (pin) => bcrypt.hash(pin, 4),
    comparePin: (pin, hash) => bcrypt.compare(pin, hash),
    issueToken: (user) => `token-for-${user.username}`,
    now: () => clock.now,
    log: () => undefined,
  });
}

async function rejectsWith(promise: Promise<unknown>, code: string) {
  await assert.rejects(promise, (error: unknown) => error instanceof AppError && error.code === code);
}

test('first visit sets the PIN (hashed, confirmed); afterwards the PIN unlocks', async () => {
  await withTempDatabase(async () => {
    const clock = { now: Date.now() };
    const pins = service(clock);

    assert.equal(pins.status(ALICE).needsSetup, true);
    await rejectsWith(pins.setup(ALICE, '12345', undefined), 'PIN_FORMAT');
    await rejectsWith(pins.setup(ALICE, 'abcdef', undefined), 'PIN_FORMAT');
    await rejectsWith(pins.setup(ALICE, '123456', '654321'), 'PIN_MISMATCH');

    const created = await pins.setup(ALICE, '123456', '123456');
    assert.equal(created.token, `token-for-${ALICE}`);
    assert.equal(pins.status(ALICE).needsSetup, false);

    const row = pinRepository.getUserByEmail(ALICE);
    assert.ok(row);
    assert.notEqual(row.password_hash, '123456');
    assert.match(row.password_hash, /^\$2[aby]\$/);

    // The PIN cannot be re-chosen through setup once it exists.
    await rejectsWith(pins.setup(ALICE, '999999', '999999'), 'PIN_ALREADY_SET');

    const unlocked = await pins.unlock(ALICE, '123456');
    assert.equal(unlocked.user.username, ALICE);
  });
});

test('five wrong PINs lock the user for 15 minutes, even for the right PIN', async () => {
  await withTempDatabase(async () => {
    const clock = { now: Date.now() };
    const pins = service(clock);
    await pins.setup(ALICE, '123456', '123456');

    for (let attempt = 1; attempt < MAX_FAILED_ATTEMPTS; attempt += 1) {
      await assert.rejects(pins.unlock(ALICE, '000000'), (error: unknown) =>
        error instanceof AppError
        && error.code === 'PIN_INVALID'
        && (error.details as { attemptsLeft: number }).attemptsLeft === MAX_FAILED_ATTEMPTS - attempt);
    }
    await rejectsWith(pins.unlock(ALICE, '000000'), 'PIN_LOCKED');
    await rejectsWith(pins.unlock(ALICE, '123456'), 'PIN_LOCKED');
    assert.ok(pins.status(ALICE).lockedUntil);

    clock.now += LOCK_MS - 1000;
    await rejectsWith(pins.unlock(ALICE, '123456'), 'PIN_LOCKED');

    clock.now += 2000;
    const unlocked = await pins.unlock(ALICE, '123456');
    assert.equal(unlocked.success, true);
    assert.equal(pins.status(ALICE).lockedUntil, null);
  });
});

test('a success resets the failure counter', async () => {
  await withTempDatabase(async () => {
    const pins = service({ now: Date.now() });
    await pins.setup(ALICE, '123456', '123456');
    for (let i = 0; i < MAX_FAILED_ATTEMPTS - 1; i += 1) {
      await rejectsWith(pins.unlock(ALICE, '000000'), 'PIN_INVALID');
    }
    await pins.unlock(ALICE, '123456');
    await rejectsWith(pins.unlock(ALICE, '000000'), 'PIN_INVALID');
  });
});

test('parallel wrong attempts are all counted', async () => {
  await withTempDatabase(async () => {
    const pins = service({ now: Date.now() });
    await pins.setup(ALICE, '123456', '123456');
    const results = await Promise.allSettled(
      Array.from({ length: MAX_FAILED_ATTEMPTS + 2 }, () => pins.unlock(ALICE, '000000')),
    );
    const codes = results.map((r) => (r.status === 'rejected' ? (r.reason as AppError).code : 'ok'));
    assert.equal(codes.filter((c) => c === 'PIN_INVALID').length, MAX_FAILED_ATTEMPTS - 1);
    assert.equal(codes.filter((c) => c === 'PIN_LOCKED').length, 3);
  });
});

test('per-user isolation: separate users, PINs and lockouts per Access email', async () => {
  await withTempDatabase(async () => {
    const pins = service({ now: Date.now() });
    const alice = await pins.setup(ALICE, '111111', '111111');
    assert.equal(pins.status(BOB).needsSetup, true);
    const bob = await pins.setup(BOB, '222222', '222222');
    assert.notEqual(alice.user.id, bob.user.id);

    await rejectsWith(pins.unlock(BOB, '111111'), 'PIN_INVALID');
    for (let i = 0; i < MAX_FAILED_ATTEMPTS; i += 1) {
      await pins.unlock(ALICE, '000000').catch(() => undefined);
    }
    await rejectsWith(pins.unlock(ALICE, '111111'), 'PIN_LOCKED');
    // Alice's lock does not touch Bob.
    assert.equal((await pins.unlock(BOB, '222222')).user.username, BOB);
  });
});

test('every attempt is logged with its outcome', async () => {
  await withTempDatabase(async () => {
    const pins = service({ now: Date.now() });
    await pins.setup(ALICE, '123456', '123456', '203.0.113.7');
    await pins.unlock(ALICE, '000000', '203.0.113.7').catch(() => undefined);
    await pins.unlock(ALICE, '123456', '203.0.113.7');
    const rows = getConnection()
      .prepare('SELECT email, outcome, ip FROM forja_pin_attempts ORDER BY id')
      .all() as Array<{ email: string; outcome: string; ip: string }>;
    assert.deepEqual(rows.map((r) => r.outcome), ['setup', 'fail', 'success']);
    assert.ok(rows.every((r) => r.email === ALICE && r.ip === '203.0.113.7'));
  });
});
