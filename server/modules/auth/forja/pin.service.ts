/**
 * Forja: 6-digit PIN unlock, one app user per Cloudflare Access email.
 *
 * The caller has already verified the Access identity; this service never
 * sees a username typed by a human. First visit for an email: set the PIN
 * (twice). Afterwards: PIN only. MAX_FAILED_ATTEMPTS wrong PINs lock that user
 * for LOCK_MS. Every attempt is logged.
 */
import { AppError } from '@/shared/utils.js';

import type { PinRepository } from './pin.repository.js';

export const PIN_PATTERN = /^\d{6}$/;
export const MAX_FAILED_ATTEMPTS = 5;
export const LOCK_MS = 15 * 60 * 1000;

type PinUser = { id: number; username: string };

export type PinServiceDependencies = {
  repo: Pick<PinRepository, 'getUserByEmail' | 'createUser' | 'getState' | 'saveState' | 'logAttempt' | 'updateLastLogin'>;
  hashPin(pin: string): Promise<string>;
  comparePin(pin: string, hash: string): Promise<boolean>;
  issueToken(user: PinUser): string;
  now?: () => number;
  log?: (message: string) => void;
};

function readPin(value: unknown): string {
  const pin = typeof value === 'string' ? value : '';
  if (!PIN_PATTERN.test(pin)) {
    throw new AppError('The PIN must be exactly 6 digits', { code: 'PIN_FORMAT', statusCode: 400 });
  }
  return pin;
}

export function createPinService(dependencies: PinServiceDependencies) {
  const now = dependencies.now ?? (() => Date.now());
  const log = dependencies.log ?? ((message: string) => console.log(message));
  const { repo } = dependencies;

  function record(email: string, outcome: string, ip: string | null) {
    log(`[forja-pin] email=${email} outcome=${outcome} ip=${ip ?? '-'}`);
    try {
      repo.logAttempt(email, outcome, ip);
    } catch (error) {
      console.error('[forja-pin] could not log attempt:', error instanceof Error ? error.message : String(error));
    }
  }

  // Serialise attempts per email so parallel wrong PINs cannot undercount.
  const queues = new Map<string, Promise<unknown>>();
  function serialize<T>(email: string, task: () => Promise<T>): Promise<T> {
    const previous = queues.get(email) ?? Promise.resolve();
    const next = previous.catch(() => undefined).then(task);
    queues.set(email, next);
    void next.catch(() => undefined).finally(() => {
      if (queues.get(email) === next) queues.delete(email);
    });
    return next;
  }

  function session(user: PinUser) {
    return {
      success: true,
      user: { id: user.id, username: user.username },
      token: dependencies.issueToken(user),
    };
  }

  async function setupNow(email: string, pinInput: unknown, confirmInput: unknown, ip: string | null) {
    const pin = readPin(pinInput);
    if (confirmInput !== undefined && confirmInput !== pin) {
      throw new AppError('The two PINs do not match', { code: 'PIN_MISMATCH', statusCode: 400 });
    }
    if (repo.getUserByEmail(email)) {
      record(email, 'setup-rejected-exists', ip);
      throw new AppError('A PIN is already set for this account', { code: 'PIN_ALREADY_SET', statusCode: 409 });
    }
    const hash = await dependencies.hashPin(pin);
    let user: PinUser;
    try {
      user = repo.createUser(email, hash);
    } catch (error) {
      // Two concurrent first visits: the UNIQUE(username) constraint wins.
      if (typeof error === 'object' && error && 'code' in error && error.code === 'SQLITE_CONSTRAINT_UNIQUE') {
        throw new AppError('A PIN is already set for this account', { code: 'PIN_ALREADY_SET', statusCode: 409 });
      }
      throw error;
    }
    repo.saveState(user.id, { failedAttempts: 0, lockedUntil: null });
    repo.updateLastLogin(user.id);
    record(email, 'setup', ip);
    return session(user);
  }

  async function unlockNow(email: string, pinInput: unknown, ip: string | null) {
    const user = repo.getUserByEmail(email);
    if (!user) {
      throw new AppError('No PIN set for this account yet', { code: 'PIN_NOT_SET', statusCode: 409 });
    }
    const state = repo.getState(user.id);
    if (state.lockedUntil && state.lockedUntil > now()) {
      record(email, 'locked', ip);
      throw new AppError(`Too many wrong PINs. Locked for ${Math.ceil((state.lockedUntil - now()) / 60_000)} more minute(s).`, {
        code: 'PIN_LOCKED',
        statusCode: 429,
        details: { lockedUntil: state.lockedUntil },
      });
    }
    const pin = typeof pinInput === 'string' && PIN_PATTERN.test(pinInput) ? pinInput : null;
    const valid = pin ? await dependencies.comparePin(pin, user.password_hash) : false;

    if (!valid) {
      // An expired lock starts a fresh window of attempts.
      const previous = state.lockedUntil ? 0 : state.failedAttempts;
      const failedAttempts = previous + 1;
      if (failedAttempts >= MAX_FAILED_ATTEMPTS) {
        const lockedUntil = now() + LOCK_MS;
        repo.saveState(user.id, { failedAttempts: 0, lockedUntil });
        record(email, 'fail-locked', ip);
        throw new AppError('Too many wrong PINs. Locked for 15 minutes.', {
          code: 'PIN_LOCKED',
          statusCode: 429,
          details: { lockedUntil },
        });
      }
      repo.saveState(user.id, { failedAttempts, lockedUntil: null });
      record(email, 'fail', ip);
      const left = MAX_FAILED_ATTEMPTS - failedAttempts;
      throw new AppError(`Wrong PIN. ${left} attempt${left === 1 ? '' : 's'} left before a 15-minute lock.`, {
        code: 'PIN_INVALID',
        statusCode: 401,
        details: { attemptsLeft: MAX_FAILED_ATTEMPTS - failedAttempts },
      });
    }

    repo.saveState(user.id, { failedAttempts: 0, lockedUntil: null });
    repo.updateLastLogin(user.id);
    record(email, 'success', ip);
    return session(user);
  }

  return {
    status(email: string) {
      const user = repo.getUserByEmail(email);
      const state = user ? repo.getState(user.id) : null;
      const lockedUntil = state?.lockedUntil && state.lockedUntil > now() ? state.lockedUntil : null;
      return {
        authMode: 'pin' as const,
        email,
        needsSetup: !user,
        isAuthenticated: false,
        lockedUntil,
      };
    },

    setup(email: string, pinInput: unknown, confirmInput: unknown, ip: string | null = null) {
      return serialize(email, () => setupNow(email, pinInput, confirmInput, ip));
    },

    unlock(email: string, pinInput: unknown, ip: string | null = null) {
      return serialize(email, () => unlockNow(email, pinInput, ip));
    },
  };
}


export type PinService = ReturnType<typeof createPinService>;
