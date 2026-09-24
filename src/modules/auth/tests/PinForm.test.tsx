import assert from 'node:assert/strict';

import { act, fireEvent, render, screen } from '@testing-library/react';
import { beforeEach, test, vi } from 'vitest';

const login = vi.fn(async () => ({ success: true as const }));
const register = vi.fn(async () => ({ success: true as const }));

vi.mock('@/modules/auth/context/AuthContext', () => ({
  useAuth: () => ({ accessEmail: 'alice@example.com', error: null, login, register }),
}));

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (_key: string, options?: { defaultValue?: string }) => options?.defaultValue ?? _key }),
}));

const { default: PinForm } = await import('@/modules/auth/PinForm');

async function typePin(pin: string) {
  for (const digit of pin) {
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: digit }));
    });
  }
}

beforeEach(() => {
  login.mockClear();
  register.mockClear();
});

test('unlock: six digits submit the PIN for the Access email, no username field', async () => {
  render(<PinForm mode="unlock" />);
  assert.equal(screen.queryByLabelText(/username/i), null);
  assert.ok(screen.getByText('Enter your PIN'));

  await typePin('123456');

  assert.deepEqual(login.mock.calls, [['alice@example.com', '123456']]);
});

test('setup: the PIN is asked twice and only a matching pair is registered', async () => {
  render(<PinForm mode="setup" />);
  assert.ok(screen.getByText('Choose your 6-digit PIN'));

  await typePin('111111');
  assert.ok(screen.getByText('Confirm your PIN'));
  await typePin('222222');
  assert.equal(register.mock.calls.length, 0);
  assert.ok(screen.getByRole('alert').textContent?.includes('do not match'));

  await typePin('333333');
  await typePin('333333');
  assert.deepEqual(register.mock.calls, [['alice@example.com', '333333']]);
});

test('backspace removes the last digit', async () => {
  render(<PinForm mode="unlock" />);
  await typePin('12345');
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name: 'Delete' }));
  });
  await typePin('96');
  assert.deepEqual(login.mock.calls, [['alice@example.com', '123496']]);
});
