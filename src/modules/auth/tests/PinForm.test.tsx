import assert from 'node:assert/strict';

import { act, fireEvent, render, screen } from '@testing-library/react';
import { beforeEach, test, vi } from 'vitest';

type Result = { success: true } | { success: false; error: string; code?: string; details?: unknown };
const login = vi.fn(async (_email: string, _pin: string): Promise<Result> => ({ success: true }));
const register = vi.fn(async (_email: string, _pin: string): Promise<Result> => ({ success: true }));

vi.mock('@/modules/auth/context/AuthContext', () => ({
  useAuth: () => ({ accessEmail: 'alice@example.com', error: null, login, register }),
}));

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (key: string) => key }),
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
  localStorage.clear();
  login.mockReset();
  login.mockImplementation(async () => ({ success: true }));
  register.mockReset();
  register.mockImplementation(async () => ({ success: true }));
});

test('unlock: six digits submit the PIN for the Access email, no username field', async () => {
  render(<PinForm mode="unlock" />);
  assert.equal(screen.queryByLabelText(/username/i), null);
  assert.ok(screen.getByText('Introduz o teu código'));

  await typePin('123456');

  assert.deepEqual(login.mock.calls, [['alice@example.com', '123456']]);
});

test('setup: the PIN is asked twice and only a matching pair is registered', async () => {
  render(<PinForm mode="setup" />);
  assert.ok(screen.getByText('Escolhe um código de 6 dígitos'));

  await typePin('111111');
  assert.ok(screen.getByText('Confirma o código'));
  await typePin('222222');
  assert.equal(register.mock.calls.length, 0);
  assert.ok(screen.getByRole('alert').textContent?.includes('não coincidem'));

  await typePin('333333');
  await typePin('333333');
  assert.deepEqual(register.mock.calls, [['alice@example.com', '333333']]);
});

test('backspace removes the last digit', async () => {
  render(<PinForm mode="unlock" />);
  await typePin('12345');
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name: 'Apagar' }));
  });
  await typePin('96');
  assert.deepEqual(login.mock.calls, [['alice@example.com', '123496']]);
});

test('server errors are shown in European Portuguese by default', async () => {
  login.mockImplementationOnce(async () => ({ success: false, error: 'Wrong PIN', code: 'PIN_INVALID', details: { attemptsLeft: 3 } }));
  render(<PinForm mode="unlock" />);
  await typePin('000000');
  assert.equal(screen.getByRole('alert').textContent, 'Código errado — faltam 3 tentativas');

  login.mockImplementationOnce(async () => ({
    success: false,
    error: 'locked',
    code: 'PIN_LOCKED',
    details: { lockedUntil: Date.now() + 15 * 60_000 },
  }));
  await typePin('000000');
  assert.equal(screen.getByRole('alert').textContent, 'Bloqueado durante 15 minutos');
});

test('English stays available and the choice is remembered', async () => {
  const first = render(<PinForm mode="unlock" />);
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name: 'English' }));
  });
  assert.ok(screen.getByText('Enter your PIN'));
  first.unmount();
  render(<PinForm mode="unlock" />);
  assert.ok(screen.getByText('Enter your PIN'));
});
