/**
 * Forja: PIN screen strings. European Portuguese is the default; English is
 * one tap away. Kept outside the upstream i18n bundles (fork mergeability).
 */
export type PinLang = 'pt-PT' | 'en';

const STRINGS = {
  'pt-PT': {
    unlockTitle: 'Introduz o teu código',
    setupTitle: 'Escolhe um código de 6 dígitos',
    confirmTitle: 'Confirma o código',
    footer: 'Só aparelhos registados têm acesso. O código é pedido sempre que abres a app.',
    digitsEntered: 'Dígitos introduzidos',
    delete: 'Apagar',
    switchLanguage: 'English',
    mismatch: 'Os códigos não coincidem. Escolhe outra vez.',
    wrongPin: (left: number) => `Código errado — ${left === 1 ? 'falta 1 tentativa' : `faltam ${left} tentativas`}`,
    locked: (minutes: number) => (minutes >= 15 ? 'Bloqueado durante 15 minutos' : `Bloqueado — tenta daqui a ${minutes} min`),
    format: 'O código tem de ter exatamente 6 dígitos.',
    alreadySet: 'Esta conta já tem código. Recarrega a página.',
    notSet: 'Esta conta ainda não tem código. Recarrega a página.',
    generic: 'Não foi possível entrar. Tenta outra vez.',
  },
  en: {
    unlockTitle: 'Enter your PIN',
    setupTitle: 'Choose your 6-digit PIN',
    confirmTitle: 'Confirm your PIN',
    footer: 'Access is limited to enrolled devices. The PIN is asked every time the app opens.',
    digitsEntered: 'Digits entered',
    delete: 'Delete',
    switchLanguage: 'Português',
    mismatch: 'The PINs do not match. Choose it again.',
    wrongPin: (left: number) => `Wrong PIN — ${left} attempt${left === 1 ? '' : 's'} left`,
    locked: (minutes: number) => (minutes >= 15 ? 'Locked for 15 minutes' : `Locked — try again in ${minutes} min`),
    format: 'The PIN must be exactly 6 digits.',
    alreadySet: 'This account already has a PIN. Reload the page.',
    notSet: 'This account has no PIN yet. Reload the page.',
    generic: 'Could not sign in. Try again.',
  },
} as const;

export type PinStrings = (typeof STRINGS)[PinLang];

export const pinStrings = (lang: PinLang): PinStrings => STRINGS[lang];

const LANG_KEY = 'forja-pin-lang';

export const readPinLang = (): PinLang => {
  try {
    return localStorage.getItem(LANG_KEY) === 'en' ? 'en' : 'pt-PT';
  } catch {
    return 'pt-PT';
  }
};

export const savePinLang = (lang: PinLang): void => {
  try {
    localStorage.setItem(LANG_KEY, lang);
  } catch {
    // Preference only; ignore unavailable storage.
  }
};

/** Maps a server PIN error code to a message in the chosen language. */
export const pinErrorMessage = (
  strings: PinStrings,
  result: { error: string; code?: string; details?: unknown },
  now: number = Date.now(),
): string => {
  const details = (result.details ?? {}) as { attemptsLeft?: unknown; lockedUntil?: unknown };
  switch (result.code) {
    case 'PIN_INVALID':
      return typeof details.attemptsLeft === 'number' ? strings.wrongPin(details.attemptsLeft) : strings.generic;
    case 'PIN_LOCKED': {
      const until = typeof details.lockedUntil === 'number' ? details.lockedUntil : now + 15 * 60_000;
      return strings.locked(Math.max(1, Math.ceil((until - now) / 60_000)));
    }
    case 'PIN_FORMAT':
      return strings.format;
    case 'PIN_MISMATCH':
      return strings.mismatch;
    case 'PIN_ALREADY_SET':
      return strings.alreadySet;
    case 'PIN_NOT_SET':
      return strings.notSet;
    default:
      return result.error || strings.generic;
  }
};
