import { useCallback, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Delete, Loader2 } from 'lucide-react';

import { useAuth } from '@/modules/auth/context/AuthContext';
import AuthErrorAlert from '@/modules/auth/AuthErrorAlert';
import AuthScreenLayout from '@/modules/auth/AuthScreenLayout';

const PIN_LENGTH = 6;
const KEYS = ['1', '2', '3', '4', '5', '6', '7', '8', '9', '', '0', 'back'] as const;

type PinFormProps = {
  /** 'setup' on the first visit of this Access email, 'unlock' afterwards. */
  mode: 'setup' | 'unlock';
};

/**
 * Forja: 6-digit PIN pad (Cloudflare Access identity + PIN, no username or
 * password). Rendered by ProtectedRoute when the server runs in PIN mode.
 */
export default function PinForm({ mode }: PinFormProps) {
  const { t } = useTranslation('auth');
  const { accessEmail, error: sessionError, login, register } = useAuth();

  const [pin, setPin] = useState('');
  const [firstPin, setFirstPin] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);

  const isConfirming = mode === 'setup' && firstPin !== null;

  const submit = useCallback(
    async (value: string) => {
      setErrorMessage('');
      if (mode === 'setup' && firstPin === null) {
        setFirstPin(value);
        setPin('');
        return;
      }
      if (mode === 'setup' && firstPin !== value) {
        setFirstPin(null);
        setPin('');
        setErrorMessage(t('pin.errors.mismatch', { defaultValue: 'The PINs do not match. Choose it again.' }));
        return;
      }

      setIsSubmitting(true);
      const email = accessEmail ?? '';
      const result = mode === 'setup' ? await register(email, value) : await login(email, value);
      setIsSubmitting(false);
      if (!result.success) {
        setPin('');
        if (mode === 'setup') setFirstPin(null);
        setErrorMessage(result.error);
      }
    },
    [accessEmail, firstPin, login, mode, register, t],
  );

  const press = useCallback(
    (key: string) => {
      if (isSubmitting) return;
      if (key === 'back') {
        setPin((current) => current.slice(0, -1));
        return;
      }
      if (!/^\d$/.test(key) || pin.length >= PIN_LENGTH) return;
      const next = pin + key;
      setPin(next);
      if (next.length === PIN_LENGTH) {
        void submit(next);
      }
    },
    [isSubmitting, pin, submit],
  );

  // Physical keyboard support (computer).
  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Backspace') press('back');
      else if (/^\d$/.test(event.key)) press(event.key);
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [press]);

  const title = mode === 'unlock'
    ? t('pin.unlockTitle', { defaultValue: 'Enter your PIN' })
    : isConfirming
      ? t('pin.confirmTitle', { defaultValue: 'Confirm your PIN' })
      : t('pin.setupTitle', { defaultValue: 'Choose your 6-digit PIN' });

  return (
    <AuthScreenLayout
      title={title}
      description={accessEmail ?? ''}
      footerText={t('pin.footer', { defaultValue: 'Access is limited to enrolled devices. The PIN is asked every time the app opens.' })}
    >
      <div className="space-y-6">
        <div className="flex justify-center gap-3" aria-label={t('pin.digitsEntered', { defaultValue: 'Digits entered' })} aria-live="polite">
          {Array.from({ length: PIN_LENGTH }, (_, index) => (
            <span
              key={index}
              data-testid="pin-dot"
              className={`h-3.5 w-3.5 rounded-full border border-primary/60 transition-colors ${index < pin.length ? 'bg-primary' : 'bg-transparent'}`}
            />
          ))}
        </div>

        <AuthErrorAlert errorMessage={errorMessage || sessionError || ''} />

        <div className="mx-auto grid max-w-[16rem] grid-cols-3 gap-3">
          {KEYS.map((key, index) =>
            key === '' ? (
              <span key={`empty-${index}`} />
            ) : (
              <button
                key={key}
                type="button"
                onClick={() => press(key)}
                disabled={isSubmitting}
                aria-label={key === 'back' ? t('pin.delete', { defaultValue: 'Delete' }) : key}
                className="flex h-16 items-center justify-center rounded-2xl bg-muted/60 text-2xl font-medium text-foreground transition-colors hover:bg-muted active:scale-95 disabled:opacity-50"
              >
                {key === 'back' ? <Delete className="h-6 w-6" /> : key}
              </button>
            ),
          )}
        </div>

        {isSubmitting && (
          <div className="flex justify-center">
            <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
          </div>
        )}
      </div>
    </AuthScreenLayout>
  );
}
