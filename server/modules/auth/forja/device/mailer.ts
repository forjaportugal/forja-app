/**
 * Forja device mode: how the one-time enrolment code reaches the person.
 *
 * No production mail transport exists on the server yet (no SMTP, no Gmail
 * API, no Cloudflare email sending). Until one is chosen, FORJA_MAIL may only
 * be `log` outside production (code printed to the server log, for tests and
 * development); otherwise enrolment answers 503 MAIL_NOT_CONFIGURED.
 */
export type MailMessage = { to: string; subject: string; text: string };

export type Mailer = { send(message: MailMessage): Promise<void> };

export function loadMailer(env: NodeJS.ProcessEnv = process.env): Mailer | null {
  const mode = (env.FORJA_MAIL ?? '').trim();
  if (mode === 'log') {
    if (env.NODE_ENV === 'production') {
      console.error('[forja-device] FORJA_MAIL=log ignored: NODE_ENV=production');
      return null;
    }
    return {
      async send(message) {
        console.log(`[forja-device] (dev mail) to=${message.to} subject=${message.subject}\n${message.text}`);
      },
    };
  }
  if (mode) {
    console.error(`[forja-device] FORJA_MAIL=${mode} is not a known transport`);
  }
  return null;
}
