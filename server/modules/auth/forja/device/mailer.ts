/**
 * Forja device mode: how the one-time enrolment code reaches the person.
 *
 * FORJA_MAIL selects the transport:
 * - `gmail-smtp`: smtp.gmail.com:587, mandatory STARTTLS with a verified
 *   certificate, logged in as FORJA_MAIL_USER (default forjaportugal@gmail.com)
 *   with the Gmail app password in FORJA_MAIL_PASSWORD_FILE (default
 *   /srv/forja/.secrets/gmail-app-password). Missing/unreadable/empty password
 *   file → no mailer → enrolment answers 503 MAIL_NOT_CONFIGURED (fail closed).
 * - `log`: outside production only, prints the message to the server log (for
 *   tests and development).
 * - anything else / unset: no mailer (503 MAIL_NOT_CONFIGURED).
 *
 * The gmail-smtp transport never logs the message body, the code or the
 * password: only success/failure and the recipient's domain.
 */
import { readFileSync } from 'node:fs';

import nodemailer from 'nodemailer';

import { sendMailViaSecretd } from './secretd-client.js';

export type MailMessage = { to: string; subject: string; text: string; html?: string };

export type Mailer = { send(message: MailMessage): Promise<void> };

export const GMAIL_SMTP = { host: 'smtp.gmail.com', port: 587 } as const; // STARTTLS: Hetzner blocks outbound 465
export const DEFAULT_MAIL_USER = 'forjaportugal@gmail.com';
export const DEFAULT_MAIL_PASSWORD_FILE = '/srv/forja/.secrets/gmail-app-password';

export type SmtpConfig = { host: string; port: number; user: string; password: string };
export type SmtpEnvelope = { from: string; to: string; subject: string; text: string; html?: string };
export type SmtpSend = (envelope: SmtpEnvelope) => Promise<unknown>;

export type MailerOptions = {
  readFile?: (path: string) => string;
  createSmtpSend?: (config: SmtpConfig) => SmtpSend;
  log?: (line: string) => void;
  logError?: (line: string) => void;
};

/** nodemailer SMTP options: STARTTLS required, certificate verified, no file/URL access. */
export function smtpTransportOptions(config: SmtpConfig) {
  return {
    host: config.host,
    port: config.port,
    secure: false,
    requireTLS: true, // STARTTLS mandatory; never falls back to plaintext
    auth: { user: config.user, pass: config.password },
    tls: { rejectUnauthorized: true, servername: config.host, minVersion: 'TLSv1.2' as const },
    connectionTimeout: 15_000,
    greetingTimeout: 10_000,
    socketTimeout: 20_000,
    disableFileAccess: true,
    disableUrlAccess: true,
    logger: false,
    debug: false,
  };
}

function nodemailerSmtpSend(config: SmtpConfig): SmtpSend {
  const transport = nodemailer.createTransport(smtpTransportOptions(config));
  return (envelope) => transport.sendMail(envelope);
}

function domainOf(address: string): string {
  const at = address.lastIndexOf('@');
  return at >= 0 ? address.slice(at + 1).toLowerCase() : '?';
}

/** Only fixed, secret-free fields of a transport error (never its message text). */
function describeError(error: unknown): string {
  const e = (error ?? {}) as { code?: unknown; responseCode?: unknown; command?: unknown };
  const code = typeof e.code === 'string' && /^[A-Z_]{1,32}$/.test(e.code) ? e.code : 'UNKNOWN';
  const responseCode = typeof e.responseCode === 'number' ? ` smtp=${e.responseCode}` : '';
  const command = typeof e.command === 'string' && /^[A-Z ]{1,16}$/.test(e.command) ? ` command=${e.command}` : '';
  return `code=${code}${responseCode}${command}`;
}

function loadGmailSmtp(env: NodeJS.ProcessEnv, options: MailerOptions): Mailer | null {
  const logError = options.logError ?? ((line: string) => console.error(line));
  const log = options.log ?? ((line: string) => console.log(line));
  const user = (env.FORJA_MAIL_USER ?? '').trim() || DEFAULT_MAIL_USER;
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(user)) {
    logError('[forja-device] FORJA_MAIL=gmail-smtp: FORJA_MAIL_USER is not an email address; mail disabled');
    return null;
  }
  const passwordFile = (env.FORJA_MAIL_PASSWORD_FILE ?? '').trim() || DEFAULT_MAIL_PASSWORD_FILE;
  let password: string;
  try {
    password = (options.readFile ?? ((path: string) => readFileSync(path, 'utf8')))(passwordFile).replace(/\s+/g, '');
  } catch (error) {
    const reason = (error as { code?: unknown })?.code;
    logError(
      `[forja-device] FORJA_MAIL=gmail-smtp: cannot read the app password file ${passwordFile} `
      + `(${typeof reason === 'string' ? reason : 'read error'}); mail disabled, enrolment answers 503`,
    );
    return null;
  }
  if (!password) {
    logError(`[forja-device] FORJA_MAIL=gmail-smtp: app password file ${passwordFile} is empty; mail disabled, enrolment answers 503`);
    return null;
  }

  const send = (options.createSmtpSend ?? nodemailerSmtpSend)({ ...GMAIL_SMTP, user, password });
  const from = `"Forja" <${user}>`;
  log(`[forja-device] mail transport gmail-smtp ready (${GMAIL_SMTP.host}:${GMAIL_SMTP.port}, user domain=${domainOf(user)})`);
  return {
    async send(message) {
      const domain = domainOf(message.to);
      try {
        await send({ from, to: message.to, subject: message.subject, text: message.text, ...(message.html ? { html: message.html } : {}) });
      } catch (error) {
        const detail = describeError(error);
        logError(`[forja-device] mail via gmail-smtp FAILED to domain=${domain} ${detail}`);
        throw new Error(`gmail-smtp send failed (${detail})`);
      }
      log(`[forja-device] mail via gmail-smtp sent to domain=${domain}`);
    },
  };
}

/** forja-secretd (system-state-migration.md §7 override 1, 2026-09-30): the daemon holds
 * gmail-app-password and does the SMTP send itself -- this app process never reads it, on disk or
 * in memory, at any point. Only the already-rendered subject/text (from buildEnrollmentCodeMail
 * or the fixed "slot taken" message below) crosses the socket. */
function loadSecretdMailer(options: MailerOptions): Mailer {
  const log = options.log ?? ((line: string) => console.log(line));
  log('[forja-device] mail transport forja-secretd ready');
  return {
    async send(message) {
      const domain = domainOf(message.to);
      try {
        await sendMailViaSecretd(message.to, message.subject, message.text);
      } catch (error) {
        const logError = options.logError ?? ((line: string) => console.error(line));
        logError(`[forja-device] mail via forja-secretd FAILED to domain=${domain}: ${error instanceof Error ? error.message : String(error)}`);
        throw error;
      }
      log(`[forja-device] mail via forja-secretd sent to domain=${domain}`);
    },
  };
}

export function loadMailer(env: NodeJS.ProcessEnv = process.env, options: MailerOptions = {}): Mailer | null {
  const mode = (env.FORJA_MAIL ?? '').trim();
  if (mode === 'secretd') return loadSecretdMailer(options);
  if (mode === 'gmail-smtp') return loadGmailSmtp(env, options);
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

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c] as string);
}

/** The enrolment-code email, in European Portuguese (plain text + simple HTML). */
export function buildEnrollmentCodeMail(input: { to: string; code: string; deviceLabel: string; deviceName: string }): MailMessage {
  const { to, code, deviceLabel, deviceName } = input;
  const text = 'Olá,\n\n'
    + `Foi pedido o registo de um ${deviceLabel} ("${deviceName}") na Forja. O teu código é:\n\n`
    + `    ${code}\n\n`
    + 'O código é válido durante 10 minutos.\n\n'
    + 'Se não foste tu, ignora este email e avisa o Maestro.\n';
  const html = '<!doctype html><html lang="pt-PT"><body style="font-family:sans-serif;line-height:1.5">'
    + '<p>Olá,</p>'
    + `<p>Foi pedido o registo de um ${escapeHtml(deviceLabel)} (&quot;${escapeHtml(deviceName)}&quot;) na Forja. O teu código é:</p>`
    + `<p style="font-size:28px;font-weight:bold;letter-spacing:4px">${escapeHtml(code)}</p>`
    + '<p>O código é válido durante 10 minutos.</p>'
    + '<p><strong>Se não foste tu, ignora este email e avisa o Maestro.</strong></p>'
    + '</body></html>';
  return { to, subject: `Código Forja: ${code}`, text, html };
}
