/**
 * Forja device mode: gmail-smtp mail transport (mocked SMTP, no network).
 */
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { deviceRepository } from '../device.repository.js';
import { createEnrollmentService } from '../enrollment.service.js';
import {
  buildEnrollmentCodeMail,
  DEFAULT_MAIL_PASSWORD_FILE,
  DEFAULT_MAIL_USER,
  GMAIL_SMTP,
  loadMailer,
  smtpTransportOptions,
  type SmtpConfig,
  type SmtpEnvelope,
} from '../mailer.js';
import { ALICE, withTempDatabase } from '../../tests/helpers.js';

import { makeCsr, makeFakeSigner } from './device-helpers.js';

const PASSWORD = 'abcd efgh ijkl mnop';
const PASSWORD_NO_SPACES = 'abcdefghijklmnop';

function harness(options: { readFile?: (p: string) => string; fail?: Error } = {}) {
  const logs: string[] = [];
  const configs: SmtpConfig[] = [];
  const sent: SmtpEnvelope[] = [];
  const readPaths: string[] = [];
  const mailerOptions = {
    readFile: options.readFile ?? ((p: string) => { readPaths.push(p); return `  ${PASSWORD}\n`; }),
    createSmtpSend: (config: SmtpConfig) => {
      configs.push(config);
      return async (envelope: SmtpEnvelope) => {
        if (options.fail) throw options.fail;
        sent.push(envelope);
        return { messageId: 'x' };
      };
    },
    log: (line: string) => logs.push(line),
    logError: (line: string) => logs.push(line),
  };
  return { logs, configs, sent, readPaths, mailerOptions };
}

test('gmail-smtp: smtp.gmail.com:587, default user and password file, password trimmed and de-spaced', async () => {
  const h = harness();
  const mailer = loadMailer({ FORJA_MAIL: 'gmail-smtp' }, h.mailerOptions);
  assert.ok(mailer);
  assert.deepEqual(h.readPaths, [DEFAULT_MAIL_PASSWORD_FILE]);
  assert.deepEqual(h.configs, [{ host: 'smtp.gmail.com', port: 587, user: DEFAULT_MAIL_USER, password: PASSWORD_NO_SPACES }]);
  assert.equal(DEFAULT_MAIL_USER, 'forjaportugal@gmail.com');
  assert.equal(DEFAULT_MAIL_PASSWORD_FILE, '/srv/forja/.secrets/gmail-app-password');

  await mailer.send(buildEnrollmentCodeMail({ to: ALICE, code: '123456', deviceLabel: 'telemóvel', deviceName: 'Pixel' }));
  assert.equal(h.sent.length, 1);
  assert.equal(h.sent[0].to, ALICE);
  assert.equal(h.sent[0].from, '"Forja" <forjaportugal@gmail.com>');
  assert.equal(h.sent[0].subject, 'Código Forja: 123456');
  assert.ok(h.sent[0].html);
});

test('gmail-smtp: FORJA_MAIL_USER and FORJA_MAIL_PASSWORD_FILE override the defaults', () => {
  const h = harness();
  loadMailer({ FORJA_MAIL: 'gmail-smtp', FORJA_MAIL_USER: 'other@gmail.com', FORJA_MAIL_PASSWORD_FILE: '/x/pw' }, h.mailerOptions);
  assert.deepEqual(h.readPaths, ['/x/pw']);
  assert.equal(h.configs[0].user, 'other@gmail.com');
});

test('gmail-smtp: nodemailer options require STARTTLS with a verified certificate', () => {
  const options = smtpTransportOptions({ ...GMAIL_SMTP, user: 'u@gmail.com', password: 'p' });
  assert.equal(options.host, 'smtp.gmail.com');
  assert.equal(options.port, 587);
  assert.equal(options.secure, false);
  assert.equal(options.requireTLS, true);
  assert.equal(options.tls.rejectUnauthorized, true);
  assert.equal(options.tls.servername, 'smtp.gmail.com');
  assert.equal(options.logger, false);
  assert.equal(options.debug, false);
});

test('code email: European Portuguese, code in subject, 10 minutes, device type, warning; HTML escapes the name', () => {
  const mail = buildEnrollmentCodeMail({ to: ALICE, code: '042917', deviceLabel: 'computador', deviceName: '<b>PC & "casa"</b>' });
  assert.equal(mail.subject, 'Código Forja: 042917');
  for (const body of [mail.text, mail.html ?? '']) {
    assert.match(body, /042917/);
    assert.match(body, /válido durante 10 minutos/);
    assert.match(body, /computador/);
    assert.match(body, /Se não foste tu, ignora este email e avisa/);
  }
  assert.match(mail.text, /<b>PC & "casa"<\/b>/);
  assert.ok(!mail.html?.includes('<b>PC'));
  assert.match(mail.html ?? '', /&lt;b&gt;PC &amp; &quot;casa&quot;&lt;\/b&gt;/);
});

test('gmail-smtp logs never contain the code or the password (success and failure)', async () => {
  const ok = harness();
  const mailer = loadMailer({ FORJA_MAIL: 'gmail-smtp' }, ok.mailerOptions);
  assert.ok(mailer);
  await mailer.send(buildEnrollmentCodeMail({ to: ALICE, code: '918273', deviceLabel: 'computador', deviceName: 'PC' }));
  assert.ok(ok.logs.some((line) => /sent to domain=example\.com/.test(line)));

  const failure = Object.assign(new Error(`Invalid login for ${PASSWORD_NO_SPACES} code 918273`), {
    code: 'EAUTH', responseCode: 535, command: 'AUTH PLAIN', response: `535 ${PASSWORD_NO_SPACES} 918273`,
  });
  const bad = harness({ fail: failure });
  const badMailer = loadMailer({ FORJA_MAIL: 'gmail-smtp' }, bad.mailerOptions);
  assert.ok(badMailer);
  const thrown = await badMailer.send(buildEnrollmentCodeMail({ to: ALICE, code: '918273', deviceLabel: 'computador', deviceName: 'PC' }))
    .then(() => null, (error: Error) => error);
  assert.ok(thrown);
  assert.ok(bad.logs.some((line) => /FAILED to domain=example\.com code=EAUTH smtp=535/.test(line)));

  for (const text of [...ok.logs, ...bad.logs, thrown.message]) {
    assert.ok(!text.includes('918273'), `code leaked: ${text}`);
    assert.ok(!text.includes(PASSWORD_NO_SPACES) && !text.includes(PASSWORD), `password leaked: ${text}`);
    assert.ok(!text.includes(ALICE), `full recipient leaked: ${text}`);
  }
});

test('gmail-smtp: missing, unreadable or empty password file → no mailer, clear log line', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'forja-mail-'));
  try {
    const missing = harness({ readFile: undefined });
    const logs: string[] = [];
    const mailer = loadMailer(
      { FORJA_MAIL: 'gmail-smtp', FORJA_MAIL_PASSWORD_FILE: path.join(dir, 'nope') },
      { createSmtpSend: missing.mailerOptions.createSmtpSend, log: (l) => logs.push(l), logError: (l) => logs.push(l) },
    );
    assert.equal(mailer, null);
    assert.equal(missing.configs.length, 0);
    assert.ok(logs.some((line) => /cannot read the app password file .*nope \(ENOENT\).*503/.test(line)), logs.join('\n'));

    const emptyFile = path.join(dir, 'empty');
    writeFileSync(emptyFile, '  \n');
    const emptyLogs: string[] = [];
    assert.equal(loadMailer(
      { FORJA_MAIL: 'gmail-smtp', FORJA_MAIL_PASSWORD_FILE: emptyFile },
      { createSmtpSend: missing.mailerOptions.createSmtpSend, logError: (l) => emptyLogs.push(l) },
    ), null);
    assert.ok(emptyLogs.some((line) => /is empty.*503/.test(line)));

    const realFile = path.join(dir, 'pw');
    writeFileSync(realFile, `${PASSWORD}\n`);
    const real = harness({ readFile: undefined });
    assert.ok(loadMailer({ FORJA_MAIL: 'gmail-smtp', FORJA_MAIL_PASSWORD_FILE: realFile }, { ...real.mailerOptions, readFile: undefined }));
    assert.equal(real.configs[0].password, PASSWORD_NO_SPACES);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('enrolment with gmail-smtp: missing password file → 503 MAIL_NOT_CONFIGURED; SMTP failure → 503 MAIL_FAILED without leaking the code', async () => {
  await withTempDatabase(async () => {
    const service = (mailer: ReturnType<typeof loadMailer>, log: (line: string) => void = () => undefined) => createEnrollmentService({
      repo: deviceRepository, allowedEmails: [ALICE], mailer, signer: makeFakeSigner(), secret: 'test-secret', log,
    });
    const body = () => ({ email: ALICE, platform: 'phone', name: 'Pixel', csr: makeCsr().csr });

    const unconfigured = loadMailer(
      { FORJA_MAIL: 'gmail-smtp', FORJA_MAIL_PASSWORD_FILE: '/nonexistent/forja/gmail-app-password' },
      { logError: () => undefined },
    );
    await assert.rejects(service(unconfigured).start(body(), '203.0.113.9'), { code: 'MAIL_NOT_CONFIGURED', statusCode: 503 });

    const ok = harness();
    await service(loadMailer({ FORJA_MAIL: 'gmail-smtp' }, ok.mailerOptions)).start(body(), '203.0.113.10');
    assert.equal(ok.sent.length, 1);
    const code = /^Código Forja: (\d{6})$/.exec(ok.sent[0].subject)?.[1];
    assert.ok(code);
    assert.match(ok.sent[0].text, /telemóvel \("Pixel"\)/);

    const bad = harness({ fail: Object.assign(new Error('boom'), { code: 'ECONNECTION' }) });
    const serviceLogs: string[] = [];
    await assert.rejects(
      service(loadMailer({ FORJA_MAIL: 'gmail-smtp' }, bad.mailerOptions), (l) => serviceLogs.push(l)).start(body(), '203.0.113.11'),
      { code: 'MAIL_FAILED', statusCode: 503 },
    );
    assert.ok(serviceLogs.some((line) => /enroll mail failed: gmail-smtp send failed \(code=ECONNECTION\)/.test(line)), serviceLogs.join('\n'));
    for (const line of [...serviceLogs, ...bad.logs]) assert.ok(!line.includes(PASSWORD_NO_SPACES));
  });
});
