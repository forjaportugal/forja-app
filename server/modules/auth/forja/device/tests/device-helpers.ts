import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import type { CertificateSigner } from '../cf-client-certs.js';
import type { MailMessage, Mailer } from '../mailer.js';

export const EDGE_SECRET = 'edge-secret-for-tests-0123456789abcdef';

function tmp() {
  return mkdtempSync(path.join(os.tmpdir(), 'forja-device-test-'));
}

function openssl(args: string[], cwd: string) {
  execFileSync('openssl', args, { cwd, stdio: ['ignore', 'ignore', 'pipe'] });
}

/** A device key + CSR, like the Windows/Android app produces (key stays in the test "device"). */
export function makeCsr(kind: 'ec' | 'rsa2048' | 'rsa1024' = 'ec'): { csr: string; keyPem: string } {
  const dir = tmp();
  try {
    if (kind === 'ec') openssl(['ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', 'k.pem'], dir);
    else openssl(['genrsa', '-out', 'k.pem', kind === 'rsa2048' ? '2048' : '1024'], dir);
    openssl(['req', '-new', '-key', 'k.pem', '-subj', '/CN=forja-device', '-out', 'r.csr'], dir);
    return { csr: readFileSync(path.join(dir, 'r.csr'), 'utf8'), keyPem: readFileSync(path.join(dir, 'k.pem'), 'utf8') };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/** Stand-in for the Cloudflare-managed CA: signs CSRs with a throwaway local CA. */
export function makeFakeSigner(): CertificateSigner & { revoked: string[]; issued: number; swapKey?: boolean } {
  const dir = tmp();
  openssl(['ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', 'ca.key'], dir);
  openssl(['req', '-x509', '-new', '-key', 'ca.key', '-subj', '/CN=test-ca', '-days', '2', '-out', 'ca.pem'], dir);
  let serial = 0;
  const signer = {
    revoked: [] as string[],
    issued: 0,
    swapKey: false,
    async issue(csrPem: string) {
      serial += 1;
      const csr = signer.swapKey ? makeCsr().csr : csrPem;
      writeFileSync(path.join(dir, `r${serial}.csr`), csr);
      openssl(['x509', '-req', '-in', `r${serial}.csr`, '-CA', 'ca.pem', '-CAkey', 'ca.key', '-set_serial', String(serial),
        '-days', '2', '-out', `c${serial}.pem`], dir);
      signer.issued += 1;
      return { cfCertId: `cf-${serial}`, certificatePem: readFileSync(path.join(dir, `c${serial}.pem`), 'utf8') };
    },
    async revoke(id: string) {
      signer.revoked.push(id);
    },
  };
  return signer;
}

export function makeMailbox(): Mailer & { sent: MailMessage[]; lastCode(): string | null } {
  const box = {
    sent: [] as MailMessage[],
    async send(message: MailMessage) {
      box.sent.push(message);
    },
    lastCode() {
      const last = box.sent.at(-1);
      const match = last ? /\b(\d{6})\b/.exec(last.text) : null;
      return match ? match[1] : null;
    },
  };
  return box;
}
