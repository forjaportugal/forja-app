/**
 * Client for forja-secretd, the root-installed helper that now holds forja-app.service's three
 * most sensitive secrets (forja-edge-secret, gmail-app-password, cloudflare-cert-token) so this
 * app never reads them from a file again (plano/trabalho/system-state-migration.md §7 override 1,
 * human order 2026-09-30 "app secrets out of forja"). See gate-staging/migration/app-secretd/
 * forja-secretd for the daemon and its module docstring for the one documented v1 limitation
 * (the edge secret is fetched once at startup, not verified per request -- dated exception
 * 2026-10-04, DECISIONS.md).
 *
 * Protocol: one JSON object + "\n" per connection, one JSON response + "\n" back, socket then
 * closes. Socket path is FORJA_SECRETD_SOCKET (default /run/forja-secretd.sock), group-readable
 * only by the app's own group -- see forja-secretd.socket.
 */
import { execFileSync } from 'node:child_process';
import { createConnection } from 'node:net';

const DEFAULT_SOCKET = '/run/forja-secretd.sock';
const DEFAULT_EDGE_SECRET_HELPER = '/usr/local/lib/forja/forja-secretd-get-edge-secret';

function socketPath(env: NodeJS.ProcessEnv): string {
  return (env.FORJA_SECRETD_SOCKET ?? '').trim() || DEFAULT_SOCKET;
}

/** True when this app instance is configured to use forja-secretd at all (vs. the older,
 * pre-migration direct-file-read path still supported for a non-device/dev checkout). */
export function secretdEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  return (env.FORJA_SECRETD ?? '').trim() === '1';
}

type SecretdResponse = Record<string, unknown> & { ok: boolean; error?: string };

function callSecretd(env: NodeJS.ProcessEnv, request: Record<string, unknown>, timeoutMs = 15_000): Promise<SecretdResponse> {
  return new Promise((resolve, reject) => {
    const sock = createConnection(socketPath(env));
    let buf = '';
    const timer = setTimeout(() => {
      sock.destroy();
      reject(new Error('forja-secretd timed out'));
    }, timeoutMs);
    sock.on('connect', () => sock.write(`${JSON.stringify(request)}\n`));
    sock.on('data', (chunk) => {
      buf += chunk.toString('utf8');
      const nl = buf.indexOf('\n');
      if (nl === -1) return;
      clearTimeout(timer);
      sock.end();
      try {
        resolve(JSON.parse(buf.slice(0, nl)) as SecretdResponse);
      } catch {
        reject(new Error('forja-secretd: invalid response'));
      }
    });
    sock.on('error', (error) => {
      clearTimeout(timer);
      reject(error);
    });
  });
}

/**
 * Fetched ONCE, synchronously, at process startup (device-verifier.ts's loadDeviceModeConfig).
 * Runs the tiny stdlib-only Python client as a subprocess (same uid as this process, so
 * forja-secretd's SO_PEERCRED check passes the same way it would for a direct socket connection)
 * because Node has no synchronous unix-socket API and this one call happens before the server
 * starts listening, where async would otherwise be free -- kept sync deliberately so this slots
 * into the existing, unchanged, synchronous loadDeviceModeConfig() call site.
 */
export function getEdgeSecretSync(env: NodeJS.ProcessEnv = process.env): string {
  const helper = (env.FORJA_SECRETD_EDGE_HELPER ?? '').trim() || DEFAULT_EDGE_SECRET_HELPER;
  try {
    return execFileSync('python3', [helper], { timeout: 5000, encoding: 'utf8' }).trim();
  } catch (error) {
    console.error('[forja-secretd] get-edge-secret failed:', error instanceof Error ? error.message : String(error));
    return '';
  }
}

/** Forwards the app's own already-rendered subject/text (see mailer.ts's loadSecretdMailer) --
 * forja-secretd does the actual SMTP send with gmail-app-password, which the app never sees. */
export async function sendMailViaSecretd(to: string, subject: string, text: string, env: NodeJS.ProcessEnv = process.env): Promise<void> {
  const resp = await callSecretd(env, { op: 'send-mail', to, subject, text });
  if (!resp.ok) throw new Error(`secretd send-mail failed: ${resp.error ?? 'unknown'}`);
}

export async function certIssueViaSecretd(csrPem: string, env: NodeJS.ProcessEnv = process.env):
  Promise<{ cfCertId: string; certificatePem: string }> {
  const resp = await callSecretd(env, { op: 'cert-issue', csr_pem: csrPem });
  if (!resp.ok || typeof resp.cf_cert_id !== 'string' || typeof resp.certificate_pem !== 'string') {
    throw new Error(`secretd cert-issue failed: ${resp.error ?? 'unknown'}`);
  }
  return { cfCertId: resp.cf_cert_id, certificatePem: resp.certificate_pem };
}

export async function certRevokeViaSecretd(cfCertId: string, env: NodeJS.ProcessEnv = process.env): Promise<void> {
  const resp = await callSecretd(env, { op: 'cert-revoke', cf_cert_id: cfCertId });
  if (!resp.ok) throw new Error(`secretd cert-revoke failed: ${resp.error ?? 'unknown'}`);
}
