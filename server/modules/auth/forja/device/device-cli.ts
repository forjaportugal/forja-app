/**
 * Forja device admin (run on the server as `forja`, with the app's env):
 *
 *   DATABASE_PATH=/srv/forja/data/app/auth.db node dist-server/server/modules/auth/forja/device/device-cli.js list
 *   ... device-cli.js revoke <deviceId>
 *
 * `revoke` marks the device revoked here (refused at the origin immediately)
 * and revokes its client certificate at Cloudflare when the signer is configured.
 */
import { initializeDatabase, closeConnection } from '@/modules/database/index.js';

import { loadCloudflareSigner } from './cf-client-certs.js';
import { deviceRepository } from './device.repository.js';
import { createEnrollmentService } from './enrollment.service.js';

async function main(argv: string[]): Promise<number> {
  const [command, id] = argv;
  await initializeDatabase();
  try {
    if (command === 'list') {
      for (const d of deviceRepository.list()) {
        const seen = d.last_seen_at ? new Date(d.last_seen_at).toISOString() : '-';
        console.log([d.id, d.status, d.email, d.platform, d.name, `seen=${seen}`, `sha256=${d.cert_sha256.slice(0, 16)}…`].join('\t'));
      }
      return 0;
    }
    if (command === 'revoke' && id) {
      const service = createEnrollmentService({
        repo: deviceRepository,
        allowedEmails: [],
        mailer: null,
        signer: loadCloudflareSigner(),
        secret: 'unused',
      });
      console.log(JSON.stringify(await service.revoke(id)));
      return 0;
    }
    console.error('usage: device-cli list | revoke <deviceId>');
    return 2;
  } finally {
    closeConnection();
  }
}

main(process.argv.slice(2)).then(
  (code) => process.exit(code),
  (error: unknown) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exit(1);
  },
);
