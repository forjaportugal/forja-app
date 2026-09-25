/**
 * Forja device mode: the gate in front of the whole app.
 *
 * Mounted as the very first Express middleware and wrapped around every
 * HTTP `upgrade` listener, so no CloudCLI route, static file, SSE stream or
 * WebSocket is reached by a tunnel request without a registered device.
 * Only the two enrolment POSTs pass without a device (they still need the
 * edge secret, i.e. must have come through Cloudflare).
 *
 * Direct local calls (no Cloudflare/Forja headers: the Browser MCP bridge on
 * 127.0.0.1) are left to the routes' own session checks, as in PIN mode.
 * Every internet request carries cf-ray / cf-connecting-ip, which Cloudflare
 * always adds and a client cannot remove.
 */
import type { IncomingHttpHeaders, IncomingMessage, Server } from 'node:http';
import type { Duplex } from 'node:stream';

import type { RequestHandler } from 'express';

import type { AccessResult } from '../cf-access.js';

import { CLIENT_CERT_SHA256_HEADER, EDGE_AUTH_HEADER } from './device-verifier.js';

export type GateVerifier = {
  verifyEdge(headers: IncomingHttpHeaders): { ok: true } | { ok: false; reason: string };
  verifySync(headers: IncomingHttpHeaders): AccessResult;
};

const STATUS: Record<string, number> = {
  missing: 401,
  invalid: 401,
  'not-registered': 403,
  revoked: 403,
  'not-allowed': 403,
  misconfigured: 503,
  'keys-unavailable': 503,
};

export function isTunnelRequest(headers: IncomingHttpHeaders): boolean {
  return Boolean(
    headers['cf-ray'] || headers['cf-connecting-ip'] || headers['cf-access-jwt-assertion']
    || headers[EDGE_AUTH_HEADER] || headers[CLIENT_CERT_SHA256_HEADER],
  );
}

function pathOf(url: string | undefined): string {
  const raw = url ?? '/';
  const q = raw.indexOf('?');
  return q === -1 ? raw : raw.slice(0, q);
}

/** null = let through; otherwise the refusal reason. */
export function checkDeviceRequest(
  verifier: GateVerifier,
  enrollPaths: Set<string>,
  req: { method?: string; url?: string; headers: IncomingHttpHeaders },
): string | null {
  if (!isTunnelRequest(req.headers)) return null;
  if (req.method === 'POST' && enrollPaths.has(pathOf(req.url))) {
    const edge = verifier.verifyEdge(req.headers);
    return edge.ok ? null : edge.reason;
  }
  const result = verifier.verifySync(req.headers);
  return result.ok ? null : result.reason;
}

export function createDeviceGate(getVerifier: () => GateVerifier, enrollPaths: Set<string>): RequestHandler {
  return (req, res, next) => {
    const reason = checkDeviceRequest(getVerifier(), enrollPaths, { method: req.method, url: req.originalUrl, headers: req.headers });
    if (!reason) return next();
    res.setHeader('Cache-Control', 'no-store');
    return res.status(STATUS[reason] ?? 401).json({
      error: 'This device is not registered.',
      code: `DEVICE_${reason.toUpperCase().replace('-', '_')}`,
    });
  };
}

/**
 * Refuses WebSocket/upgrade handshakes before ANY `upgrade` listener runs,
 * including listeners added later, by intercepting the event at emit time.
 */
export function installUpgradeGate(server: Server, getVerifier: () => GateVerifier): void {
  const originalEmit = server.emit;
  server.emit = function gatedEmit(this: Server, event: string | symbol, ...args: unknown[]): boolean {
    if (event === 'upgrade') {
      const [req, socket] = args as [IncomingMessage, Duplex];
      const reason = checkDeviceRequest(getVerifier(), new Set(), req);
      if (reason) {
        const status = STATUS[reason] ?? 401;
        const text = status === 403 ? 'Forbidden' : status === 503 ? 'Service Unavailable' : 'Unauthorized';
        socket.end(`HTTP/1.1 ${status} ${text}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n`);
        return true;
      }
    }
    return originalEmit.apply(this, [event, ...args] as Parameters<Server['emit']>);
  } as Server['emit'];
}
