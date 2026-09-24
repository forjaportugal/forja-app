/**
 * Forja PIN mode: EventSource cannot send an Authorization header, so the
 * streaming URLs carry a 60 s single-purpose ticket instead of the session
 * token (URLs end up in logs). While PIN mode is active a fresh ticket is kept
 * in memory, refreshed every 25 s and when the app becomes visible again.
 * Outside PIN mode the upstream behaviour (session token in the URL) is kept.
 */
import { getStoredAuthToken } from '@/shared/authToken';

const REFRESH_MS = 25_000;

let active = false;
let ticket: string | null = null;
let ticketExpiresAt = 0;

export const refreshSseTicket = async (): Promise<void> => {
  const token = getStoredAuthToken();
  if (!token) return;
  try {
    const response = await fetch('/api/auth/sse-ticket', {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!response.ok) return;
    const payload = (await response.json()) as { ticket?: unknown; expiresIn?: unknown };
    if (typeof payload.ticket === 'string') {
      ticket = payload.ticket;
      ticketExpiresAt = Date.now() + (typeof payload.expiresIn === 'number' ? payload.expiresIn : 60) * 1000;
    }
  } catch {
    // Next interval or visibility change retries.
  }
};

/** Starts ticket upkeep; returns the stop function (used by AuthContext). */
export const startSseTickets = (): (() => void) => {
  active = true;
  void refreshSseTicket();
  const timer = setInterval(() => void refreshSseTicket(), REFRESH_MS);
  const onVisible = () => {
    if (document.visibilityState === 'visible') void refreshSseTicket();
  };
  document.addEventListener('visibilitychange', onVisible);
  return () => {
    active = false;
    ticket = null;
    ticketExpiresAt = 0;
    clearInterval(timer);
    document.removeEventListener('visibilitychange', onVisible);
  };
};

/** Credential for `?token=` on EventSource URLs. Never the session token in PIN mode. */
export const sseQueryToken = (): string | null => {
  if (!active) return getStoredAuthToken();
  return ticket && Date.now() < ticketExpiresAt ? ticket : null;
};
