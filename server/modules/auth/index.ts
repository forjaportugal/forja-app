// authRoutes: used by the server entrypoint to mount public authentication endpoints.
export { authRoutes } from './auth.module.js';

// authenticateToken: used by the server entrypoint to protect authenticated API modules.
export { authenticateToken } from './auth.middleware.js';
// authenticateWebSocket: used by WebSocket setup to verify connection tokens.
export { authenticateWebSocket } from './auth.middleware.js';
// validateApiKey: used by the server entrypoint for optional API-wide key validation.
export { validateApiKey } from './auth.middleware.js';
// forjaRouteGate: Forja PIN mode gate for routes upstream mounts without a session (no-op otherwise).
export { forjaRouteGate } from './forja/forja-auth.js';
// forjaDeviceGate / installForjaUpgradeGate: Forja device mode gate in front of the whole app (no-op otherwise).
export { forjaDeviceGate, installForjaUpgradeGate } from './forja/forja-auth.js';
