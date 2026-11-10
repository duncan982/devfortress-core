/**
 * DevFortress SDK — Version Source
 *
 * Derived from package.json — the single source of truth for the published SDK version.
 * Kept as its own module (rather than sourced from index.ts) so internal modules
 * (devfortress.ts, telemetry.ts, license-manager.ts, client.ts) can import it without
 * creating a circular import back through index.ts, which re-exports all of them.
 */
export const SDK_VERSION: string = require('../package.json').version;
