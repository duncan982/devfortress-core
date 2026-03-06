/**
 * Development Whitelist — DEPRECATED / DEAD CODE
 *
 * This module is NOT imported anywhere in the application.
 * The `DEVELOPMENT_MODE` flag defaults to false, so even if this were
 * imported, `isWhitelisted()` would return true for everyone.
 *
 * Login restrictions are NOT enforced. All users can sign up and log in.
 *
 * Kept for reference only — can be safely deleted when convenient.
 */

export const DEVELOPMENT_MODE =
  process.env.NEXT_PUBLIC_DEVELOPMENT_MODE === 'true';

// Whitelist your email addresses (GitHub OAuth)
export const WHITELISTED_EMAILS = [
  'ndegwaduncan193@gmail.com',
];

// Whitelist your GitHub username (GitHub OAuth)
export const WHITELISTED_GITHUB_USERS = [
  'duncan982',
];

/**
 * Check if user is whitelisted.
 * Returns true for ALL users when DEVELOPMENT_MODE is false (default).
 */
export function isWhitelisted(
  email?: string | null,
  githubUsername?: string | null
): boolean {
  // In production (default), allow all users
  if (!DEVELOPMENT_MODE) {
    return true;
  }

  if (email && WHITELISTED_EMAILS.includes(email.toLowerCase())) {
    return true;
  }

  if (
    githubUsername &&
    WHITELISTED_GITHUB_USERS.includes(githubUsername.toLowerCase())
  ) {
    return true;
  }

  return false;
}

/**
 * Get unauthorized message
 */
export function getUnauthorizedMessage(): string {
  return DEVELOPMENT_MODE
    ? 'This application is currently in private development. Access is restricted to authorized users only.'
    : 'Unauthorized access';
}
