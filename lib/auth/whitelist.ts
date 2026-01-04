/**
 * Development Whitelist - REMOVE BEFORE PUBLIC LAUNCH
 * Only whitelisted users can access the application during development
 */

export const DEVELOPMENT_MODE =
  process.env.NEXT_PUBLIC_DEVELOPMENT_MODE === 'true';

// Whitelist your email addresses (GitHub OAuth)
export const WHITELISTED_EMAILS = [
  'ndegwaduncan193@gmail.com', // Replace with your actual email
  // Add additional emails if needed
];

// Whitelist your GitHub username (GitHub OAuth - primary authentication method)
export const WHITELISTED_GITHUB_USERS = [
  'duncan982', // Your GitHub username
  // Add additional GitHub usernames if needed
];

/**
 * Check if user is whitelisted
 */
export function isWhitelisted(
  email?: string | null,
  githubUsername?: string | null
): boolean {
  // In production with public access, allow all
  if (!DEVELOPMENT_MODE) {
    return true;
  }

  // Check email whitelist
  if (email && WHITELISTED_EMAILS.includes(email.toLowerCase())) {
    return true;
  }

  // Check GitHub username whitelist
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
