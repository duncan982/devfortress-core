import { prisma } from '@core/lib/prisma';
import { env } from '@core/lib/env';
import { logError, logInfo } from '@core/lib/logger';

type GitHubAccount = {
  id: string;
  userId: string;
  access_token: string | null;
  refresh_token: string | null;
  refresh_token_expires_in: number | null;
  token_type: string | null;
  scope: string | null;
  expires_at: number | null;
};

const GITHUB_REFRESH_ENDPOINT = 'https://github.com/login/oauth/access_token';

const isTokenExpired = (expiresAt?: number | null) => {
  if (!expiresAt) {
    return false;
  }

  const bufferSeconds = 60;
  const nowInSeconds = Math.floor(Date.now() / 1000);
  return nowInSeconds >= expiresAt - bufferSeconds;
};

async function refreshGitHubAccessToken(
  account: GitHubAccount
): Promise<GitHubAccount> {
  if (!account.refresh_token) {
    throw new Error('GitHub refresh token missing');
  }

  const clientId = env.GITHUB_CLIENT_ID;
  const clientSecret = env.GITHUB_CLIENT_SECRET;

  if (!clientId || !clientSecret) {
    throw new Error('GitHub client credentials missing for refresh');
  }

  const response = await fetch(GITHUB_REFRESH_ENDPOINT, {
    method: 'POST',
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({
      client_id: clientId,
      client_secret: clientSecret,
      grant_type: 'refresh_token',
      refresh_token: account.refresh_token,
    }),
  });

  if (!response.ok) {
    const errorBody = await response.text();
    logError('Failed to refresh GitHub access token', {
      status: response.status,
      body: errorBody,
    });
    throw new Error('GitHub token refresh failed');
  }

  const json = (await response.json()) as {
    access_token: string;
    refresh_token?: string;
    expires_in?: number;
    refresh_token_expires_in?: number;
    token_type?: string;
    scope?: string;
  };

  const updatedAccount = await prisma.account.update({
    where: { id: account.id },
    data: {
      access_token: json.access_token,
      refresh_token: json.refresh_token ?? account.refresh_token,
      refresh_token_expires_in:
        json.refresh_token_expires_in ?? account.refresh_token_expires_in,
      expires_at: json.expires_in
        ? Math.floor(Date.now() / 1000) + json.expires_in
        : account.expires_at,
      token_type: json.token_type ?? account.token_type,
      scope: json.scope ?? account.scope,
    },
  });

  logInfo('Refreshed GitHub access token', {
    accountId: account.id,
    userId: account.userId,
  });

  return updatedAccount as GitHubAccount;
}

export async function getGitHubAccessToken(userId: string): Promise<string> {
  const account = (await prisma.account.findFirst({
    where: { userId, provider: 'github' },
  })) as GitHubAccount | null;

  if (!account) {
    throw new Error('GitHub account not connected');
  }

  let effectiveAccount = account;

  if (isTokenExpired(account.expires_at)) {
    effectiveAccount = await refreshGitHubAccessToken(account);
  }

  if (!effectiveAccount.access_token) {
    throw new Error('GitHub access token unavailable');
  }

  return effectiveAccount.access_token;
}
