import { Octokit } from '@octokit/rest';
import { getGitHubAccessToken } from './token';

export async function createUserOctokit(userId: string) {
  const token = await getGitHubAccessToken(userId);
  return new Octokit({ auth: token });
}

export async function getOctokit(userId: string): Promise<Octokit | null> {
  try {
    const token = await getGitHubAccessToken(userId);
    if (!token) {
      return null;
    }
    return new Octokit({ auth: token });
  } catch {
    return null;
  }
}
