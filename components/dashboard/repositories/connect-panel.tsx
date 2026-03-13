'use client';

import {
  useActionState,
  useCallback,
  useState,
  useEffect,
  startTransition,
} from 'react';
import {
  fetchUserRepos,
  type FetchReposState,
} from '@/app/dashboard/actions/fetch-user-repos';
import {
  connectRepository,
  connectAllRepositories,
  type ConnectRepoState,
} from '@/app/dashboard/actions/connect-repositories';
import {
  fetchConnectedRepositories,
  disconnectRepository,
  type ConnectedReposState,
  type DisconnectRepoState,
} from '@/app/dashboard/actions/manage-repositories';
import { createSupabaseClientComponentClient } from '@core/lib/supabase/client';
import { createBrowserClient } from '@supabase/ssr';

const initialState: FetchReposState = {};

export function RepositoryConnectPanel() {
  const [state, formAction, isPending] = useActionState(
    fetchUserRepos,
    initialState
  );
  const [connectState, connectAction, isConnecting] = useActionState(
    connectRepository,
    {} as ConnectRepoState
  );
  const [bulkConnectState, bulkConnectAction, isBulkConnecting] =
    useActionState(connectAllRepositories, {} as ConnectRepoState);
  const [connectedState, connectedAction, isLoadingConnected] = useActionState(
    fetchConnectedRepositories,
    {} as ConnectedReposState
  );
  const [disconnectState, disconnectAction, isDisconnecting] = useActionState(
    disconnectRepository,
    {} as DisconnectRepoState
  );
  const [isRedirecting, setIsRedirecting] = useState(false);
  const [oauthError, setOauthError] = useState<string | null>(null);
  const [selectedRepos, setSelectedRepos] = useState<Set<number>>(new Set());
  const [activeTab, setActiveTab] = useState<'connect' | 'manage'>('connect');

  const hasRepos = Array.isArray(state.repos) && state.repos.length > 0;
  const hasConnectedRepos =
    Array.isArray(connectedState.repositories) &&
    connectedState.repositories.length > 0;

  useEffect(() => {
    // Load connected repositories on mount
    startTransition(() => {
      const formData = new FormData();
      connectedAction(formData);
    });
  }, [connectedAction]);

  const handleGitHubConnect = useCallback(async () => {
    setOauthError(null);
    setIsRedirecting(true);

    try {
      // Use a direct Supabase browser client for OAuth to bypass local auth override.
      // Local auth's signInWithOAuth simulates success without actually redirecting.
      const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
      const supabaseKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;

      if (!supabaseUrl || !supabaseKey || supabaseUrl.includes('placeholder')) {
        setOauthError(
          'Supabase is not configured. GitHub OAuth requires a valid Supabase project.'
        );
        setIsRedirecting(false);
        return;
      }

      const supabase = createBrowserClient(supabaseUrl, supabaseKey, {
        auth: {
          persistSession: true,
          autoRefreshToken: true,
          detectSessionInUrl: true,
        },
      });

      const { data, error } = await supabase.auth.signInWithOAuth({
        provider: 'github',
        options: {
          scopes: 'repo',
          redirectTo: `${location.origin}/auth/callback`,
        },
      });

      if (error) {
        setOauthError(`Unable to open GitHub authorization: ${error.message}`);
        setIsRedirecting(false);
        return;
      }

      // signInWithOAuth returns a URL — ensure we redirect
      if (data?.url) {
        window.location.href = data.url;
      }
    } catch (err) {
      setOauthError(
        `Unexpected error starting the GitHub connection: ${err instanceof Error ? err.message : 'Unknown error'}`
      );
      setIsRedirecting(false);
    }
  }, []);

  const handleConnectRepo = useCallback(
    async (repoId: number) => {
      const formData = new FormData();
      formData.append('repoId', repoId.toString());
      connectAction(formData);
    },
    [connectAction]
  );

  const handleConnectAll = useCallback(async () => {
    if (selectedRepos.size === 0) return;

    const formData = new FormData();
    selectedRepos.forEach(repoId => {
      formData.append('repoIds', repoId.toString());
    });
    bulkConnectAction(formData);
  }, [selectedRepos, bulkConnectAction]);

  const handleSelectRepo = useCallback((repoId: number, checked: boolean) => {
    setSelectedRepos(prev => {
      const newSet = new Set(prev);
      if (checked) {
        newSet.add(repoId);
      } else {
        newSet.delete(repoId);
      }
      return newSet;
    });
  }, []);

  const handleSelectAll = useCallback(() => {
    if (!Array.isArray(state.repos)) return;

    const allIds = state.repos
      .map((repo: { id: number }) => repo.id)
      .filter(Boolean);
    setSelectedRepos(new Set(allIds));
  }, [state.repos]);

  const handleDeselectAll = useCallback(() => {
    setSelectedRepos(new Set());
  }, []);

  const handleDisconnectRepo = useCallback(
    async (repoId: string) => {
      const formData = new FormData();
      formData.append('repoId', repoId);
      disconnectAction(formData);
    },
    [disconnectAction]
  );

  return (
    <section className="rounded-3xl border border-neutral-200 bg-white p-8 shadow-lg dark:border-neutral-800 dark:bg-neutral-900">
      <header className="mb-6 space-y-2">
        <h1 className="text-2xl font-semibold text-neutral-900 dark:text-neutral-100">
          GitHub Repository Management
        </h1>
        <p className="text-sm text-neutral-600 dark:text-neutral-300">
          Connect via Supabase OAuth to sync and manage repositories securely.
        </p>
      </header>

      {/* Tab Navigation */}
      <div className="mb-6 flex border-b border-neutral-200 dark:border-neutral-700">
        <button
          onClick={() => setActiveTab('connect')}
          className={`px-4 py-2 text-sm font-medium ${
            activeTab === 'connect'
              ? 'border-b-2 border-primary-600 text-primary-600 dark:text-primary-400'
              : 'text-neutral-600 hover:text-neutral-900 dark:text-neutral-400 dark:hover:text-neutral-100'
          }`}
        >
          Connect Repositories
        </button>
        <button
          onClick={() => setActiveTab('manage')}
          className={`px-4 py-2 text-sm font-medium ${
            activeTab === 'manage'
              ? 'border-b-2 border-primary-600 text-primary-600 dark:text-primary-400'
              : 'text-neutral-600 hover:text-neutral-900 dark:text-neutral-400 dark:hover:text-neutral-100'
          }`}
        >
          Manage Connected ({connectedState.repositories?.length || 0})
        </button>
      </div>

      {activeTab === 'connect' && (
        <>
          <div className="space-y-4">
            <button
              type="button"
              onClick={handleGitHubConnect}
              disabled={isRedirecting}
              className="w-full rounded-xl bg-primary-600 px-4 py-2 text-sm font-semibold text-white transition-colors hover:bg-primary-700 disabled:cursor-not-allowed disabled:opacity-70"
            >
              {isRedirecting
                ? 'Redirecting to GitHub…'
                : 'Connect GitHub via Supabase'}
            </button>

            <form action={formAction} className="space-y-4">
              <button
                type="submit"
                disabled={isPending}
                className="w-full rounded-xl bg-neutral-900 px-4 py-2 text-sm font-semibold text-white transition-colors hover:bg-neutral-800 disabled:cursor-not-allowed disabled:opacity-70 dark:bg-white dark:text-neutral-900 dark:hover:bg-neutral-200"
              >
                {isPending
                  ? 'Fetching repositories…'
                  : 'Fetch GitHub repositories'}
              </button>
            </form>
          </div>

          {state.error ? (
            <p className="mt-4 text-sm text-error-600 dark:text-error-400">
              {state.error}
            </p>
          ) : null}

          {oauthError ? (
            <p className="mt-4 text-sm text-error-600 dark:text-error-400">
              {oauthError}
            </p>
          ) : null}

          {connectState.error ? (
            <p className="mt-4 text-sm text-error-600 dark:text-error-400">
              {connectState.error}
            </p>
          ) : null}

          {bulkConnectState.error ? (
            <p className="mt-4 text-sm text-error-600 dark:text-error-400">
              {bulkConnectState.error}
            </p>
          ) : null}

          {connectState.success ? (
            <p className="mt-4 text-sm text-success-600 dark:text-success-400">
              Repository connected successfully!
            </p>
          ) : null}

          {bulkConnectState.success ? (
            <p className="mt-4 text-sm text-success-600 dark:text-success-400">
              Repositories connected successfully!
            </p>
          ) : null}

          {hasRepos ? (
            <div className="mt-6 space-y-4">
              <div className="flex items-center justify-between">
                <h2 className="text-lg font-semibold text-neutral-900 dark:text-neutral-100">
                  Your Repositories
                </h2>
                <div className="flex gap-2">
                  <button
                    type="button"
                    onClick={handleSelectAll}
                    className="rounded-lg bg-neutral-100 px-3 py-1 text-xs font-medium text-neutral-700 hover:bg-neutral-200 dark:bg-neutral-800 dark:text-neutral-300 dark:hover:bg-neutral-700"
                  >
                    Select All
                  </button>
                  <button
                    type="button"
                    onClick={handleDeselectAll}
                    className="rounded-lg bg-neutral-100 px-3 py-1 text-xs font-medium text-neutral-700 hover:bg-neutral-200 dark:bg-neutral-800 dark:text-neutral-300 dark:hover:bg-neutral-700"
                  >
                    Deselect All
                  </button>
                  {selectedRepos.size > 0 && (
                    <button
                      type="button"
                      onClick={handleConnectAll}
                      disabled={isBulkConnecting}
                      className="rounded-lg bg-primary-600 px-3 py-1 text-xs font-medium text-white hover:bg-primary-700 disabled:cursor-not-allowed disabled:opacity-70"
                    >
                      {isBulkConnecting
                        ? 'Connecting…'
                        : `Connect ${selectedRepos.size} Selected`}
                    </button>
                  )}
                </div>
              </div>

              <ul className="space-y-3">
                {(
                  state.repos as Array<{
                    id?: number;
                    name?: string;
                    html_url?: string;
                    private?: boolean;
                    owner?: { login?: string };
                  }>
                ).map(repo => (
                  <li
                    key={repo.id ?? repo.name}
                    className="flex items-center gap-3 rounded-2xl border border-neutral-200 px-4 py-3 dark:border-neutral-800"
                  >
                    <input
                      type="checkbox"
                      checked={selectedRepos.has(repo.id!)}
                      onChange={e =>
                        handleSelectRepo(repo.id!, e.target.checked)
                      }
                      className="rounded border-neutral-300 text-primary-600 focus:ring-primary-500 dark:border-neutral-600 dark:bg-neutral-700"
                    />
                    <div className="flex-1">
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-semibold text-neutral-900 dark:text-neutral-100">
                          {repo.name ?? 'Unnamed repository'}
                        </span>
                        {repo.private && (
                          <span className="rounded bg-neutral-100 px-1.5 py-0.5 text-xs text-neutral-600 dark:bg-neutral-800 dark:text-neutral-400">
                            Private
                          </span>
                        )}
                      </div>
                      {repo.owner?.login && (
                        <span className="text-xs text-neutral-500 dark:text-neutral-400">
                          {repo.owner.login}
                        </span>
                      )}
                      {repo.html_url ? (
                        <a
                          href={repo.html_url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-xs font-medium text-primary-600 hover:underline dark:text-primary-300"
                        >
                          View on GitHub
                        </a>
                      ) : null}
                    </div>
                    <button
                      type="button"
                      onClick={() => handleConnectRepo(repo.id!)}
                      disabled={isConnecting}
                      className="rounded-lg bg-neutral-900 px-3 py-1 text-xs font-medium text-white hover:bg-neutral-800 disabled:cursor-not-allowed disabled:opacity-70 dark:bg-white dark:text-neutral-900 dark:hover:bg-neutral-200"
                    >
                      {isConnecting ? 'Connecting…' : 'Connect'}
                    </button>
                  </li>
                ))}
              </ul>
            </div>
          ) : null}
        </>
      )}

      {activeTab === 'manage' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold text-neutral-900 dark:text-neutral-100">
              Connected Repositories
            </h2>
            <button
              type="button"
              onClick={() => {
                const formData = new FormData();
                connectedAction(formData);
              }}
              disabled={isLoadingConnected}
              className="rounded-lg bg-neutral-100 px-3 py-1 text-xs font-medium text-neutral-700 hover:bg-neutral-200 dark:bg-neutral-800 dark:text-neutral-300 dark:hover:bg-neutral-700"
            >
              {isLoadingConnected ? 'Loading…' : 'Refresh'}
            </button>
          </div>

          {connectedState.error ? (
            <p className="text-sm text-error-600 dark:text-error-400">
              {connectedState.error}
            </p>
          ) : null}

          {disconnectState.error ? (
            <p className="text-sm text-error-600 dark:text-error-400">
              {disconnectState.error}
            </p>
          ) : null}

          {disconnectState.success ? (
            <p className="text-sm text-success-600 dark:text-success-400">
              Repository disconnected successfully!
            </p>
          ) : null}

          {hasConnectedRepos ? (
            <ul className="space-y-3">
              {connectedState.repositories!.map(repo => (
                <li
                  key={repo.id}
                  className="flex items-center gap-3 rounded-2xl border border-neutral-200 px-4 py-3 dark:border-neutral-800"
                >
                  <div className="flex-1">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-semibold text-neutral-900 dark:text-neutral-100">
                        {repo.name}
                      </span>
                      <span className="rounded bg-green-100 px-1.5 py-0.5 text-xs text-green-700 dark:bg-green-900 dark:text-green-300">
                        Connected
                      </span>
                    </div>
                    <span className="text-xs text-neutral-500 dark:text-neutral-400">
                      {repo.ownerLogin} • {repo.defaultBranch}
                    </span>
                    {typeof repo.metadata?.htmlUrl === 'string' ? (
                      <a
                        href={repo.metadata.htmlUrl}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-xs font-medium text-primary-600 hover:underline dark:text-primary-300"
                      >
                        View on GitHub
                      </a>
                    ) : null}
                  </div>
                  <button
                    type="button"
                    onClick={() => handleDisconnectRepo(repo.id)}
                    disabled={isDisconnecting}
                    className="rounded-lg bg-red-600 px-3 py-1 text-xs font-medium text-white hover:bg-red-700 disabled:cursor-not-allowed disabled:opacity-70"
                  >
                    {isDisconnecting ? 'Disconnecting…' : 'Disconnect'}
                  </button>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-sm text-neutral-600 dark:text-neutral-400">
              No repositories connected yet. Switch to the &quot;Connect
              Repositories&quot; tab to get started.
            </p>
          )}
        </div>
      )}
    </section>
  );
}
