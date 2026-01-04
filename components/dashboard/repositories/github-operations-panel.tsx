'use client';

import { useActionState, useCallback, useState, useEffect, startTransition } from 'react';
import {
  checkRepositoryStatus,
  createBranch,
  type RepoStatusState,
  type CreateBranchState,
} from '@/app/dashboard/actions/github-operations';
import {
  fetchConnectedRepositories,
  type ConnectedReposState,
} from '@/app/dashboard/actions/manage-repositories';

export function GitHubOperationsPanel() {
  const [statusState, statusAction, isCheckingStatus] = useActionState(
    checkRepositoryStatus,
    {} as RepoStatusState
  );
  const [branchState, branchAction, isCreatingBranch] = useActionState(
    createBranch,
    {} as CreateBranchState
  );
  const [connectedState, connectedAction] = useActionState(
    fetchConnectedRepositories,
    {} as ConnectedReposState
  );
  const [selectedRepo, setSelectedRepo] = useState<string>('');
  const [branchName, setBranchName] = useState<string>('');
  const [sourceBranch, setSourceBranch] = useState<string>('main');

  useEffect(() => {
    // Load connected repositories
    startTransition(() => {
      const formData = new FormData();
      connectedAction(formData);
    });
  }, [connectedAction]);

  const handleCheckStatus = useCallback(() => {
    const formData = new FormData();
    statusAction(formData);
  }, [statusAction]);

  const handleCreateBranch = useCallback(() => {
    if (!selectedRepo || !branchName.trim()) return;

    const formData = new FormData();
    formData.append('repoId', selectedRepo);
    formData.append('branchName', branchName.trim());
    formData.append('sourceBranch', sourceBranch);
    branchAction(formData);
  }, [selectedRepo, branchName, sourceBranch, branchAction]);

  return (
    <section className="rounded-3xl border border-neutral-200 bg-white p-8 shadow-lg dark:border-neutral-800 dark:bg-neutral-900">
      <header className="mb-6 space-y-2">
        <h1 className="text-2xl font-semibold text-neutral-900 dark:text-neutral-100">
          Advanced GitHub Operations
        </h1>
        <p className="text-sm text-neutral-600 dark:text-neutral-300">
          Monitor repository health, create branches, and manage GitHub
          integrations.
        </p>
      </header>

      <div className="space-y-8">
        {/* Repository Status Check */}
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold text-neutral-900 dark:text-neutral-100">
              Repository Health Check
            </h2>
            <button
              type="button"
              onClick={handleCheckStatus}
              disabled={isCheckingStatus}
              className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700 disabled:cursor-not-allowed disabled:opacity-70"
            >
              {isCheckingStatus ? 'Checking…' : 'Check Status'}
            </button>
          </div>

          {statusState.error && (
            <p className="text-sm text-error-600 dark:text-error-400">
              {statusState.error}
            </p>
          )}

          {Array.isArray(statusState.repositories) &&
            statusState.repositories.length > 0 && (
              <div className="space-y-3">
                <h3 className="text-sm font-medium text-neutral-700 dark:text-neutral-300">
                  Status Results:
                </h3>
                <ul className="space-y-2">
                  {statusState.repositories.map(repo => (
                    <li
                      key={repo.id}
                      className="flex items-center gap-3 rounded-lg border border-neutral-200 px-4 py-3 dark:border-neutral-700"
                    >
                      <div
                        className={`w-3 h-3 rounded-full ${repo.isAccessible ? 'bg-green-500' : 'bg-red-500'}`}
                      />
                      <div className="flex-1">
                        <span className="text-sm font-medium text-neutral-900 dark:text-neutral-100">
                          {repo.name}
                        </span>
                        <span className="ml-2 text-xs text-neutral-500 dark:text-neutral-400">
                          {repo.ownerLogin}
                        </span>
                        {!repo.isAccessible && repo.error && (
                          <span className="ml-2 text-xs text-red-600 dark:text-red-400">
                            {repo.error}
                          </span>
                        )}
                      </div>
                      <span className="text-xs text-neutral-500 dark:text-neutral-400">
                        {new Date(repo.lastChecked).toLocaleTimeString()}
                      </span>
                    </li>
                  ))}
                </ul>
              </div>
            )}
        </div>

        {/* Branch Creation */}
        <div className="space-y-4">
          <h2 className="text-lg font-semibold text-neutral-900 dark:text-neutral-100">
            Create Branch
          </h2>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div>
              <label className="block text-sm font-medium text-neutral-700 dark:text-neutral-300 mb-1">
                Repository
              </label>
              <select
                value={selectedRepo}
                onChange={e => setSelectedRepo(e.target.value)}
                className="w-full rounded-lg border border-neutral-300 px-3 py-2 text-sm dark:border-neutral-600 dark:bg-neutral-800 dark:text-neutral-100"
              >
                <option value="">Select repository</option>
                {connectedState.repositories?.map(repo => (
                  <option key={repo.id} value={repo.id}>
                    {repo.name} ({repo.ownerLogin})
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="block text-sm font-medium text-neutral-700 dark:text-neutral-300 mb-1">
                Branch Name
              </label>
              <input
                type="text"
                value={branchName}
                onChange={e => setBranchName(e.target.value)}
                placeholder="feature/new-api"
                className="w-full rounded-lg border border-neutral-300 px-3 py-2 text-sm dark:border-neutral-600 dark:bg-neutral-800 dark:text-neutral-100"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-neutral-700 dark:text-neutral-300 mb-1">
                Source Branch
              </label>
              <input
                type="text"
                value={sourceBranch}
                onChange={e => setSourceBranch(e.target.value)}
                placeholder="main"
                className="w-full rounded-lg border border-neutral-300 px-3 py-2 text-sm dark:border-neutral-600 dark:bg-neutral-800 dark:text-neutral-100"
              />
            </div>
          </div>

          <button
            type="button"
            onClick={handleCreateBranch}
            disabled={isCreatingBranch || !selectedRepo || !branchName.trim()}
            className="rounded-lg bg-green-600 px-4 py-2 text-sm font-medium text-white hover:bg-green-700 disabled:cursor-not-allowed disabled:opacity-70"
          >
            {isCreatingBranch ? 'Creating…' : 'Create Branch'}
          </button>

          {branchState.error && (
            <p className="text-sm text-error-600 dark:text-error-400">
              {branchState.error}
            </p>
          )}

          {branchState.success && branchState.branch && (
            <div className="rounded-lg bg-green-50 border border-green-200 p-4 dark:bg-green-900 dark:border-green-700">
              <p className="text-sm text-green-800 dark:text-green-200">
                Branch created successfully!
              </p>
              <p className="text-sm text-green-700 dark:text-green-300 mt-1">
                <a
                  href={branchState.branch.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="underline hover:no-underline"
                >
                  {branchState.branch.name}
                </a>
                (SHA: {branchState.branch.sha.slice(0, 7)})
              </p>
            </div>
          )}
        </div>

        {/* Future Operations Placeholder */}
        <div className="space-y-4">
          <h2 className="text-lg font-semibold text-neutral-900 dark:text-neutral-100">
            Planned Operations
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="rounded-lg border border-neutral-200 p-4 dark:border-neutral-700">
              <h3 className="font-medium text-neutral-900 dark:text-neutral-100 mb-2">
                Pull Request Management
              </h3>
              <p className="text-sm text-neutral-600 dark:text-neutral-400">
                Create PRs for pushed API code, manage reviews and merges.
              </p>
            </div>
            <div className="rounded-lg border border-neutral-200 p-4 dark:border-neutral-700">
              <h3 className="font-medium text-neutral-900 dark:text-neutral-100 mb-2">
                Webhook Integration
              </h3>
              <p className="text-sm text-neutral-600 dark:text-neutral-400">
                Set up webhooks for repository events and CI/CD integration.
              </p>
            </div>
            <div className="rounded-lg border border-neutral-200 p-4 dark:border-neutral-700">
              <h3 className="font-medium text-neutral-900 dark:text-neutral-100 mb-2">
                Issue Tracking
              </h3>
              <p className="text-sm text-neutral-600 dark:text-neutral-400">
                Create issues for deployment failures and security alerts.
              </p>
            </div>
            <div className="rounded-lg border border-neutral-200 p-4 dark:border-neutral-700">
              <h3 className="font-medium text-neutral-900 dark:text-neutral-100 mb-2">
                Release Management
              </h3>
              <p className="text-sm text-neutral-600 dark:text-neutral-400">
                Create GitHub releases for deployed API versions.
              </p>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
