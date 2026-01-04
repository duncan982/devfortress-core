/**
 * Teams Dashboard Component
 * Displays user's teams with create and manage functionality
 */

'use client';

import { useState, useEffect, useCallback } from 'react';
import Link from 'next/link';
import Image from 'next/image';
import { logError } from '@core/lib/logger/client';

interface Team {
  id: string;
  name: string;
  slug: string;
  members: {
    id: string;
    role: string;
    user: {
      id: string;
      name: string | null;
      email: string | null;
      image: string | null;
    };
  }[];
  _count?: {
    members: number;
  };
  createdAt: string;
}

interface CreateTeamModalProps {
  isOpen: boolean;
  onClose: () => void;
  onCreated: (team: Team) => void;
}

function CreateTeamModal({ isOpen, onClose, onCreated }: CreateTeamModalProps) {
  const [name, setName] = useState('');
  const [slug, setSlug] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState('');

  const handleSlugChange = (value: string) => {
    // OWASP A01: Broken Access Control - Input validation for slug
    const sanitized = value.toLowerCase().replace(/[^a-z0-9-]/g, '');
    setSlug(sanitized);
    if (sanitized !== value) {
      setError('Slug contains invalid characters. Only lowercase letters, numbers, and hyphens are allowed.');
    } else {
      setError('');
    }
  };

  const handleNameChange = (value: string) => {
    setName(value);
    if (!slug || slug === value.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '')) {
      setSlug(value.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, ''));
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setIsSubmitting(true);

    try {
      const response = await fetch('/api/teams', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, slug }),
      });

      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.error || 'Failed to create team');
      }

      const team = await response.json();
      onCreated(team);
      setName('');
      setSlug('');
      onClose();
    } catch (err) {
      const errorMessage =
        err instanceof Error ? err.message : 'Failed to create team';
      setError(errorMessage);
      logError('Failed to create team', { error: err });
    } finally {
      setIsSubmitting(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
      <div className="w-full max-w-md rounded-2xl bg-white p-6 shadow-xl dark:bg-neutral-900">
        <h2 className="text-xl font-semibold text-neutral-900 dark:text-white mb-4">
          Create New Team
        </h2>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label
              htmlFor="team-name"
              className="block text-sm font-medium text-neutral-700 dark:text-neutral-300 mb-1"
            >
              Team Name
            </label>
            <input
              id="team-name"
              type="text"
              value={name}
              onChange={e => handleNameChange(e.target.value)}
              placeholder="My Awesome Team"
              className="w-full rounded-lg border border-neutral-300 px-3 py-2 text-sm dark:border-neutral-600 dark:bg-neutral-800 dark:text-neutral-100"
              required
            />
          </div>

          <div>
            <label
              htmlFor="team-slug"
              className="block text-sm font-medium text-neutral-700 dark:text-neutral-300 mb-1"
            >
              Team URL Slug
            </label>
            <div className="flex items-center">
              <span className="text-sm text-neutral-500 dark:text-neutral-400 mr-1">
                /teams/
              </span>
              <input
                id="team-slug"
                type="text"
                value={slug}
                onChange={e => handleSlugChange(e.target.value)}
                placeholder="my-team"
                pattern="^[a-z0-9-]+$"
                className="flex-1 rounded-lg border border-neutral-300 px-3 py-2 text-sm dark:border-neutral-600 dark:bg-neutral-800 dark:text-neutral-100"
                required
              />
            </div>
            <p className="mt-1 text-xs text-neutral-500 dark:text-neutral-400">
              Only lowercase letters, numbers, and hyphens
            </p>
          </div>

          {error && (
            <div className="rounded-lg bg-error-50 p-3 text-sm text-error-700 dark:bg-error-900/20 dark:text-error-400">
              {error}
            </div>
          )}

          <div className="flex gap-3 justify-end pt-4">
            <button
              type="button"
              onClick={onClose}
              className="rounded-lg border border-neutral-200 px-4 py-2 text-sm font-medium text-neutral-700 hover:bg-neutral-50 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isSubmitting || !name || !slug}
              className="rounded-lg bg-primary-600 px-4 py-2 text-sm font-semibold text-white hover:bg-primary-700 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {isSubmitting ? 'Creating...' : 'Create Team'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

export function TeamsDashboard() {
  const [teams, setTeams] = useState<Team[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreateModal, setShowCreateModal] = useState(false);

  const fetchTeams = useCallback(async () => {
    try {
      const response = await fetch('/api/teams');
      if (!response.ok) {
        throw new Error('Failed to fetch teams');
      }
      const data = await response.json();
      setTeams(data);
    } catch (error) {
      logError('Failed to fetch teams', { error });
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchTeams();
  }, [fetchTeams]);

  const handleTeamCreated = (team: Team) => {
    setTeams(prev => [team, ...prev]);
  };

  if (loading) {
    return (
      <div className="flex min-h-[400px] items-center justify-center">
        <div className="text-center">
          <div className="h-8 w-8 animate-spin rounded-full border-4 border-neutral-300 dark:border-neutral-700 border-t-primary-600 dark:border-t-primary-500"></div>
          <p className="mt-4 text-sm text-neutral-600 dark:text-neutral-400">
            Loading teams...
          </p>
        </div>
      </div>
    );
  }

  return (
    <>
      <div className="mb-6">
        <h2 className="text-2xl font-semibold text-neutral-900 dark:text-white">Teams & Collaboration</h2>
        <p className="mt-2 text-neutral-600 dark:text-neutral-400">Manage your teams and collaborate on API projects</p>
      </div>
      {teams.length === 0 ? (
        <div className="rounded-2xl border border-neutral-200 bg-neutral-50 p-8 dark:border-neutral-800 dark:bg-neutral-900">
          <div className="text-center py-12">
            <svg
              className="mx-auto h-12 w-12 text-neutral-400"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
              aria-hidden="true"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z"
              />
            </svg>
            <h3 className="mt-4 text-lg font-semibold text-neutral-900 dark:text-white">
              No teams yet
            </h3>
            <p className="mt-2 text-sm text-neutral-600 dark:text-neutral-400">
              Create a team to collaborate with others on API projects.
            </p>
            <div className="mt-6">
              <button
                onClick={() => setShowCreateModal(true)}
                className="inline-flex rounded-lg bg-primary-600 px-4 py-2 text-sm font-semibold text-white hover:bg-primary-700"
              >
                Create Your First Team
              </button>
            </div>
          </div>
        </div>
      ) : (
        <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
          {teams.map(team => (
            <div
              key={team.id}
              className="rounded-2xl border border-neutral-200 bg-white p-6 shadow-sm transition-shadow hover:shadow-md dark:border-neutral-800 dark:bg-neutral-900"
            >
              <div className="flex items-start justify-between mb-4">
                <div>
                  <h3 className="text-lg font-semibold text-neutral-900 dark:text-white">
                    {team.name}
                  </h3>
                  <p className="text-sm text-neutral-500 dark:text-neutral-400">
                    /{team.slug}
                  </p>
                </div>
                <span className="inline-flex items-center rounded-full bg-primary-50 px-2.5 py-0.5 text-xs font-medium text-primary-700 dark:bg-primary-900/20 dark:text-primary-400">
                  {team.members?.find(m => m.role === 'OWNER')
                    ? 'Owner'
                    : 'Member'}
                </span>
              </div>

              <div className="flex items-center gap-2 mb-4">
                <svg
                  className="h-4 w-4 text-neutral-500"
                  fill="none"
                  viewBox="0 0 24 24"
                  stroke="currentColor"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0"
                  />
                </svg>
                <span className="text-sm text-neutral-600 dark:text-neutral-400">
                  {team._count?.members || team.members?.length || 0} member
                  {(team._count?.members || team.members?.length || 0) !== 1
                    ? 's'
                    : ''}
                </span>
              </div>

              {/* Member Avatars */}
              <div className="flex -space-x-2 mb-4">
                {team.members?.slice(0, 5).map(member => (
                  <div
                    key={member.id}
                    className="relative h-8 w-8 rounded-full border-2 border-white bg-neutral-200 dark:border-neutral-900 dark:bg-neutral-700 overflow-hidden"
                    title={member.user.name || member.user.email || 'Member'}
                  >
                    {member.user.image ? (
                      <Image
                        src={member.user.image}
                        alt={member.user.name || 'Member'}
                        fill
                        className="object-cover"
                        sizes="32px"
                      />
                    ) : (
                      <span className="flex h-full w-full items-center justify-center text-xs font-medium text-neutral-600 dark:text-neutral-300">
                        {(member.user.name ||
                          member.user.email ||
                          'M')[0].toUpperCase()}
                      </span>
                    )}
                  </div>
                ))}
                {team.members && team.members.length > 5 && (
                  <div className="relative flex h-8 w-8 items-center justify-center rounded-full border-2 border-white bg-neutral-100 dark:border-neutral-900 dark:bg-neutral-800">
                    <span className="text-xs font-medium text-neutral-600 dark:text-neutral-400">
                      +{team.members.length - 5}
                    </span>
                  </div>
                )}
              </div>

              <div className="flex gap-2">
                <Link
                  href={`/dashboard/monitoring?teamId=${team.id}`}
                  className="flex-1 rounded-lg border border-neutral-200 px-3 py-2 text-center text-sm font-medium text-neutral-700 hover:bg-neutral-50 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
                >
                  Monitoring
                </Link>
                <Link
                  href={`/dashboard/teams/${team.id}/manage`}
                  className="flex-1 rounded-lg bg-primary-600 px-3 py-2 text-center text-sm font-medium text-white hover:bg-primary-700"
                >
                  Manage
                </Link>
              </div>
            </div>
          ))}
        </div>
      )}

      <CreateTeamModal
        isOpen={showCreateModal}
        onClose={() => setShowCreateModal(false)}
        onCreated={handleTeamCreated}
      />
    </>
  );
}
