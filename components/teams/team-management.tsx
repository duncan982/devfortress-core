/**
 * Team Management Component
 * Provides interface for managing team members and settings
 */

'use client';

import { useState, useEffect, useCallback } from 'react';
import Image from 'next/image';
import { logError } from '@core/lib/logger/client';

interface TeamInvitation {
  id: string;
  email: string;
  role: 'OWNER' | 'ADMIN' | 'DEVELOPER' | 'VIEWER';
  invitedAt: string;
  expiresAt: string;
  invitedBy: {
    id: string;
    name: string | null;
    email: string;
  };
}

interface TeamMember {
  id: string;
  role: 'OWNER' | 'ADMIN' | 'DEVELOPER' | 'VIEWER';
  user: {
    id: string;
    name: string | null;
    email: string;
    image: string | null;
  };
}

interface TeamInvitation {
  id: string;
  email: string;
  role: 'OWNER' | 'ADMIN' | 'DEVELOPER' | 'VIEWER';
  invitedAt: string;
  expiresAt: string;
  invitedBy: {
    id: string;
    name: string | null;
    email: string;
  };
}

interface TeamManagementProps {
  teamId: string;
  userRole: string;
}

interface SubscriptionInfo {
  seats: number;
  plan: string;
}

export function TeamManagement({ teamId, userRole }: TeamManagementProps) {
  const [members, setMembers] = useState<TeamMember[]>([]);
  const [invitations, setInvitations] = useState<TeamInvitation[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [inviteEmail, setInviteEmail] = useState('');
  const [inviteRole, setInviteRole] = useState<'DEVELOPER'>('DEVELOPER');
  const [isInviting, setIsInviting] = useState(false);
  const [subscriptionInfo, setSubscriptionInfo] =
    useState<SubscriptionInfo | null>(null);

  const fetchMembers = useCallback(async () => {
    try {
      const response = await fetch(`/api/teams/${teamId}/members`);
      if (!response.ok) {
        throw new Error('Failed to fetch team members');
      }
      const data = await response.json();
      setMembers(data);
    } catch (err) {
      logError('Failed to fetch team members', { error: err });
      setError('Failed to load team members');
    } finally {
      setLoading(false);
    }
  }, [teamId]);

  const fetchInvitations = useCallback(async () => {
    try {
      const response = await fetch(`/api/teams/${teamId}/invitations`);
      if (!response.ok) {
        throw new Error('Failed to fetch team invitations');
      }
      const data = await response.json();
      setInvitations(data);
    } catch (err) {
      logError('Failed to fetch team invitations', { error: err });
      // Don't set error for invitations, as it's not critical
    }
  }, [teamId]);

  const fetchSubscriptionInfo = useCallback(async () => {
    try {
      const response = await fetch('/api/subscription/status');
      if (!response.ok) {
        throw new Error('Failed to fetch subscription info');
      }
      const data = await response.json();
      let seats = data.seats || 1;
      // Admin and Owner roles have unlimited seats
      if (userRole === 'OWNER' || userRole === 'ADMIN') {
        seats = -1;
      }
      if (
        data.hasSubscription ||
        userRole === 'OWNER' ||
        userRole === 'ADMIN'
      ) {
        setSubscriptionInfo({
          seats,
          plan: data.plan || 'FREE',
        });
      }
    } catch (err) {
      logError('Failed to fetch subscription info', { error: err });
      // For admin/owner, still set unlimited even if API fails
      if (userRole === 'OWNER' || userRole === 'ADMIN') {
        setSubscriptionInfo({
          seats: -1,
          plan: 'ENTERPRISE',
        });
      }
    }
  }, [userRole]);

  useEffect(() => {
    fetchMembers();
    fetchInvitations();
    fetchSubscriptionInfo();
  }, [fetchMembers, fetchInvitations, fetchSubscriptionInfo]);

  const updateMemberRole = async (
    memberId: string,
    newRole: 'OWNER' | 'ADMIN' | 'DEVELOPER' | 'VIEWER'
  ) => {
    try {
      const response = await fetch(`/api/teams/${teamId}/members/${memberId}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ role: newRole }),
      });

      if (!response.ok) {
        throw new Error('Failed to update member role');
      }

      // Update local state
      setMembers(prev =>
        prev.map(member =>
          member.id === memberId ? { ...member, role: newRole } : member
        )
      );
    } catch (err) {
      logError('Failed to update member role', { error: err });
      setError('Failed to update member role');
    }
  };

  const removeMember = async (memberId: string) => {
    if (!confirm('Are you sure you want to remove this member?')) return;

    try {
      const response = await fetch(`/api/teams/${teamId}/members/${memberId}`, {
        method: 'DELETE',
      });

      if (!response.ok) {
        throw new Error('Failed to remove member');
      }

      setMembers(prev => prev.filter(member => member.id !== memberId));
    } catch (err) {
      logError('Failed to remove member', { error: err });
      setError('Failed to remove member');
    }
  };

  const sendInvitation = async () => {
    if (!inviteEmail.trim()) return;

    setIsInviting(true);
    setError('');

    try {
      const response = await fetch(`/api/teams/${teamId}/invitations`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: inviteEmail, role: inviteRole }),
      });

      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.error || 'Failed to send invitation');
      }

      const newInvitation = await response.json();
      setInvitations(prev => [newInvitation, ...prev]);
      setInviteEmail('');
      setInviteRole('DEVELOPER');
    } catch (err) {
      logError('Failed to send invitation', { error: err });
      setError(
        err instanceof Error ? err.message : 'Failed to send invitation'
      );
    } finally {
      setIsInviting(false);
    }
  };

  const cancelInvitation = async (invitationId: string) => {
    if (!confirm('Are you sure you want to cancel this invitation?')) return;

    try {
      const response = await fetch(
        `/api/teams/${teamId}/invitations/${invitationId}`,
        {
          method: 'DELETE',
        }
      );

      if (!response.ok) {
        throw new Error('Failed to cancel invitation');
      }

      setInvitations(prev => prev.filter(inv => inv.id !== invitationId));
    } catch (err) {
      logError('Failed to cancel invitation', { error: err });
      setError('Failed to cancel invitation');
    }
  };

  if (loading) {
    return (
      <div className="flex min-h-[200px] items-center justify-center">
        <div className="text-center">
          <div className="h-8 w-8 animate-spin rounded-full border-4 border-neutral-300 dark:border-neutral-700 border-t-primary-600 dark:border-t-primary-500"></div>
          <p className="mt-4 text-sm text-neutral-600 dark:text-neutral-400">
            Loading team members...
          </p>
        </div>
      </div>
    );
  }

  const canInvite =
    userRole === 'OWNER' || userRole === 'ADMIN' || userRole === 'DEVELOPER';
  const canManage = userRole === 'OWNER' || userRole === 'ADMIN';

  const currentMemberCount = members.length;
  const maxSeats = subscriptionInfo?.seats || 1;
  const seatsUsed = currentMemberCount;
  const isUnlimited = maxSeats === -1;
  const seatsRemaining = isUnlimited
    ? Infinity
    : Math.max(0, maxSeats - seatsUsed);
  const isNearLimit = !isUnlimited && seatsRemaining <= 1;

  return (
    <div className="space-y-6">
      {error && (
        <div className="rounded-lg bg-error-50 p-4 text-sm text-error-700 dark:bg-error-900/20 dark:text-error-400">
          {error}
        </div>
      )}

      {/* Seat Usage Display */}
      {subscriptionInfo && (
        <div className="rounded-lg border border-neutral-200 bg-white p-6 dark:border-neutral-800 dark:bg-neutral-900">
          <h3 className="text-lg font-semibold mb-4">Team Seats</h3>
          <div className="flex items-center justify-between mb-2">
            <span className="text-sm text-neutral-600 dark:text-neutral-400">
              {isUnlimited
                ? 'Unlimited seats'
                : `${seatsUsed} of ${maxSeats} seats used`}
            </span>
            <span
              className={`text-sm font-medium ${isNearLimit ? 'text-orange-600 dark:text-orange-400' : 'text-green-600 dark:text-green-400'}`}
            >
              {isUnlimited
                ? 'Unlimited remaining'
                : `${seatsRemaining} remaining`}
            </span>
          </div>
          <div className="w-full bg-neutral-200 rounded-full h-2 dark:bg-neutral-700">
            <div
              className={`h-2 rounded-full ${isNearLimit ? 'bg-orange-500' : 'bg-green-500'}`}
              style={{
                width: isUnlimited
                  ? '0%'
                  : `${Math.min(100, (seatsUsed / maxSeats) * 100)}%`,
              }}
            ></div>
          </div>
          {isNearLimit && (
            <p className="text-sm text-orange-600 dark:text-orange-400 mt-2">
              You&apos;re running low on seats. Consider upgrading your plan for
              more team members.
            </p>
          )}
        </div>
      )}

      {/* Invite Members Section */}
      {canInvite && (
        <div className="rounded-lg border border-neutral-200 bg-white p-6 dark:border-neutral-800 dark:bg-neutral-900">
          <h3 className="text-lg font-semibold mb-4">Invite Team Members</h3>
          <p className="text-sm text-neutral-600 dark:text-neutral-400 mb-4">
            To invite team members, enter their email address and select their
            role. They will receive an email with instructions to join your
            team.
          </p>
          <div className="flex gap-4">
            <input
              type="email"
              placeholder="Enter email address"
              value={inviteEmail}
              onChange={e => setInviteEmail(e.target.value)}
              className="flex-1 rounded-lg border border-neutral-300 px-3 py-2 dark:border-neutral-600 dark:bg-neutral-800"
            />
            <select
              value={inviteRole}
              onChange={e => setInviteRole(e.target.value as 'DEVELOPER')}
              className="rounded-lg border border-neutral-300 px-3 py-2 dark:border-neutral-600 dark:bg-neutral-800"
            >
              <option value="VIEWER">Viewer</option>
              <option value="DEVELOPER">Developer</option>
              <option value="ADMIN">Admin</option>
            </select>
            <button
              onClick={sendInvitation}
              disabled={
                isInviting ||
                !inviteEmail.trim() ||
                (!isUnlimited && seatsRemaining === 0)
              }
              className="rounded-lg bg-primary-600 px-4 py-2 text-white hover:bg-primary-700 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {isInviting
                ? 'Sending...'
                : !isUnlimited && seatsRemaining === 0
                  ? 'No Seats Available'
                  : 'Send Invite'}
            </button>
          </div>
          {!isUnlimited && seatsRemaining === 0 && (
            <p className="text-sm text-red-600 dark:text-red-400 mt-2">
              You&apos;ve reached your seat limit. Upgrade your plan to invite
              more members.
            </p>
          )}
        </div>
      )}

      {/* Pending Invitations */}
      {invitations.length > 0 && (
        <div>
          <h2 className="text-xl font-semibold mb-4">Pending Invitations</h2>
          <div className="space-y-4">
            {invitations.map(invitation => (
              <div
                key={invitation.id}
                className="flex items-center justify-between rounded-lg border border-neutral-200 bg-white p-4 dark:border-neutral-800 dark:bg-neutral-900"
              >
                <div>
                  <p className="font-medium text-neutral-900 dark:text-white">
                    {invitation.email}
                  </p>
                  <p className="text-sm text-neutral-500 dark:text-neutral-400">
                    Invited by{' '}
                    {invitation.invitedBy.name || invitation.invitedBy.email} •
                    Expires{' '}
                    {new Date(invitation.expiresAt).toLocaleDateString()}
                  </p>
                </div>
                <div className="flex items-center gap-3">
                  <span className="inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium bg-blue-50 text-blue-700 dark:bg-blue-900/20 dark:text-blue-400">
                    {invitation.role}
                  </span>
                  {canManage && (
                    <button
                      onClick={() => cancelInvitation(invitation.id)}
                      className="rounded border border-red-300 px-2 py-1 text-sm text-red-700 hover:bg-red-50 dark:border-red-700 dark:text-red-400 dark:hover:bg-red-900/20"
                    >
                      Cancel
                    </button>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      <div>
        <h2 className="text-xl font-semibold mb-4">Team Members</h2>
        <div className="space-y-4">
          {members.map(member => (
            <div
              key={member.id}
              className="flex items-center justify-between rounded-lg border border-neutral-200 bg-white p-4 dark:border-neutral-800 dark:bg-neutral-900"
            >
              <div className="flex items-center gap-3">
                <div className="relative h-10 w-10 rounded-full border-2 border-white bg-neutral-200 dark:border-neutral-900 dark:bg-neutral-700 overflow-hidden">
                  {member.user.image ? (
                    <Image
                      src={member.user.image}
                      alt={member.user.name || 'Member'}
                      fill
                      className="object-cover"
                      sizes="40px"
                    />
                  ) : (
                    <span className="flex h-full w-full items-center justify-center text-sm font-medium text-neutral-600 dark:text-neutral-300">
                      {(member.user.name || member.user.email)[0].toUpperCase()}
                    </span>
                  )}
                </div>
                <div>
                  <p className="font-medium text-neutral-900 dark:text-white">
                    {member.user.name || 'Unknown'}
                  </p>
                  <p className="text-sm text-neutral-500 dark:text-neutral-400">
                    {member.user.email}
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-3">
                <span
                  className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium ${
                    member.role === 'OWNER'
                      ? 'bg-primary-50 text-primary-700 dark:bg-primary-900/20 dark:text-primary-400'
                      : 'bg-neutral-100 text-neutral-700 dark:bg-neutral-800 dark:text-neutral-300'
                  }`}
                >
                  {member.role}
                </span>

                {canManage && member.role !== 'OWNER' && (
                  <div className="flex gap-2">
                    <select
                      value={member.role}
                      onChange={e =>
                        updateMemberRole(
                          member.id,
                          e.target.value as
                            | 'OWNER'
                            | 'ADMIN'
                            | 'DEVELOPER'
                            | 'VIEWER'
                        )
                      }
                      className="rounded border border-neutral-300 px-2 py-1 text-sm dark:border-neutral-600 dark:bg-neutral-800"
                    >
                      <option value="VIEWER">Viewer</option>
                      <option value="DEVELOPER">Developer</option>
                      <option value="ADMIN">Admin</option>
                      <option value="OWNER">Owner</option>
                    </select>
                    <button
                      onClick={() => removeMember(member.id)}
                      className="rounded border border-red-300 px-2 py-1 text-sm text-red-700 hover:bg-red-50 dark:border-red-700 dark:text-red-400 dark:hover:bg-red-900/20"
                    >
                      Remove
                    </button>
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
