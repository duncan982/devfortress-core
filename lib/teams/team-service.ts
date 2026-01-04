/**
 * Team management service
 * Handles team creation, member management, and permissions
 */

import { PrismaClient, TeamRole } from '@prisma/client';
import { logInfo, logError } from '../logger';
import { randomUUID } from 'crypto';
import { getUserSubscription } from '../payments/subscription-service';

const prisma = new PrismaClient();

interface CreateTeamParams {
  name: string;
  slug: string;
  createdById: string;
  organizationId?: string;
}

interface AddTeamMemberParams {
  teamId: string;
  userId: string;
  role?: TeamRole;
  requesterId: string;
}

interface UpdateTeamMemberRoleParams {
  teamId: string;
  userId: string;
  role: TeamRole;
  requesterId: string;
}

interface InviteUserToTeamParams {
  teamId: string;
  email: string;
  role?: TeamRole;
  invitedById: string;
}

interface AcceptInvitationParams {
  token: string;
  userId: string;
}

/**
 * Create a new team
 */
export async function createTeam(params: CreateTeamParams) {
  const { name, slug, createdById, organizationId } = params;

  // Check subscription for team creation
  const subscription = await getUserSubscription(createdById);
  if (!subscription || !['PRO', 'ENTERPRISE'].includes(subscription.plan)) {
    throw new Error(
      'Team creation requires a PRO or ENTERPRISE subscription. Please upgrade to access team features.'
    );
  }

  try {
    logInfo('Creating team', { name, slug, createdById, organizationId });

    // Check if slug is already taken
    const existingTeam = await prisma.team.findUnique({
      where: { slug },
    });

    if (existingTeam) {
      throw new Error('Team slug already exists');
    }

    // Create team with creator as owner
    const team = await prisma.team.create({
      data: {
        name,
        slug,
        createdById,
        organizationId,
        members: {
          create: {
            userId: createdById,
            role: TeamRole.OWNER,
          },
        },
      },
      include: {
        members: {
          include: {
            user: {
              select: {
                id: true,
                name: true,
                email: true,
                image: true,
              },
            },
          },
        },
        organization: true,
      },
    });

    logInfo('Team created successfully', { teamId: team.id, name: team.name });

    return team;
  } catch (error) {
    logError('Failed to create team', { error, params });
    throw error;
  }
}

/**
 * Get team by ID with members
 */
export async function getTeam(teamId: string) {
  try {
    const team = await prisma.team.findUnique({
      where: { id: teamId },
      include: {
        members: {
          include: {
            user: {
              select: {
                id: true,
                name: true,
                email: true,
                image: true,
                role: true,
              },
            },
          },
        },
        organization: true,
        createdBy: {
          select: {
            id: true,
            name: true,
            email: true,
          },
        },
      },
    });

    return team;
  } catch (error) {
    logError('Failed to get team', { error, teamId });
    throw error;
  }
}

/**
 * Get teams for a user
 */
export async function getUserTeams(userId: string) {
  try {
    const teams = await prisma.team.findMany({
      where: {
        members: {
          some: {
            userId,
          },
        },
      },
      include: {
        members: {
          include: {
            user: {
              select: {
                id: true,
                name: true,
                email: true,
                image: true,
              },
            },
          },
        },
        organization: true,
      },
      orderBy: {
        createdAt: 'desc',
      },
    });

    return teams;
  } catch (error) {
    logError('Failed to get user teams', { error, userId });
    throw error;
  }
}

/**
 * Check if user has permission to perform action on team
 */
export async function checkTeamPermission(
  userId: string,
  teamId: string,
  requiredRole: TeamRole = TeamRole.DEVELOPER
): Promise<boolean> {
  try {
    const membership = await prisma.teamMember.findUnique({
      where: {
        teamId_userId: {
          teamId,
          userId,
        },
      },
    });

    if (!membership) {
      return false;
    }

    // Role hierarchy: OWNER > ADMIN > DEVELOPER > VIEWER
    const roleHierarchy = {
      [TeamRole.OWNER]: 4,
      [TeamRole.ADMIN]: 3,
      [TeamRole.DEVELOPER]: 2,
      [TeamRole.VIEWER]: 1,
    };

    return roleHierarchy[membership.role] >= roleHierarchy[requiredRole];
  } catch (error) {
    logError('Failed to check team permission', { error, userId, teamId });
    return false;
  }
}

/**
 * Add a member to a team
 */
export async function addTeamMember(params: AddTeamMemberParams) {
  const { teamId, userId, role = TeamRole.DEVELOPER, requesterId } = params;

  try {
    logInfo('Adding team member', { teamId, userId, role });

    // Check if requester has permission (must be ADMIN or OWNER)
    const hasPermission = await checkTeamPermission(
      requesterId,
      teamId,
      TeamRole.ADMIN
    );

    if (!hasPermission) {
      throw new Error('Insufficient permissions to add team members');
    }

    // Check if user is already a member
    const existingMember = await prisma.teamMember.findUnique({
      where: {
        teamId_userId: {
          teamId,
          userId,
        },
      },
    });

    if (existingMember) {
      throw new Error('User is already a team member');
    }

    // Get team to check seat limits
    const team = await prisma.team.findUnique({
      where: { id: teamId },
      select: { createdById: true },
    });

    if (!team) {
      throw new Error('Team not found');
    }

    // Check seat limits
    const ownerSubscription = await getUserSubscription(team.createdById);
    const currentMembers = await prisma.teamMember.count({
      where: { teamId },
    });
    const maxSeats = ownerSubscription?.seats || 1;

    if (currentMembers >= maxSeats) {
      throw new Error(
        `Cannot add member. Team has reached maximum seats (${maxSeats}). Please upgrade your plan for more seats.`
      );
    }

    // Add member
    const member = await prisma.teamMember.create({
      data: {
        teamId,
        userId,
        role,
      },
      include: {
        user: {
          select: {
            id: true,
            name: true,
            email: true,
            image: true,
          },
        },
        team: {
          select: {
            id: true,
            name: true,
            slug: true,
          },
        },
      },
    });

    logInfo('Team member added successfully', {
      teamId,
      userId,
      memberId: member.id,
    });

    return member;
  } catch (error) {
    logError('Failed to add team member', { error, params });
    throw error;
  }
}

/**
 * Remove a member from a team
 */
export async function removeTeamMember(
  teamId: string,
  userId: string,
  requesterId: string
) {
  try {
    logInfo('Removing team member', { teamId, userId });

    // Check if requester has permission (must be ADMIN or OWNER)
    const hasPermission = await checkTeamPermission(
      requesterId,
      teamId,
      TeamRole.ADMIN
    );

    if (!hasPermission) {
      throw new Error('Insufficient permissions to remove team members');
    }

    // Check if user is the team owner
    const member = await prisma.teamMember.findUnique({
      where: {
        teamId_userId: {
          teamId,
          userId,
        },
      },
    });

    if (!member) {
      throw new Error('User is not a team member');
    }

    if (member.role === TeamRole.OWNER) {
      throw new Error('Cannot remove team owner');
    }

    // Remove member
    await prisma.teamMember.delete({
      where: {
        teamId_userId: {
          teamId,
          userId,
        },
      },
    });

    logInfo('Team member removed successfully', { teamId, userId });
  } catch (error) {
    logError('Failed to remove team member', { error, teamId, userId });
    throw error;
  }
}

/**
 * Update team member role
 */
export async function updateTeamMemberRole(params: UpdateTeamMemberRoleParams) {
  const { teamId, userId, role, requesterId } = params;

  try {
    logInfo('Updating team member role', { teamId, userId, role });

    // Check if requester has permission (must be OWNER)
    const hasPermission = await checkTeamPermission(
      requesterId,
      teamId,
      TeamRole.OWNER
    );

    if (!hasPermission) {
      throw new Error('Only team owners can change member roles');
    }

    // Check if user is the team owner
    const member = await prisma.teamMember.findUnique({
      where: {
        teamId_userId: {
          teamId,
          userId,
        },
      },
    });

    if (!member) {
      throw new Error('User is not a team member');
    }

    if (member.role === TeamRole.OWNER) {
      throw new Error('Cannot change team owner role');
    }

    // Update role
    const updatedMember = await prisma.teamMember.update({
      where: {
        teamId_userId: {
          teamId,
          userId,
        },
      },
      data: { role },
      include: {
        user: {
          select: {
            id: true,
            name: true,
            email: true,
            image: true,
          },
        },
      },
    });

    logInfo('Team member role updated successfully', { teamId, userId, role });

    return updatedMember;
  } catch (error) {
    logError('Failed to update team member role', { error, params });
    throw error;
  }
}

/**
 * Delete a team
 */
export async function deleteTeam(teamId: string, requesterId: string) {
  try {
    logInfo('Deleting team', { teamId });

    // Check if requester is the team owner
    const hasPermission = await checkTeamPermission(
      requesterId,
      teamId,
      TeamRole.OWNER
    );

    if (!hasPermission) {
      throw new Error('Only team owners can delete teams');
    }

    // Delete team (cascade will handle members)
    await prisma.team.delete({
      where: { id: teamId },
    });

    logInfo('Team deleted successfully', { teamId });
  } catch (error) {
    logError('Failed to delete team', { error, teamId });
    throw error;
  }
}

/**
 * Update team details
 */
export async function updateTeam(
  teamId: string,
  updates: { name?: string; slug?: string },
  requesterId: string
) {
  try {
    logInfo('Updating team', { teamId, updates });

    // Check if requester has permission (must be OWNER or ADMIN)
    const hasPermission = await checkTeamPermission(
      requesterId,
      teamId,
      TeamRole.ADMIN
    );

    if (!hasPermission) {
      throw new Error('Insufficient permissions to update team');
    }

    // If slug is being updated, check if it's available
    if (updates.slug) {
      const existingTeam = await prisma.team.findUnique({
        where: { slug: updates.slug },
      });

      if (existingTeam && existingTeam.id !== teamId) {
        throw new Error('Team slug already exists');
      }
    }

    // Update team
    const team = await prisma.team.update({
      where: { id: teamId },
      data: updates,
      include: {
        members: {
          include: {
            user: {
              select: {
                id: true,
                name: true,
                email: true,
                image: true,
              },
            },
          },
        },
      },
    });

    logInfo('Team updated successfully', { teamId });

    return team;
  } catch (error) {
    logError('Failed to update team', { error, teamId, updates });
    throw error;
  }
}

/**
 * Invite a user to join a team
 */
export async function inviteUserToTeam(params: InviteUserToTeamParams) {
  const { teamId, email, role = TeamRole.DEVELOPER, invitedById } = params;

  try {
    logInfo('Inviting user to team', { teamId, email, role, invitedById });

    // Check if inviter has permission
    const membership = await prisma.teamMember.findUnique({
      where: {
        teamId_userId: {
          teamId,
          userId: invitedById,
        },
      },
    });

    if (!membership || !['OWNER', 'ADMIN'].includes(membership.role)) {
      throw new Error('Insufficient permissions to invite users');
    }

    // Actually, check if there's already an invitation for this email
    const existingInvitation = await prisma.teamInvitation.findUnique({
      where: {
        teamId_email: {
          teamId,
          email,
        },
      },
    });

    if (existingInvitation && existingInvitation.status === 'PENDING') {
      throw new Error('User already has a pending invitation');
    }

    // Generate token
    const token = randomUUID();

    // Create invitation
    const invitation = await prisma.teamInvitation.create({
      data: {
        teamId,
        email,
        role,
        invitedById,
        token,
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
      },
      include: {
        team: true,
        invitedBy: {
          select: {
            id: true,
            name: true,
            email: true,
          },
        },
      },
    });

    logInfo('Team invitation created', { invitationId: invitation.id, email });

    return invitation;
  } catch (error) {
    logError('Failed to invite user to team', { error, params });
    throw error;
  }
}

/**
 * Accept a team invitation
 */
export async function acceptInvitation(params: AcceptInvitationParams) {
  const { token, userId } = params;

  try {
    logInfo('Accepting team invitation', { token, userId });

    // Find invitation
    const invitation = await prisma.teamInvitation.findUnique({
      where: { token },
      include: {
        team: true,
      },
    });

    if (!invitation) {
      throw new Error('Invalid invitation token');
    }

    if (invitation.status !== 'PENDING') {
      throw new Error('Invitation is no longer valid');
    }

    if (invitation.expiresAt < new Date()) {
      throw new Error('Invitation has expired');
    }

    // Check if user email matches
    const user = await prisma.user.findUnique({
      where: { id: userId },
    });

    if (!user || user.email !== invitation.email) {
      throw new Error('Invitation email does not match user email');
    }

    // Check if user is already a member
    const existingMember = await prisma.teamMember.findUnique({
      where: {
        teamId_userId: {
          teamId: invitation.teamId,
          userId,
        },
      },
    });

    if (existingMember) {
      throw new Error('User is already a member of this team');
    }

    // Check seat limits before accepting
    const ownerSubscription = await getUserSubscription(
      invitation.team.createdById
    );
    const currentMembers = await prisma.teamMember.count({
      where: { teamId: invitation.teamId },
    });
    const maxSeats = ownerSubscription?.seats || 1;

    if (currentMembers >= maxSeats) {
      throw new Error(
        `Cannot accept invitation. Team has reached maximum seats (${maxSeats}). Please upgrade your plan for more seats.`
      );
    }

    // Start transaction
    await prisma.$transaction(async tx => {
      // Add user to team
      await tx.teamMember.create({
        data: {
          teamId: invitation.teamId,
          userId,
          role: invitation.role,
        },
      });

      // Update invitation
      await tx.teamInvitation.update({
        where: { id: invitation.id },
        data: {
          status: 'ACCEPTED',
          acceptedAt: new Date(),
        },
      });
    });

    logInfo('Team invitation accepted', {
      invitationId: invitation.id,
      userId,
    });

    return invitation.team;
  } catch (error) {
    logError('Failed to accept invitation', { error, params });
    throw error;
  }
}

/**
 * Get pending invitations for a team
 */
export async function getTeamInvitations(teamId: string, requesterId: string) {
  try {
    // Check permission
    const membership = await prisma.teamMember.findUnique({
      where: {
        teamId_userId: {
          teamId,
          userId: requesterId,
        },
      },
    });

    if (!membership || !['OWNER', 'ADMIN'].includes(membership.role)) {
      throw new Error('Insufficient permissions to view invitations');
    }

    const invitations = await prisma.teamInvitation.findMany({
      where: {
        teamId,
        status: 'PENDING',
      },
      include: {
        invitedBy: {
          select: {
            id: true,
            name: true,
            email: true,
          },
        },
      },
      orderBy: {
        invitedAt: 'desc',
      },
    });

    return invitations;
  } catch (error) {
    logError('Failed to get team invitations', { error, teamId, requesterId });
    throw error;
  }
}

/**
 * Cancel a team invitation
 */
export async function cancelInvitation(
  invitationId: string,
  requesterId: string
) {
  try {
    logInfo('Cancelling team invitation', { invitationId, requesterId });

    // Find invitation
    const invitation = await prisma.teamInvitation.findUnique({
      where: { id: invitationId },
      include: {
        team: true,
      },
    });

    if (!invitation) {
      throw new Error('Invitation not found');
    }

    // Check permission
    const membership = await prisma.teamMember.findUnique({
      where: {
        teamId_userId: {
          teamId: invitation.teamId,
          userId: requesterId,
        },
      },
    });

    if (
      !membership ||
      (!['OWNER', 'ADMIN'].includes(membership.role) &&
        invitation.invitedById !== requesterId)
    ) {
      throw new Error('Insufficient permissions to cancel invitation');
    }

    // Update invitation
    await prisma.teamInvitation.update({
      where: { id: invitationId },
      data: {
        status: 'CANCELLED',
      },
    });

    logInfo('Team invitation cancelled', { invitationId });

    return true;
  } catch (error) {
    logError('Failed to cancel invitation', {
      error,
      invitationId,
      requesterId,
    });
    throw error;
  }
}

/**
 * Get all members of a team
 */
export async function getTeamMembers(teamId: string) {
  try {
    const members = await prisma.teamMember.findMany({
      where: { teamId },
      include: {
        user: {
          select: {
            id: true,
            name: true,
            email: true,
            image: true,
          },
        },
      },
    });

    return members;
  } catch (error) {
    logError('Failed to get team members', { error, teamId });
    throw error;
  }
}
