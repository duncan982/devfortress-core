/**
 * Portal Access Control Service
 * Manages access to portal sections based on team roles and subscription tiers
 */

import { logInfo, logWarn } from '@core/lib/logger';

// User role enum (should match Prisma UserRole schema)
export enum TeamRole {
  OWNER = 'OWNER',
  ADMIN = 'ADMIN',
  DEVELOPER = 'DEVELOPER',
  VIEWER = 'VIEWER',
}

// Subscription tier enum (aligned with payments/types.ts SubscriptionTier)
export enum SubscriptionTier {
  // FREE = 'FREE', // Commented out - free tier removed, targeting paying customers only
  STARTER = 'STARTER',
  PRO = 'PRO',
  /** @deprecated Renamed to TEAM in pricing v3. Kept for backward compatibility. */
  ENTERPRISE = 'ENTERPRISE',
  /** Team plan ($499/mo) — renamed from Enterprise in pricing v3 */
  TEAM = 'TEAM',
  /** Business plan ($2,000/mo) — Coming Soon */
  BUSINESS = 'BUSINESS',
  /** Enterprise Plus (custom pricing) — Coming Soon */
  ENTERPRISE_PLUS = 'ENTERPRISE_PLUS',
}

export interface PortalSection {
  id: string;
  title: string;
  description: string;
  icon: string;
  href: string;
  category: 'docs' | 'security' | 'monitoring' | 'data' | 'admin';
  minRole?: TeamRole; // Minimum role required
  minTier?: SubscriptionTier; // Minimum tier required
  isPremium?: boolean; // Premium feature flag
}

export interface AccessControlResult {
  hasAccess: boolean;
  reason?: string;
  upgradeRequired?: boolean;
  requiredTier?: SubscriptionTier;
}

export class PortalAccessControl {
  /**
   * Check if a user has access to a portal section
   */
  static checkAccess(
    section: PortalSection,
    userRole: TeamRole,
    subscriptionTier: SubscriptionTier | null
  ): AccessControlResult {
    // Admin/Developer/Owner roles bypass all subscription checks
    const isPrivilegedUser =
      userRole === TeamRole.ADMIN ||
      userRole === TeamRole.DEVELOPER ||
      userRole === TeamRole.OWNER;

    if (isPrivilegedUser) {
      logInfo('Portal access granted - privileged user bypass', {
        section: section.id,
        userRole,
      });
      return { hasAccess: true };
    }

    // For regular users: require active subscription (FREE tier commented out)
    // if (subscriptionTier === SubscriptionTier.FREE) {
    //   logWarn('Portal access denied - subscription required', {
    //     section: section.id,
    //     subscriptionTier,
    //   });
    //   return {
    //     hasAccess: false,
    //     reason: 'Active subscription required for this feature',
    //     upgradeRequired: true,
    //     requiredTier: SubscriptionTier.STARTER,
    //   };
    // }

    // Check if user has any subscription (FREE tier removed, so any subscription is paid)
    if (!subscriptionTier) {
      logWarn('Portal access denied - subscription required', {
        section: section.id,
        subscriptionTier,
      });
      return {
        hasAccess: false,
        reason: 'Active subscription required for this feature',
        upgradeRequired: true,
        requiredTier: SubscriptionTier.STARTER,
      };
    }

    // Check role-based access for regular users
    if (section.minRole) {
      if (!this.hasRequiredRole(userRole, section.minRole)) {
        logWarn('Portal access denied - insufficient role', {
          section: section.id,
          userRole,
          minRole: section.minRole,
        });
        return {
          hasAccess: false,
          reason: `This feature requires ${section.minRole} role or higher`,
        };
      }
    }

    // Check tier-based access for regular users
    if (section.minTier) {
      if (!this.hasRequiredTier(subscriptionTier, section.minTier)) {
        logWarn('Portal access denied - insufficient tier', {
          section: section.id,
          subscriptionTier,
          minTier: section.minTier,
        });
        return {
          hasAccess: false,
          reason: `This feature requires ${section.minTier} tier or higher`,
          upgradeRequired: true,
          requiredTier: section.minTier,
        };
      }
    }

    logInfo('Portal access granted', {
      section: section.id,
      userRole,
      subscriptionTier,
    });

    return { hasAccess: true };
  }

  /**
   * Check if user role meets minimum requirement
   */
  private static hasRequiredRole(
    userRole: TeamRole,
    minRole: TeamRole
  ): boolean {
    const roleHierarchy = {
      [TeamRole.OWNER]: 4,
      [TeamRole.ADMIN]: 3,
      [TeamRole.DEVELOPER]: 2,
      [TeamRole.VIEWER]: 1,
    };

    return roleHierarchy[userRole] >= roleHierarchy[minRole];
  }

  /**
   * Check if subscription tier meets minimum requirement
   */
  private static hasRequiredTier(
    userTier: SubscriptionTier,
    minTier: SubscriptionTier
  ): boolean {
    const tierHierarchy = {
      // [SubscriptionTier.FREE]: 0, // Commented out - FREE tier removed
      [SubscriptionTier.STARTER]: 1,
      [SubscriptionTier.PRO]: 2,
      [SubscriptionTier.ENTERPRISE]: 3, // Legacy alias for TEAM
      [SubscriptionTier.TEAM]: 3,
      [SubscriptionTier.BUSINESS]: 4,
      [SubscriptionTier.ENTERPRISE_PLUS]: 5,
    };

    return tierHierarchy[userTier] >= tierHierarchy[minTier];
  }

  /**
   * Filter portal sections based on user access
   */
  static filterSections(
    sections: PortalSection[],
    userRole: TeamRole,
    subscriptionTier: SubscriptionTier | null
  ): PortalSection[] {
    return sections.filter(section => {
      const access = this.checkAccess(section, userRole, subscriptionTier);
      return access.hasAccess;
    });
  }

  /**
   * Get all sections with access status
   */
  static getSectionsWithAccess(
    sections: PortalSection[],
    userRole: TeamRole,
    subscriptionTier: SubscriptionTier | null
  ): Array<PortalSection & { access: AccessControlResult }> {
    return sections.map(section => ({
      ...section,
      access: this.checkAccess(section, userRole, subscriptionTier),
    }));
  }

  /**
   * Get tier-specific feature limits
   */
  static getTierFeatureLimits(tier: SubscriptionTier): {
    maxAPIs: number;
    maxHoneypots: number;
    maxTeamMembers: number;
    maxMonitors: number;
    apiCallsPerMonth: number;
    hasAdvancedSecurity: boolean;
    hasAnalytics: boolean;
    hasCustomDomain: boolean;
    hasPrioritySupport: boolean;
  } {
    switch (tier) {
      // case SubscriptionTier.FREE: // Commented out - FREE tier removed
      //   return {
      //     maxAPIs: 3,
      //     maxHoneypots: 1,
      //     maxTeamMembers: 1,
      //     maxMonitors: 5,
      //     apiCallsPerMonth: 1000,
      //     hasAdvancedSecurity: false,
      //     hasAnalytics: false,
      //     hasCustomDomain: false,
      //     hasPrioritySupport: false,
      //   };
      case SubscriptionTier.STARTER:
        return {
          maxAPIs: 10,
          maxHoneypots: 1,
          maxTeamMembers: 1,
          maxMonitors: 20,
          apiCallsPerMonth: 10000,
          hasAdvancedSecurity: false,
          hasAnalytics: true,
          hasCustomDomain: false,
          hasPrioritySupport: false,
        };
      case SubscriptionTier.PRO:
        return {
          maxAPIs: 50,
          maxHoneypots: 3,
          maxTeamMembers: 5,
          maxMonitors: 100,
          apiCallsPerMonth: 100000,
          hasAdvancedSecurity: true,
          hasAnalytics: true,
          hasCustomDomain: true,
          hasPrioritySupport: false,
        };
      case SubscriptionTier.TEAM:
      case SubscriptionTier.ENTERPRISE:
        return {
          maxAPIs: 250,
          maxHoneypots: 10,
          maxTeamMembers: 10,
          maxMonitors: 500,
          apiCallsPerMonth: 500000,
          hasAdvancedSecurity: true,
          hasAnalytics: true,
          hasCustomDomain: true,
          hasPrioritySupport: true,
        };
      case SubscriptionTier.BUSINESS:
      case SubscriptionTier.ENTERPRISE_PLUS:
        return {
          maxAPIs: -1, // Unlimited
          maxHoneypots: -1, // Unlimited
          maxTeamMembers: -1, // Unlimited
          maxMonitors: -1, // Unlimited
          apiCallsPerMonth: -1, // Unlimited
          hasAdvancedSecurity: true,
          hasAnalytics: true,
          hasCustomDomain: true,
          hasPrioritySupport: true,
        };
      default:
        return this.getTierFeatureLimits(SubscriptionTier.STARTER); // Default to STARTER (FREE removed)
    }
  }

  /**
   * Check if user can perform an action (e.g., create API, add team member)
   */
  static async canPerformAction(
    action:
      | 'CREATE_API'
      | 'CREATE_HONEYPOT'
      | 'ADD_TEAM_MEMBER'
      | 'CREATE_MONITOR',
    currentCount: number,
    tier: SubscriptionTier
  ): Promise<{ allowed: boolean; reason?: string; limit?: number }> {
    const limits = this.getTierFeatureLimits(tier);

    let limit: number;
    let resource: string;

    switch (action) {
      case 'CREATE_API':
        limit = limits.maxAPIs;
        resource = 'APIs';
        break;
      case 'CREATE_HONEYPOT':
        limit = limits.maxHoneypots;
        resource = 'honeypots';
        break;
      case 'ADD_TEAM_MEMBER':
        limit = limits.maxTeamMembers;
        resource = 'team members';
        break;
      case 'CREATE_MONITOR':
        limit = limits.maxMonitors;
        resource = 'monitors';
        break;
      default:
        return { allowed: false, reason: 'Unknown action' };
    }

    // -1 means unlimited
    if (limit === -1) {
      return { allowed: true };
    }

    if (currentCount >= limit) {
      return {
        allowed: false,
        reason: `You've reached the maximum number of ${resource} (${limit}) for your ${tier} plan`,
        limit,
      };
    }

    return { allowed: true, limit };
  }

  /**
   * Get role permissions
   */
  static getRolePermissions(role: TeamRole): {
    canManageTeam: boolean;
    canManageProjects: boolean;
    canManageHoneypots: boolean;
    canManageMonitors: boolean;
    canViewAnalytics: boolean;
    canManageBilling: boolean;
    canDeleteProject: boolean;
    canInviteMembers: boolean;
  } {
    switch (role) {
      case TeamRole.OWNER:
        return {
          canManageTeam: true,
          canManageProjects: true,
          canManageHoneypots: true,
          canManageMonitors: true,
          canViewAnalytics: true,
          canManageBilling: true,
          canDeleteProject: true,
          canInviteMembers: true,
        };
      case TeamRole.ADMIN:
        return {
          canManageTeam: true,
          canManageProjects: true,
          canManageHoneypots: true,
          canManageMonitors: true,
          canViewAnalytics: true,
          canManageBilling: false,
          canDeleteProject: true,
          canInviteMembers: true,
        };
      case TeamRole.DEVELOPER:
        return {
          canManageTeam: false,
          canManageProjects: true,
          canManageHoneypots: true,
          canManageMonitors: true,
          canViewAnalytics: true,
          canManageBilling: false,
          canDeleteProject: false,
          canInviteMembers: false,
        };
      case TeamRole.VIEWER:
        return {
          canManageTeam: false,
          canManageProjects: false,
          canManageHoneypots: false,
          canManageMonitors: false,
          canViewAnalytics: true,
          canManageBilling: false,
          canDeleteProject: false,
          canInviteMembers: false,
        };
      default:
        return this.getRolePermissions(TeamRole.VIEWER);
    }
  }
}
