/**
 * Permission Middleware
 * Role-based access control and permission checking
 */

import { NextRequest, NextResponse } from 'next/server';
import { getRouteSession } from '@core/lib/auth/session';
import { UserRole } from '@prisma/client';
import { logWarn, logInfo, logError } from '@core/lib/logger';

export interface PermissionCheck {
  requiredRoles?: UserRole[];
  requiredPermissions?: string[];
  allowPublic?: boolean;
}

export interface AuthenticatedUser {
  id: string;
  email: string;
  role: UserRole;
  hasGitHubAccount: boolean;
  supabaseUserId: string;
}

export interface AuthenticatedRequest extends NextRequest {
  user?: AuthenticatedUser;
}

/**
 * Check if user has required permissions
 */
export function hasPermission(
  userRole: UserRole,
  requiredRoles?: UserRole[],
  requiredPermissions?: string[]
): boolean {
  // Check role-based access
  if (requiredRoles && requiredRoles.length > 0) {
    if (!requiredRoles.includes(userRole)) {
      return false;
    }
  }

  // Check permission-based access (for future granular permissions)
  if (requiredPermissions && requiredPermissions.length > 0) {
    // For now, map roles to permissions
    // This can be expanded to a proper permission system
    const rolePermissions: Record<UserRole, string[]> = {
      [UserRole.ADMIN]: ['*'], // All permissions
      [UserRole.OWNER]: ['manage_team', 'manage_honeypots', 'view_analytics'],
      [UserRole.DEVELOPER]: ['manage_honeypots', 'view_analytics'],
      [UserRole.VIEWER]: ['view_analytics'],
    };

    const userPermissions = rolePermissions[userRole] || [];
    const hasAllPermissions = requiredPermissions.every(
      permission =>
        userPermissions.includes(permission) || userPermissions.includes('*')
    );

    if (!hasAllPermissions) {
      return false;
    }
  }
  return true;
}

/**
 * Middleware function for permission checking
 */
export async function withPermissions(
  req: NextRequest,
  check: PermissionCheck
): Promise<{
  allowed: boolean;
  response?: NextResponse;
  user?: AuthenticatedUser;
}> {
  const { requiredRoles, requiredPermissions, allowPublic = false } = check;

  // Get client IP and user agent for audit logging
  const ipAddress =
    req.headers.get('x-forwarded-for') ||
    req.headers.get('x-real-ip') ||
    'unknown';
  const userAgent = req.headers.get('user-agent') || 'unknown';
  const endpoint = req.nextUrl.pathname;

  try {
    const session = await getRouteSession();

    if (!session) {
      if (allowPublic) {
        logInfo('Public access granted', { endpoint, ipAddress });
        return { allowed: true };
      }

      logWarn('Unauthorized access attempt', {
        endpoint,
        ipAddress,
        userAgent,
        reason: 'No valid session',
      });

      return {
        allowed: false,
        response: NextResponse.json(
          { error: 'Authentication required' },
          { status: 401 }
        ),
      };
    }

    // Check permissions
    const hasRequiredPermission = hasPermission(
      session.user.role,
      requiredRoles,
      requiredPermissions
    );

    if (!hasRequiredPermission) {
      logWarn('Insufficient permissions', {
        userId: session.user.id,
        userRole: session.user.role,
        requiredRoles,
        requiredPermissions,
        endpoint,
        ipAddress,
        userAgent,
      });

      return {
        allowed: false,
        response: NextResponse.json(
          { error: 'Insufficient permissions' },
          { status: 403 }
        ),
      };
    }

    // Access granted
    logInfo('Access granted', {
      userId: session.user.id,
      userRole: session.user.role,
      endpoint,
      ipAddress,
      userAgent,
    });

    // Create authenticated request
    const authenticatedReq = req as AuthenticatedRequest;
    authenticatedReq.user = session.user;

    return { allowed: true, user: session.user };
  } catch (error) {
    logError('Permission check error', {
      error: error instanceof Error ? error.message : String(error),
      endpoint,
      ipAddress,
      userAgent,
    });

    return {
      allowed: false,
      response: NextResponse.json(
        { error: 'Internal server error' },
        { status: 500 }
      ),
    };
  }
}

/**
 * Higher-order function to create permission-protected API routes
 */
export function withRoleProtection(requiredRoles: UserRole[]) {
  return async function (
    req: NextRequest,
    handler: (
      req: AuthenticatedRequest,
      user: AuthenticatedUser
    ) => Promise<NextResponse>
  ): Promise<NextResponse> {
    const result = await withPermissions(req, { requiredRoles });

    if (!result.allowed) {
      return result.response!;
    }

    if (!result.user) {
      return NextResponse.json({ error: 'User not found' }, { status: 500 });
    }

    return handler(req as AuthenticatedRequest, result.user);
  };
}

/**
 * Predefined permission checks for common use cases
 */
export const PermissionChecks = {
  // Admin only
  ADMIN_ONLY: { requiredRoles: [UserRole.ADMIN] },

  // Owner and above
  OWNER_PLUS: { requiredRoles: [UserRole.ADMIN, UserRole.OWNER] },

  // Developer and above
  DEVELOPER_PLUS: {
    requiredRoles: [UserRole.ADMIN, UserRole.OWNER, UserRole.DEVELOPER],
  },

  // Any authenticated user
  AUTHENTICATED: { requiredRoles: [] },

  // Public access
  PUBLIC: { allowPublic: true },
};
