/**
 * Account Lock Service
 * Enterprise-tier feature: Automated account locking based on threat detection
 * Integrates with playbook engine for condition-based locking
 */

import { logInfo, logError, logWarn } from '@core/lib/logger';

/* ─── Types ─── */

export enum AccountLockReason {
  BRUTE_FORCE = 'brute_force',
  CREDENTIAL_STUFFING = 'credential_stuffing',
  TOKEN_REPLAY = 'token_replay',
  PRIVILEGE_ESCALATION = 'privilege_escalation',
  MANUAL_ADMIN = 'manual_admin',
  PLAYBOOK_TRIGGERED = 'playbook_triggered',
  SUSPICIOUS_ACTIVITY = 'suspicious_activity',
  EXCESSIVE_FAILED_LOGINS = 'excessive_failed_logins',
}

export enum AccountLockStatus {
  ACTIVE = 'active',
  LOCKED = 'locked',
  TEMPORARILY_LOCKED = 'temporarily_locked',
  PENDING_REVIEW = 'pending_review',
}

export interface AccountLockRecord {
  userId: string;
  status: AccountLockStatus;
  reason: AccountLockReason;
  lockedAt: Date;
  expiresAt: Date | null;
  lockedBy: 'system' | 'admin' | 'playbook';
  unlockToken: string | null;
  metadata: Record<string, unknown>;
}

export interface LockPolicy {
  maxFailedAttempts: number;
  lockDurationMinutes: number;
  escalationMultiplier: number;
  maxLockDurationMinutes: number;
  autoUnlock: boolean;
  notifyAdmin: boolean;
  notifyUser: boolean;
}

export interface LockResult {
  success: boolean;
  userId: string;
  status: AccountLockStatus;
  reason: AccountLockReason;
  expiresAt: Date | null;
  sessionsRevoked: number;
  message: string;
}

export interface UnlockResult {
  success: boolean;
  userId: string;
  previousStatus: AccountLockStatus;
  message: string;
}

/* ─── Default Policies ─── */

const DEFAULT_LOCK_POLICIES: Record<AccountLockReason, LockPolicy> = {
  [AccountLockReason.BRUTE_FORCE]: {
    maxFailedAttempts: 5,
    lockDurationMinutes: 30,
    escalationMultiplier: 2,
    maxLockDurationMinutes: 1440, // 24 hours
    autoUnlock: true,
    notifyAdmin: true,
    notifyUser: true,
  },
  [AccountLockReason.CREDENTIAL_STUFFING]: {
    maxFailedAttempts: 3,
    lockDurationMinutes: 60,
    escalationMultiplier: 3,
    maxLockDurationMinutes: 4320, // 72 hours
    autoUnlock: true,
    notifyAdmin: true,
    notifyUser: true,
  },
  [AccountLockReason.TOKEN_REPLAY]: {
    maxFailedAttempts: 1,
    lockDurationMinutes: 120,
    escalationMultiplier: 4,
    maxLockDurationMinutes: 10080, // 7 days
    autoUnlock: false,
    notifyAdmin: true,
    notifyUser: true,
  },
  [AccountLockReason.PRIVILEGE_ESCALATION]: {
    maxFailedAttempts: 1,
    lockDurationMinutes: 0, // Permanent until admin review
    escalationMultiplier: 1,
    maxLockDurationMinutes: 0, // No auto-unlock
    autoUnlock: false,
    notifyAdmin: true,
    notifyUser: true,
  },
  [AccountLockReason.MANUAL_ADMIN]: {
    maxFailedAttempts: 1,
    lockDurationMinutes: 0,
    escalationMultiplier: 1,
    maxLockDurationMinutes: 0,
    autoUnlock: false,
    notifyAdmin: false,
    notifyUser: true,
  },
  [AccountLockReason.PLAYBOOK_TRIGGERED]: {
    maxFailedAttempts: 1,
    lockDurationMinutes: 60,
    escalationMultiplier: 2,
    maxLockDurationMinutes: 1440,
    autoUnlock: true,
    notifyAdmin: true,
    notifyUser: true,
  },
  [AccountLockReason.SUSPICIOUS_ACTIVITY]: {
    maxFailedAttempts: 1,
    lockDurationMinutes: 120,
    escalationMultiplier: 2,
    maxLockDurationMinutes: 2880, // 48 hours
    autoUnlock: true,
    notifyAdmin: true,
    notifyUser: true,
  },
  [AccountLockReason.EXCESSIVE_FAILED_LOGINS]: {
    maxFailedAttempts: 10,
    lockDurationMinutes: 15,
    escalationMultiplier: 2,
    maxLockDurationMinutes: 720, // 12 hours
    autoUnlock: true,
    notifyAdmin: false,
    notifyUser: true,
  },
};

/* ─── Service ─── */

class AccountLockService {
  private locks: Map<string, AccountLockRecord> = new Map();
  private failedAttempts: Map<
    string,
    { count: number; firstAttempt: Date; lockCount: number }
  > = new Map();
  private policies: Map<AccountLockReason, LockPolicy> = new Map();
  private lockHistory: Array<{
    userId: string;
    action: 'lock' | 'unlock';
    timestamp: Date;
    details: Record<string, unknown>;
  }> = [];

  constructor() {
    // Initialize with default policies
    for (const [reason, policy] of Object.entries(DEFAULT_LOCK_POLICIES)) {
      this.policies.set(reason as AccountLockReason, { ...policy });
    }

    logInfo('AccountLockService initialized', {
      policiesLoaded: this.policies.size,
    });
  }

  /**
   * Record a failed authentication attempt and auto-lock if threshold exceeded
   */
  recordFailedAttempt(
    userId: string,
    reason: AccountLockReason = AccountLockReason.EXCESSIVE_FAILED_LOGINS
  ): LockResult | null {
    const attempts = this.failedAttempts.get(userId) || {
      count: 0,
      firstAttempt: new Date(),
      lockCount: 0,
    };

    attempts.count += 1;
    this.failedAttempts.set(userId, attempts);

    const policy = this.policies.get(reason) || DEFAULT_LOCK_POLICIES[reason];

    logInfo('Failed auth attempt recorded', {
      userId,
      attemptCount: attempts.count,
      threshold: policy.maxFailedAttempts,
      reason,
    });

    if (attempts.count >= policy.maxFailedAttempts) {
      return this.lockAccount(userId, reason, 'system');
    }

    return null;
  }

  /**
   * Lock an account with the specified reason
   */
  lockAccount(
    userId: string,
    reason: AccountLockReason,
    lockedBy: 'system' | 'admin' | 'playbook' = 'system',
    metadata: Record<string, unknown> = {}
  ): LockResult {
    try {
      const policy = this.policies.get(reason) || DEFAULT_LOCK_POLICIES[reason];
      const attempts = this.failedAttempts.get(userId);
      const lockCount = attempts?.lockCount || 0;

      // Calculate lock duration with escalation
      let lockDurationMinutes = policy.lockDurationMinutes;
      if (lockCount > 0 && policy.escalationMultiplier > 1) {
        lockDurationMinutes = Math.min(
          policy.lockDurationMinutes *
            Math.pow(policy.escalationMultiplier, lockCount),
          policy.maxLockDurationMinutes || Infinity
        );
      }

      const now = new Date();
      const expiresAt =
        lockDurationMinutes > 0
          ? new Date(now.getTime() + lockDurationMinutes * 60 * 1000)
          : null; // null = permanent until manual unlock

      const status = expiresAt
        ? AccountLockStatus.TEMPORARILY_LOCKED
        : AccountLockStatus.LOCKED;

      const unlockToken = this.generateUnlockToken();

      const lockRecord: AccountLockRecord = {
        userId,
        status,
        reason,
        lockedAt: now,
        expiresAt,
        lockedBy,
        unlockToken,
        metadata: {
          ...metadata,
          failedAttempts: attempts?.count || 0,
          lockCount: lockCount + 1,
          lockDurationMinutes,
          policyApplied: reason,
        },
      };

      this.locks.set(userId, lockRecord);

      // Update lock count for escalation tracking
      if (attempts) {
        attempts.lockCount += 1;
        attempts.count = 0; // Reset failed attempts after lock
      }

      // Record in history
      this.lockHistory.push({
        userId,
        action: 'lock',
        timestamp: now,
        details: {
          reason,
          lockedBy,
          status,
          expiresAt: expiresAt?.toISOString() || 'permanent',
          lockDurationMinutes,
        },
      });

      // Simulate session revocation (in production, integrate with session service)
      const sessionsRevoked = this.revokeUserSessions(userId);

      logWarn('Account locked', {
        userId,
        reason,
        lockedBy,
        status,
        expiresAt: expiresAt?.toISOString() || 'permanent',
        lockDurationMinutes,
        sessionsRevoked,
        lockCount: lockCount + 1,
      });

      return {
        success: true,
        userId,
        status,
        reason,
        expiresAt,
        sessionsRevoked,
        message: expiresAt
          ? `Account temporarily locked for ${lockDurationMinutes} minutes due to ${reason}`
          : `Account permanently locked due to ${reason}. Admin review required.`,
      };
    } catch (error) {
      logError('Failed to lock account', { userId, reason, error });
      return {
        success: false,
        userId,
        status: AccountLockStatus.ACTIVE,
        reason,
        expiresAt: null,
        sessionsRevoked: 0,
        message: `Failed to lock account: ${error instanceof Error ? error.message : 'Unknown error'}`,
      };
    }
  }

  /**
   * Unlock an account (admin action or auto-unlock on expiry)
   */
  unlockAccount(
    userId: string,
    unlockedBy: 'admin' | 'system' | 'token' = 'admin'
  ): UnlockResult {
    const lock = this.locks.get(userId);

    if (!lock) {
      return {
        success: false,
        userId,
        previousStatus: AccountLockStatus.ACTIVE,
        message: 'Account is not locked',
      };
    }

    const previousStatus = lock.status;
    this.locks.delete(userId);
    this.failedAttempts.delete(userId);

    this.lockHistory.push({
      userId,
      action: 'unlock',
      timestamp: new Date(),
      details: {
        previousStatus,
        unlockedBy,
        wasLocked: lock.lockedAt.toISOString(),
        reason: lock.reason,
      },
    });

    logInfo('Account unlocked', {
      userId,
      previousStatus,
      unlockedBy,
      wasLockedSince: lock.lockedAt.toISOString(),
      originalReason: lock.reason,
    });

    return {
      success: true,
      userId,
      previousStatus,
      message: `Account unlocked successfully by ${unlockedBy}`,
    };
  }

  /**
   * Check if an account is currently locked
   */
  isAccountLocked(userId: string): {
    locked: boolean;
    record: AccountLockRecord | null;
  } {
    const lock = this.locks.get(userId);

    if (!lock) {
      return { locked: false, record: null };
    }

    // Check if temporary lock has expired
    if (lock.expiresAt && new Date() > lock.expiresAt) {
      const policy = this.policies.get(lock.reason);
      if (policy?.autoUnlock) {
        this.unlockAccount(userId, 'system');
        return { locked: false, record: null };
      }
      // Move to pending review if auto-unlock is disabled
      lock.status = AccountLockStatus.PENDING_REVIEW;
    }

    return { locked: true, record: lock };
  }

  /**
   * Get lock history for a user
   */
  getLockHistory(
    userId: string
  ): Array<{
    action: string;
    timestamp: Date;
    details: Record<string, unknown>;
  }> {
    return this.lockHistory.filter(h => h.userId === userId);
  }

  /**
   * Get all currently locked accounts
   */
  getLockedAccounts(): AccountLockRecord[] {
    return Array.from(this.locks.values());
  }

  /**
   * Update a lock policy
   */
  updatePolicy(reason: AccountLockReason, policy: Partial<LockPolicy>): void {
    const existing = this.policies.get(reason) || DEFAULT_LOCK_POLICIES[reason];
    this.policies.set(reason, { ...existing, ...policy });
    logInfo('Lock policy updated', { reason, policy });
  }

  /**
   * Get current policy for a reason
   */
  getPolicy(reason: AccountLockReason): LockPolicy {
    return this.policies.get(reason) || DEFAULT_LOCK_POLICIES[reason];
  }

  /**
   * Get service statistics
   */
  getStats(): {
    activeLocksCount: number;
    totalLockEvents: number;
    totalUnlockEvents: number;
    failedAttemptsTracked: number;
    locksByReason: Record<string, number>;
  } {
    const locksByReason: Record<string, number> = {};
    for (const lock of this.locks.values()) {
      locksByReason[lock.reason] = (locksByReason[lock.reason] || 0) + 1;
    }

    return {
      activeLocksCount: this.locks.size,
      totalLockEvents: this.lockHistory.filter(h => h.action === 'lock').length,
      totalUnlockEvents: this.lockHistory.filter(h => h.action === 'unlock')
        .length,
      failedAttemptsTracked: this.failedAttempts.size,
      locksByReason,
    };
  }

  /* ─── Private Helpers ─── */

  private revokeUserSessions(userId: string): number {
    // In production, this integrates with the session service
    // to invalidate all active sessions for the locked user
    logInfo('Revoking sessions for locked account', { userId });
    // Simulated: return count of revoked sessions
    return Math.floor(Math.random() * 3) + 1;
  }

  private generateUnlockToken(): string {
    const chars =
      'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let token = '';
    for (let i = 0; i < 48; i++) {
      token += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return token;
  }
}

/* ─── Singleton Export ─── */

export const accountLockService = new AccountLockService();
