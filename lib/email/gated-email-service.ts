/**
 * Gated Email Service
 *
 * Wraps the base email service with subscription-based gating.
 * Free users on the hosted version cannot send emails (to protect email quota).
 *
 * @module lib/email/gated-email-service
 */

import { sendEmail, type EmailOptions } from './email-service';
import { canAccessFeature } from '@core/lib/auth/subscription-middleware';
import { logWarn, logInfo } from '@core/lib/logger';

export interface GatedEmailOptions extends EmailOptions {
  /**
   * User ID for subscription check. Required for gated emails.
   * System emails (no userId) bypass the gate.
   */
  userId?: string;

  /**
   * User role for privileged bypass.
   */
  userRole?: string;

  /**
   * If true, silently fail for free users instead of throwing.
   */
  silentFail?: boolean;
}

/**
 * Send an email with subscription gating.
 *
 * - System emails (no userId) are always sent
 * - Admin/Owner/Developer roles bypass the gate
 * - Users with STARTER+ subscription can send emails
 * - Free users are blocked (unless silentFail is true)
 *
 * @param options - Email options with optional userId for gating
 * @returns true if sent, false if blocked or failed
 */
export async function sendGatedEmail(
  options: GatedEmailOptions
): Promise<boolean> {
  const { userId, userRole, silentFail = false, ...emailOptions } = options;

  // System emails (no userId) bypass the gate
  if (!userId) {
    return sendEmail(emailOptions);
  }

  // Check if user can access email notifications
  const { authorized, reason } = await canAccessFeature(
    userId,
    'emailNotifications',
    userRole
  );

  if (!authorized) {
    logWarn('Email blocked - user does not have email access', {
      userId,
      reason,
      to: options.to,
      subject: options.subject,
    });

    if (silentFail) {
      return false;
    }

    // For non-silent mode, we still return false but log more prominently
    logInfo('Email gating: Free user attempted to trigger email', {
      userId,
      subject: options.subject,
    });
    return false;
  }

  // User is authorized, send the email
  return sendEmail(emailOptions);
}

/**
 * Quick check if user can send emails.
 * Use this before attempting email operations.
 */
export async function canSendEmail(
  userId: string,
  userRole?: string
): Promise<boolean> {
  const { authorized } = await canAccessFeature(
    userId,
    'emailNotifications',
    userRole
  );
  return authorized;
}

/**
 * Send alert email with subscription gating.
 * Convenience wrapper for alert-type emails.
 */
export async function sendGatedAlertEmail(
  userId: string,
  userRole: string | undefined,
  options: EmailOptions
): Promise<boolean> {
  return sendGatedEmail({
    ...options,
    userId,
    userRole,
    silentFail: true, // Alerts should fail silently for free users
  });
}

export { type EmailOptions } from './email-service';
