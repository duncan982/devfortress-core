/**
 * Email Service Wrapper
 * Generic email sending functionality using SendGrid
 * @deprecated This file is maintained for backward compatibility.
 * For new code, import sendEmail directly from '@core/lib/email/email-service'
 */

import { sendEmail as sendEmailViaSendGrid } from '@core/lib/email/email-service';

interface EmailOptions {
  to: string;
  subject: string;
  html: string;
  from?: string;
}

/**
 * Send an email using SendGrid
 * @deprecated Use sendEmail from '@core/lib/email/email-service' directly
 */
export async function sendEmail(options: EmailOptions): Promise<boolean> {
  return sendEmailViaSendGrid({
    to: options.to,
    subject: options.subject,
    html: options.html,
    from: options.from,
  });
}
