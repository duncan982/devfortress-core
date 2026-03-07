/**
 * Email Service
 * Handles sending transactional emails using Brevo (formerly Sendinblue) SMTP API
 */
import { logInfo, logError } from '@core/lib/logger';

const BREVO_API_URL = 'https://api.brevo.com/v3/smtp/email';

function getBrevoApiKey(): string | null {
  return process.env.BREVO_API_KEY || null;
}

const FROM_EMAIL = process.env.FROM_EMAIL || 'noreply@devfortress.dev';
const FROM_NAME = process.env.FROM_NAME || 'DevFortress';
const COMPANY_NAME = 'DevFortress';

export interface EmailOptions {
  to: string | string[];
  subject: string;
  html: string;
  text?: string;
  from?: string;
}

/**
 * Send an email using Brevo SMTP API
 */
export async function sendEmail(options: EmailOptions): Promise<boolean> {
  try {
    const apiKey = getBrevoApiKey();
    if (!apiKey) {
      logError('BREVO_API_KEY not configured');
      return false;
    }

    const recipients = Array.isArray(options.to) ? options.to : [options.to];

    const response = await fetch(BREVO_API_URL, {
      method: 'POST',
      headers: {
        accept: 'application/json',
        'api-key': apiKey,
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        sender: {
          name: FROM_NAME,
          email: options.from || FROM_EMAIL,
        },
        to: recipients.map(email => ({ email })),
        subject: options.subject,
        htmlContent: options.html,
        textContent: options.text,
      }),
    });

    if (!response.ok) {
      const errorBody = await response.text();
      logError('Brevo email sending failed', {
        status: response.status,
        body: errorBody,
      });
      return false;
    }

    logInfo('Email sent successfully via Brevo', { to: options.to });
    return true;
  } catch (error) {
    logError('Email sending exception', error);
    return false;
  }
}

/**
 * Send account verification email
 */
export async function sendVerificationEmail(
  email: string,
  verificationUrl: string
): Promise<boolean> {
  const html = `
    <!DOCTYPE html>
    <html>
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Verify Your Email</title>
      </head>
      <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
        <div style="background: linear-gradient(135deg, #0ea5e9 0%, #0284c7 100%); color: white; padding: 30px; border-radius: 10px 10px 0 0; text-align: center;">
          <h1 style="margin: 0; font-size: 28px;">${COMPANY_NAME}</h1>
          <p style="margin: 10px 0 0 0; font-size: 16px; opacity: 0.9;">Secure API Generation Platform</p>
        </div>
        
        <div style="background: #ffffff; padding: 40px; border: 1px solid #e5e7eb; border-top: none; border-radius: 0 0 10px 10px;">
          <h2 style="color: #0ea5e9; margin-top: 0;">Verify Your Email Address</h2>
          
          <p>Thank you for signing up with ${COMPANY_NAME}! To complete your registration and start building secure APIs, please verify your email address.</p>
          
          <div style="text-align: center; margin: 30px 0;">
            <a href="${verificationUrl}" style="display: inline-block; background: #0ea5e9; color: white; padding: 14px 40px; text-decoration: none; border-radius: 6px; font-weight: 600; font-size: 16px;">Verify Email</a>
          </div>
          
          <p style="color: #6b7280; font-size: 14px;">Or copy and paste this link into your browser:</p>
          <p style="color: #0ea5e9; word-break: break-all; font-size: 14px;">${verificationUrl}</p>
          
          <hr style="border: none; border-top: 1px solid #e5e7eb; margin: 30px 0;">
          
          <p style="color: #9ca3af; font-size: 13px; margin: 0;">
            If you didn't create an account with ${COMPANY_NAME}, you can safely ignore this email.
          </p>
        </div>
        
        <div style="text-align: center; padding: 20px; color: #9ca3af; font-size: 12px;">
          <p style="margin: 5px 0;">© ${new Date().getFullYear()} ${COMPANY_NAME}. All rights reserved.</p>
          <p style="margin: 5px 0;">
            <a href="${process.env.NEXT_PUBLIC_APP_URL}/privacy" style="color: #0ea5e9; text-decoration: none;">Privacy Policy</a> • 
            <a href="${process.env.NEXT_PUBLIC_APP_URL}/terms" style="color: #0ea5e9; text-decoration: none;">Terms of Service</a>
          </p>
        </div>
      </body>
    </html>
  `;

  const text = `
Verify Your Email - ${COMPANY_NAME}

Thank you for signing up! Please verify your email address by clicking the link below:

${verificationUrl}

If you didn't create an account with ${COMPANY_NAME}, you can safely ignore this email.

© ${new Date().getFullYear()} ${COMPANY_NAME}. All rights reserved.
  `.trim();

  return sendEmail({
    to: email,
    subject: `Verify your ${COMPANY_NAME} account`,
    html,
    text,
  });
}

/**
 * Send password reset email
 */
export async function sendPasswordResetEmail(
  email: string,
  resetUrl: string
): Promise<boolean> {
  const html = `
    <!DOCTYPE html>
    <html>
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Reset Your Password</title>
      </head>
      <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
        <div style="background: linear-gradient(135deg, #0ea5e9 0%, #0284c7 100%); color: white; padding: 30px; border-radius: 10px 10px 0 0; text-align: center;">
          <h1 style="margin: 0; font-size: 28px;">${COMPANY_NAME}</h1>
        </div>
        
        <div style="background: #ffffff; padding: 40px; border: 1px solid #e5e7eb; border-top: none; border-radius: 0 0 10px 10px;">
          <h2 style="color: #0ea5e9; margin-top: 0;">Reset Your Password</h2>
          
          <p>We received a request to reset your password. Click the button below to create a new password:</p>
          
          <div style="text-align: center; margin: 30px 0;">
            <a href="${resetUrl}" style="display: inline-block; background: #0ea5e9; color: white; padding: 14px 40px; text-decoration: none; border-radius: 6px; font-weight: 600; font-size: 16px;">Reset Password</a>
          </div>
          
          <p style="color: #6b7280; font-size: 14px;">This link will expire in 1 hour for security reasons.</p>
          
          <p style="color: #6b7280; font-size: 14px;">Or copy and paste this link into your browser:</p>
          <p style="color: #0ea5e9; word-break: break-all; font-size: 14px;">${resetUrl}</p>
          
          <hr style="border: none; border-top: 1px solid #e5e7eb; margin: 30px 0;">
          
          <p style="color: #9ca3af; font-size: 13px; margin: 0;">
            If you didn't request a password reset, please ignore this email or contact support if you have concerns.
          </p>
        </div>
        
        <div style="text-align: center; padding: 20px; color: #9ca3af; font-size: 12px;">
          <p style="margin: 5px 0;">© ${new Date().getFullYear()} ${COMPANY_NAME}. All rights reserved.</p>
        </div>
      </body>
    </html>
  `;

  const text = `
Reset Your Password - ${COMPANY_NAME}

We received a request to reset your password. Click the link below to create a new password:

${resetUrl}

This link will expire in 1 hour for security reasons.

If you didn't request a password reset, please ignore this email or contact support if you have concerns.

© ${new Date().getFullYear()} ${COMPANY_NAME}. All rights reserved.
  `.trim();

  return sendEmail({
    to: email,
    subject: `Reset your ${COMPANY_NAME} password`,
    html,
    text,
  });
}

/**
 * Send payment confirmation email
 */
export async function sendPaymentConfirmationEmail(
  email: string,
  amount: number,
  currency: string,
  credits: number
): Promise<boolean> {
  const formattedAmount = new Intl.NumberFormat('en-US', {
    style: 'currency',
    currency,
  }).format(amount / 100);

  const html = `
    <!DOCTYPE html>
    <html>
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Payment Confirmation</title>
      </head>
      <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
        <div style="background: linear-gradient(135deg, #22c55e 0%, #16a34a 100%); color: white; padding: 30px; border-radius: 10px 10px 0 0; text-align: center;">
          <h1 style="margin: 0; font-size: 28px;">✓ Payment Successful</h1>
        </div>
        
        <div style="background: #ffffff; padding: 40px; border: 1px solid #e5e7eb; border-top: none; border-radius: 0 0 10px 10px;">
          <h2 style="color: #22c55e; margin-top: 0;">Thank You for Your Purchase!</h2>
          
          <p>Your payment has been successfully processed. Here are the details:</p>
          
          <div style="background: #f9fafb; padding: 20px; border-radius: 8px; margin: 20px 0;">
            <table style="width: 100%; border-collapse: collapse;">
              <tr>
                <td style="padding: 8px 0; color: #6b7280;">Amount Paid:</td>
                <td style="padding: 8px 0; text-align: right; font-weight: 600;">${formattedAmount}</td>
              </tr>
              <tr>
                <td style="padding: 8px 0; color: #6b7280;">Credits Added:</td>
                <td style="padding: 8px 0; text-align: right; font-weight: 600; color: #22c55e;">${credits} credits</td>
              </tr>
            </table>
          </div>
          
          <p>You can now use these credits to generate APIs, deploy honeypots, and access premium features.</p>
          
          <div style="text-align: center; margin: 30px 0;">
            <a href="${process.env.NEXT_PUBLIC_APP_URL}/dashboard" style="display: inline-block; background: #0ea5e9; color: white; padding: 14px 40px; text-decoration: none; border-radius: 6px; font-weight: 600; font-size: 16px;">Go to Dashboard</a>
          </div>
        </div>
        
        <div style="text-align: center; padding: 20px; color: #9ca3af; font-size: 12px;">
          <p style="margin: 5px 0;">© ${new Date().getFullYear()} ${COMPANY_NAME}. All rights reserved.</p>
        </div>
      </body>
    </html>
  `;

  const text = `
Payment Confirmation - ${COMPANY_NAME}

Your payment has been successfully processed!

Amount Paid: ${formattedAmount}
Credits Added: ${credits} credits

You can now use these credits to generate APIs, deploy honeypots, and access premium features.

Visit your dashboard: ${process.env.NEXT_PUBLIC_APP_URL}/dashboard

© ${new Date().getFullYear()} ${COMPANY_NAME}. All rights reserved.
  `.trim();

  return sendEmail({
    to: email,
    subject: `Payment confirmation - ${formattedAmount}`,
    html,
    text,
  });
}

/**
 * Send GitHub Marketplace pending plan change notification
 */
export async function sendPendingPlanChangeEmail(
  email: string,
  currentPlan: string,
  newPlan: string,
  effectiveDate: string
): Promise<boolean> {
  const html = `
    <!DOCTYPE html>
    <html>
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Plan Change Notification</title>
      </head>
      <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
        <div style="background: linear-gradient(135deg, #3b82f6 0%, #1d4ed8 100%); color: white; padding: 30px; border-radius: 10px 10px 0 0; text-align: center;">
          <h1 style="margin: 0; font-size: 28px;">📅 Plan Change Scheduled</h1>
        </div>

        <div style="background: #ffffff; padding: 40px; border: 1px solid #e5e7eb; border-top: none; border-radius: 0 0 10px 10px;">
          <h2 style="color: #3b82f6; margin-top: 0;">Your Subscription Plan Will Change</h2>

          <p>Your GitHub Marketplace subscription plan change has been scheduled and will take effect on your next billing cycle.</p>

          <div style="background: #f9fafb; padding: 20px; border-radius: 8px; margin: 20px 0;">
            <table style="width: 100%; border-collapse: collapse;">
              <tr>
                <td style="padding: 8px 0; color: #6b7280;">Current Plan:</td>
                <td style="padding: 8px 0; text-align: right; font-weight: 600;">${currentPlan}</td>
              </tr>
              <tr>
                <td style="padding: 8px 0; color: #6b7280;">New Plan:</td>
                <td style="padding: 8px 0; text-align: right; font-weight: 600; color: #3b82f6;">${newPlan}</td>
              </tr>
              <tr>
                <td style="padding: 8px 0; color: #6b7280;">Effective Date:</td>
                <td style="padding: 8px 0; text-align: right; font-weight: 600;">${effectiveDate}</td>
              </tr>
            </table>
          </div>

          <p>If you have any questions about this change or need to modify your subscription, please contact our support team.</p>

          <div style="text-align: center; margin: 30px 0;">
            <a href="${process.env.NEXT_PUBLIC_APP_URL}/dashboard" style="display: inline-block; background: #0ea5e9; color: white; padding: 14px 40px; text-decoration: none; border-radius: 6px; font-weight: 600; font-size: 16px;">View Subscription</a>
          </div>
        </div>

        <div style="text-align: center; padding: 20px; color: #9ca3af; font-size: 12px;">
          <p style="margin: 5px 0;">© ${new Date().getFullYear()} ${COMPANY_NAME}. All rights reserved.</p>
        </div>
      </body>
    </html>
  `;

  const text = `
Plan Change Notification - ${COMPANY_NAME}

Your GitHub Marketplace subscription plan change has been scheduled.

Current Plan: ${currentPlan}
New Plan: ${newPlan}
Effective Date: ${effectiveDate}

If you have any questions, please contact support.

View your subscription: ${process.env.NEXT_PUBLIC_APP_URL}/dashboard

© ${new Date().getFullYear()} ${COMPANY_NAME}. All rights reserved.
  `.trim();

  return sendEmail({
    to: email,
    subject: `Plan change scheduled - ${newPlan}`,
    html,
    text,
  });
}

/**
 * Send credit usage alert
 */
export async function sendCreditAlertEmail(
  email: string,
  remainingCredits: number,
  threshold: number
): Promise<boolean> {
  const percentage = Math.round((remainingCredits / threshold) * 100);

  const html = `
    <!DOCTYPE html>
    <html>
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Credit Alert</title>
      </head>
      <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
        <div style="background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%); color: white; padding: 30px; border-radius: 10px 10px 0 0; text-align: center;">
          <h1 style="margin: 0; font-size: 28px;">⚠️ Low Credits Alert</h1>
        </div>
        
        <div style="background: #ffffff; padding: 40px; border: 1px solid #e5e7eb; border-top: none; border-radius: 0 0 10px 10px;">
          <h2 style="color: #f59e0b; margin-top: 0;">Your Credits Are Running Low</h2>
          
          <p>You currently have <strong>${remainingCredits} credits</strong> remaining (${percentage}% of your threshold).</p>
          
          <p>To continue using ${COMPANY_NAME} services without interruption, consider purchasing additional credits.</p>
          
          <div style="text-align: center; margin: 30px 0;">
            <a href="${process.env.NEXT_PUBLIC_APP_URL}/pricing" style="display: inline-block; background: #f59e0b; color: white; padding: 14px 40px; text-decoration: none; border-radius: 6px; font-weight: 600; font-size: 16px;">Purchase Credits</a>
          </div>
          
          <p style="color: #6b7280; font-size: 14px;">You can also view your credit usage history in your dashboard.</p>
        </div>
        
        <div style="text-align: center; padding: 20px; color: #9ca3af; font-size: 12px;">
          <p style="margin: 5px 0;">© ${new Date().getFullYear()} ${COMPANY_NAME}. All rights reserved.</p>
        </div>
      </body>
    </html>
  `;

  const text = `
Low Credits Alert - ${COMPANY_NAME}

Your credits are running low!

Remaining Credits: ${remainingCredits} (${percentage}% of threshold)

To continue using ${COMPANY_NAME} services without interruption, consider purchasing additional credits.

Purchase credits: ${process.env.NEXT_PUBLIC_APP_URL}/pricing

© ${new Date().getFullYear()} ${COMPANY_NAME}. All rights reserved.
  `.trim();

  return sendEmail({
    to: email,
    subject: `Low credits alert - ${remainingCredits} remaining`,
    html,
    text,
  });
}

/**
 * Send API generation completion email
 */
export async function sendAPIGenerationEmail(
  email: string,
  projectName: string,
  apiUrl: string
): Promise<boolean> {
  const html = `
    <!DOCTYPE html>
    <html>
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>API Generation Complete</title>
      </head>
      <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
        <div style="background: linear-gradient(135deg, #0ea5e9 0%, #0284c7 100%); color: white; padding: 30px; border-radius: 10px 10px 0 0; text-align: center;">
          <h1 style="margin: 0; font-size: 28px;">🚀 API Ready!</h1>
        </div>
        
        <div style="background: #ffffff; padding: 40px; border: 1px solid #e5e7eb; border-top: none; border-radius: 0 0 10px 10px;">
          <h2 style="color: #0ea5e9; margin-top: 0;">Your API is Ready to Use</h2>
          
          <p>Great news! Your API "<strong>${projectName}</strong>" has been successfully generated and is now ready for deployment.</p>
          
          <div style="background: #f0f9ff; padding: 20px; border-radius: 8px; border-left: 4px solid #0ea5e9; margin: 20px 0;">
            <p style="margin: 0; color: #0369a1;"><strong>What's included:</strong></p>
            <ul style="margin: 10px 0; padding-left: 20px; color: #0c4a6e;">
              <li>Complete API documentation</li>
              <li>Automated test suites</li>
              <li>Security scanning report</li>
              <li>Deployment configurations</li>
            </ul>
          </div>
          
          <div style="text-align: center; margin: 30px 0;">
            <a href="${apiUrl}" style="display: inline-block; background: #0ea5e9; color: white; padding: 14px 40px; text-decoration: none; border-radius: 6px; font-weight: 600; font-size: 16px;">View Your API</a>
          </div>
          
          <p style="color: #6b7280; font-size: 14px;">Ready to deploy? Check out our <a href="${process.env.NEXT_PUBLIC_APP_URL}/help/article/deployment-guide" style="color: #0ea5e9;">deployment guide</a> to get started.</p>
        </div>
        
        <div style="text-align: center; padding: 20px; color: #9ca3af; font-size: 12px;">
          <p style="margin: 5px 0;">© ${new Date().getFullYear()} ${COMPANY_NAME}. All rights reserved.</p>
        </div>
      </body>
    </html>
  `;

  const text = `
API Generation Complete - ${COMPANY_NAME}

Your API "${projectName}" is ready!

What's included:
- Complete API documentation
- Automated test suites
- Security scanning report
- Deployment configurations

View your API: ${apiUrl}

Ready to deploy? Check out our deployment guide: ${process.env.NEXT_PUBLIC_APP_URL}/help/article/deployment-guide

© ${new Date().getFullYear()} ${COMPANY_NAME}. All rights reserved.
  `.trim();

  return sendEmail({
    to: email,
    subject: `Your API "${projectName}" is ready!`,
    html,
    text,
  });
}

/**
 * Send welcome email for new users
 */
export async function sendWelcomeEmail(
  email: string,
  name: string
): Promise<boolean> {
  const html = `
    <!DOCTYPE html>
    <html>
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Welcome to ${COMPANY_NAME}</title>
      </head>
      <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
        <div style="background: linear-gradient(135deg, #0ea5e9 0%, #0284c7 100%); color: white; padding: 30px; border-radius: 10px 10px 0 0; text-align: center;">
          <h1 style="margin: 0; font-size: 32px;">Welcome to ${COMPANY_NAME}!</h1>
          <p style="margin: 10px 0 0 0; font-size: 18px; opacity: 0.9;">Let's Build Something Amazing</p>
        </div>
        
        <div style="background: #ffffff; padding: 40px; border: 1px solid #e5e7eb; border-top: none; border-radius: 0 0 10px 10px;">
          <p style="font-size: 18px; margin-top: 0;">Hi ${name},</p>
          
          <p>Thank you for joining ${COMPANY_NAME}! We're excited to help you build secure, production-ready APIs with the power of AI.</p>
          
          <h3 style="color: #0ea5e9;">🚀 Get Started in 3 Simple Steps:</h3>
          
          <div style="background: #f9fafb; padding: 20px; border-radius: 8px; margin: 20px 0;">
            <ol style="margin: 0; padding-left: 20px;">
              <li style="margin: 10px 0;"><strong>Connect Your Repository:</strong> Link your GitHub repo containing your API code.</li>
              <li style="margin: 10px 0;"><strong>Generate Your API:</strong> Let our AI analyze your code and create comprehensive documentation.</li>
              <li style="margin: 10px 0;"><strong>Deploy with Confidence:</strong> Use our security scans and deployment tools to go live.</li>
            </ol>
          </div>
          
          <div style="text-align: center; margin: 30px 0;">
            <a href="${process.env.NEXT_PUBLIC_APP_URL}/dashboard" style="display: inline-block; background: #0ea5e9; color: white; padding: 14px 40px; text-decoration: none; border-radius: 6px; font-weight: 600; font-size: 16px;">Start Building</a>
          </div>
          
          <h3 style="color: #0ea5e9;">📚 Helpful Resources:</h3>
          <ul style="list-style: none; padding: 0;">
            <li style="margin: 10px 0;">📖 <a href="${process.env.NEXT_PUBLIC_APP_URL}/help/article/getting-started" style="color: #0ea5e9; text-decoration: none;">Getting Started Guide</a></li>
            <li style="margin: 10px 0;">🛡️ <a href="${process.env.NEXT_PUBLIC_APP_URL}/help/article/security-best-practices" style="color: #0ea5e9; text-decoration: none;">Security Best Practices</a></li>
            <li style="margin: 10px 0;">💬 <a href="${process.env.NEXT_PUBLIC_APP_URL}/help" style="color: #0ea5e9; text-decoration: none;">Help Center</a></li>
          </ul>
          
          <p style="color: #6b7280; font-size: 14px; margin-top: 30px;">
            Need help? Our support team is here for you. Just reply to this email or visit our <a href="${process.env.NEXT_PUBLIC_APP_URL}/contact" style="color: #0ea5e9;">contact page</a>.
          </p>
        </div>
        
        <div style="text-align: center; padding: 20px; color: #9ca3af; font-size: 12px;">
          <p style="margin: 5px 0;">© ${new Date().getFullYear()} ${COMPANY_NAME}. All rights reserved.</p>
          <p style="margin: 5px 0;">
            <a href="${process.env.NEXT_PUBLIC_APP_URL}/privacy" style="color: #0ea5e9; text-decoration: none;">Privacy Policy</a> • 
            <a href="${process.env.NEXT_PUBLIC_APP_URL}/terms" style="color: #0ea5e9; text-decoration: none;">Terms of Service</a> • 
            <a href="${process.env.NEXT_PUBLIC_APP_URL}/contact" style="color: #0ea5e9; text-decoration: none;">Contact Support</a>
          </p>
        </div>
      </body>
    </html>
  `;

  const text = `
Welcome to ${COMPANY_NAME}!

Hi ${name},

Thank you for joining ${COMPANY_NAME}! We're excited to help you build secure, production-ready APIs with the power of AI.

🚀 Get Started in 3 Simple Steps:

1. Connect Your Repository: Link your GitHub repo containing your API code.
2. Generate Your API: Let our AI analyze your code and create comprehensive documentation.
3. Deploy with Confidence: Use our security scans and deployment tools to go live.

Start building: ${process.env.NEXT_PUBLIC_APP_URL}/dashboard

📚 Helpful Resources:
- Getting Started Guide: ${process.env.NEXT_PUBLIC_APP_URL}/help/article/getting-started
- Security Best Practices: ${process.env.NEXT_PUBLIC_APP_URL}/help/article/security-best-practices
- Help Center: ${process.env.NEXT_PUBLIC_APP_URL}/help

Need help? Our support team is here for you. Just reply to this email or visit ${process.env.NEXT_PUBLIC_APP_URL}/contact

© ${new Date().getFullYear()} ${COMPANY_NAME}. All rights reserved.
  `.trim();

  return sendEmail({
    to: email,
    subject: `Welcome to ${COMPANY_NAME} - Let's get started!`,
    html,
    text,
  });
}

export const EmailService = {
  sendEmail,
  sendVerificationEmail,
  sendPasswordResetEmail,
  sendPaymentConfirmationEmail,
  sendCreditAlertEmail,
  sendAPIGenerationEmail,
  sendWelcomeEmail,
};
