import { logInfo, logError } from '@core/lib/logger';
import { sendEmail } from '@core/lib/email/email-service';

// Email service configuration
const SENDGRID_API_KEY = process.env.SENDGRID_API_KEY;
const SUPPORT_EMAIL = process.env.SUPPORT_EMAIL || 'support@vortexsecure.dev';

interface ContactEmailData {
  name: string;
  email: string;
  subject: string;
  priority: string;
  message: string;
  userId?: string;
  ticketId: string;
}

/**
 * Send contact form submission to support email
 */
export async function sendContactEmail(
  data: ContactEmailData
): Promise<boolean> {
  if (!SENDGRID_API_KEY) {
    logError('SendGrid API key not configured', {
      context: 'sendContactEmail',
    });
    // Return true in development to allow testing without SendGrid
    if (process.env.NODE_ENV === 'development') {
      logInfo('Development mode: Skipping email send', { data });
      return true;
    }
    return false;
  }

  try {
    const subjectLabels: Record<string, string> = {
      technical: 'Technical Support',
      billing: 'Billing & Payments',
      account: 'Account & Security',
      features: 'Feature Request',
      bug: 'Bug Report',
      enterprise: 'Enterprise Inquiry',
      other: 'Other',
    };

    const priorityEmojis: Record<string, string> = {
      low: '🔵',
      medium: '🟡',
      high: '🟠',
      critical: '🔴',
    };

    const emailSubject = `[${data.ticketId}] ${priorityEmojis[data.priority]} ${subjectLabels[data.subject]} - ${data.name}`;

    const htmlContent = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Contact Form Submission</title>
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
      line-height: 1.6;
      color: #333;
      max-width: 600px;
      margin: 0 auto;
      padding: 20px;
    }
    .header {
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      color: white;
      padding: 30px;
      border-radius: 8px 8px 0 0;
      text-align: center;
    }
    .header h1 {
      margin: 0;
      font-size: 24px;
    }
    .content {
      background: #f9fafb;
      padding: 30px;
      border: 1px solid #e5e7eb;
      border-top: none;
    }
    .field {
      margin-bottom: 20px;
    }
    .label {
      font-weight: 600;
      color: #374151;
      margin-bottom: 5px;
      display: block;
    }
    .value {
      color: #1f2937;
      padding: 10px;
      background: white;
      border-radius: 4px;
      border: 1px solid #d1d5db;
    }
    .message {
      white-space: pre-wrap;
      word-wrap: break-word;
    }
    .priority {
      display: inline-block;
      padding: 4px 12px;
      border-radius: 12px;
      font-size: 12px;
      font-weight: 600;
      text-transform: uppercase;
    }
    .priority-low { background: #dbeafe; color: #1e40af; }
    .priority-medium { background: #fef3c7; color: #92400e; }
    .priority-high { background: #fed7aa; color: #9a3412; }
    .priority-critical { background: #fee2e2; color: #991b1b; }
    .footer {
      background: #f9fafb;
      padding: 20px;
      text-align: center;
      color: #6b7280;
      font-size: 14px;
      border: 1px solid #e5e7eb;
      border-top: none;
      border-radius: 0 0 8px 8px;
    }
  </style>
</head>
<body>
  <div class="header">
    <h1>🎫 New Support Request</h1>
    <p style="margin: 10px 0 0 0; opacity: 0.9;">${data.ticketId}</p>
  </div>
  
  <div class="content">
    <div class="field">
      <span class="label">From:</span>
      <div class="value">${data.name}</div>
    </div>
    
    <div class="field">
      <span class="label">Email:</span>
      <div class="value">
        <a href="mailto:${data.email}" style="color: #2563eb; text-decoration: none;">${data.email}</a>
      </div>
    </div>
    
    ${
      data.userId
        ? `
    <div class="field">
      <span class="label">User ID:</span>
      <div class="value">${data.userId}</div>
    </div>
    `
        : ''
    }
    
    <div class="field">
      <span class="label">Subject:</span>
      <div class="value">${subjectLabels[data.subject]}</div>
    </div>
    
    <div class="field">
      <span class="label">Priority:</span>
      <div class="value">
        <span class="priority priority-${data.priority}">
          ${priorityEmojis[data.priority]} ${data.priority}
        </span>
      </div>
    </div>
    
    <div class="field">
      <span class="label">Message:</span>
      <div class="value message">${data.message}</div>
    </div>
  </div>
  
  <div class="footer">
    <p>This message was sent via the VortexSecure contact form.</p>
    <p>Reply directly to this email to respond to ${data.name}.</p>
  </div>
</body>
</html>
    `.trim();

    const textContent = `
New Support Request - ${data.ticketId}

From: ${data.name}
Email: ${data.email}
${data.userId ? `User ID: ${data.userId}\n` : ''}
Subject: ${subjectLabels[data.subject]}
Priority: ${data.priority.toUpperCase()}

Message:
${data.message}

---
This message was sent via the VortexSecure contact form.
Reply directly to this email to respond to ${data.name}.
    `.trim();

    const emailSent = await sendEmail({
      to: SUPPORT_EMAIL,
      subject: emailSubject,
      html: htmlContent,
      text: textContent,
    });

    if (!emailSent) {
      logError('Failed to send contact email via SendGrid', {
        ticketId: data.ticketId,
      });
      return false;
    }

    logInfo('Contact email sent successfully', {
      ticketId: data.ticketId,
      subject: data.subject,
      priority: data.priority,
    });

    return true;
  } catch (error) {
    logError('Error sending contact email', {
      error,
      ticketId: data.ticketId,
    });
    return false;
  }
}

/**
 * Send confirmation email to user
 */
export async function sendConfirmationEmail(
  userEmail: string,
  userName: string,
  ticketId: string
): Promise<boolean> {
  if (!SENDGRID_API_KEY) {
    if (process.env.NODE_ENV === 'development') {
      logInfo('Development mode: Skipping confirmation email', {
        userEmail,
        ticketId,
      });
      return true;
    }
    return false;
  }

  try {
    const htmlContent = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Support Request Received</title>
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
      line-height: 1.6;
      color: #333;
      max-width: 600px;
      margin: 0 auto;
      padding: 20px;
    }
    .header {
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      color: white;
      padding: 30px;
      border-radius: 8px 8px 0 0;
      text-align: center;
    }
    .content {
      background: #f9fafb;
      padding: 30px;
      border: 1px solid #e5e7eb;
      border-top: none;
    }
    .ticket-id {
      background: white;
      border: 2px dashed #d1d5db;
      padding: 15px;
      border-radius: 8px;
      text-align: center;
      margin: 20px 0;
      font-family: monospace;
      font-size: 18px;
      font-weight: bold;
      color: #1f2937;
    }
    .cta {
      text-align: center;
      margin: 30px 0;
    }
    .button {
      display: inline-block;
      padding: 12px 30px;
      background: #2563eb;
      color: white !important;
      text-decoration: none;
      border-radius: 6px;
      font-weight: 600;
    }
    .footer {
      background: #f9fafb;
      padding: 20px;
      text-align: center;
      color: #6b7280;
      font-size: 14px;
      border: 1px solid #e5e7eb;
      border-top: none;
      border-radius: 0 0 8px 8px;
    }
  </style>
</head>
<body>
  <div class="header">
    <h1>✅ We've Received Your Message</h1>
  </div>
  
  <div class="content">
    <p>Hi ${userName},</p>
    
    <p>Thank you for contacting VortexSecure support. We've received your message and our team will review it shortly.</p>
    
    <div class="ticket-id">
      Ticket ID: ${ticketId}
    </div>
    
    <p>We typically respond within:</p>
    <ul>
      <li><strong>Low priority:</strong> 48 hours</li>
      <li><strong>Medium priority:</strong> 24 hours</li>
      <li><strong>High priority:</strong> 12 hours</li>
      <li><strong>Critical priority:</strong> 4 hours</li>
    </ul>
    
    <p>You can check your dashboard for updates or reply directly to this email with any additional information.</p>
    
    <div class="cta">
      <a href="${process.env.NEXTAUTH_URL}/dashboard" class="button">Go to Dashboard</a>
    </div>
  </div>
  
  <div class="footer">
    <p>Need immediate help? Check our <a href="${process.env.NEXTAUTH_URL}/help" style="color: #2563eb;">Help Center</a></p>
    <p>© 2025 DevFortress. All rights reserved.</p>
  </div>
</body>
</html>
    `.trim();

    const textContent = `
We've Received Your Message

Hi ${userName},

Thank you for contacting VortexSecure support. We've received your message and our team will review it shortly.

Ticket ID: ${ticketId}

We typically respond within:
- Low priority: 48 hours
- Medium priority: 24 hours
- High priority: 12 hours
- Critical priority: 4 hours

You can check your dashboard for updates or reply directly to this email with any additional information.

Need immediate help? Check our Help Center at ${process.env.NEXTAUTH_URL}/help

© 2025 DevFortress. All rights reserved.
    `.trim();

    const emailSent = await sendEmail({
      to: userEmail,
      subject: `Support Request Received - ${ticketId}`,
      html: htmlContent,
      text: textContent,
    });

    if (!emailSent) {
      logError('Failed to send confirmation email via SendGrid', {
        ticketId,
      });
      return false;
    }

    logInfo('Confirmation email sent successfully', {
      ticketId,
      userEmail,
    });

    return true;
  } catch (error) {
    logError('Error sending confirmation email', {
      error,
      ticketId,
    });
    return false;
  }
}
