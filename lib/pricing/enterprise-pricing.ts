/**
 * Enterprise Pricing Calculator Service
 * Generates custom quotes for enterprise customers
 */

import { prisma } from '@core/lib/prisma';
import { logInfo, logError, logWarn } from '@core/lib/logger';
import { sendEmail } from '@core/lib/email/resend';
import { z } from 'zod';

enum QuoteStatus {
  PENDING = 'PENDING',
  SENT = 'SENT',
  ACCEPTED = 'ACCEPTED',
  REJECTED = 'REJECTED',
  EXPIRED = 'EXPIRED',
}

interface PricingInput {
  companyName: string;
  contactName: string;
  contactEmail: string;
  teamSize: number;
  expectedAPIs: number;
  expectedEventsPerMonth: number;
  requiresSupport: boolean;
  requiresSLA: boolean;
  requiresCustomIntegration: boolean;
  additionalNotes?: string;
}

interface PricingBreakdown {
  basePrice: number;
  perUserPrice: number;
  apiPrice: number;
  eventsPrice: number;
  supportPrice: number;
  slaPrice: number;
  customIntegrationPrice: number;
  subtotal: number;
  discount: number;
  total: number;
  currency: string;
}

const pricingBreakdownSchema: z.ZodType<PricingBreakdown> = z.object({
  basePrice: z.number(),
  perUserPrice: z.number(),
  apiPrice: z.number(),
  eventsPrice: z.number(),
  supportPrice: z.number(),
  slaPrice: z.number(),
  customIntegrationPrice: z.number(),
  subtotal: z.number(),
  discount: z.number(),
  total: z.number(),
  currency: z.string(),
});

interface Quote {
  id: string;
  companyName: string;
  contactName: string;
  contactEmail: string;
  breakdown: PricingBreakdown;
  status: QuoteStatus;
  validUntil: Date;
  createdAt: Date;
}

export class EnterprisePricingService {
  // Base pricing constants
  private static readonly BASE_MONTHLY_PRICE = 299; // per user minimum
  private static readonly VOLUME_DISCOUNT_THRESHOLD = 20; // team size
  private static readonly VOLUME_DISCOUNT_RATE = 0.1; // 10% discount
  private static readonly API_PRICE_PER_UNIT = 50; // per API after first 10
  private static readonly EVENTS_PRICE_PER_1000 = 10; // per 1000 events after first 10000
  private static readonly SUPPORT_PREMIUM_PRICE = 500; // monthly
  private static readonly SLA_PRICE = 1000; // monthly
  private static readonly CUSTOM_INTEGRATION_BASE = 5000; // one-time

  /**
   * Calculate enterprise pricing based on inputs
   */
  static calculatePricing(input: PricingInput): PricingBreakdown {
    // Base price (per user)
    const basePrice = this.BASE_MONTHLY_PRICE * input.teamSize;

    // Additional API costs (after first 10 free)
    const additionalAPIs = Math.max(0, input.expectedAPIs - 10);
    const apiPrice = additionalAPIs * this.API_PRICE_PER_UNIT;

    // Event costs (after first 10,000 free)
    const additionalEvents = Math.max(0, input.expectedEventsPerMonth - 10000);
    const eventsPrice =
      Math.ceil(additionalEvents / 1000) * this.EVENTS_PRICE_PER_1000;

    // Support costs
    const supportPrice = input.requiresSupport ? this.SUPPORT_PREMIUM_PRICE : 0;

    // SLA costs
    const slaPrice = input.requiresSLA ? this.SLA_PRICE : 0;

    // Custom integration (one-time, amortized over 12 months)
    const customIntegrationPrice = input.requiresCustomIntegration
      ? this.CUSTOM_INTEGRATION_BASE / 12
      : 0;

    // Calculate subtotal
    const subtotal =
      basePrice +
      apiPrice +
      eventsPrice +
      supportPrice +
      slaPrice +
      customIntegrationPrice;

    // Apply volume discount
    let discount = 0;
    if (input.teamSize >= this.VOLUME_DISCOUNT_THRESHOLD) {
      discount = subtotal * this.VOLUME_DISCOUNT_RATE;
    }

    // Calculate total
    const total = subtotal - discount;

    return {
      basePrice,
      perUserPrice: this.BASE_MONTHLY_PRICE,
      apiPrice,
      eventsPrice,
      supportPrice,
      slaPrice,
      customIntegrationPrice,
      subtotal,
      discount,
      total: Math.round(total * 100) / 100,
      currency: 'USD',
    };
  }

  /**
   * Create and store a new quote
   */
  static async createQuote(
    input: PricingInput,
    userId?: string
  ): Promise<Quote> {
    try {
      logInfo('Creating enterprise quote', {
        companyName: input.companyName,
        teamSize: input.teamSize,
      });

      const breakdown = this.calculatePricing(input);

      // Valid for 30 days
      const validUntil = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);

      const quote = await prisma.enterpriseQuote.create({
        data: {
          userId,
          companyName: input.companyName,
          contactName: input.contactName,
          contactEmail: input.contactEmail,
          teamSize: input.teamSize,
          expectedAPIs: input.expectedAPIs,
          expectedEventsPerMonth: input.expectedEventsPerMonth,
          requiresSupport: input.requiresSupport,
          requiresSLA: input.requiresSLA,
          requiresCustomIntegration: input.requiresCustomIntegration,
          additionalNotes: input.additionalNotes,
          breakdown: JSON.parse(JSON.stringify(breakdown)), // JSON field
          status: QuoteStatus.PENDING,
          validUntil,
        },
      });

      logInfo('Enterprise quote created', { quoteId: quote.id });

      // Send quote email
      await this.sendQuoteEmail(input, breakdown, quote.id);

      return {
        id: quote.id,
        companyName: quote.companyName,
        contactName: quote.contactName,
        contactEmail: quote.contactEmail,
        breakdown,
        status: quote.status as QuoteStatus,
        validUntil: quote.validUntil,
        createdAt: quote.createdAt,
      };
    } catch (error) {
      logError('Failed to create enterprise quote', { error, input });
      throw error;
    }
  }

  /**
   * Send quote via email
   */
  private static async sendQuoteEmail(
    input: PricingInput,
    breakdown: PricingBreakdown,
    quoteId: string
  ) {
    try {
      await sendEmail({
        to: input.contactEmail,
        subject: `Enterprise Quote for ${input.companyName} - VortexSecure`,
        html: `
          <h2>Enterprise Quote</h2>
          <p>Dear ${input.contactName},</p>
          <p>Thank you for your interest in VortexSecure Enterprise. Based on your requirements, here's your custom quote:</p>
          
          <h3>Company Details</h3>
          <ul>
            <li><strong>Company:</strong> ${input.companyName}</li>
            <li><strong>Team Size:</strong> ${input.teamSize} users</li>
            <li><strong>Expected APIs:</strong> ${input.expectedAPIs}</li>
            <li><strong>Expected Events:</strong> ${input.expectedEventsPerMonth.toLocaleString()}/month</li>
          </ul>
          
          <h3>Pricing Breakdown</h3>
          <table style="border-collapse: collapse; width: 100%; max-width: 500px;">
            <tr style="border-bottom: 1px solid #ddd;">
              <td style="padding: 8px;">Base Price (${input.teamSize} users × $${breakdown.perUserPrice})</td>
              <td style="padding: 8px; text-align: right;">$${breakdown.basePrice.toFixed(2)}</td>
            </tr>
            ${
              breakdown.apiPrice > 0
                ? `
            <tr style="border-bottom: 1px solid #ddd;">
              <td style="padding: 8px;">Additional APIs</td>
              <td style="padding: 8px; text-align: right;">$${breakdown.apiPrice.toFixed(2)}</td>
            </tr>
            `
                : ''
            }
            ${
              breakdown.eventsPrice > 0
                ? `
            <tr style="border-bottom: 1px solid #ddd;">
              <td style="padding: 8px;">Additional Events</td>
              <td style="padding: 8px; text-align: right;">$${breakdown.eventsPrice.toFixed(2)}</td>
            </tr>
            `
                : ''
            }
            ${
              breakdown.supportPrice > 0
                ? `
            <tr style="border-bottom: 1px solid #ddd;">
              <td style="padding: 8px;">Premium Support</td>
              <td style="padding: 8px; text-align: right;">$${breakdown.supportPrice.toFixed(2)}</td>
            </tr>
            `
                : ''
            }
            ${
              breakdown.slaPrice > 0
                ? `
            <tr style="border-bottom: 1px solid #ddd;">
              <td style="padding: 8px;">SLA Agreement</td>
              <td style="padding: 8px; text-align: right;">$${breakdown.slaPrice.toFixed(2)}</td>
            </tr>
            `
                : ''
            }
            ${
              breakdown.customIntegrationPrice > 0
                ? `
            <tr style="border-bottom: 1px solid #ddd;">
              <td style="padding: 8px;">Custom Integration (amortized)</td>
              <td style="padding: 8px; text-align: right;">$${breakdown.customIntegrationPrice.toFixed(2)}</td>
            </tr>
            `
                : ''
            }
            <tr style="border-bottom: 1px solid #ddd;">
              <td style="padding: 8px;"><strong>Subtotal</strong></td>
              <td style="padding: 8px; text-align: right;"><strong>$${breakdown.subtotal.toFixed(2)}</strong></td>
            </tr>
            ${
              breakdown.discount > 0
                ? `
            <tr style="border-bottom: 1px solid #ddd;">
              <td style="padding: 8px; color: green;">Volume Discount (10%)</td>
              <td style="padding: 8px; text-align: right; color: green;">-$${breakdown.discount.toFixed(2)}</td>
            </tr>
            `
                : ''
            }
            <tr style="border-top: 2px solid #333;">
              <td style="padding: 8px;"><strong>Monthly Total</strong></td>
              <td style="padding: 8px; text-align: right;"><strong>$${breakdown.total.toFixed(2)}</strong></td>
            </tr>
          </table>
          
          <p style="margin-top: 20px;"><strong>Quote ID:</strong> ${quoteId}</p>
          <p><strong>Valid Until:</strong> ${new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toLocaleDateString()}</p>
          
          ${
            input.additionalNotes
              ? `
          <h3>Your Notes</h3>
          <p>${input.additionalNotes}</p>
          `
              : ''
          }
          
          <p style="margin-top: 30px;">To accept this quote or discuss further, please reply to this email or contact our sales team.</p>
          
          <p>Best regards,<br>The VortexSecure Team</p>
        `,
      });

      logInfo('Quote email sent', { quoteId, email: input.contactEmail });
    } catch (error) {
      logError('Failed to send quote email', { error, quoteId });
    }
  }

  /**
   * Get all quotes for a user/company
   */
  static async getQuotes(userId?: string, email?: string) {
    try {
      const quotes = await prisma.enterpriseQuote.findMany({
        where: {
          OR: [
            userId ? { userId } : {},
            email ? { contactEmail: email } : {},
          ].filter(condition => Object.keys(condition).length > 0),
        },
        orderBy: { createdAt: 'desc' },
      });

      return quotes.map(q => {
        const parseResult = pricingBreakdownSchema.safeParse(q.breakdown);

        if (!parseResult.success) {
          logWarn('Invalid pricing breakdown in quote', {
            quoteId: q.id,
            issues: parseResult.error.issues,
          });
          throw new Error('Invalid pricing breakdown data');
        }

        return {
          id: q.id,
          companyName: q.companyName,
          contactName: q.contactName,
          contactEmail: q.contactEmail,
          breakdown: parseResult.data,
          status: q.status as QuoteStatus,
          validUntil: q.validUntil,
          createdAt: q.createdAt,
        };
      });
    } catch (error) {
      logError('Failed to get quotes', { error, userId, email });
      throw error;
    }
  }

  /**
   * Update quote status
   */
  static async updateQuoteStatus(quoteId: string, status: QuoteStatus) {
    try {
      logInfo('Updating quote status', { quoteId, status });

      const quote = await prisma.enterpriseQuote.update({
        where: { id: quoteId },
        data: { status },
      });

      logInfo('Quote status updated', { quoteId, status });
      return quote;
    } catch (error) {
      logError('Failed to update quote status', { error, quoteId });
      throw error;
    }
  }

  /**
   * Get quote by ID
   */
  static async getQuoteById(quoteId: string): Promise<Quote | null> {
    try {
      const quote = await prisma.enterpriseQuote.findUnique({
        where: { id: quoteId },
      });

      if (!quote) return null;

      const parseResult = pricingBreakdownSchema.safeParse(quote.breakdown);

      if (!parseResult.success) {
        logWarn('Invalid pricing breakdown on quote fetch', {
          quoteId: quote.id,
          issues: parseResult.error.issues,
        });
        return null;
      }

      return {
        id: quote.id,
        companyName: quote.companyName,
        contactName: quote.contactName,
        contactEmail: quote.contactEmail,
        breakdown: parseResult.data,
        status: quote.status as QuoteStatus,
        validUntil: quote.validUntil,
        createdAt: quote.createdAt,
      };
    } catch (error) {
      logError('Failed to get quote', { error, quoteId });
      return null;
    }
  }
}

export { QuoteStatus };
export type { PricingInput, PricingBreakdown, Quote };
