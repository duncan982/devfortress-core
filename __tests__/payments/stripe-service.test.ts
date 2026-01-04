/**
 * Tests for Stripe subscription service
 */

import { createCheckoutSession, handleWebhookEvent } from '../../lib/stripe/services/stripe-service';
import { SubscriptionTier } from '../../lib/payments/types';

// Mock Stripe
jest.mock('stripe', () => {
  return jest.fn().mockImplementation(() => ({
    checkout: {
      sessions: {
        create: jest.fn(),
      },
    },
  }));
});

describe('Stripe Service', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    // Mock environment variables
    process.env.STRIPE_SECRET_KEY = 'sk_test_mock_key';
    process.env.STRIPE_PRICE_STARTER = 'price_starter';
    process.env.STRIPE_PRICE_PRO = 'price_pro';
    process.env.STRIPE_PRICE_ENTERPRISE = 'price_enterprise';
  });

  describe('createCheckoutSession', () => {
    it('should create a checkout session successfully', async () => {
      const mockSession = {
        id: 'cs_test_123',
        url: 'https://checkout.stripe.com/test',
      };

      const stripeMock = jest.requireMock('stripe');
      stripeMock.mockImplementation(() => ({
        checkout: {
          sessions: {
            create: jest.fn().mockResolvedValue(mockSession),
          },
        },
      }));

      const result = await createCheckoutSession({
        tier: SubscriptionTier.PRO,
        userId: 'user123',
        userEmail: 'test@example.com',
        successUrl: 'https://example.com/success',
        cancelUrl: 'https://example.com/cancel',
      });

      expect(result).toEqual(mockSession);
    });
  });

  describe('handleWebhookEvent', () => {
    it('should handle customer.subscription.created', async () => {
      const event = {
        id: 'evt_test_123',
        object: 'event' as const,
        api_version: '2023-10-16',
        created: Math.floor(Date.now() / 1000),
        livemode: false,
        pending_webhooks: 0,
        request: { id: null, idempotency_key: null },
        type: 'customer.subscription.created',
        data: {
          object: {
            id: 'sub_test_123',
            metadata: {
              userId: 'user123',
              tier: 'PRO',
            },
          },
        },
      } as any;

      await expect(handleWebhookEvent(event)).resolves.not.toThrow();
    });

    it('should handle customer.subscription.deleted', async () => {
      const event = {
        id: 'evt_test_124',
        object: 'event' as const,
        api_version: '2023-10-16',
        created: Math.floor(Date.now() / 1000),
        livemode: false,
        pending_webhooks: 0,
        request: { id: null, idempotency_key: null },
        type: 'customer.subscription.deleted',
        data: {
          object: {
            id: 'sub_test_123',
            customer: 'cus_test_123',
          },
        },
      } as any;

      await expect(handleWebhookEvent(event)).resolves.not.toThrow();
    });

    it('should handle invoice.payment_failed', async () => {
      const event = {
        id: 'evt_test_125',
        object: 'event' as const,
        api_version: '2023-10-16',
        created: Math.floor(Date.now() / 1000),
        livemode: false,
        pending_webhooks: 0,
        request: { id: null, idempotency_key: null },
        type: 'invoice.payment_failed',
        data: {
          object: {
            id: 'in_test_123',
            customer: 'cus_test_123',
          },
        },
      } as any;

      await expect(handleWebhookEvent(event)).resolves.not.toThrow();
    });

    it('should handle unknown events', async () => {
      const event = {
        id: 'evt_test_126',
        object: 'event' as const,
        api_version: '2023-10-16',
        created: Math.floor(Date.now() / 1000),
        livemode: false,
        pending_webhooks: 0,
        request: { id: null, idempotency_key: null },
        type: 'unknown.event',
        data: {},
      } as any;

      await expect(handleWebhookEvent(event)).resolves.not.toThrow();
    });
  });
});