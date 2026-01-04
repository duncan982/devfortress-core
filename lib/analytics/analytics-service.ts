/**
 * Analytics Service
 * Centralized analytics tracking for events, page views, and user actions
 */

import { trackEvent as gaTrackEvent } from '@core/components/analytics/google-analytics';
import { addBreadcrumb, captureMessage } from '@core/lib/analytics/sentry';
import { logInfo } from '@core/lib/logger';

export interface AnalyticsEvent {
  name: string;
  category?: string;
  label?: string;
  value?: number;
  properties?: Record<string, unknown>;
}

export interface OnboardingStepEvent {
  userId: string;
  step: string;
  action: string;
  metadata?: Record<string, unknown>;
}

export class AnalyticsService {
  /**
   * Track a custom event
   */
  static trackEvent(event: AnalyticsEvent): void {
    const { name, category, label, value, properties } = event;

    // Log the event
    logInfo('Analytics event tracked', { event });

    // Track with Google Analytics
    gaTrackEvent(name, {
      event_category: category,
      event_label: label,
      value,
      ...properties,
    });

    // Add breadcrumb to Sentry
    addBreadcrumb(`Event: ${name}`, 'analytics', 'info');
  }

  /**
   * Track page view
   */
  static trackPageView(path: string, title?: string): void {
    logInfo('Page view tracked', { path, title });

    // Google Analytics handles this automatically via the component
    // But we can add a breadcrumb for Sentry
    addBreadcrumb(`Page view: ${path}`, 'navigation', 'info');
  }

  /**
   * Track user signup
   */
  static trackSignup(method: 'google' | 'github' | 'email'): void {
    this.trackEvent({
      name: 'signup',
      category: 'authentication',
      label: method,
      properties: { method },
    });
  }

  /**
   * Track user login
   */
  static trackLogin(method: 'google' | 'github' | 'email'): void {
    this.trackEvent({
      name: 'login',
      category: 'authentication',
      label: method,
      properties: { method },
    });
  }

  /**
   * Track API generation
   */
  static trackAPIGeneration(framework: string, tier: string): void {
    this.trackEvent({
      name: 'api_generated',
      category: 'build',
      label: framework,
      properties: { framework, tier },
    });
  }

  /**
   * Track honeypot deployment
   */
  static trackHoneypotDeployment(tier: string, type: string): void {
    this.trackEvent({
      name: 'honeypot_deployed',
      category: 'defend',
      label: type,
      properties: { tier, type },
    });
  }

  /**
   * Track subscription change
   */
  static trackSubscriptionChange(
    oldTier: string,
    newTier: string,
    action: 'upgrade' | 'downgrade'
  ): void {
    this.trackEvent({
      name: 'subscription_changed',
      category: 'billing',
      label: action,
      value: action === 'upgrade' ? 1 : -1,
      properties: { oldTier, newTier, action },
    });
  }

  /**
   * Track credit purchase
   */
  static trackCreditPurchase(amount: number, price: number): void {
    this.trackEvent({
      name: 'credits_purchased',
      category: 'billing',
      value: price,
      properties: { amount, price },
    });
  }

  /**
   * Track error
   */
  static trackError(error: Error, context?: Record<string, unknown>): void {
    logInfo('Error tracked', { error: error.message, context });

    captureMessage(`Error: ${error.message}`, 'error');

    this.trackEvent({
      name: 'error',
      category: 'error',
      label: error.name,
      properties: {
        message: error.message,
        stack: error.stack,
        ...context,
      },
    });
  }

  /**
   * Track feature usage
   */
  static trackFeatureUsage(featureName: string, action: string): void {
    this.trackEvent({
      name: 'feature_used',
      category: 'feature',
      label: featureName,
      properties: { feature: featureName, action },
    });
  }

  /**
   * Track search
   */
  static trackSearch(query: string, resultsCount: number): void {
    this.trackEvent({
      name: 'search',
      category: 'engagement',
      label: query,
      value: resultsCount,
      properties: { query, resultsCount },
    });
  }

  /**
   * Track team action
   */
  static trackTeamAction(
    action: 'create' | 'invite' | 'remove' | 'update',
    teamId: string
  ): void {
    this.trackEvent({
      name: 'team_action',
      category: 'team',
      label: action,
      properties: { action, teamId },
    });
  }

  /**
   * Track help article view
   */
  static trackHelpArticleView(articleId: string, title: string): void {
    this.trackEvent({
      name: 'help_article_viewed',
      category: 'help',
      label: title,
      properties: { articleId, title },
    });
  }

  /**
   * Track onboarding progress
   */
  static trackOnboardingStep({
    userId,
    step,
    action,
    metadata,
  }: OnboardingStepEvent): void {
    const properties = {
      userId,
      step,
      action,
      ...(metadata ? { metadata } : {}),
    };

    this.trackEvent({
      name: 'onboarding_step',
      category: 'onboarding',
      label: step,
      properties,
    });
  }
}
