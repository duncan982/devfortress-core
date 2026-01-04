'use client';

import { useState } from 'react';
import Link from 'next/link';

/**
 * Error types and their corresponding recovery suggestions
 */
export interface ErrorRecovery {
  title: string;
  description: string;
  action?: {
    label: string;
    href?: string;
    onClick?: () => void;
  };
}

export interface ErrorInfo {
  code?: string;
  message: string;
  details?: string;
  recoveryOptions?: ErrorRecovery[];
}

/**
 * Common error codes and their user-friendly messages
 */
export const ERROR_MESSAGES: Record<string, ErrorInfo> = {
  // Authentication Errors
  AUTH_REQUIRED: {
    code: 'AUTH_REQUIRED',
    message: 'Authentication required',
    details:
      'You need to sign in to access this feature. Create a free account or log in to continue.',
    recoveryOptions: [
      {
        title: 'Sign in with GitHub',
        description:
          'Connect your GitHub account to access all features and sync your projects.',
        action: { label: 'Sign In', href: '/auth/login' },
      },
      {
        title: 'Learn More',
        description:
          'Not sure what this platform offers? Check out our features and pricing.',
        action: { label: 'View Features', href: '/#features' },
      },
    ],
  },
  SESSION_EXPIRED: {
    code: 'SESSION_EXPIRED',
    message: 'Your session has expired',
    details:
      'For security reasons, you have been logged out after a period of inactivity.',
    recoveryOptions: [
      {
        title: 'Sign in again',
        description: 'Log back in to continue where you left off.',
        action: { label: 'Sign In', href: '/auth/login' },
      },
    ],
  },
  UNAUTHORIZED: {
    code: 'UNAUTHORIZED',
    message: 'Access denied',
    details: "You don't have permission to access this resource.",
    recoveryOptions: [
      {
        title: 'Upgrade your plan',
        description:
          'This feature may be available on a higher tier. Check our pricing for more details.',
        action: { label: 'View Pricing', href: '/pricing' },
      },
      {
        title: 'Contact Support',
        description:
          'If you believe this is an error, our support team can help you resolve it.',
        action: { label: 'Get Help', href: '/contact' },
      },
    ],
  },

  // Rate Limiting Errors
  RATE_LIMITED: {
    code: 'RATE_LIMITED',
    message: 'Too many requests',
    details:
      "You've exceeded the rate limit for this action. Please wait a moment before trying again.",
    recoveryOptions: [
      {
        title: 'Wait and retry',
        description:
          'Rate limits reset after a short period. Wait a few moments and try again.',
      },
      {
        title: 'Upgrade for higher limits',
        description:
          'Paid plans include higher rate limits for power users and teams.',
        action: { label: 'View Plans', href: '/pricing' },
      },
    ],
  },

  // API Key Errors
  API_KEY_MISSING: {
    code: 'API_KEY_MISSING',
    message: 'API key not configured',
    details:
      'This feature requires an AI provider API key. Free users need to bring their own keys.',
    recoveryOptions: [
      {
        title: 'Configure your API key',
        description:
          'Add your OpenAI, Anthropic, or other provider API key in settings.',
        action: { label: 'Add API Key', href: '/dashboard/settings/api-keys' },
      },
      {
        title: 'Upgrade for included credits',
        description:
          "Paid plans include AI credits so you don't need to manage your own keys.",
        action: { label: 'View Plans', href: '/pricing' },
      },
    ],
  },
  API_KEY_INVALID: {
    code: 'API_KEY_INVALID',
    message: 'Invalid API key',
    details:
      "The configured API key isn't working. Please verify it's correct and has sufficient credits.",
    recoveryOptions: [
      {
        title: 'Update your API key',
        description:
          "Check that your API key is entered correctly and hasn't expired.",
        action: { label: 'Update Key', href: '/dashboard/settings/api-keys' },
      },
      {
        title: 'Check provider status',
        description:
          'Your AI provider may be experiencing issues. Check their status page.',
      },
    ],
  },

  // Subscription Errors
  SUBSCRIPTION_REQUIRED: {
    code: 'SUBSCRIPTION_REQUIRED',
    message: 'Subscription required',
    details:
      'This feature is only available to paid subscribers. Upgrade your plan to access it.',
    recoveryOptions: [
      {
        title: 'Upgrade your plan',
        description:
          'Get access to premium features with a STARTER, PRO, or ENTERPRISE subscription.',
        action: { label: 'View Pricing', href: '/pricing' },
      },
      {
        title: 'Self-host for free',
        description:
          'Run your own instance with your own API keys for unlimited access.',
        action: { label: 'Self-Host Guide', href: '/docs/self-hosting' },
      },
    ],
  },
  TIER_INSUFFICIENT: {
    code: 'TIER_INSUFFICIENT',
    message: 'Feature not available on your plan',
    details:
      'This feature requires a higher subscription tier than your current plan.',
    recoveryOptions: [
      {
        title: 'Upgrade your plan',
        description:
          'Unlock this feature by upgrading to a higher tier subscription.',
        action: { label: 'Upgrade', href: '/pricing' },
      },
    ],
  },

  // Network Errors
  NETWORK_ERROR: {
    code: 'NETWORK_ERROR',
    message: 'Connection error',
    details:
      "We couldn't connect to the server. Check your internet connection and try again.",
    recoveryOptions: [
      {
        title: 'Check your connection',
        description:
          'Make sure you have a stable internet connection and try again.',
      },
      {
        title: 'Refresh the page',
        description:
          'Sometimes a simple refresh can resolve connection issues.',
      },
    ],
  },
  SERVER_ERROR: {
    code: 'SERVER_ERROR',
    message: 'Server error',
    details:
      'Something went wrong on our end. Our team has been notified and is working on it.',
    recoveryOptions: [
      {
        title: 'Try again later',
        description:
          'Our team is working to resolve this. Please try again in a few minutes.',
      },
      {
        title: 'Contact Support',
        description: 'If this persists, our support team can help you.',
        action: { label: 'Get Help', href: '/contact' },
      },
    ],
  },
  SERVICE_UNAVAILABLE: {
    code: 'SERVICE_UNAVAILABLE',
    message: 'Service temporarily unavailable',
    details:
      "We're experiencing high demand or performing maintenance. Please try again shortly.",
    recoveryOptions: [
      {
        title: 'Wait and retry',
        description:
          'The service should be back online shortly. Please try again in a few minutes.',
      },
      {
        title: 'Check status',
        description:
          'Visit our status page to see if there are any known issues.',
        action: { label: 'Status Page', href: '/status' },
      },
    ],
  },

  // Validation Errors
  VALIDATION_ERROR: {
    code: 'VALIDATION_ERROR',
    message: 'Invalid input',
    details:
      'Some of the information you provided is invalid. Please check your input and try again.',
    recoveryOptions: [
      {
        title: 'Review your input',
        description: 'Check for typos, missing fields, or invalid formats.',
      },
    ],
  },

  // Resource Errors
  NOT_FOUND: {
    code: 'NOT_FOUND',
    message: 'Resource not found',
    details:
      "The resource you're looking for doesn't exist or has been deleted.",
    recoveryOptions: [
      {
        title: 'Go to Dashboard',
        description: 'Return to your dashboard to find what you need.',
        action: { label: 'Dashboard', href: '/dashboard' },
      },
    ],
  },

  // Generic Error
  UNKNOWN_ERROR: {
    code: 'UNKNOWN_ERROR',
    message: 'Something went wrong',
    details:
      'An unexpected error occurred. Please try again or contact support if the problem persists.',
    recoveryOptions: [
      {
        title: 'Try again',
        description:
          'Sometimes issues resolve themselves. Try your action again.',
      },
      {
        title: 'Contact Support',
        description:
          'If this keeps happening, our support team can investigate.',
        action: { label: 'Get Help', href: '/contact' },
      },
    ],
  },
};

/**
 * Get error info by code or return unknown error
 */
export function getErrorInfo(code: string, customMessage?: string): ErrorInfo {
  const info = ERROR_MESSAGES[code] || ERROR_MESSAGES.UNKNOWN_ERROR;
  if (customMessage) {
    return { ...info, details: customMessage };
  }
  return info;
}

/**
 * Parse API error responses into ErrorInfo
 */
export function parseApiError(
  response: { error?: string; message?: string; code?: string } | string
): ErrorInfo {
  if (typeof response === 'string') {
    // Check if it matches a known error message
    for (const [code, info] of Object.entries(ERROR_MESSAGES)) {
      if (
        response.toLowerCase().includes(info.message.toLowerCase()) ||
        response.toLowerCase().includes(code.toLowerCase())
      ) {
        return info;
      }
    }
    return { ...ERROR_MESSAGES.UNKNOWN_ERROR, details: response };
  }

  const errorCode = response.code || response.error || 'UNKNOWN_ERROR';
  const errorMessage = response.message || response.error;

  return getErrorInfo(
    errorCode.toUpperCase().replace(/[- ]/g, '_'),
    errorMessage
  );
}

interface ErrorDisplayProps {
  error: ErrorInfo | string;
  variant?: 'full' | 'compact' | 'inline';
  showDetails?: boolean;
  showRecovery?: boolean;
  onRetry?: () => void;
  className?: string;
}

/**
 * Error display component with user-friendly messages and recovery options
 */
export function ErrorDisplay({
  error,
  variant = 'full',
  showDetails = true,
  showRecovery = true,
  onRetry,
  className = '',
}: ErrorDisplayProps) {
  const [expanded, setExpanded] = useState(false);
  const errorInfo: ErrorInfo =
    typeof error === 'string' ? parseApiError(error) : error;

  if (variant === 'inline') {
    return (
      <div
        className={`flex items-center gap-2 text-red-600 dark:text-red-400 ${className}`}
      >
        <span className="text-lg">⚠️</span>
        <span>{errorInfo.message}</span>
        {onRetry && (
          <button
            onClick={onRetry}
            className="ml-2 text-sm text-blue-600 hover:underline dark:text-blue-400"
          >
            Retry
          </button>
        )}
      </div>
    );
  }

  if (variant === 'compact') {
    return (
      <div
        className={`rounded-lg border border-red-200 bg-red-50 p-4 dark:border-red-800 dark:bg-red-900/20 ${className}`}
      >
        <div className="flex items-start gap-3">
          <span className="text-2xl">⚠️</span>
          <div className="flex-1">
            <h3 className="font-semibold text-red-800 dark:text-red-200">
              {errorInfo.message}
            </h3>
            {showDetails && errorInfo.details && (
              <p className="mt-1 text-sm text-red-700 dark:text-red-300">
                {errorInfo.details}
              </p>
            )}
            <div className="mt-3 flex gap-2">
              {onRetry && (
                <button
                  onClick={onRetry}
                  className="rounded-md bg-red-600 px-3 py-1.5 text-sm text-white hover:bg-red-700"
                >
                  Try Again
                </button>
              )}
              {errorInfo.recoveryOptions?.[0]?.action?.href && (
                <Link
                  href={errorInfo.recoveryOptions[0].action.href}
                  className="rounded-md border border-red-300 px-3 py-1.5 text-sm text-red-700 hover:bg-red-100 dark:border-red-700 dark:text-red-300 dark:hover:bg-red-800/30"
                >
                  {errorInfo.recoveryOptions[0].action.label}
                </Link>
              )}
            </div>
          </div>
        </div>
      </div>
    );
  }

  // Full variant
  return (
    <div
      className={`rounded-xl border border-red-200 bg-white p-6 shadow-sm dark:border-red-800 dark:bg-gray-900 ${className}`}
    >
      <div className="text-center">
        <span className="text-5xl">⚠️</span>
        <h2 className="mt-4 text-2xl font-bold text-gray-900 dark:text-white">
          {errorInfo.message}
        </h2>
        {errorInfo.code && (
          <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
            Error code: {errorInfo.code}
          </p>
        )}
        {showDetails && errorInfo.details && (
          <p className="mx-auto mt-4 max-w-md text-gray-600 dark:text-gray-300">
            {errorInfo.details}
          </p>
        )}
      </div>

      {/* Recovery Options */}
      {showRecovery && errorInfo.recoveryOptions && (
        <div className="mt-8">
          <h3 className="mb-4 text-center text-sm font-medium text-gray-500 dark:text-gray-400">
            What you can do:
          </h3>
          <div className="grid gap-4 md:grid-cols-2">
            {errorInfo.recoveryOptions.map((option, index) => (
              <div
                key={index}
                className="rounded-lg border border-gray-200 p-4 dark:border-gray-700"
              >
                <h4 className="font-semibold text-gray-900 dark:text-white">
                  {option.title}
                </h4>
                <p className="mt-1 text-sm text-gray-600 dark:text-gray-300">
                  {option.description}
                </p>
                {option.action && (
                  <div className="mt-3">
                    {option.action.href ? (
                      <Link
                        href={option.action.href}
                        className="inline-flex items-center text-sm font-medium text-blue-600 hover:underline dark:text-blue-400"
                      >
                        {option.action.label} →
                      </Link>
                    ) : option.action.onClick ? (
                      <button
                        onClick={option.action.onClick}
                        className="inline-flex items-center text-sm font-medium text-blue-600 hover:underline dark:text-blue-400"
                      >
                        {option.action.label} →
                      </button>
                    ) : null}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Action Buttons */}
      <div className="mt-8 flex justify-center gap-4">
        {onRetry && (
          <button
            onClick={onRetry}
            className="rounded-lg bg-blue-600 px-6 py-2.5 font-medium text-white hover:bg-blue-700"
          >
            Try Again
          </button>
        )}
        <Link
          href="/dashboard"
          className="rounded-lg border border-gray-300 px-6 py-2.5 font-medium text-gray-700 hover:bg-gray-50 dark:border-gray-600 dark:text-gray-300 dark:hover:bg-gray-800"
        >
          Go to Dashboard
        </Link>
      </div>

      {/* Technical Details (expandable) */}
      <div className="mt-6 text-center">
        <button
          onClick={() => setExpanded(!expanded)}
          className="text-sm text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200"
        >
          {expanded ? 'Hide' : 'Show'} technical details
        </button>
        {expanded && (
          <div className="mt-4 rounded-lg bg-gray-100 p-4 text-left dark:bg-gray-800">
            <pre className="overflow-auto text-xs text-gray-600 dark:text-gray-400">
              {JSON.stringify(errorInfo, null, 2)}
            </pre>
          </div>
        )}
      </div>
    </div>
  );
}

export default ErrorDisplay;
