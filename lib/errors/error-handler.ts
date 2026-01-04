/**
 * Error Handling Service
 * Provides user-friendly error messages and recovery strategies
 * 
 * Features:
 * - User-friendly error messages
 * - Error recovery suggestions
 * - Error categorization
 * - Error tracking and reporting
 */

import { logError, logWarn, logInfo } from '@core/lib/logger';

/**
 * Error categories
 */
export enum ErrorCategory {
  AUTHENTICATION = 'authentication',
  AUTHORIZATION = 'authorization',
  VALIDATION = 'validation',
  NETWORK = 'network',
  DATABASE = 'database',
  EXTERNAL_SERVICE = 'external_service',
  RATE_LIMIT = 'rate_limit',
  NOT_FOUND = 'not_found',
  CONFLICT = 'conflict',
  INTERNAL = 'internal',
}

/**
 * Error severity levels
 */
export enum ErrorSeverity {
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
  CRITICAL = 'critical',
}

/**
 * Recovery strategy
 */
export interface RecoveryStrategy {
  action: string;
  description: string;
  automated?: boolean;
}

/**
 * Enhanced error
 */
export interface EnhancedError {
  code: string;
  message: string;
  userMessage: string;
  category: ErrorCategory;
  severity: ErrorSeverity;
  details?: Record<string, unknown>;
  recoveryStrategies: RecoveryStrategy[];
  timestamp: Date;
  trackingId: string;
}

/**
 * Error handling service
 */
class ErrorHandler {
  private errorRegistry = new Map<string, EnhancedError>();

  /**
   * Handle an error and return enhanced error information
   */
  handle(
    error: Error | unknown,
    context?: Record<string, unknown>
  ): EnhancedError {
    const trackingId = this.generateTrackingId();
    
    let enhancedError: EnhancedError;

    if (error instanceof AppError) {
      enhancedError = {
        code: error.code,
        message: error.message,
        userMessage: error.userMessage,
        category: error.category,
        severity: error.severity,
        details: { ...error.details, ...context },
        recoveryStrategies: error.recoveryStrategies,
        timestamp: new Date(),
        trackingId,
      };
    } else if (error instanceof Error) {
      enhancedError = this.categorizeError(error, context, trackingId);
    } else {
      enhancedError = {
        code: 'UNKNOWN_ERROR',
        message: String(error),
        userMessage: 'An unexpected error occurred. Please try again.',
        category: ErrorCategory.INTERNAL,
        severity: ErrorSeverity.HIGH,
        details: context,
        recoveryStrategies: [
          {
            action: 'retry',
            description: 'Try the operation again',
          },
          {
            action: 'contact_support',
            description: 'Contact support if the issue persists',
          },
        ],
        timestamp: new Date(),
        trackingId,
      };
    }

    // Log error
    this.logError(enhancedError);

    // Store in registry
    this.errorRegistry.set(trackingId, enhancedError);

    return enhancedError;
  }

  /**
   * Categorize generic errors
   */
  private categorizeError(
    error: Error,
    context: Record<string, unknown> | undefined,
    trackingId: string
  ): EnhancedError {
    const message = error.message.toLowerCase();

    // Network errors
    if (message.includes('network') || message.includes('fetch') || message.includes('timeout')) {
      return {
        code: 'NETWORK_ERROR',
        message: error.message,
        userMessage: 'Network connection issue. Please check your internet connection.',
        category: ErrorCategory.NETWORK,
        severity: ErrorSeverity.MEDIUM,
        details: context,
        recoveryStrategies: [
          {
            action: 'check_connection',
            description: 'Check your internet connection',
          },
          {
            action: 'retry',
            description: 'Try again in a few moments',
            automated: true,
          },
        ],
        timestamp: new Date(),
        trackingId,
      };
    }

    // Database errors
    if (message.includes('database') || message.includes('prisma') || message.includes('query')) {
      return {
        code: 'DATABASE_ERROR',
        message: error.message,
        userMessage: 'A database error occurred. Our team has been notified.',
        category: ErrorCategory.DATABASE,
        severity: ErrorSeverity.HIGH,
        details: context,
        recoveryStrategies: [
          {
            action: 'retry',
            description: 'Try again in a few moments',
          },
          {
            action: 'check_status',
            description: 'Check system status page',
          },
        ],
        timestamp: new Date(),
        trackingId,
      };
    }

    // Authentication errors
    if (message.includes('auth') || message.includes('token') || message.includes('session')) {
      return {
        code: 'AUTH_ERROR',
        message: error.message,
        userMessage: 'Your session has expired. Please sign in again.',
        category: ErrorCategory.AUTHENTICATION,
        severity: ErrorSeverity.MEDIUM,
        details: context,
        recoveryStrategies: [
          {
            action: 'sign_in',
            description: 'Sign in to your account',
            automated: true,
          },
        ],
        timestamp: new Date(),
        trackingId,
      };
    }

    // Rate limit errors
    if (message.includes('rate limit') || message.includes('too many')) {
      return {
        code: 'RATE_LIMIT_ERROR',
        message: error.message,
        userMessage: 'Too many requests. Please wait a moment and try again.',
        category: ErrorCategory.RATE_LIMIT,
        severity: ErrorSeverity.LOW,
        details: context,
        recoveryStrategies: [
          {
            action: 'wait',
            description: 'Wait 60 seconds before retrying',
          },
          {
            action: 'upgrade',
            description: 'Upgrade to a higher tier for more requests',
          },
        ],
        timestamp: new Date(),
        trackingId,
      };
    }

    // Default internal error
    return {
      code: 'INTERNAL_ERROR',
      message: error.message,
      userMessage: 'An internal error occurred. Please try again.',
      category: ErrorCategory.INTERNAL,
      severity: ErrorSeverity.HIGH,
      details: context,
      recoveryStrategies: [
        {
          action: 'retry',
          description: 'Try the operation again',
        },
        {
          action: 'contact_support',
          description: 'Contact support with tracking ID: ' + trackingId,
        },
      ],
      timestamp: new Date(),
      trackingId,
    };
  }

  /**
   * Log error with appropriate level
   */
  private logError(error: EnhancedError): void {
    const logData = {
      code: error.code,
      category: error.category,
      severity: error.severity,
      trackingId: error.trackingId,
      details: error.details,
    };

    switch (error.severity) {
      case ErrorSeverity.CRITICAL:
      case ErrorSeverity.HIGH:
        logError(error.message, logData);
        break;
      case ErrorSeverity.MEDIUM:
        logWarn(error.message, logData);
        break;
      case ErrorSeverity.LOW:
        logInfo(error.message, logData);
        break;
    }
  }

  /**
   * Generate unique tracking ID
   */
  private generateTrackingId(): string {
    return `ERR-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Get error by tracking ID
   */
  getError(trackingId: string): EnhancedError | undefined {
    return this.errorRegistry.get(trackingId);
  }

  /**
   * Get recent errors
   */
  getRecentErrors(limit = 100): EnhancedError[] {
    const errors = Array.from(this.errorRegistry.values());
    return errors
      .sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime())
      .slice(0, limit);
  }

  /**
   * Clear error registry
   */
  clear(): void {
    this.errorRegistry.clear();
  }
}

/**
 * Custom application error class
 */
export class AppError extends Error {
  constructor(
    public code: string,
    message: string,
    public userMessage: string,
    public category: ErrorCategory,
    public severity: ErrorSeverity,
    public details?: Record<string, unknown>,
    public recoveryStrategies: RecoveryStrategy[] = []
  ) {
    super(message);
    this.name = 'AppError';
  }
}

/**
 * Singleton error handler
 */
export const errorHandler = new ErrorHandler();

/**
 * Common application errors
 */
export const ErrorCodes = {
  // Authentication
  INVALID_CREDENTIALS: 'INVALID_CREDENTIALS',
  SESSION_EXPIRED: 'SESSION_EXPIRED',
  UNAUTHORIZED: 'UNAUTHORIZED',

  // Validation
  INVALID_INPUT: 'INVALID_INPUT',
  MISSING_FIELD: 'MISSING_FIELD',
  INVALID_FORMAT: 'INVALID_FORMAT',

  // Resources
  NOT_FOUND: 'NOT_FOUND',
  ALREADY_EXISTS: 'ALREADY_EXISTS',
  CONFLICT: 'CONFLICT',

  // External services
  OPENAI_ERROR: 'OPENAI_ERROR',
  SUPABASE_ERROR: 'SUPABASE_ERROR',
  VERCEL_ERROR: 'VERCEL_ERROR',

  // System
  DATABASE_ERROR: 'DATABASE_ERROR',
  NETWORK_ERROR: 'NETWORK_ERROR',
  INTERNAL_ERROR: 'INTERNAL_ERROR',
  RATE_LIMIT_ERROR: 'RATE_LIMIT_ERROR',
};

/**
 * Create common errors
 */
export const createError = {
  notFound: (resource: string, id?: string): AppError =>
    new AppError(
      ErrorCodes.NOT_FOUND,
      `${resource} not found${id ? `: ${id}` : ''}`,
      `The ${resource} you're looking for doesn't exist.`,
      ErrorCategory.NOT_FOUND,
      ErrorSeverity.LOW,
      { resource, id },
      [
        {
          action: 'check_input',
          description: 'Verify the ID or name is correct',
        },
        {
          action: 'create',
          description: `Create a new ${resource}`,
        },
      ]
    ),

  unauthorized: (action: string): AppError =>
    new AppError(
      ErrorCodes.UNAUTHORIZED,
      `Unauthorized: ${action}`,
      "You don't have permission to perform this action.",
      ErrorCategory.AUTHORIZATION,
      ErrorSeverity.MEDIUM,
      { action },
      [
        {
          action: 'sign_in',
          description: 'Sign in to continue',
        },
        {
          action: 'upgrade',
          description: 'Upgrade your plan for access',
        },
      ]
    ),

  validation: (field: string, message: string): AppError =>
    new AppError(
      ErrorCodes.INVALID_INPUT,
      `Validation error: ${field} - ${message}`,
      `Invalid ${field}: ${message}`,
      ErrorCategory.VALIDATION,
      ErrorSeverity.LOW,
      { field, message },
      [
        {
          action: 'correct_input',
          description: 'Check your input and try again',
        },
      ]
    ),

  rateLimit: (limit: number, window: string): AppError =>
    new AppError(
      ErrorCodes.RATE_LIMIT_ERROR,
      `Rate limit exceeded: ${limit} requests per ${window}`,
      `You've made too many requests. Please wait ${window} before trying again.`,
      ErrorCategory.RATE_LIMIT,
      ErrorSeverity.LOW,
      { limit, window },
      [
        {
          action: 'wait',
          description: `Wait ${window} before retrying`,
        },
        {
          action: 'upgrade',
          description: 'Upgrade for higher rate limits',
        },
      ]
    ),
};
