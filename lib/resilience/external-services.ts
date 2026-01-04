/**
 * External Service Resilience Module
 * Provides retry logic, circuit breakers, and fallbacks for external APIs
 * 
 * Supported Services:
 * - OpenAI (code generation, analysis)
 * - Anthropic (alternative LLM)
 * - Supabase (database, auth)
 * - Vercel (deployments)
 * - GitHub (OAuth, repos)
 */

import { logWarn, logError, logInfo } from '@core/lib/logger';

/**
 * Circuit breaker states
 */
enum CircuitState {
  CLOSED = 'CLOSED', // Normal operation
  OPEN = 'OPEN', // Failing, reject requests
  HALF_OPEN = 'HALF_OPEN', // Testing if service recovered
}

/**
 * Circuit breaker configuration
 */
interface CircuitBreakerConfig {
  failureThreshold: number; // Number of failures before opening
  successThreshold: number; // Successes needed to close from half-open
  timeout: number; // Time to wait before trying half-open (ms)
  monitoringPeriod: number; // Time window for counting failures (ms)
}

/**
 * Retry configuration
 */
interface RetryConfig {
  maxRetries: number;
  baseDelay: number; // Initial delay in ms
  maxDelay: number; // Maximum delay in ms
  backoffMultiplier: number; // Exponential backoff multiplier
  retryableStatusCodes: number[]; // HTTP status codes to retry
}

/**
 * Service health status
 */
export interface ServiceHealth {
  service: string;
  healthy: boolean;
  lastCheck: Date;
  failureCount: number;
  circuitState: CircuitState;
  avgResponseTime?: number;
  errorRate?: number;
}

/**
 * Circuit Breaker implementation
 */
class CircuitBreaker {
  private state: CircuitState = CircuitState.CLOSED;
  private failureCount = 0;
  private successCount = 0;
  private lastFailureTime?: Date;
  private nextAttemptTime?: Date;

  constructor(
    private serviceName: string,
    private config: CircuitBreakerConfig
  ) {}

  /**
   * Execute an operation through the circuit breaker
   */
  async execute<T>(operation: () => Promise<T>): Promise<T> {
    // Check if circuit is open
    if (this.state === CircuitState.OPEN) {
      if (this.nextAttemptTime && new Date() < this.nextAttemptTime) {
        throw new Error(
          `Circuit breaker OPEN for ${this.serviceName}. Service unavailable.`
        );
      }
      // Transition to half-open to test service
      this.state = CircuitState.HALF_OPEN;
      this.successCount = 0;
      logInfo(`Circuit breaker HALF_OPEN for ${this.serviceName}, testing service`);
    }

    try {
      const result = await operation();
      this.onSuccess();
      return result;
    } catch (error) {
      this.onFailure();
      throw error;
    }
  }

  /**
   * Handle successful operation
   */
  private onSuccess(): void {
    this.failureCount = 0;

    if (this.state === CircuitState.HALF_OPEN) {
      this.successCount++;
      if (this.successCount >= this.config.successThreshold) {
        this.state = CircuitState.CLOSED;
        logInfo(`Circuit breaker CLOSED for ${this.serviceName}, service recovered`);
      }
    }
  }

  /**
   * Handle failed operation
   */
  private onFailure(): void {
    this.failureCount++;
    this.lastFailureTime = new Date();

    if (this.state === CircuitState.HALF_OPEN) {
      this.state = CircuitState.OPEN;
      this.nextAttemptTime = new Date(Date.now() + this.config.timeout);
      logWarn(`Circuit breaker OPEN for ${this.serviceName}, service still failing`);
    } else if (this.failureCount >= this.config.failureThreshold) {
      this.state = CircuitState.OPEN;
      this.nextAttemptTime = new Date(Date.now() + this.config.timeout);
      logError(`Circuit breaker OPEN for ${this.serviceName}, threshold exceeded`, {
        failureCount: this.failureCount,
        threshold: this.config.failureThreshold,
      });
    }
  }

  /**
   * Get current circuit breaker status
   */
  getStatus(): ServiceHealth {
    return {
      service: this.serviceName,
      healthy: this.state === CircuitState.CLOSED,
      lastCheck: this.lastFailureTime || new Date(),
      failureCount: this.failureCount,
      circuitState: this.state,
    };
  }

  /**
   * Reset circuit breaker (for testing or manual intervention)
   */
  reset(): void {
    this.state = CircuitState.CLOSED;
    this.failureCount = 0;
    this.successCount = 0;
    this.nextAttemptTime = undefined;
    logInfo(`Circuit breaker manually reset for ${this.serviceName}`);
  }
}

/**
 * Retry with exponential backoff
 */
async function retryWithBackoff<T>(
  operation: () => Promise<T>,
  config: RetryConfig,
  serviceName: string
): Promise<T> {
  let lastError: Error | unknown;

  for (let attempt = 0; attempt <= config.maxRetries; attempt++) {
    try {
      return await operation();
    } catch (error) {
      lastError = error;

      // Check if error is retryable
      const isRetryable = isRetryableError(error, config);

      if (!isRetryable || attempt === config.maxRetries) {
        throw error;
      }

      // Calculate delay with exponential backoff
      const delay = Math.min(
        config.baseDelay * Math.pow(config.backoffMultiplier, attempt),
        config.maxDelay
      );

      logWarn(`${serviceName} request failed, retrying...`, {
        attempt: attempt + 1,
        maxRetries: config.maxRetries,
        nextRetryIn: `${delay}ms`,
        error: error instanceof Error ? error.message : 'Unknown error',
      });

      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }

  throw lastError;
}

/**
 * Check if an error is retryable
 */
function isRetryableError(error: unknown, config: RetryConfig): boolean {
  // Network errors are retryable
  if (error instanceof Error && error.message.includes('ECONNREFUSED')) {
    return true;
  }

  // Timeout errors are retryable
  if (error instanceof Error && error.message.includes('timeout')) {
    return true;
  }

  // Check HTTP status codes
  if (
    error &&
    typeof error === 'object' &&
    'status' in error &&
    typeof error.status === 'number'
  ) {
    return config.retryableStatusCodes.includes(error.status);
  }

  return false;
}

/**
 * Default configurations for external services
 */
const DEFAULT_CONFIGS = {
  openai: {
    circuitBreaker: {
      failureThreshold: 5,
      successThreshold: 2,
      timeout: 60000, // 1 minute
      monitoringPeriod: 60000,
    },
    retry: {
      maxRetries: 3,
      baseDelay: 1000,
      maxDelay: 10000,
      backoffMultiplier: 2,
      retryableStatusCodes: [429, 500, 502, 503, 504],
    },
  },
  supabase: {
    circuitBreaker: {
      failureThreshold: 3,
      successThreshold: 2,
      timeout: 30000, // 30 seconds
      monitoringPeriod: 60000,
    },
    retry: {
      maxRetries: 3,
      baseDelay: 500,
      maxDelay: 5000,
      backoffMultiplier: 2,
      retryableStatusCodes: [500, 502, 503, 504],
    },
  },
  vercel: {
    circuitBreaker: {
      failureThreshold: 3,
      successThreshold: 2,
      timeout: 30000,
      monitoringPeriod: 60000,
    },
    retry: {
      maxRetries: 2,
      baseDelay: 1000,
      maxDelay: 5000,
      backoffMultiplier: 2,
      retryableStatusCodes: [429, 500, 502, 503],
    },
  },
};

/**
 * Circuit breakers for each service
 */
const circuitBreakers = {
  openai: new CircuitBreaker('OpenAI', DEFAULT_CONFIGS.openai.circuitBreaker),
  supabase: new CircuitBreaker('Supabase', DEFAULT_CONFIGS.supabase.circuitBreaker),
  vercel: new CircuitBreaker('Vercel', DEFAULT_CONFIGS.vercel.circuitBreaker),
};

/**
 * Execute OpenAI request with resilience
 */
export async function executeOpenAIRequest<T>(
  operation: () => Promise<T>,
  fallback?: T
): Promise<T> {
  try {
    return await circuitBreakers.openai.execute(() =>
      retryWithBackoff(operation, DEFAULT_CONFIGS.openai.retry, 'OpenAI')
    );
  } catch (error) {
    logError('OpenAI request failed after retries', {
      error: error instanceof Error ? error.message : 'Unknown error',
    });

    if (fallback !== undefined) {
      logInfo('Using fallback response for OpenAI');
      return fallback;
    }

    throw error;
  }
}

/**
 * Execute Supabase request with resilience
 */
export async function executeSupabaseRequest<T>(
  operation: () => Promise<T>,
  fallback?: T
): Promise<T> {
  try {
    return await circuitBreakers.supabase.execute(() =>
      retryWithBackoff(operation, DEFAULT_CONFIGS.supabase.retry, 'Supabase')
    );
  } catch (error) {
    logError('Supabase request failed after retries', {
      error: error instanceof Error ? error.message : 'Unknown error',
    });

    if (fallback !== undefined) {
      logInfo('Using fallback response for Supabase');
      return fallback;
    }

    throw error;
  }
}

/**
 * Execute Vercel request with resilience
 */
export async function executeVercelRequest<T>(
  operation: () => Promise<T>,
  fallback?: T
): Promise<T> {
  try {
    return await circuitBreakers.vercel.execute(() =>
      retryWithBackoff(operation, DEFAULT_CONFIGS.vercel.retry, 'Vercel')
    );
  } catch (error) {
    logError('Vercel request failed after retries', {
      error: error instanceof Error ? error.message : 'Unknown error',
    });

    if (fallback !== undefined) {
      logInfo('Using fallback response for Vercel');
      return fallback;
    }

    throw error;
  }
}

/**
 * Get health status for all external services
 */
export function getExternalServicesHealth(): ServiceHealth[] {
  return [
    circuitBreakers.openai.getStatus(),
    circuitBreakers.supabase.getStatus(),
    circuitBreakers.vercel.getStatus(),
  ];
}

/**
 * Reset all circuit breakers (for testing or manual recovery)
 */
export function resetAllCircuitBreakers(): void {
  Object.values(circuitBreakers).forEach(breaker => breaker.reset());
  logInfo('All circuit breakers reset');
}

/**
 * Execute with timeout
 */
export async function executeWithTimeout<T>(
  operation: () => Promise<T>,
  timeoutMs: number,
  serviceName: string
): Promise<T> {
  return Promise.race([
    operation(),
    new Promise<never>((_, reject) =>
      setTimeout(
        () =>
          reject(
            new Error(`${serviceName} request timeout after ${timeoutMs}ms`)
          ),
        timeoutMs
      )
    ),
  ]);
}
