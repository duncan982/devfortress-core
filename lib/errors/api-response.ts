/**
 * Standardized API Error Response Utility
 * Provides consistent error response formatting across all API routes
 */

import { NextResponse } from 'next/server';
import { errorHandler as errorHandlerInstance } from '@core/lib/errors/error-handler';

const errorHandler = errorHandlerInstance;

/**
 * Standardized API error response format
 */
export interface ApiErrorResponse {
  success: false;
  error: {
    code: string;
    message: string;
    details?: Record<string, unknown>;
    trackingId: string;
  };
  timestamp: string;
}

/**
 * Standardized API success response format
 */
export interface ApiSuccessResponse<T = unknown> {
  success: true;
  data: T;
  timestamp: string;
}

/**
 * Create a standardized error response
 */
export function createErrorResponse(
  error: Error | unknown,
  context?: Record<string, unknown>,
  statusCode: number = 500
): NextResponse<ApiErrorResponse> {
  const enhancedError = errorHandler.handle(error, context);

  const response: ApiErrorResponse = {
    success: false,
    error: {
      code: enhancedError.code,
      message: enhancedError.userMessage, // Use user-friendly message
      details:
        process.env.NODE_ENV === 'development'
          ? enhancedError.details
          : undefined,
      trackingId: enhancedError.trackingId,
    },
    timestamp: enhancedError.timestamp.toISOString(),
  };

  return NextResponse.json(response, { status: statusCode });
}

/**
 * Create a standardized success response
 */
export function createSuccessResponse<T = unknown>(
  data: T,
  statusCode: number = 200
): NextResponse<ApiSuccessResponse<T>> {
  const response: ApiSuccessResponse<T> = {
    success: true,
    data,
    timestamp: new Date().toISOString(),
  };

  return NextResponse.json(response, { status: statusCode });
}

/**
 * Common error responses for frequent use cases
 */
export const commonErrors = {
  unauthorized: (message = 'Authentication required') =>
    createErrorResponse(new Error(message), { type: 'authentication' }, 401),

  forbidden: (message = 'Access denied') =>
    createErrorResponse(new Error(message), { type: 'authorization' }, 403),

  notFound: (resource = 'Resource') =>
    createErrorResponse(
      new Error(`${resource} not found`),
      { type: 'not_found', resource },
      404
    ),

  badRequest: (message = 'Invalid request') =>
    createErrorResponse(new Error(message), { type: 'validation' }, 400),

  internalServerError: (message = 'Internal server error') =>
    createErrorResponse(new Error(message), { type: 'internal' }, 500),

  rateLimit: (limit: number, window: string) =>
    createErrorResponse(
      new Error(`Rate limit exceeded: ${limit} requests per ${window}`),
      { type: 'rate_limit', limit, window },
      429
    ),

  conflict: (message = 'Resource conflict') =>
    createErrorResponse(new Error(message), { type: 'conflict' }, 409),
};
