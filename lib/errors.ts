import { NextResponse } from 'next/server';

export interface ErrorResponse {
  code: string;
  message: string;
  requestId?: string;
}

/**
 * Creates a standardized error response
 */
export function createErrorResponse(
  status: number,
  message: string,
  requestId?: string
): NextResponse<ErrorResponse> {
  const errorResponse: ErrorResponse = {
    code: status.toString(),
    message,
    ...(requestId && { requestId }),
  };

  return NextResponse.json(errorResponse, { status });
}

/**
 * Common error responses
 */
export const errors = {
  unauthorized: (requestId?: string) =>
    createErrorResponse(401, 'Unauthorized', requestId),
  forbidden: (requestId?: string) =>
    createErrorResponse(403, 'Forbidden', requestId),
  notFound: (requestId?: string) =>
    createErrorResponse(404, 'Not found', requestId),
  badRequest: (message: string, requestId?: string) =>
    createErrorResponse(400, message, requestId),
  internalServerError: (requestId?: string) =>
    createErrorResponse(500, 'Internal server error', requestId),
  quotaExceeded: (requestId?: string) =>
    createErrorResponse(403, 'Quota exceeded', requestId),
};