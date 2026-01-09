'use client';

/**
 * Error Boundary Component
 * Catches React errors and displays user-friendly fallback UI
 */

import React, { Component, ReactNode } from 'react';
import { errorHandler, ErrorSeverity } from '@core/lib/errors/error-handler';

interface Props {
  children: ReactNode;
  fallback?: ReactNode;
}

interface State {
  hasError: boolean;
  errorInfo?: {
    message: string;
    userMessage: string;
    trackingId: string;
    severity: ErrorSeverity;
    recoveryStrategies: Array<{ action: string; description: string }>;
  };
}

/**
 * Error Boundary for React components
 */
export class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { hasError: false };
  }

  static getDerivedStateFromError(): State {
    return { hasError: true };
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo): void {
    // Handle error with error handler service
    const enhanced = errorHandler.handle(error, {
      componentStack: errorInfo.componentStack,
      type: 'react_error',
    });

    this.setState({
      hasError: true,
      errorInfo: {
        message: enhanced.message,
        userMessage: enhanced.userMessage,
        trackingId: enhanced.trackingId,
        severity: enhanced.severity,
        recoveryStrategies: enhanced.recoveryStrategies,
      },
    });
  }

  handleRetry = (): void => {
    this.setState({ hasError: false, errorInfo: undefined });
    window.location.reload();
  };

  handleGoBack = (): void => {
    window.history.back();
  };

  render(): ReactNode {
    if (this.state.hasError) {
      if (this.props.fallback) {
        return this.props.fallback;
      }

      const { errorInfo } = this.state;

      return (
        <div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-neutral-900 px-4">
          <div className="max-w-md w-full bg-white dark:bg-neutral-800 rounded-lg shadow-lg dark:shadow-neutral-900/50 p-6">
            <div className="flex items-center justify-center w-12 h-12 mx-auto bg-red-100 dark:bg-red-900/50 rounded-full mb-4">
              <svg
                className="w-6 h-6 text-red-600"
                fill="none"
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth="2"
                viewBox="0 0 24 24"
                stroke="currentColor"
              >
                <path d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
              </svg>
            </div>

            <h2 className="text-xl font-bold text-gray-900 dark:text-neutral-100 text-center mb-2">
              Something went wrong
            </h2>

            <p className="text-gray-600 dark:text-neutral-400 text-center mb-4">
              {errorInfo?.userMessage || 'An unexpected error occurred'}
            </p>

            {errorInfo?.trackingId && (
              <div className="bg-gray-50 dark:bg-neutral-700 rounded p-3 mb-4">
                <p className="text-xs text-gray-500 dark:text-neutral-400">
                  Error ID:
                </p>
                <p className="text-sm font-mono text-gray-700 dark:text-neutral-300">
                  {errorInfo.trackingId}
                </p>
              </div>
            )}

            {errorInfo?.recoveryStrategies &&
              errorInfo.recoveryStrategies.length > 0 && (
                <div className="mb-4">
                  <p className="text-sm font-medium text-gray-700 dark:text-neutral-300 mb-2">
                    What you can do:
                  </p>
                  <ul className="space-y-2">
                    {errorInfo.recoveryStrategies.map((strategy, index) => (
                      <li key={index} className="flex items-start">
                        <svg
                          className="w-4 h-4 text-blue-500 mt-0.5 mr-2 flex-shrink-0"
                          fill="currentColor"
                          viewBox="0 0 20 20"
                        >
                          <path
                            fillRule="evenodd"
                            d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z"
                            clipRule="evenodd"
                          />
                        </svg>
                        <span className="text-sm text-gray-600 dark:text-neutral-400">
                          {strategy.description}
                        </span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

            <div className="flex gap-3">
              <button
                onClick={this.handleRetry}
                className="flex-1 bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700 transition-colors"
              >
                Retry
              </button>
              <button
                onClick={this.handleGoBack}
                className="flex-1 bg-gray-200 text-gray-700 px-4 py-2 rounded-md hover:bg-gray-300 transition-colors"
              >
                Go Back
              </button>
            </div>

            {errorInfo?.severity === ErrorSeverity.CRITICAL && (
              <p className="text-xs text-center text-gray-500 mt-4">
                This is a critical error. Our team has been automatically
                notified.
              </p>
            )}
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
