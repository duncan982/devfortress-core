/**
 * Feedback Widget Component
 * Floating feedback button with thumbs up/down and optional text feedback
 * Following industry best practices for user feedback collection
 */

'use client';

import { useState, useCallback } from 'react';
import { usePathname } from 'next/navigation';
import {
  ThumbsUp,
  ThumbsDown,
  MessageSquare,
  X,
  Send,
  CheckCircle,
  Bug,
  Lightbulb,
} from 'lucide-react';
import { useAuthSession } from '@core/components/providers/session-provider';

type FeedbackType =
  | 'THUMBS_UP'
  | 'THUMBS_DOWN'
  | 'FEATURE_REQUEST'
  | 'BUG_REPORT'
  | 'GENERAL';
type FeedbackStep = 'closed' | 'quick' | 'detailed' | 'success';

interface FeedbackWidgetProps {
  position?: 'bottom-right' | 'bottom-left';
  showOnPages?: string[]; // If specified, only show on these pages
  hideOnPages?: string[]; // Pages to hide the widget on
}

export function FeedbackWidget({
  position = 'bottom-left',
  hideOnPages = ['/login', '/signup', '/auth'],
}: FeedbackWidgetProps) {
  const pathname = usePathname();
  const { session, status, isInitialized } = useAuthSession();
  const [step, setStep] = useState<FeedbackStep>('closed');
  const [feedbackType, setFeedbackType] = useState<FeedbackType | null>(null);
  const [description, setDescription] = useState('');
  const [title, setTitle] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Check if should hide on specific pages
  const shouldHide = hideOnPages.some(page => pathname.startsWith(page));

  const positionClasses =
    position === 'bottom-right' ? 'right-4 bottom-4' : 'left-4 bottom-4';

  const getCategoryFromType = useCallback((type: FeedbackType): string => {
    switch (type) {
      case 'THUMBS_UP':
      case 'THUMBS_DOWN':
        return 'satisfaction';
      case 'FEATURE_REQUEST':
        return 'feature';
      case 'BUG_REPORT':
        return 'bug';
      default:
        return 'general';
    }
  }, []);

  const submitFeedback = useCallback(
    async (type: FeedbackType, includeDetails = false) => {
      setIsSubmitting(true);
      setError(null);

      try {
        const response = await fetch('/api/feedback', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            type,
            page: pathname,
            title: includeDetails ? title : undefined,
            description: includeDetails ? description : undefined,
            category: getCategoryFromType(type),
            metadata: {
              userAgent:
                typeof navigator !== 'undefined' ? navigator.userAgent : null,
              screenWidth:
                typeof window !== 'undefined' ? window.innerWidth : null,
              screenHeight:
                typeof window !== 'undefined' ? window.innerHeight : null,
              timestamp: new Date().toISOString(),
            },
          }),
        });

        if (!response.ok) {
          throw new Error('Failed to submit feedback');
        }

        setStep('success');
        // Reset after showing success
        setTimeout(() => {
          setStep('closed');
          setFeedbackType(null);
          setDescription('');
          setTitle('');
        }, 2000);
      } catch {
        setError('Failed to submit feedback. Please try again.');
      } finally {
        setIsSubmitting(false);
      }
    },
    [pathname, title, description, getCategoryFromType]
  );

  const handleQuickFeedback = useCallback(
    (type: 'THUMBS_UP' | 'THUMBS_DOWN') => {
      setFeedbackType(type);
      submitFeedback(type, false);
    },
    [submitFeedback]
  );

  const handleDetailedFeedback = useCallback(
    (type: 'FEATURE_REQUEST' | 'BUG_REPORT' | 'GENERAL') => {
      setFeedbackType(type);
      setStep('detailed');
    },
    []
  );

  const handleSubmitDetailed = useCallback(() => {
    if (feedbackType && (description.trim() || title.trim())) {
      submitFeedback(feedbackType, true);
    }
  }, [feedbackType, description, title, submitFeedback]);

  // Only show feedback widget if user is authenticated
  // During initialization, don't hide the widget - wait for auth state to be determined
  if (isInitialized && (status !== 'authenticated' || !session)) {
    return null;
  }

  // Hide on specific pages - must be after all hooks
  if (shouldHide) {
    return null;
  }

  // Closed state - just the floating button
  if (step === 'closed') {
    return (
      <button
        onClick={() => setStep('quick')}
        className={`fixed ${positionClasses} z-50 flex h-12 w-12 items-center justify-center rounded-full bg-primary-600 text-white shadow-lg transition-all hover:bg-primary-700 hover:scale-110 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2`}
        aria-label="Give feedback"
        title="Give feedback"
      >
        <MessageSquare className="h-5 w-5" />
      </button>
    );
  }

  // Success state
  if (step === 'success') {
    return (
      <div
        className={`fixed ${positionClasses} z-50 flex items-center gap-2 rounded-lg bg-success-600 px-4 py-3 text-white shadow-lg`}
      >
        <CheckCircle className="h-5 w-5" />
        <span className="font-medium">Thanks for your feedback!</span>
      </div>
    );
  }

  // Quick feedback panel
  if (step === 'quick') {
    return (
      <div
        className={`fixed ${positionClasses} z-50 w-80 rounded-xl border border-neutral-200 bg-white p-4 shadow-2xl dark:border-neutral-700 dark:bg-neutral-900`}
      >
        {/* Header */}
        <div className="mb-4 flex items-center justify-between">
          <h3 className="text-lg font-semibold text-neutral-900 dark:text-neutral-100">
            Send Feedback
          </h3>
          <button
            onClick={() => setStep('closed')}
            className="rounded-full p-1 text-neutral-500 hover:bg-neutral-100 hover:text-neutral-700 dark:hover:bg-neutral-800 dark:hover:text-neutral-300"
            aria-label="Close"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Quick satisfaction feedback */}
        <div className="mb-4">
          <p className="mb-2 text-sm text-neutral-600 dark:text-neutral-400">
            How&apos;s your experience?
          </p>
          <div className="flex gap-3">
            <button
              onClick={() => handleQuickFeedback('THUMBS_UP')}
              disabled={isSubmitting}
              className="flex flex-1 items-center justify-center gap-2 rounded-lg border border-success-200 bg-success-50 px-4 py-3 text-success-700 transition-all hover:bg-success-100 hover:border-success-300 disabled:opacity-50 dark:border-success-800 dark:bg-success-900/20 dark:text-success-400 dark:hover:bg-success-900/40"
            >
              <ThumbsUp className="h-5 w-5" />
              <span className="font-medium">Good</span>
            </button>
            <button
              onClick={() => handleQuickFeedback('THUMBS_DOWN')}
              disabled={isSubmitting}
              className="flex flex-1 items-center justify-center gap-2 rounded-lg border border-error-200 bg-error-50 px-4 py-3 text-error-700 transition-all hover:bg-error-100 hover:border-error-300 disabled:opacity-50 dark:border-error-800 dark:bg-error-900/20 dark:text-error-400 dark:hover:bg-error-900/40"
            >
              <ThumbsDown className="h-5 w-5" />
              <span className="font-medium">Bad</span>
            </button>
          </div>
        </div>

        {/* Divider */}
        <div className="mb-4 flex items-center gap-3">
          <div className="h-px flex-1 bg-neutral-200 dark:bg-neutral-700" />
          <span className="text-xs text-neutral-500">or tell us more</span>
          <div className="h-px flex-1 bg-neutral-200 dark:bg-neutral-700" />
        </div>

        {/* Detailed feedback options */}
        <div className="grid grid-cols-2 gap-2">
          <button
            onClick={() => handleDetailedFeedback('FEATURE_REQUEST')}
            className="flex items-center gap-2 rounded-lg border border-neutral-200 px-3 py-2 text-sm text-neutral-700 transition-all hover:bg-neutral-50 hover:border-neutral-300 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
          >
            <Lightbulb className="h-4 w-4 text-warning-500" />
            <span>Feature idea</span>
          </button>
          <button
            onClick={() => handleDetailedFeedback('BUG_REPORT')}
            className="flex items-center gap-2 rounded-lg border border-neutral-200 px-3 py-2 text-sm text-neutral-700 transition-all hover:bg-neutral-50 hover:border-neutral-300 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
          >
            <Bug className="h-4 w-4 text-error-500" />
            <span>Report bug</span>
          </button>
        </div>

        {error && (
          <p className="mt-3 text-sm text-error-600 dark:text-error-400">
            {error}
          </p>
        )}
      </div>
    );
  }

  // Detailed feedback form
  if (step === 'detailed') {
    const typeLabels: Record<FeedbackType, string> = {
      THUMBS_UP: 'Positive Feedback',
      THUMBS_DOWN: 'Negative Feedback',
      FEATURE_REQUEST: 'Feature Request',
      BUG_REPORT: 'Bug Report',
      GENERAL: 'General Feedback',
    };

    return (
      <div
        className={`fixed ${positionClasses} z-50 w-96 rounded-xl border border-neutral-200 bg-white p-4 shadow-2xl dark:border-neutral-700 dark:bg-neutral-900`}
      >
        {/* Header */}
        <div className="mb-4 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <button
              onClick={() => setStep('quick')}
              className="rounded-full p-1 text-neutral-500 hover:bg-neutral-100 hover:text-neutral-700 dark:hover:bg-neutral-800 dark:hover:text-neutral-300"
              aria-label="Back"
            >
              ←
            </button>
            <h3 className="text-lg font-semibold text-neutral-900 dark:text-neutral-100">
              {feedbackType ? typeLabels[feedbackType] : 'Feedback'}
            </h3>
          </div>
          <button
            onClick={() => {
              setStep('closed');
              setFeedbackType(null);
              setDescription('');
              setTitle('');
            }}
            className="rounded-full p-1 text-neutral-500 hover:bg-neutral-100 hover:text-neutral-700 dark:hover:bg-neutral-800 dark:hover:text-neutral-300"
            aria-label="Close"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Form */}
        <div className="space-y-3">
          <div>
            <label
              htmlFor="feedback-title"
              className="mb-1 block text-sm font-medium text-neutral-700 dark:text-neutral-300"
            >
              Title{' '}
              <span className="text-neutral-400 dark:text-neutral-500">
                (optional)
              </span>
            </label>
            <input
              id="feedback-title"
              type="text"
              value={title}
              onChange={e => setTitle(e.target.value)}
              placeholder={
                feedbackType === 'BUG_REPORT'
                  ? 'Brief description of the issue'
                  : 'Brief summary'
              }
              className="w-full rounded-lg border border-neutral-300 px-3 py-2 text-sm transition-colors focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500 dark:border-neutral-600 dark:bg-neutral-800 dark:text-neutral-100"
              maxLength={200}
            />
          </div>

          <div>
            <label
              htmlFor="feedback-description"
              className="mb-1 block text-sm font-medium text-neutral-700 dark:text-neutral-300"
            >
              Details
            </label>
            <textarea
              id="feedback-description"
              value={description}
              onChange={e => setDescription(e.target.value)}
              placeholder={
                feedbackType === 'BUG_REPORT'
                  ? 'What happened? What did you expect to happen?'
                  : feedbackType === 'FEATURE_REQUEST'
                    ? 'Describe the feature you&apos;d like to see...'
                    : 'Share your thoughts...'
              }
              className="h-28 w-full resize-none rounded-lg border border-neutral-300 px-3 py-2 text-sm transition-colors focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500 dark:border-neutral-600 dark:bg-neutral-800 dark:text-neutral-100"
              maxLength={5000}
            />
            <p className="mt-1 text-xs text-neutral-500">
              {description.length}/5000 characters
            </p>
          </div>

          {/* Current page info */}
          <p className="text-xs text-neutral-500 dark:text-neutral-400">
            📍 Feedback about:{' '}
            <code className="text-primary-600">{pathname}</code>
          </p>

          {error && (
            <p className="text-sm text-error-600 dark:text-error-400">
              {error}
            </p>
          )}

          <button
            onClick={handleSubmitDetailed}
            disabled={isSubmitting || (!description.trim() && !title.trim())}
            className="flex w-full items-center justify-center gap-2 rounded-lg bg-primary-600 px-4 py-2.5 font-medium text-white transition-colors hover:bg-primary-700 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {isSubmitting ? (
              <>
                <span className="h-4 w-4 animate-spin rounded-full border-2 border-white border-t-transparent" />
                <span>Submitting...</span>
              </>
            ) : (
              <>
                <Send className="h-4 w-4" />
                <span>Submit Feedback</span>
              </>
            )}
          </button>
        </div>
      </div>
    );
  }

  return null;
}

export default FeedbackWidget;
