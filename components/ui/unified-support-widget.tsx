/**
 * Unified Support Widget Component
 * Combines chat and feedback functionality in a single toggleable widget
 * Positioned at bottom left, visible only for authenticated users with active subscriptions
 */

'use client';

import React, { useState, useCallback, useEffect } from 'react';
import { usePathname } from 'next/navigation';
import {
  MessageCircle,
  ThumbsUp,
  ThumbsDown,
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
type WidgetMode = 'chat' | 'feedback';

interface Message {
  role: 'user' | 'assistant';
  content: string;
  timestamp: Date;
}

export function UnifiedSupportWidget() {
  const pathname = usePathname();
  const { session, status: authStatus, isInitialized } = useAuthSession();

  const [mode, setMode] = useState<WidgetMode>('feedback');
  const [isOpen, setIsOpen] = useState(false);

  // Feedback state
  const [feedbackStep, setFeedbackStep] = useState<FeedbackStep>('closed');
  const [feedbackType, setFeedbackType] = useState<FeedbackType | null>(null);
  const [description, setDescription] = useState('');
  const [title, setTitle] = useState('');
  const [isSubmittingFeedback, setIsSubmittingFeedback] = useState(false);
  const [feedbackError, setFeedbackError] = useState<string | null>(null);

  // Chat state
  const [chatMessages, setChatMessages] = useState<Message[]>([]);
  const [chatInput, setChatInput] = useState('');
  const [isLoadingChat, setIsLoadingChat] = useState(false);
  const [conversationId, setConversationId] = useState<string | null>(null);

  // Check if user has access (authenticated users)
  const hasAccess = () => {
    // During initialization, don't hide the widget - wait for auth state to be determined
    if (!isInitialized) {
      return true; // Show widget during initialization to prevent premature hiding
    }

    if (authStatus !== 'authenticated' || !session) {
      return false;
    }

    // All authenticated users can access the support widget
    return true;
  };

  const userHasAccess = hasAccess();

  // Hide on auth-related pages
  const shouldHide =
    pathname?.startsWith('/auth') ||
    pathname?.startsWith('/login') ||
    pathname?.startsWith('/signup') ||
    pathname?.startsWith('/onboarding');

  // Feedback functionality
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
      setIsSubmittingFeedback(true);
      setFeedbackError(null);

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

        setFeedbackStep('success');
        // Reset after showing success
        setTimeout(() => {
          setFeedbackStep('closed');
          setFeedbackType(null);
          setDescription('');
          setTitle('');
          setIsOpen(false);
        }, 2000);
      } catch {
        setFeedbackError('Failed to submit feedback. Please try again.');
      } finally {
        setIsSubmittingFeedback(false);
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
      setFeedbackStep('detailed');
    },
    []
  );

  const handleSubmitDetailed = useCallback(() => {
    if (feedbackType && (description.trim() || title.trim())) {
      submitFeedback(feedbackType, true);
    }
  }, [feedbackType, description, title, submitFeedback]);

  // Chat functionality
  const handleSendChatMessage = async () => {
    if (!chatInput.trim() || isLoadingChat) return;

    const userMessage: Message = {
      role: 'user',
      content: chatInput.trim(),
      timestamp: new Date(),
    };

    setChatMessages(prev => [...prev, userMessage]);
    setChatInput('');
    setIsLoadingChat(true);

    try {
      const response = await fetch('/api/support/chatbot', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: userMessage.content,
          conversationId,
        }),
      });

      if (!response.ok) {
        throw new Error('Failed to send message');
      }

      const data = await response.json();
      setConversationId(data.conversationId);

      const assistantMessage: Message = {
        role: 'assistant',
        content: data.response,
        timestamp: new Date(),
      };

      setChatMessages(prev => [...prev, assistantMessage]);
    } catch {
      const errorMessage: Message = {
        role: 'assistant',
        content: 'Sorry, I encountered an error. Please try again.',
        timestamp: new Date(),
      };
      setChatMessages(prev => [...prev, errorMessage]);
    } finally {
      setIsLoadingChat(false);
    }
  };

  const handleChatKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSendChatMessage();
    }
  };

  // Initialize chat greeting
  useEffect(() => {
    if (mode === 'chat' && isOpen && chatMessages.length === 0) {
      setChatMessages([
        {
          role: 'assistant',
          content:
            "Hi! I'm your DevFortress support assistant. How can I help you today?",
          timestamp: new Date(),
        },
      ]);
    }
  }, [mode, isOpen, chatMessages.length]);

  // Switch mode
  const switchMode = (newMode: WidgetMode) => {
    if (newMode === mode) return;
    setMode(newMode);
    // Reset states when switching
    setFeedbackStep('closed');
    setFeedbackType(null);
    setDescription('');
    setTitle('');
    setFeedbackError(null);
    if (newMode === 'chat') {
      setChatMessages([]);
      setConversationId(null);
    }
  };

  // Early returns after all hooks
  if (shouldHide) {
    return null;
  }

  // Show loading state while checking auth
  if (authStatus === 'loading') {
    return (
      <button
        className="fixed bottom-4 right-4 z-50 rounded-full bg-neutral-400 p-4 text-white shadow-lg"
        disabled
        aria-label="Loading support widget"
      >
        <MessageCircle className="h-6 w-6 animate-spin" />
      </button>
    );
  }

  // Don't show if user doesn't have access
  if (!userHasAccess) {
    return null; // No widget shown for unauthenticated users
  }

  // Closed state - floating button
  if (!isOpen) {
    return (
      <button
        onClick={() => setIsOpen(true)}
        className="fixed bottom-4 right-4 z-50 rounded-full bg-primary-600 p-4 text-white shadow-lg transition-all duration-200 hover:scale-110 hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2"
        aria-label="Open Chat & Feedback Support"
      >
        <MessageCircle className="h-6 w-6" />
      </button>
    );
  }

  // Open state - full widget
  return (
    <div className="fixed bottom-4 right-4 z-50 w-[calc(100vw-2rem)] max-w-96 rounded-lg border border-neutral-200 bg-white shadow-2xl dark:border-neutral-700 dark:bg-neutral-900">
      {/* Header */}
      <div className="flex items-center justify-between rounded-t-lg bg-gradient-to-r from-primary-600 to-primary-700 p-4 text-white">
        <div className="flex items-center gap-2">
          <h3 className="font-semibold">Chat & Feedback</h3>
        </div>
        <div className="flex items-center gap-2">
          <div className="flex rounded-lg bg-primary-500 p-1">
            <button
              onClick={() => switchMode('chat')}
              className={`rounded px-3 py-1 text-sm transition-colors ${
                mode === 'chat'
                  ? 'bg-white text-primary-700'
                  : 'text-white hover:bg-primary-400'
              }`}
            >
              Chat
            </button>
            <button
              onClick={() => switchMode('feedback')}
              className={`rounded px-3 py-1 text-sm transition-colors ${
                mode === 'feedback'
                  ? 'bg-white text-primary-700'
                  : 'text-white hover:bg-primary-400'
              }`}
            >
              Feedback
            </button>
          </div>
          <button
            onClick={() => setIsOpen(false)}
            className="rounded p-1 transition-colors hover:bg-primary-500"
            aria-label="Close widget"
          >
            <X className="h-4 w-4" />
          </button>
        </div>
      </div>

      {/* Content */}
      <div className="max-h-96 overflow-y-auto p-4">
        {mode === 'feedback' ? (
          // Feedback Content
          <>
            {feedbackStep === 'closed' && (
              <div className="space-y-4">
                <p className="text-sm text-neutral-600 dark:text-neutral-400">
                  How was your experience?
                </p>
                <div className="flex gap-2">
                  <button
                    onClick={() => handleQuickFeedback('THUMBS_UP')}
                    disabled={isSubmittingFeedback}
                    className="flex items-center gap-2 rounded-lg border border-neutral-300 px-3 py-2 text-sm transition-colors hover:bg-neutral-50 focus:outline-none focus:ring-2 focus:ring-primary-500 dark:border-neutral-700 dark:hover:bg-neutral-800"
                  >
                    <ThumbsUp className="h-4 w-4 text-green-600" />
                    Good
                  </button>
                  <button
                    onClick={() => handleQuickFeedback('THUMBS_DOWN')}
                    disabled={isSubmittingFeedback}
                    className="flex items-center gap-2 rounded-lg border border-neutral-300 px-3 py-2 text-sm transition-colors hover:bg-neutral-50 focus:outline-none focus:ring-2 focus:ring-primary-500 dark:border-neutral-700 dark:hover:bg-neutral-800"
                  >
                    <ThumbsDown className="h-4 w-4 text-red-600" />
                    Poor
                  </button>
                </div>
                <div className="flex gap-2">
                  <button
                    onClick={() => handleDetailedFeedback('FEATURE_REQUEST')}
                    className="flex items-center gap-2 rounded-lg border border-neutral-300 px-3 py-2 text-sm transition-colors hover:bg-neutral-50 focus:outline-none focus:ring-2 focus:ring-primary-500 dark:border-neutral-700 dark:hover:bg-neutral-800"
                  >
                    <Lightbulb className="h-4 w-4 text-yellow-600" />
                    Feature Request
                  </button>
                  <button
                    onClick={() => handleDetailedFeedback('BUG_REPORT')}
                    className="flex items-center gap-2 rounded-lg border border-neutral-300 px-3 py-2 text-sm transition-colors hover:bg-neutral-50 focus:outline-none focus:ring-2 focus:ring-primary-500 dark:border-neutral-700 dark:hover:bg-neutral-800"
                  >
                    <Bug className="h-4 w-4 text-red-600" />
                    Bug Report
                  </button>
                </div>
              </div>
            )}

            {feedbackStep === 'detailed' && (
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-neutral-700 dark:text-neutral-300">
                    Title (optional)
                  </label>
                  <input
                    type="text"
                    value={title}
                    onChange={e => setTitle(e.target.value)}
                    className="mt-1 block w-full rounded-md border border-neutral-300 px-3 py-2 text-sm focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500 dark:border-neutral-700 dark:bg-neutral-800 dark:text-neutral-100"
                    placeholder="Brief title for your feedback"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-neutral-700 dark:text-neutral-300">
                    Description
                  </label>
                  <textarea
                    value={description}
                    onChange={e => setDescription(e.target.value)}
                    rows={4}
                    className="mt-1 block w-full rounded-md border border-neutral-300 px-3 py-2 text-sm focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500 dark:border-neutral-700 dark:bg-neutral-800 dark:text-neutral-100"
                    placeholder="Please provide details..."
                    required
                  />
                </div>
                <div className="flex gap-2">
                  <button
                    onClick={() => setFeedbackStep('closed')}
                    className="rounded-lg border border-neutral-300 px-4 py-2 text-sm transition-colors hover:bg-neutral-50 focus:outline-none focus:ring-2 focus:ring-primary-500 dark:border-neutral-700 dark:hover:bg-neutral-800"
                  >
                    Back
                  </button>
                  <button
                    onClick={handleSubmitDetailed}
                    disabled={isSubmittingFeedback || !description.trim()}
                    className="rounded-lg bg-primary-600 px-4 py-2 text-sm text-white transition-colors hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2 disabled:cursor-not-allowed disabled:bg-neutral-300 dark:focus:ring-offset-neutral-900 dark:disabled:bg-neutral-700"
                  >
                    {isSubmittingFeedback ? 'Submitting...' : 'Submit'}
                  </button>
                </div>
                {feedbackError && (
                  <p className="text-sm text-red-600 dark:text-red-400">
                    {feedbackError}
                  </p>
                )}
              </div>
            )}

            {feedbackStep === 'success' && (
              <div className="flex items-center gap-2 text-green-600 dark:text-green-400">
                <CheckCircle className="h-5 w-5" />
                <span className="text-sm">Thank you for your feedback!</span>
              </div>
            )}
          </>
        ) : (
          // Chat Content
          <>
            <div className="space-y-4">
              {chatMessages.map((message, index) => (
                <div
                  key={index}
                  className={`flex ${
                    message.role === 'user' ? 'justify-end' : 'justify-start'
                  }`}
                >
                  <div
                    className={`rounded-lg px-3 py-2 text-sm ${
                      message.role === 'user'
                        ? 'bg-primary-600 text-white'
                        : 'border border-neutral-200 bg-white dark:border-neutral-700 dark:bg-neutral-800'
                    }`}
                  >
                    {message.content}
                  </div>
                </div>
              ))}

              {isLoadingChat && (
                <div className="flex justify-start">
                  <div className="rounded-lg border border-neutral-200 bg-white p-3 dark:border-neutral-700 dark:bg-neutral-800">
                    <div className="flex space-x-2">
                      <div className="h-2 w-2 animate-bounce rounded-full bg-neutral-400 dark:bg-neutral-500"></div>
                      <div
                        className="h-2 w-2 animate-bounce rounded-full bg-neutral-400 dark:bg-neutral-500"
                        style={{ animationDelay: '0.1s' }}
                      ></div>
                      <div
                        className="h-2 w-2 animate-bounce rounded-full bg-neutral-400 dark:bg-neutral-500"
                        style={{ animationDelay: '0.2s' }}
                      ></div>
                    </div>
                  </div>
                </div>
              )}
            </div>

            {/* Chat Input */}
            <div className="mt-4 flex gap-2">
              <textarea
                value={chatInput}
                onChange={e => setChatInput(e.target.value)}
                onKeyDown={handleChatKeyDown}
                placeholder="Type your message..."
                className="flex-1 resize-none rounded-lg border border-neutral-300 px-3 py-2 text-sm focus:border-transparent focus:outline-none focus:ring-2 focus:ring-primary-500 dark:border-neutral-700 dark:bg-neutral-800 dark:text-neutral-100"
                rows={2}
                disabled={isLoadingChat}
              />
              <button
                onClick={handleSendChatMessage}
                disabled={isLoadingChat || !chatInput.trim()}
                className="rounded-lg bg-primary-600 px-4 py-2 text-white transition-colors hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2 disabled:cursor-not-allowed disabled:bg-neutral-300 dark:focus:ring-offset-neutral-900 dark:disabled:bg-neutral-700"
                aria-label="Send message"
              >
                <Send className="h-5 w-5" />
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
