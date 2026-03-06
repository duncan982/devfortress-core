'use client';

/**
 * Support Chatbot Widget
 * Floating chatbot widget for in-app support
 * Restricted to authenticated users with subscriptions or admin/developer roles
 */

import { useState, useEffect, useRef } from 'react';
import { usePathname } from 'next/navigation';
import { Send, X, MessageCircle, Minimize2, Lock } from 'lucide-react';
import { logError } from '@core/lib/logger/client';
import Link from 'next/link';
import { useAuthSession } from '@core/components/providers/session-provider';

interface Message {
  role: 'user' | 'assistant';
  content: string;
  timestamp: Date;
}

interface SuggestedArticle {
  title: string;
  slug: string;
  relevance: number;
}

export function SupportChatbot() {
  const { session, status, isInitialized } = useAuthSession();
  const pathname = usePathname();
  const [isOpen, setIsOpen] = useState(false);
  const [isMinimized, setIsMinimized] = useState(false);
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [conversationId, setConversationId] = useState<string | null>(null);
  const [sessionId] = useState(
    () => `session_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
  );
  const [suggestedArticles, setSuggestedArticles] = useState<
    SuggestedArticle[]
  >([]);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  // Check if user has access to chat
  const hasAccess = () => {
    // During initialization, don't hide the widget - wait for auth state to be determined
    if (!isInitialized) {
      return true; // Show widget during initialization to prevent premature hiding
    }

    if (status !== 'authenticated' || !session) {
      return false;
    }

    const role = session.user.role;
    const isPrivilegedUser =
      role === 'ADMIN' || role === 'DEVELOPER' || role === 'OWNER';

    // TODO: Implement proper subscription checking when Supabase metadata is extended
    // For now, privileged users have access regardless of subscription status
    const hasActiveSubscription = isPrivilegedUser; // Temporary: privileged users always have access

    return isPrivilegedUser || hasActiveSubscription;
  };

  const userHasAccess = hasAccess();
  // Auto-scroll to bottom on new messages
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  // Initial greeting
  useEffect(() => {
    if (isOpen && messages.length === 0) {
      setMessages([
        {
          role: 'assistant',
          content:
            "Hi! I'm your DevFortress support assistant. How can I help you today?",
          timestamp: new Date(),
        },
      ]);
    }
  }, [isOpen, messages.length]);

  const handleSendMessage = async () => {
    if (!input.trim() || isLoading) return;

    const userMessage: Message = {
      role: 'user',
      content: input.trim(),
      timestamp: new Date(),
    };

    setMessages(prev => [...prev, userMessage]);
    setInput('');
    setIsLoading(true);

    try {
      const response = await fetch('/api/support/chatbot', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: userMessage.content,
          conversationId,
          sessionId,
        }),
      });

      if (!response.ok) {
        throw new Error('Failed to send message');
      }

      const data = await response.json();

      // Update conversation ID
      if (data.conversationId && !conversationId) {
        setConversationId(data.conversationId);
      }

      // Add assistant response
      const assistantMessage: Message = {
        role: 'assistant',
        content: data.response,
        timestamp: new Date(),
      };
      setMessages(prev => [...prev, assistantMessage]);

      // Update suggested articles
      if (data.suggestedArticles && data.suggestedArticles.length > 0) {
        setSuggestedArticles(data.suggestedArticles);
      }
    } catch (error) {
      logError('Error sending chatbot message', error);

      let errorMessage =
        "I'm sorry, I encountered an error. Please try again or visit our contact page at /contact for assistance.";

      // Handle specific error types
      if (error instanceof Error) {
        if (
          error.message.includes('Failed to fetch') ||
          error.message.includes('NetworkError')
        ) {
          errorMessage =
            "I'm having trouble connecting right now. Please check your internet connection and try again.";
        } else if (error.message.includes('403')) {
          errorMessage =
            'Access denied. Support chat is available to users with active subscriptions.';
        } else if (error.message.includes('503')) {
          errorMessage =
            'Service temporarily unavailable. Please try again in a few minutes.';
        }
      }

      const assistantErrorMessage: Message = {
        role: 'assistant',
        content: errorMessage,
        timestamp: new Date(),
      };
      setMessages(prev => [...prev, assistantErrorMessage]);
    } finally {
      setIsLoading(false);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSendMessage();
    }
  };

  const handleClose = async () => {
    if (conversationId) {
      try {
        await fetch(`/api/support/chatbot/${conversationId}/close`, {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({}),
        });
      } catch (error) {
        logError('Error closing conversation', error);
      }
    }
    setIsOpen(false);
    setMessages([]);
    setConversationId(null);
    setSuggestedArticles([]);
  };

  const shouldHideChat =
    pathname?.startsWith('/auth') || pathname?.startsWith('/onboarding');

  if (shouldHideChat) {
    return null;
  }

  // Show loading state while session is loading
  if (status === 'loading') {
    return (
      <button
        className="fixed bottom-6 right-6 z-50 rounded-full bg-neutral-400 p-4 text-white shadow-lg"
        disabled
        aria-label="Loading support chat"
      >
        <MessageCircle className="h-6 w-6 animate-spin" />
      </button>
    );
  }

  // Don't show if user doesn't have access
  if (!userHasAccess) {
    return (
      <button
        onClick={() => setIsOpen(true)}
        className="fixed bottom-6 right-6 z-50 rounded-full bg-neutral-400 p-4 text-white shadow-lg transition-all duration-200 hover:scale-110 hover:bg-neutral-500 focus:outline-none focus:ring-2 focus:ring-neutral-400 focus:ring-offset-2 dark:bg-neutral-600 dark:hover:bg-neutral-500"
        aria-label="Support chat (requires subscription)"
      >
        <Lock className="h-6 w-6" />
      </button>
    );
  }

  if (!isOpen) {
    return (
      <button
        onClick={() => setIsOpen(true)}
        className="fixed bottom-6 right-6 z-50 rounded-full bg-primary-600 p-4 text-white shadow-lg transition-all duration-200 hover:scale-110 hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2"
        aria-label="Open support chat"
      >
        <MessageCircle className="h-6 w-6" />
      </button>
    );
  }

  // Show access required message if opened without access
  if (!userHasAccess) {
    return (
      <div
        className={`fixed bottom-4 right-4 z-50 flex w-[calc(100vw-2rem)] max-w-96 flex-col rounded-lg border border-neutral-200 bg-white shadow-2xl transition-all duration-200 dark:border-neutral-700 dark:bg-neutral-900 ${
          isMinimized ? 'h-14' : 'h-auto'
        }`}
      >
        {/* Header */}
        <div className="flex items-center justify-between rounded-t-lg bg-gradient-to-r from-neutral-500 to-neutral-600 p-4 text-white">
          <div className="flex items-center gap-2">
            <Lock className="h-5 w-5" />
            <h3 className="font-semibold">Support Chat</h3>
          </div>
          <button
            onClick={() => setIsOpen(false)}
            className="rounded p-1 transition-colors hover:bg-neutral-400"
            aria-label="Close chat"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        {!isMinimized && (
          <div className="p-6">
            <div className="mb-4 rounded-lg border border-amber-200 bg-amber-50 p-4 dark:border-amber-800 dark:bg-amber-900/30">
              <div className="flex items-start gap-3">
                <Lock className="h-5 w-5 text-amber-600 dark:text-amber-400 mt-0.5" />
                <div>
                  <h4 className="font-semibold text-amber-900 dark:text-amber-100 mb-2">
                    Support Chat Access Required
                  </h4>
                  <p className="text-sm text-amber-800 dark:text-amber-200 mb-3">
                    Live support chat is available to:
                  </p>
                  <ul className="text-sm text-amber-800 dark:text-amber-200 space-y-1 mb-4 list-disc list-inside">
                    <li>Users with active subscriptions</li>
                    <li>Admin and Developer accounts</li>
                  </ul>
                  {!session ? (
                    <p className="text-sm text-amber-800 dark:text-amber-200 mb-3">
                      Please sign in to access support features.
                    </p>
                  ) : (
                    <p className="text-sm text-amber-800 dark:text-amber-200 mb-3">
                      Upgrade your account to get live support assistance.
                    </p>
                  )}
                  <div className="flex gap-2">
                    {!session ? (
                      <Link
                        href="/auth/signin"
                        className="inline-flex items-center rounded-lg bg-primary-600 px-4 py-2 text-sm font-semibold text-white transition-colors hover:bg-primary-700"
                      >
                        Sign In
                      </Link>
                    ) : (
                      <Link
                        href="/pricing"
                        className="inline-flex items-center rounded-lg bg-primary-600 px-4 py-2 text-sm font-semibold text-white transition-colors hover:bg-primary-700"
                      >
                        View Plans
                      </Link>
                    )}
                    <Link
                      href="/help"
                      className="inline-flex items-center rounded-lg border border-amber-300 bg-white px-4 py-2 text-sm font-semibold text-amber-900 transition-colors hover:bg-amber-50 dark:border-amber-700 dark:bg-neutral-800 dark:text-amber-100 dark:hover:bg-neutral-700"
                    >
                      Help Center
                    </Link>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    );
  }

  return (
    <div
      className={`fixed bottom-4 right-4 z-50 flex w-[calc(100vw-2rem)] max-w-96 flex-col rounded-lg border border-neutral-200 bg-white shadow-2xl transition-all duration-200 dark:border-neutral-700 dark:bg-neutral-900 ${
        isMinimized ? 'h-14' : 'h-[min(600px,calc(100vh-6rem))]'
      }`}
    >
      {/* Header */}
      <div className="flex items-center justify-between rounded-t-lg bg-gradient-to-r from-primary-600 to-primary-700 p-4 text-white">
        <div className="flex items-center gap-2">
          <MessageCircle className="h-5 w-5" />
          <h3 className="font-semibold">Support Assistant</h3>
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => setIsMinimized(!isMinimized)}
            className="rounded p-1 transition-colors hover:bg-primary-500"
            aria-label={isMinimized ? 'Maximize' : 'Minimize'}
          >
            <Minimize2 className="h-4 w-4" />
          </button>
          <button
            onClick={handleClose}
            className="rounded p-1 transition-colors hover:bg-primary-500"
            aria-label="Close chat"
          >
            <X className="h-4 w-4" />
          </button>
        </div>
      </div>

      {!isMinimized && (
        <>
          {/* Messages */}
          <div className="flex-1 space-y-4 overflow-y-auto bg-neutral-50 p-4 dark:bg-neutral-900">
            {messages.map((message, index) => (
              <div
                key={index}
                className={`flex ${
                  message.role === 'user' ? 'justify-end' : 'justify-start'
                }`}
              >
                <div
                  className={`max-w-[80%] rounded-lg p-3 ${
                    message.role === 'user'
                      ? 'bg-primary-600 text-white'
                      : 'border border-neutral-200 bg-white text-neutral-900 dark:border-neutral-700 dark:bg-neutral-800 dark:text-neutral-100'
                  }`}
                >
                  <p className="text-sm whitespace-pre-wrap">
                    {message.content}
                  </p>
                  <p
                    className={`text-xs mt-1 ${
                      message.role === 'user'
                        ? 'text-primary-100'
                        : 'text-neutral-500 dark:text-neutral-400'
                    }`}
                  >
                    {message.timestamp.toLocaleTimeString([], {
                      hour: '2-digit',
                      minute: '2-digit',
                    })}
                  </p>
                </div>
              </div>
            ))}

            {/* Suggested Articles */}
            {suggestedArticles.length > 0 && (
              <div className="rounded-lg border border-primary-200 bg-primary-50 p-3 dark:border-primary-700/60 dark:bg-primary-900/30">
                <p className="mb-2 text-xs font-semibold text-primary-900 dark:text-primary-200">
                  📚 Helpful articles:
                </p>
                <ul className="space-y-1">
                  {suggestedArticles.map((article, index) => (
                    <li key={index}>
                      <a
                        href={`/help/${article.slug}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-xs text-primary-600 hover:text-primary-700 hover:underline dark:text-primary-300 dark:hover:text-primary-200"
                      >
                        {article.title}
                      </a>
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {isLoading && (
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
            <div ref={messagesEndRef} />
          </div>

          {/* Input */}
          <div className="rounded-b-lg border-t border-neutral-200 bg-white p-4 dark:border-neutral-700 dark:bg-neutral-900">
            <div className="flex gap-2">
              <textarea
                value={input}
                onChange={e => setInput(e.target.value)}
                onKeyDown={handleKeyDown}
                placeholder="Type your message..."
                className="flex-1 resize-none rounded-lg border border-neutral-300 px-3 py-2 text-sm focus:border-transparent focus:outline-none focus:ring-2 focus:ring-primary-500 dark:border-neutral-700 dark:bg-neutral-900 dark:text-neutral-100"
                rows={2}
                disabled={isLoading}
              />
              <button
                onClick={handleSendMessage}
                disabled={isLoading || !input.trim()}
                className="rounded-lg bg-primary-600 px-4 py-2 text-white transition-colors hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2 disabled:cursor-not-allowed disabled:bg-neutral-300 dark:focus:ring-offset-neutral-900 dark:disabled:bg-neutral-700"
                aria-label="Send message"
              >
                <Send className="h-5 w-5" />
              </button>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
