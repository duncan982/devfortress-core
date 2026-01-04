/**
 * Admin Chatbot Escalations Dashboard Component
 * View and manage escalated chatbot conversations
 */

'use client';

import { useState, useEffect, useCallback } from 'react';
import {
  MessageSquare,
  AlertCircle,
  CheckCircle,
  RefreshCw,
  ExternalLink,
  User,
  Clock,
} from 'lucide-react';

type ConversationStatus = 'ACTIVE' | 'RESOLVED' | 'ESCALATED' | 'CLOSED';

interface ChatbotConversation {
  id: string;
  userId: string | null;
  sessionId: string;
  status: ConversationStatus;
  topic: string | null;
  escalatedAt: string | null;
  escalatedReason: string | null;
  resolvedAt: string | null;
  satisfaction: number | null;
  createdAt: string;
  updatedAt: string;
  user: {
    id: string;
    name: string | null;
    email: string;
  } | null;
  messages: Array<{
    id: string;
    role: 'USER' | 'ASSISTANT' | 'SYSTEM';
    content: string;
    createdAt: string;
  }>;
  _count: {
    messages: number;
  };
}

interface EscalationStats {
  totalEscalated: number;
  pendingTickets: number;
}

export function AdminChatbotEscalations() {
  const [conversations, setConversations] = useState<ChatbotConversation[]>([]);
  const [stats, setStats] = useState<EscalationStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [selectedConversation, setSelectedConversation] = useState<ChatbotConversation | null>(null);

  const fetchConversations = useCallback(async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams({
        page: page.toString(),
        pageSize: '25',
      });

      const response = await fetch(`/api/admin/chatbot-escalations?${params.toString()}`);
      const data = await response.json();

      if (response.ok) {
        setConversations(data.conversations);
        setTotalPages(data.totalPages);
        setStats(data.stats);
      }
    } catch {
      // Error handled silently - component will show loading state
    } finally {
      setLoading(false);
    }
  }, [page]);

  useEffect(() => {
    fetchConversations();
  }, [fetchConversations]);

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleString();
  };

  const getStatusColor = (status: ConversationStatus) => {
    switch (status) {
      case 'ESCALATED':
        return 'text-red-600 bg-red-100';
      case 'RESOLVED':
        return 'text-green-600 bg-green-100';
      case 'ACTIVE':
        return 'text-blue-600 bg-blue-100';
      case 'CLOSED':
        return 'text-gray-600 bg-gray-100';
      default:
        return 'text-gray-600 bg-gray-100';
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-neutral-900 dark:text-neutral-100">
            Chatbot Escalations
          </h1>
          <p className="text-neutral-600 dark:text-neutral-400">
            Manage escalated chatbot conversations that need human attention
          </p>
        </div>
        <button
          onClick={fetchConversations}
          className="flex items-center gap-2 px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 transition-colors"
        >
          <RefreshCw className="w-4 h-4" />
          Refresh
        </button>
      </div>

      {/* Stats */}
      {stats && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="bg-white dark:bg-neutral-800 p-6 rounded-lg border border-neutral-200 dark:border-neutral-700">
            <div className="flex items-center gap-3">
              <AlertCircle className="w-8 h-8 text-red-600" />
              <div>
                <p className="text-sm text-neutral-600 dark:text-neutral-400">
                  Escalated Conversations
                </p>
                <p className="text-2xl font-bold text-neutral-900 dark:text-neutral-100">
                  {stats.totalEscalated}
                </p>
              </div>
            </div>
          </div>
          <div className="bg-white dark:bg-neutral-800 p-6 rounded-lg border border-neutral-200 dark:border-neutral-700">
            <div className="flex items-center gap-3">
              <CheckCircle className="w-8 h-8 text-green-600" />
              <div>
                <p className="text-sm text-neutral-600 dark:text-neutral-400">
                  Pending Support Tickets
                </p>
                <p className="text-2xl font-bold text-neutral-900 dark:text-neutral-100">
                  {stats.pendingTickets}
                </p>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Conversations List */}
      <div className="bg-white dark:bg-neutral-800 rounded-lg border border-neutral-200 dark:border-neutral-700">
        {loading ? (
          <div className="p-8 text-center">
            <RefreshCw className="w-8 h-8 animate-spin mx-auto mb-4 text-neutral-400" />
            <p className="text-neutral-600 dark:text-neutral-400">Loading escalations...</p>
          </div>
        ) : conversations.length === 0 ? (
          <div className="p-8 text-center">
            <MessageSquare className="w-12 h-12 mx-auto mb-4 text-neutral-400" />
            <p className="text-neutral-600 dark:text-neutral-400">No escalated conversations</p>
          </div>
        ) : (
          <div className="divide-y divide-neutral-200 dark:divide-neutral-700">
            {conversations.map((conversation) => (
              <div
                key={conversation.id}
                className="p-6 hover:bg-neutral-50 dark:hover:bg-neutral-700 cursor-pointer"
                onClick={() => setSelectedConversation(conversation)}
              >
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <div className="flex items-center gap-3 mb-2">
                      <span
                        className={`px-2 py-1 text-xs font-medium rounded-full ${getStatusColor(
                          conversation.status
                        )}`}
                      >
                        {conversation.status}
                      </span>
                      <span className="text-sm text-neutral-500 dark:text-neutral-400">
                        {conversation._count.messages} messages
                      </span>
                    </div>

                    <div className="flex items-center gap-4 text-sm text-neutral-600 dark:text-neutral-400 mb-2">
                      {conversation.user ? (
                        <div className="flex items-center gap-1">
                          <User className="w-4 h-4" />
                          {conversation.user.name || conversation.user.email}
                        </div>
                      ) : (
                        <span>Anonymous user</span>
                      )}
                      <div className="flex items-center gap-1">
                        <Clock className="w-4 h-4" />
                        {conversation.escalatedAt
                          ? `Escalated ${formatDate(conversation.escalatedAt)}`
                          : `Created ${formatDate(conversation.createdAt)}`
                        }
                      </div>
                    </div>

                    {conversation.topic && (
                      <p className="text-neutral-900 dark:text-neutral-100 font-medium mb-1">
                        {conversation.topic}
                      </p>
                    )}

                    {conversation.escalatedReason && (
                      <p className="text-neutral-600 dark:text-neutral-400 text-sm">
                        {conversation.escalatedReason}
                      </p>
                    )}

                    {/* Last message preview */}
                    {conversation.messages.length > 0 && (
                      <div className="mt-2 p-3 bg-neutral-50 dark:bg-neutral-700 rounded text-sm">
                        <span className="font-medium text-neutral-700 dark:text-neutral-300">
                          {conversation.messages[conversation.messages.length - 1].role}:
                        </span>{' '}
                        {conversation.messages[conversation.messages.length - 1].content.length > 100
                          ? `${conversation.messages[conversation.messages.length - 1].content.substring(0, 100)}...`
                          : conversation.messages[conversation.messages.length - 1].content
                        }
                      </div>
                    )}
                  </div>

                  <ExternalLink className="w-5 h-5 text-neutral-400" />
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex justify-center gap-2">
          <button
            onClick={() => setPage(Math.max(1, page - 1))}
            disabled={page === 1}
            className="px-3 py-1 border border-neutral-300 dark:border-neutral-600 rounded disabled:opacity-50 disabled:cursor-not-allowed"
          >
            Previous
          </button>
          <span className="px-3 py-1">
            Page {page} of {totalPages}
          </span>
          <button
            onClick={() => setPage(Math.min(totalPages, page + 1))}
            disabled={page === totalPages}
            className="px-3 py-1 border border-neutral-300 dark:border-neutral-600 rounded disabled:opacity-50 disabled:cursor-not-allowed"
          >
            Next
          </button>
        </div>
      )}

      {/* Conversation Detail Modal */}
      {selectedConversation && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
          <div className="bg-white dark:bg-neutral-800 rounded-lg max-w-4xl w-full max-h-[80vh] overflow-hidden">
            <div className="p-6 border-b border-neutral-200 dark:border-neutral-700">
              <div className="flex items-center justify-between">
                <h2 className="text-xl font-bold text-neutral-900 dark:text-neutral-100">
                  Escalated Conversation
                </h2>
                <button
                  onClick={() => setSelectedConversation(null)}
                  className="text-neutral-400 hover:text-neutral-600 dark:hover:text-neutral-300"
                >
                  ✕
                </button>
              </div>
              <div className="mt-2 text-sm text-neutral-600 dark:text-neutral-400">
                {selectedConversation.user ? (
                  <span>User: {selectedConversation.user.name || selectedConversation.user.email}</span>
                ) : (
                  <span>Anonymous user</span>
                )}
                {selectedConversation.escalatedAt && (
                  <span className="ml-4">
                    Escalated: {formatDate(selectedConversation.escalatedAt)}
                  </span>
                )}
              </div>
            </div>

            <div className="p-6 max-h-96 overflow-y-auto">
              <div className="space-y-4">
                {selectedConversation.messages.map((message) => (
                  <div
                    key={message.id}
                    className={`flex ${
                      message.role === 'USER' ? 'justify-end' : 'justify-start'
                    }`}
                  >
                    <div
                      className={`max-w-[70%] p-3 rounded-lg ${
                        message.role === 'USER'
                          ? 'bg-primary-600 text-white'
                          : message.role === 'ASSISTANT'
                          ? 'bg-neutral-100 dark:bg-neutral-700 text-neutral-900 dark:text-neutral-100'
                          : 'bg-yellow-100 dark:bg-yellow-900 text-yellow-800 dark:text-yellow-200'
                      }`}
                    >
                      <div className="text-xs font-medium mb-1 opacity-75">
                        {message.role}
                      </div>
                      <div className="text-sm whitespace-pre-wrap">
                        {message.content}
                      </div>
                      <div className="text-xs opacity-50 mt-1">
                        {formatDate(message.createdAt)}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default AdminChatbotEscalations;