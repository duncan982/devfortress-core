/**
 * Support Tickets Admin Interface
 * Comprehensive ticket management UI with filters, search, assignment, messaging
 */

'use client';

import { useState } from 'react';
import {
  Mail,
  MessageSquare,
  Phone,
  AlertCircle,
  CheckCircle,
  Clock,
  User,
  Send,
  Filter,
  Search,
  ChevronDown,
  ChevronUp,
} from 'lucide-react';

type TicketStatus =
  | 'OPEN'
  | 'IN_PROGRESS'
  | 'AWAITING_RESPONSE'
  | 'RESOLVED'
  | 'CLOSED';
type TicketPriority = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
type TicketSource = 'EMAIL' | 'CHATBOT' | 'MANUAL' | 'API' | 'PHONE';

 
type TicketWithRelations = any;

interface SupportMetrics {
  totalTickets: number;
  openTickets: number;
  inProgressTickets: number;
  resolvedTickets: number;
  closedTickets: number;
  averageResponseTime: number;
  averageResolutionTime: number;
  satisfactionScore: number;
  ticketsByPriority: Record<string, number>;
  ticketsBySource: Record<string, number>;
  ticketsByCategory: Record<string, number>;
}

export default function SupportTicketsAdmin() {
  const [tickets, setTickets] = useState<TicketWithRelations[]>([]);
  const [metrics] = useState<SupportMetrics | null>(null);
  const [selectedTicket, setSelectedTicket] =
    useState<TicketWithRelations | null>(null);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [showFilters, setShowFilters] = useState(false);

  // Filters
  const [statusFilter, setStatusFilter] = useState<TicketStatus | ''>('');
  const [priorityFilter, setPriorityFilter] = useState<TicketPriority | ''>('');
  const [sourceFilter, setSourceFilter] = useState<TicketSource | ''>('');
  const [searchQuery, setSearchQuery] = useState('');

  // Message input
  const [messageContent, setMessageContent] = useState('');
  const [isInternal, setIsInternal] = useState(false);

  const fetchTickets = async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams({
        page: page.toString(),
        pageSize: '25',
      });

      if (statusFilter) params.append('status', statusFilter);
      if (priorityFilter) params.append('priority', priorityFilter);
      if (sourceFilter) params.append('source', sourceFilter);
      if (searchQuery) params.append('search', searchQuery);

      const response = await fetch(`/api/admin/tickets?${params.toString()}`);
      const data = await response.json();

      if (response.ok) {
        setTickets(data.tickets);
        setTotalPages(data.totalPages);
      }
    } catch (error) {
      // Error fetching tickets
      void error;
    } finally {
      setLoading(false);
    }
  };

  const fetchTicketDetails = async (ticketId: string) => {
    try {
      const response = await fetch(`/api/admin/tickets/${ticketId}`);
      const data = await response.json();

      if (response.ok) {
        setSelectedTicket(data.ticket);
      }
    } catch (error) {
      // Error fetching ticket details
      void error;
    }
  };

  const handleUpdateStatus = async (ticketId: string, status: TicketStatus) => {
    try {
      const response = await fetch(`/api/admin/tickets/${ticketId}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status }),
      });

      if (response.ok) {
        fetchTickets();
        if (selectedTicket?.id === ticketId) {
          fetchTicketDetails(ticketId);
        }
      }
    } catch (error) {
      // Error updating ticket status
      void error;
    }
  };

  const handleUpdatePriority = async (
    ticketId: string,
    priority: TicketPriority
  ) => {
    try {
      const response = await fetch(`/api/admin/tickets/${ticketId}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ priority }),
      });

      if (response.ok) {
        fetchTickets();
        if (selectedTicket?.id === ticketId) {
          fetchTicketDetails(ticketId);
        }
      }
    } catch (error) {
      // Error updating ticket priority
      void error;
    }
  };

  const handleSendMessage = async () => {
    if (!selectedTicket || !messageContent.trim()) return;

    try {
      const response = await fetch(
        `/api/admin/tickets/${selectedTicket.id}/messages`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            content: messageContent,
            isInternal,
          }),
        }
      );

      if (response.ok) {
        setMessageContent('');
        fetchTicketDetails(selectedTicket.id);
      }
    } catch (error) {
      // Error sending message
      void error;
    }
  };

  const getStatusIcon = (status: TicketStatus) => {
    switch (status) {
      case 'OPEN':
        return <AlertCircle className="w-4 h-4 text-warning-500" />;
      case 'IN_PROGRESS':
        return <Clock className="w-4 h-4 text-primary-500" />;
      case 'AWAITING_RESPONSE':
        return <Mail className="w-4 h-4 text-warning-600" />;
      case 'RESOLVED':
        return <CheckCircle className="w-4 h-4 text-success-500" />;
      case 'CLOSED':
        return <CheckCircle className="w-4 h-4 text-neutral-500" />;
    }
  };

  const getPriorityColor = (priority: TicketPriority) => {
    switch (priority) {
      case 'LOW':
        return 'text-neutral-600 bg-neutral-100 dark:text-neutral-400 dark:bg-neutral-800';
      case 'MEDIUM':
        return 'text-primary-600 bg-primary-100 dark:text-primary-400 dark:bg-primary-900';
      case 'HIGH':
        return 'text-warning-600 bg-warning-100 dark:text-warning-400 dark:bg-warning-900';
      case 'CRITICAL':
        return 'text-error-600 bg-error-100 dark:text-error-400 dark:bg-error-900';
    }
  };

  const getSourceIcon = (source: TicketSource) => {
    switch (source) {
      case 'EMAIL':
        return <Mail className="w-4 h-4" />;
      case 'CHATBOT':
        return <MessageSquare className="w-4 h-4" />;
      case 'PHONE':
        return <Phone className="w-4 h-4" />;
      default:
        return <User className="w-4 h-4" />;
    }
  };

  const formatDuration = (minutes: number) => {
    if (minutes < 60) return `${minutes}m`;
    const hours = Math.floor(minutes / 60);
    const mins = minutes % 60;
    return `${hours}h ${mins}m`;
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:justify-between sm:items-center gap-4">
        <div>
          <h1 className="text-3xl font-bold text-neutral-900 dark:text-neutral-100">
            Support Tickets
          </h1>
          <p className="mt-1 text-sm text-neutral-600 dark:text-neutral-400">
            Manage customer support requests and escalations
          </p>
        </div>
        <button
          onClick={() => setShowFilters(!showFilters)}
          className="px-4 py-2 bg-neutral-100 dark:bg-neutral-800 rounded-lg hover:bg-neutral-200 dark:hover:bg-neutral-700 flex items-center gap-2 text-neutral-900 dark:text-neutral-100 transition-colors"
        >
          <Filter className="w-4 h-4" />
          Filters
          {showFilters ? (
            <ChevronUp className="w-4 h-4" />
          ) : (
            <ChevronDown className="w-4 h-4" />
          )}
        </button>
      </div>

      {/* Metrics Dashboard */}
      {metrics && (
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <MetricCard
            label="Total Tickets"
            value={metrics.totalTickets}
            icon={<MessageSquare className="w-5 h-5" />}
          />
          <MetricCard
            label="Open"
            value={metrics.openTickets}
            icon={<AlertCircle className="w-5 h-5 text-yellow-500" />}
          />
          <MetricCard
            label="Avg Response Time"
            value={formatDuration(metrics.averageResponseTime)}
            icon={<Clock className="w-5 h-5 text-blue-500" />}
          />
          <MetricCard
            label="Satisfaction Score"
            value={`${metrics.satisfactionScore.toFixed(1)}/5`}
            icon={<CheckCircle className="w-5 h-5 text-green-500" />}
          />
        </div>
      )}

      {/* Filters Card */}
      {showFilters && (
        <div className="rounded-2xl border border-neutral-200 bg-white p-6 dark:border-neutral-800 dark:bg-neutral-900">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div>
              <label className="block text-sm font-medium mb-2 text-neutral-900 dark:text-neutral-100">
                Status
              </label>
              <select
                value={statusFilter}
                onChange={e =>
                  setStatusFilter(e.target.value as TicketStatus | '')
                }
                className="w-full px-3 py-2 border rounded-lg bg-white text-neutral-900 border-neutral-300 dark:bg-neutral-800 dark:border-neutral-700 dark:text-neutral-100"
              >
                <option value="">All</option>
                <option value="OPEN">Open</option>
                <option value="IN_PROGRESS">In Progress</option>
                <option value="AWAITING_RESPONSE">Awaiting Response</option>
                <option value="RESOLVED">Resolved</option>
                <option value="CLOSED">Closed</option>
              </select>
            </div>

            <div>
              <label className="block text-sm font-medium mb-2 text-neutral-900 dark:text-neutral-100">
                Priority
              </label>
              <select
                value={priorityFilter}
                onChange={e =>
                  setPriorityFilter(e.target.value as TicketPriority | '')
                }
                className="w-full px-3 py-2 border rounded-lg bg-white text-neutral-900 border-neutral-300 dark:bg-neutral-800 dark:border-neutral-700 dark:text-neutral-100"
              >
                <option value="">All</option>
                <option value="LOW">Low</option>
                <option value="MEDIUM">Medium</option>
                <option value="HIGH">High</option>
                <option value="CRITICAL">Critical</option>
              </select>
            </div>

            <div>
              <label className="block text-sm font-medium mb-2 text-neutral-900 dark:text-neutral-100">
                Source
              </label>
              <select
                value={sourceFilter}
                onChange={e =>
                  setSourceFilter(e.target.value as TicketSource | '')
                }
                className="w-full px-3 py-2 border rounded-lg bg-white text-neutral-900 border-neutral-300 dark:bg-neutral-800 dark:border-neutral-700 dark:text-neutral-100"
              >
                <option value="">All</option>
                <option value="EMAIL">Email</option>
                <option value="CHATBOT">Chatbot</option>
                <option value="MANUAL">Manual</option>
                <option value="API">API</option>
                <option value="PHONE">Phone</option>
              </select>
            </div>

            <div>
              <label className="block text-sm font-medium mb-2 text-neutral-900 dark:text-neutral-100">
                Search
              </label>
              <div className="relative">
                <Search className="absolute left-3 top-2.5 w-4 h-4 text-neutral-400" />
                <input
                  type="text"
                  value={searchQuery}
                  onChange={e => setSearchQuery(e.target.value)}
                  placeholder="Ticket # or text..."
                  className="w-full pl-10 pr-3 py-2 border rounded-lg bg-white text-neutral-900 border-neutral-300 dark:bg-neutral-800 dark:border-neutral-700 dark:text-neutral-100"
                />
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Tickets Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Ticket List */}
        <div className="space-y-4">
          <h2 className="text-lg font-semibold text-neutral-900 dark:text-neutral-100">
            Tickets
          </h2>
          {loading ? (
            <div className="text-center py-12 text-neutral-600 dark:text-neutral-400">
              Loading tickets...
            </div>
          ) : tickets.length === 0 ? (
            <div className="text-center py-12 text-neutral-500 dark:text-neutral-400">
              No tickets found
            </div>
          ) : (
            <div className="space-y-3">
              {tickets.map(ticket => (
                <div
                  key={ticket.id}
                  onClick={() => fetchTicketDetails(ticket.id)}
                  className={`p-4 rounded-2xl cursor-pointer transition-colors ${
                    selectedTicket?.id === ticket.id
                      ? 'border-2 border-primary-500 bg-primary-50 dark:bg-primary-900/20'
                      : 'border border-neutral-200 dark:border-neutral-800 hover:bg-neutral-50 dark:hover:bg-neutral-800 bg-white dark:bg-neutral-900'
                  }`}
                >
                  <div className="flex items-start justify-between mb-2">
                    <div className="flex items-center gap-2">
                      {getStatusIcon(ticket.status)}
                      <span className="font-medium text-neutral-900 dark:text-neutral-100">
                        {ticket.ticketNumber}
                      </span>
                      <span
                        className={`px-2 py-1 text-xs rounded ${getPriorityColor(ticket.priority)}`}
                      >
                        {ticket.priority}
                      </span>
                    </div>
                    {getSourceIcon(ticket.source)}
                  </div>
                  <h3 className="font-semibold text-sm mb-1 text-neutral-900 dark:text-neutral-100">
                    {ticket.subject}
                  </h3>
                  <p className="text-xs text-neutral-600 dark:text-neutral-400 mb-2 line-clamp-2">
                    {ticket.description}
                  </p>
                  <div className="flex items-center justify-between text-xs text-neutral-500 dark:text-neutral-400">
                    <span>{ticket.user?.name || 'Anonymous'}</span>
                    <span>
                      {new Date(ticket.createdAt).toLocaleDateString()}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="flex justify-center gap-2 mt-4">
              <button
                onClick={() => setPage(Math.max(1, page - 1))}
                disabled={page === 1}
                className="px-4 py-2 border rounded-lg disabled:opacity-50 border-neutral-200 dark:border-neutral-700 text-neutral-900 dark:text-neutral-100 hover:bg-neutral-50 dark:hover:bg-neutral-800"
              >
                Previous
              </button>
              <span className="px-4 py-2 text-neutral-900 dark:text-neutral-100">
                Page {page} of {totalPages}
              </span>
              <button
                onClick={() => setPage(Math.min(totalPages, page + 1))}
                disabled={page === totalPages}
                className="px-4 py-2 border rounded-lg disabled:opacity-50 border-neutral-200 dark:border-neutral-700 text-neutral-900 dark:text-neutral-100 hover:bg-neutral-50 dark:hover:bg-neutral-800"
              >
                Next
              </button>
            </div>
          )}
        </div>

        {/* Ticket Details */}
        <div>
          {selectedTicket ? (
            <div className="rounded-2xl border border-neutral-200 dark:border-neutral-800 p-6 space-y-6 bg-white dark:bg-neutral-900">
              <div>
                <div className="flex items-center justify-between mb-4">
                  <h2 className="text-xl font-bold text-neutral-900 dark:text-neutral-100">
                    {selectedTicket.ticketNumber}
                  </h2>
                  <div className="flex items-center gap-2">
                    {getStatusIcon(selectedTicket.status)}
                    <span
                      className={`px-3 py-1 text-sm rounded ${getPriorityColor(selectedTicket.priority)}`}
                    >
                      {selectedTicket.priority}
                    </span>
                  </div>
                </div>

                <h3 className="font-semibold mb-2 text-neutral-900 dark:text-neutral-100">
                  {selectedTicket.subject}
                </h3>
                <p className="text-neutral-700 dark:text-neutral-300 mb-4">
                  {selectedTicket.description}
                </p>

                <div className="grid grid-cols-2 gap-4 text-sm">
                  <div>
                    <span className="text-neutral-600 dark:text-neutral-400">
                      Created by:
                    </span>
                    <div className="font-medium text-neutral-900 dark:text-neutral-100">
                      {selectedTicket.user?.name || 'Anonymous'}
                    </div>
                  </div>
                  <div>
                    <span className="text-neutral-600 dark:text-neutral-400">
                      Assigned to:
                    </span>
                    <div className="font-medium text-neutral-900 dark:text-neutral-100">
                      {selectedTicket.assignedTo?.name || 'Unassigned'}
                    </div>
                  </div>
                  <div>
                    <span className="text-neutral-600 dark:text-neutral-400">
                      Status:
                    </span>
                    <select
                      value={selectedTicket.status}
                      onChange={e =>
                        handleUpdateStatus(
                          selectedTicket.id,
                          e.target.value as TicketStatus
                        )
                      }
                      className="mt-1 w-full px-2 py-1 border rounded-lg bg-white text-neutral-900 border-neutral-300 dark:bg-neutral-800 dark:border-neutral-700 dark:text-neutral-100"
                    >
                      <option value="OPEN">Open</option>
                      <option value="IN_PROGRESS">In Progress</option>
                      <option value="AWAITING_RESPONSE">
                        Awaiting Response
                      </option>
                      <option value="RESOLVED">Resolved</option>
                      <option value="CLOSED">Closed</option>
                    </select>
                  </div>
                  <div>
                    <span className="text-neutral-600 dark:text-neutral-400">
                      Priority:
                    </span>
                    <select
                      value={selectedTicket.priority}
                      onChange={e =>
                        handleUpdatePriority(
                          selectedTicket.id,
                          e.target.value as TicketPriority
                        )
                      }
                      className="mt-1 w-full px-2 py-1 border rounded-lg bg-white text-neutral-900 border-neutral-300 dark:bg-neutral-800 dark:border-neutral-700 dark:text-neutral-100"
                    >
                      <option value="LOW">Low</option>
                      <option value="MEDIUM">Medium</option>
                      <option value="HIGH">High</option>
                      <option value="CRITICAL">Critical</option>
                    </select>
                  </div>
                </div>
              </div>

              {/* Messages */}
              <div>
                <h4 className="font-semibold mb-3 text-neutral-900 dark:text-neutral-100">
                  Messages
                </h4>
                <div className="space-y-3 max-h-96 overflow-y-auto mb-4">
                  { }
                  {selectedTicket.messages?.map((msg: any) => (
                    <div
                      key={msg.id}
                      className={`p-3 rounded-lg ${msg.isInternal ? 'bg-warning-50 dark:bg-warning-950 border border-warning-200 dark:border-warning-800' : 'bg-neutral-50 dark:bg-neutral-800'}`}
                    >
                      <div className="flex items-center justify-between text-sm mb-2">
                        <span className="font-medium text-neutral-900 dark:text-neutral-100">
                          {msg.author?.name || 'System'}
                        </span>
                        <span className="text-neutral-500 dark:text-neutral-400 text-xs">
                          {new Date(msg.createdAt).toLocaleString()}
                        </span>
                      </div>
                      <p className="text-sm text-neutral-700 dark:text-neutral-300">
                        {msg.content}
                      </p>
                      {msg.isInternal && (
                        <span className="text-xs text-warning-700 dark:text-warning-300 font-medium">
                          Internal Note
                        </span>
                      )}
                    </div>
                  ))}
                </div>

                {/* Message Input */}
                <div className="space-y-2">
                  <textarea
                    value={messageContent}
                    onChange={e => setMessageContent(e.target.value)}
                    placeholder="Type your message..."
                    className="w-full px-3 py-2 border rounded-lg resize-none bg-white text-neutral-900 border-neutral-300 dark:bg-neutral-800 dark:border-neutral-700 dark:text-neutral-100"
                    rows={3}
                  />
                  <div className="flex items-center justify-between">
                    <label className="flex items-center gap-2 text-sm text-neutral-700 dark:text-neutral-300">
                      <input
                        type="checkbox"
                        checked={isInternal}
                        onChange={e => setIsInternal(e.target.checked)}
                        className="rounded"
                      />
                      Internal Note
                    </label>
                    <button
                      onClick={handleSendMessage}
                      disabled={!messageContent.trim()}
                      className="px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 disabled:opacity-50 flex items-center gap-2 transition-colors"
                    >
                      <Send className="w-4 h-4" />
                      Send
                    </button>
                  </div>
                </div>
              </div>
            </div>
          ) : (
            <div className="rounded-2xl border border-neutral-200 dark:border-neutral-800 p-12 text-center text-neutral-500 dark:text-neutral-400 bg-white dark:bg-neutral-900">
              Select a ticket to view details
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function MetricCard({
  label,
  value,
  icon,
}: {
  label: string;
  value: string | number;
  icon: React.ReactNode;
}) {
  return (
    <div className="rounded-2xl border border-neutral-200 bg-white p-4 dark:border-neutral-800 dark:bg-neutral-900">
      <div className="flex items-center justify-between mb-2">
        <span className="text-sm text-neutral-600 dark:text-neutral-400">
          {label}
        </span>
        {icon}
      </div>
      <div className="text-2xl font-bold text-neutral-900 dark:text-neutral-100">
        {value}
      </div>
    </div>
  );
}
