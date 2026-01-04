/**
 * Support Ticket Management Service
 * Integrates with external ticketing systems (Zendesk, Intercom)
 * Provides ticket CRUD, assignment, escalation workflows, and metrics tracking
 */

import { prisma } from '@core/lib/prisma';
import { logInfo, logError } from '@core/lib/logger';
import type {
  SupportTicket,
  TicketMessage,
  TicketStatus,
  TicketPriority,
  TicketSource,
} from '@prisma/client';

/**
 * Ticket filter options
 */
export interface TicketFilters {
  userId?: string;
  assignedToId?: string;
  status?: TicketStatus;
  priority?: TicketPriority;
  source?: TicketSource;
  category?: string;
  startDate?: Date;
  endDate?: Date;
  search?: string;
}

/**
 * Support metrics for dashboards
 */
export interface SupportMetrics {
  totalTickets: number;
  openTickets: number;
  inProgressTickets: number;
  resolvedTickets: number;
  closedTickets: number;
  averageResponseTime: number; // minutes
  averageResolutionTime: number; // minutes
  satisfactionScore: number; // 1-5
  ticketsByPriority: {
    low: number;
    medium: number;
    high: number;
    critical: number;
  };
  ticketsBySource: {
    email: number;
    chatbot: number;
    manual: number;
    api: number;
    phone: number;
  };
  ticketsByCategory: Record<string, number>;
}

/**
 * External ticket system configuration
 */
interface ExternalTicketConfig {
  provider: 'zendesk' | 'intercom' | 'none';
  apiKey?: string;
  apiUrl?: string;
  subdomain?: string; // For Zendesk
  appId?: string; // For Intercom
}

/**
 * Get external ticket system configuration from environment
 */
function getExternalConfig(): ExternalTicketConfig {
  const provider = (process.env.TICKET_PROVIDER || 'none') as
    | 'zendesk'
    | 'intercom'
    | 'none';

  return {
    provider,
    apiKey: process.env.TICKET_API_KEY,
    apiUrl: process.env.TICKET_API_URL,
    subdomain: process.env.ZENDESK_SUBDOMAIN,
    appId: process.env.INTERCOM_APP_ID,
  };
}

/**
 * Generate unique ticket number
 */
async function generateTicketNumber(): Promise<string> {
  const count = await prisma.supportTicket.count();
  const number = (count + 1).toString().padStart(6, '0');
  return `TKT-${number}`;
}

/**
 * Sync ticket to external system (Zendesk/Intercom)
 */
async function syncToExternalSystem(ticket: SupportTicket): Promise<void> {
  const config = getExternalConfig();

  if (config.provider === 'none') {
    logInfo('External ticketing system not configured, skipping sync');
    return;
  }

  try {
    if (config.provider === 'zendesk') {
      await syncToZendesk(ticket, config);
    } else if (config.provider === 'intercom') {
      await syncToIntercom(ticket, config);
    }

    logInfo('Ticket synced to external system', {
      ticketId: ticket.id,
      provider: config.provider,
    });
  } catch (error) {
    logError('Failed to sync ticket to external system', error);
    // Don't throw - allow ticket to be created locally even if sync fails
  }
}

/**
 * Sync ticket to Zendesk
 */
async function syncToZendesk(
  ticket: SupportTicket,
  config: ExternalTicketConfig
): Promise<void> {
  if (!config.apiKey || !config.subdomain) {
    throw new Error('Zendesk credentials not configured');
  }

  const url = `https://${config.subdomain}.zendesk.com/api/v2/tickets.json`;
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Basic ${Buffer.from(`${config.apiKey}/token:${config.apiKey}`).toString('base64')}`,
    },
    body: JSON.stringify({
      ticket: {
        subject: ticket.subject,
        description: ticket.description,
        priority: ticket.priority.toLowerCase(),
        status: mapStatusToZendesk(ticket.status),
        tags: ticket.tags,
        custom_fields: [
          { id: 'ticket_number', value: ticket.ticketNumber },
          { id: 'source', value: ticket.source },
        ],
      },
    }),
  });

  if (!response.ok) {
    throw new Error(`Zendesk API error: ${response.statusText}`);
  }

  const data = await response.json();

  // Update ticket with Zendesk ID and URL
  await prisma.supportTicket.update({
    where: { id: ticket.id },
    data: {
      externalId: data.ticket.id.toString(),
      externalUrl: data.ticket.url,
    },
  });
}

/**
 * Sync ticket to Intercom
 */
async function syncToIntercom(
  ticket: SupportTicket,
  config: ExternalTicketConfig
): Promise<void> {
  if (!config.apiKey || !config.appId) {
    throw new Error('Intercom credentials not configured');
  }

  const url = 'https://api.intercom.io/conversations';
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${config.apiKey}`,
      'Intercom-Version': '2.11',
    },
    body: JSON.stringify({
      from: {
        type: 'user',
        id: ticket.userId,
      },
      body: `**${ticket.subject}**\n\n${ticket.description}`,
      custom_attributes: {
        ticket_number: ticket.ticketNumber,
        priority: ticket.priority,
        source: ticket.source,
        category: ticket.category,
      },
    }),
  });

  if (!response.ok) {
    throw new Error(`Intercom API error: ${response.statusText}`);
  }

  const data = await response.json();

  // Update ticket with Intercom conversation ID
  await prisma.supportTicket.update({
    where: { id: ticket.id },
    data: {
      externalId: data.id,
      externalUrl: data.conversation_url,
    },
  });
}

/**
 * Map internal status to Zendesk status
 */
function mapStatusToZendesk(status: TicketStatus): string {
  const statusMap: Record<TicketStatus, string> = {
    OPEN: 'new',
    IN_PROGRESS: 'open',
    AWAITING_RESPONSE: 'pending',
    RESOLVED: 'solved',
    CLOSED: 'closed',
  };
  return statusMap[status] || 'new';
}

/**
 * Support Ticket Service
 */
export class SupportTicketService {
  /**
   * Create a new support ticket
   */
  static async createTicket(data: {
    userId?: string;
    subject: string;
    description: string;
    priority?: TicketPriority;
    source?: TicketSource;
    category?: string;
    tags?: string[];
    conversationId?: string; // Link to chatbot conversation if escalated
  }): Promise<SupportTicket> {
    try {
      const ticketNumber = await generateTicketNumber();

      const ticket = await prisma.supportTicket.create({
        data: {
          ticketNumber,
          userId: data.userId,
          subject: data.subject,
          description: data.description,
          priority: data.priority || 'MEDIUM',
          source: data.source || 'MANUAL',
          category: data.category,
          tags: data.tags || [],
          conversationId: data.conversationId,
        },
        include: {
          user: true,
          assignedTo: true,
        },
      });

      // Sync to external system asynchronously
      syncToExternalSystem(ticket).catch(error => {
        logError('Failed to sync ticket to external system', error);
      });

      logInfo('Support ticket created', {
        ticketId: ticket.id,
        ticketNumber: ticket.ticketNumber,
      });
      return ticket;
    } catch (error) {
      logError('Failed to create support ticket', error);
      throw new Error('Failed to create support ticket');
    }
  }

  /**
   * Get ticket by ID
   */
  static async getTicket(ticketId: string): Promise<SupportTicket | null> {
    try {
      return await prisma.supportTicket.findUnique({
        where: { id: ticketId },
        include: {
          user: true,
          assignedTo: true,
          messages: {
            include: {
              author: true,
            },
            orderBy: {
              createdAt: 'asc',
            },
          },
        },
      });
    } catch (error) {
      logError('Failed to get ticket', error);
      throw new Error('Failed to retrieve ticket');
    }
  }

  /**
   * Get ticket by ticket number
   */
  static async getTicketByNumber(
    ticketNumber: string
  ): Promise<SupportTicket | null> {
    try {
      return await prisma.supportTicket.findUnique({
        where: { ticketNumber },
        include: {
          user: true,
          assignedTo: true,
          messages: {
            include: {
              author: true,
            },
            orderBy: {
              createdAt: 'asc',
            },
          },
        },
      });
    } catch (error) {
      logError('Failed to get ticket by number', error);
      throw new Error('Failed to retrieve ticket');
    }
  }

  /**
   * Query tickets with filters
   */
  static async queryTickets(
    filters: TicketFilters,
    page: number = 1,
    pageSize: number = 50
  ): Promise<{ tickets: SupportTicket[]; total: number }> {
    try {
       
      const where: any = {};

      if (filters.userId) where.userId = filters.userId;
      if (filters.assignedToId) where.assignedToId = filters.assignedToId;
      if (filters.status) where.status = filters.status;
      if (filters.priority) where.priority = filters.priority;
      if (filters.source) where.source = filters.source;
      if (filters.category) where.category = filters.category;

      if (filters.startDate || filters.endDate) {
        where.createdAt = {};
        if (filters.startDate) where.createdAt.gte = filters.startDate;
        if (filters.endDate) where.createdAt.lte = filters.endDate;
      }

      if (filters.search) {
        where.OR = [
          { subject: { contains: filters.search, mode: 'insensitive' } },
          { description: { contains: filters.search, mode: 'insensitive' } },
          { ticketNumber: { contains: filters.search, mode: 'insensitive' } },
        ];
      }

      const [tickets, total] = await Promise.all([
        prisma.supportTicket.findMany({
          where,
          include: {
            user: true,
            assignedTo: true,
          },
          orderBy: {
            createdAt: 'desc',
          },
          skip: (page - 1) * pageSize,
          take: pageSize,
        }),
        prisma.supportTicket.count({ where }),
      ]);

      logInfo('Tickets queried', { total, filters, page, pageSize });
      return { tickets, total };
    } catch (error) {
      logError('Failed to query tickets', error);
      throw new Error('Failed to query tickets');
    }
  }

  /**
   * Assign ticket to user
   */
  static async assignTicket(
    ticketId: string,
    assignedToId: string
  ): Promise<SupportTicket> {
    try {
      const ticket = await prisma.supportTicket.update({
        where: { id: ticketId },
        data: {
          assignedToId,
          status: 'IN_PROGRESS',
        },
        include: {
          user: true,
          assignedTo: true,
        },
      });

      logInfo('Ticket assigned', { ticketId, assignedToId });
      return ticket;
    } catch (error) {
      logError('Failed to assign ticket', error);
      throw new Error('Failed to assign ticket');
    }
  }

  /**
   * Update ticket status
   */
  static async updateTicketStatus(
    ticketId: string,
    status: TicketStatus
  ): Promise<SupportTicket> {
    try {
       
      const updateData: any = { status };

      // Track resolution/close times
      if (status === 'RESOLVED') {
        updateData.resolvedAt = new Date();

        // Calculate resolution time
        const ticket = await prisma.supportTicket.findUnique({
          where: { id: ticketId },
        });

        if (ticket) {
          const resolutionTime = Math.floor(
            (updateData.resolvedAt.getTime() - ticket.createdAt.getTime()) /
              60000
          );
          updateData.resolutionTime = resolutionTime;
        }
      } else if (status === 'CLOSED') {
        updateData.closedAt = new Date();
      }

      const updatedTicket = await prisma.supportTicket.update({
        where: { id: ticketId },
        data: updateData,
        include: {
          user: true,
          assignedTo: true,
        },
      });

      logInfo('Ticket status updated', { ticketId, status });
      return updatedTicket;
    } catch (error) {
      logError('Failed to update ticket status', error);
      throw new Error('Failed to update ticket status');
    }
  }

  /**
   * Update ticket priority
   */
  static async updateTicketPriority(
    ticketId: string,
    priority: TicketPriority
  ): Promise<SupportTicket> {
    try {
      const ticket = await prisma.supportTicket.update({
        where: { id: ticketId },
        data: { priority },
        include: {
          user: true,
          assignedTo: true,
        },
      });

      logInfo('Ticket priority updated', { ticketId, priority });
      return ticket;
    } catch (error) {
      logError('Failed to update ticket priority', error);
      throw new Error('Failed to update ticket priority');
    }
  }

  /**
   * Add message to ticket
   */
  static async addMessage(data: {
    ticketId: string;
    authorId?: string;
    content: string;
    isInternal?: boolean;
    isAutomated?: boolean;
    attachments?: string[];
  }): Promise<TicketMessage> {
    try {
      const message = await prisma.ticketMessage.create({
        data: {
          ticketId: data.ticketId,
          authorId: data.authorId,
          content: data.content,
          isInternal: data.isInternal || false,
          isAutomated: data.isAutomated || false,
          attachments: data.attachments || [],
        },
        include: {
          author: true,
        },
      });

      // Calculate first response time if this is the first staff response
      if (data.authorId && !data.isInternal) {
        const ticket = await prisma.supportTicket.findUnique({
          where: { id: data.ticketId },
        });

        if (ticket && !ticket.firstResponseAt) {
          const responseTime = Math.floor(
            (new Date().getTime() - ticket.createdAt.getTime()) / 60000
          );

          await prisma.supportTicket.update({
            where: { id: data.ticketId },
            data: {
              firstResponseAt: new Date(),
              responseTime,
            },
          });
        }
      }

      logInfo('Ticket message added', {
        ticketId: data.ticketId,
        messageId: message.id,
      });
      return message;
    } catch (error) {
      logError('Failed to add ticket message', error);
      throw new Error('Failed to add ticket message');
    }
  }

  /**
   * Escalate chatbot conversation to support ticket
   */
  static async escalateFromChatbot(
    conversationId: string,
    userId?: string,
    reason?: string
  ): Promise<SupportTicket> {
    try {
      // Get chatbot conversation
      const conversation = await prisma.chatbotConversation.findUnique({
        where: { id: conversationId },
        include: {
          messages: {
            orderBy: { createdAt: 'asc' },
          },
        },
      });

      if (!conversation) {
        throw new Error('Chatbot conversation not found');
      }

      // Create support ticket from conversation
      const ticket = await this.createTicket({
        userId: userId || conversation.userId || undefined,
        subject: conversation.topic || 'Escalated from chatbot',
        description: reason || 'User requested human support',
        priority: 'HIGH',
        source: 'CHATBOT',
        category: 'escalation',
        conversationId,
      });

      // Add conversation history as first message
      const conversationHistory = conversation.messages
        .map(msg => `**${msg.role}**: ${msg.content}`)
        .join('\n\n');

      await this.addMessage({
        ticketId: ticket.id,
        content: `Escalated from chatbot conversation:\n\n${conversationHistory}`,
        isInternal: true,
        isAutomated: true,
      });

      // Update chatbot conversation status
      await prisma.chatbotConversation.update({
        where: { id: conversationId },
        data: {
          status: 'ESCALATED',
          escalatedAt: new Date(),
          escalatedReason: reason,
        },
      });

      logInfo('Chatbot conversation escalated to ticket', {
        conversationId,
        ticketId: ticket.id,
      });

      // Create notifications for admins about chat escalation
      try {
        const admins = await prisma.user.findMany({
          where: { role: 'ADMIN' },
          select: { id: true },
        });

        const notificationPromises = admins.map(admin =>
          prisma.notification.create({
            data: {
              userId: admin.id,
              type: 'CHAT_ESCALATION',
              title: `Chat escalated to support ticket #${ticket.ticketNumber}`,
              message: reason || 'User requested human support during chat conversation',
              metadata: { ticketId: ticket.id, conversationId },
              status: 'UNREAD',
            },
          })
        );

        await Promise.all(notificationPromises);

        logInfo('Chat escalation notifications sent to admins', {
          ticketId: ticket.id,
          adminCount: admins.length,
        });
      } catch (notificationError) {
        logError('Failed to create chat escalation notifications', notificationError);
        // Don't fail the escalation if notifications fail
      }

      return ticket;
    } catch (error) {
      logError('Failed to escalate chatbot conversation', error);
      throw new Error('Failed to escalate conversation to ticket');
    }
  }

  /**
   * Rate ticket satisfaction
   */
  static async rateTicket(
    ticketId: string,
    satisfaction: number,
    note?: string
  ): Promise<SupportTicket> {
    try {
      if (satisfaction < 1 || satisfaction > 5) {
        throw new Error('Satisfaction rating must be between 1 and 5');
      }

      const ticket = await prisma.supportTicket.update({
        where: { id: ticketId },
        data: {
          satisfaction,
          satisfactionNote: note,
        },
        include: {
          user: true,
          assignedTo: true,
        },
      });

      logInfo('Ticket rated', { ticketId, satisfaction });
      return ticket;
    } catch (error) {
      logError('Failed to rate ticket', error);
      throw new Error('Failed to rate ticket');
    }
  }

  /**
   * Get support metrics
   */
  static async getMetrics(
    startDate?: Date,
    endDate?: Date
  ): Promise<SupportMetrics> {
    try {
       
      const where: any = {};

      if (startDate || endDate) {
        where.createdAt = {};
        if (startDate) where.createdAt.gte = startDate;
        if (endDate) where.createdAt.lte = endDate;
      }

      const [
        totalTickets,
        openTickets,
        inProgressTickets,
        resolvedTickets,
        closedTickets,
        ticketsWithResponseTime,
        ticketsWithResolutionTime,
        ticketsWithSatisfaction,
        priorityCounts,
        sourceCounts,
        categoryCounts,
      ] = await Promise.all([
        prisma.supportTicket.count({ where }),
        prisma.supportTicket.count({ where: { ...where, status: 'OPEN' } }),
        prisma.supportTicket.count({
          where: { ...where, status: 'IN_PROGRESS' },
        }),
        prisma.supportTicket.count({ where: { ...where, status: 'RESOLVED' } }),
        prisma.supportTicket.count({ where: { ...where, status: 'CLOSED' } }),
        prisma.supportTicket.findMany({
          where: { ...where, responseTime: { not: null } },
          select: { responseTime: true },
        }),
        prisma.supportTicket.findMany({
          where: { ...where, resolutionTime: { not: null } },
          select: { resolutionTime: true },
        }),
        prisma.supportTicket.findMany({
          where: { ...where, satisfaction: { not: null } },
          select: { satisfaction: true },
        }),
        prisma.supportTicket.groupBy({
          by: ['priority'],
          where,
          _count: true,
        }),
        prisma.supportTicket.groupBy({
          by: ['source'],
          where,
          _count: true,
        }),
        prisma.supportTicket.groupBy({
          by: ['category'],
          where: { ...where, category: { not: null } },
          _count: true,
        }),
      ]);

      // Calculate averages
      const averageResponseTime =
        ticketsWithResponseTime.length > 0
          ? ticketsWithResponseTime.reduce(
              (sum, t) => sum + (t.responseTime || 0),
              0
            ) / ticketsWithResponseTime.length
          : 0;

      const averageResolutionTime =
        ticketsWithResolutionTime.length > 0
          ? ticketsWithResolutionTime.reduce(
              (sum, t) => sum + (t.resolutionTime || 0),
              0
            ) / ticketsWithResolutionTime.length
          : 0;

      const satisfactionScore =
        ticketsWithSatisfaction.length > 0
          ? ticketsWithSatisfaction.reduce(
              (sum, t) => sum + (t.satisfaction || 0),
              0
            ) / ticketsWithSatisfaction.length
          : 0;

      // Process priority counts
      const ticketsByPriority = {
        low: priorityCounts.find(p => p.priority === 'LOW')?._count || 0,
        medium: priorityCounts.find(p => p.priority === 'MEDIUM')?._count || 0,
        high: priorityCounts.find(p => p.priority === 'HIGH')?._count || 0,
        critical:
          priorityCounts.find(p => p.priority === 'CRITICAL')?._count || 0,
      };

      // Process source counts
      const ticketsBySource = {
        email: sourceCounts.find(s => s.source === 'EMAIL')?._count || 0,
        chatbot: sourceCounts.find(s => s.source === 'CHATBOT')?._count || 0,
        manual: sourceCounts.find(s => s.source === 'MANUAL')?._count || 0,
        api: sourceCounts.find(s => s.source === 'API')?._count || 0,
        phone: sourceCounts.find(s => s.source === 'PHONE')?._count || 0,
      };

      // Process category counts
      const ticketsByCategory: Record<string, number> = {};
      categoryCounts.forEach(c => {
        if (c.category) {
          ticketsByCategory[c.category] = c._count;
        }
      });

      const metrics: SupportMetrics = {
        totalTickets,
        openTickets,
        inProgressTickets,
        resolvedTickets,
        closedTickets,
        averageResponseTime,
        averageResolutionTime,
        satisfactionScore,
        ticketsByPriority,
        ticketsBySource,
        ticketsByCategory,
      };

      logInfo('Support metrics calculated', { metrics });
      return metrics;
    } catch (error) {
      logError('Failed to calculate support metrics', error);
      throw new Error('Failed to retrieve support metrics');
    }
  }
}
