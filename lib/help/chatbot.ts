/**
 * Support Chatbot Service
 * AI-powered chatbot for answering user queries with escalation capabilities
 */

import { getOpenAIClient } from '@core/lib/openai/client';
import { prisma } from '@core/lib/prisma';
import { logInfo, logError, logWarn } from '@core/lib/logger';
import { HelpCenterService } from '@core/lib/help/help-center';
import { SupportTicketService } from '@core/lib/support/ticketing';

export enum ChatbotIntent {
  GREETING = 'GREETING',
  QUESTION = 'QUESTION',
  ISSUE = 'ISSUE',
  BILLING = 'BILLING',
  SECURITY = 'SECURITY',
  TECHNICAL = 'TECHNICAL',
  FEEDBACK = 'FEEDBACK',
  ESCALATE = 'ESCALATE',
  UNKNOWN = 'UNKNOWN',
}

export interface ChatbotResponse {
  message: string;
  intent: ChatbotIntent;
  confidence: number;
  suggestedArticles?: Array<{
    title: string;
    slug: string;
    relevance: number;
  }>;
  escalate?: boolean;
  escalationReason?: string;
  ticketNumber?: string;
}

export interface ConversationContext {
  conversationId: string;
  userId?: string;
  sessionId: string;
  history: Array<{
    role: 'user' | 'assistant' | 'system';
    content: string;
    timestamp: Date;
  }>;
}

export class SupportChatbotService {
  private static readonly SYSTEM_PROMPT = `You are a helpful support assistant for VortexSecure, a platform for building, defending, and learning about APIs with AI. Your role is to:

1. Answer questions about VortexSecure features (API generation, security scanning, honeypots, monitoring)
2. Help users troubleshoot issues
3. Provide guidance on pricing, billing, and subscriptions
4. Assist with onboarding and getting started
5. Escalate complex issues to human support when necessary

Guidelines:
- Be friendly, professional, and concise
- If you don't know something, admit it and offer to escalate
- Suggest relevant help articles when available
- For billing/security issues or complex technical problems, recommend escalation
- Keep responses under 200 words unless more detail is needed
- Use markdown formatting for better readability

VortexSecure Key Features:
- BUILD: AI-powered API generation from natural language prompts
- DEFEND: Automated security scanning, honeypots, and threat monitoring
- LEARN: Flywheel learning system that improves with usage
- Credit-based pricing with multiple payment processors (Paddle, Paystack, GitHub Marketplace)
- GitHub integration for repository management
- Team collaboration and role-based access control`;

  private static readonly ESCALATION_KEYWORDS = [
    'speak to human',
    'talk to someone',
    'real person',
    'agent',
    'urgent',
    'emergency',
    'critical',
    'not working',
    'broken',
    'bug',
    'refund',
    'cancel',
    'delete account',
  ];

  /**
   * Process a user message and generate a response
   */
  static async chat(
    message: string,
    context: ConversationContext
  ): Promise<ChatbotResponse> {
    try {
      logInfo('Processing chatbot message', {
        conversationId: context.conversationId,
        userId: context.userId,
        messageLength: message.length,
      });

      // Detect escalation request
      const shouldEscalate = this.shouldEscalate(message);
      if (shouldEscalate) {
        return await this.handleEscalation(message, context);
      }

      // Get relevant help articles
      const articles = await HelpCenterService.searchArticles(
        message,
        undefined,
        undefined
      );

      // Build conversation history for context
      const messages = [
        { role: 'system' as const, content: this.SYSTEM_PROMPT },
        ...context.history.slice(-10).map(msg => ({
          role: msg.role as 'user' | 'assistant',
          content: msg.content,
        })),
        { role: 'user' as const, content: message },
      ];

      // Add article context if available
      if (articles.length > 0) {
        const articleContext = articles
          .slice(0, 3)
          .map(a => `Article: ${a.article.title}\n${a.article.content}`)
          .join('\n\n');
        messages.splice(1, 0, {
          role: 'system' as const,
          content: `Relevant help articles:\n${articleContext}`,
        });
      }

      // Call OpenAI
      const openai = getOpenAIClient();
      const completion = await openai.chat.completions.create({
        model: 'gpt-4o-mini',
        messages,
        temperature: 0.7,
        max_tokens: 500,
      });

      const responseContent =
        completion.choices[0]?.message?.content ||
        'I apologize, but I encountered an issue. Please try again or contact support.';

      // Detect intent from the conversation
      const intent = await this.detectIntent(message, responseContent);

      // Save to database (non-blocking - continue even if DB fails)
      try {
        await this.saveMessage(context.conversationId, 'USER', message);
        await this.saveMessage(
          context.conversationId,
          'ASSISTANT',
          responseContent
        );
      } catch (error) {
        logWarn('Failed to save chatbot messages to database', {
          conversationId: context.conversationId,
          error: error instanceof Error ? error.message : String(error),
        });
        // Continue - the chatbot can still respond even if messages aren't saved
      }

      const response: ChatbotResponse = {
        message: responseContent,
        intent,
        confidence: 0.85,
        suggestedArticles: articles.slice(0, 3).map(a => ({
          title: a.article.title,
          slug: a.article.slug,
          relevance: a.relevance,
        })),
      };

      logInfo('Chatbot response generated', {
        conversationId: context.conversationId,
        intent,
        articlesFound: articles.length,
      });

      return response;
    } catch (error) {
      logError('Error in chatbot processing', error);
      throw new Error('Failed to process chatbot message');
    }
  }

  /**
   * Check if message should trigger escalation
   */
  private static shouldEscalate(message: string): boolean {
    const lowerMessage = message.toLowerCase();
    return this.ESCALATION_KEYWORDS.some(keyword =>
      lowerMessage.includes(keyword)
    );
  }

  /**
   * Handle escalation to human support
   */
  private static async handleEscalation(
    message: string,
    context: ConversationContext
  ): Promise<ChatbotResponse> {
    logWarn('Escalating conversation to human support', {
      conversationId: context.conversationId,
      userId: context.userId,
    });

    try {
      // Create support ticket from escalated conversation
      const ticket = await SupportTicketService.escalateFromChatbot(
        context.conversationId,
        context.userId,
        message
      );

      logInfo('Support ticket created from chatbot escalation', {
        conversationId: context.conversationId,
        ticketId: ticket.id,
        ticketNumber: ticket.ticketNumber,
      });

      const escalationMessage = `I understand you need additional assistance. I've created a support ticket (#${ticket.ticketNumber}) and escalated your request to our support team. A human agent will contact you shortly. In the meantime, is there anything else I can help you with?`;

      await this.saveMessage(
        context.conversationId,
        'ASSISTANT',
        escalationMessage
      );

      return {
        message: escalationMessage,
        intent: ChatbotIntent.ESCALATE,
        confidence: 1.0,
        escalate: true,
        escalationReason: 'User requested human support',
        ticketNumber: ticket.ticketNumber,
      };
    } catch (error) {
      logError('Failed to create support ticket from escalation', {
        conversationId: context.conversationId,
        userId: context.userId,
        error: error instanceof Error ? error.message : String(error),
      });

      // Fallback: still mark as escalated even if ticket creation fails
      await prisma.chatbotConversation.update({
        where: { id: context.conversationId },
        data: {
          status: 'ESCALATED',
          escalatedAt: new Date(),
          escalatedReason: message,
        },
      });

      const fallbackMessage = `I understand you need additional assistance. I've escalated your request to our support team. A human agent will contact you shortly via email. In the meantime, is there anything else I can help you with?`;

      await this.saveMessage(
        context.conversationId,
        'ASSISTANT',
        fallbackMessage
      );

      return {
        message: fallbackMessage,
        intent: ChatbotIntent.ESCALATE,
        confidence: 1.0,
        escalate: true,
        escalationReason: 'User requested human support',
      };
    }
  }

  /**
   * Detect user intent from message
   */
  private static async detectIntent(
    userMessage: string,
    _assistantResponse: string
  ): Promise<ChatbotIntent> {
    const lower = userMessage.toLowerCase();

    // Simple keyword-based intent detection
    if (lower.match(/\b(hi|hello|hey)\b/)) return ChatbotIntent.GREETING;
    if (lower.match(/\b(billing|payment|invoice|charge)\b/))
      return ChatbotIntent.BILLING;
    if (lower.match(/\b(security|hack|threat|honeypot)\b/))
      return ChatbotIntent.SECURITY;
    if (lower.match(/\b(error|bug|broken|issue|problem)\b/))
      return ChatbotIntent.ISSUE;
    if (lower.match(/\b(how to|guide|tutorial|help)\b/))
      return ChatbotIntent.QUESTION;
    if (lower.match(/\b(feedback|suggest|improve|feature)\b/))
      return ChatbotIntent.FEEDBACK;
    if (lower.match(/\b(api|code|technical|integration)\b/))
      return ChatbotIntent.TECHNICAL;

    return ChatbotIntent.QUESTION;
  }

  /**
   * Save message to database
   */
  private static async saveMessage(
    conversationId: string,
    role: 'USER' | 'ASSISTANT' | 'SYSTEM',
    content: string,
    metadata?: Record<string, unknown>
  ): Promise<void> {
    try {
      await prisma.chatbotMessage.create({
        data: {
          conversationId,
          role,
          content,
          metadata: metadata ? JSON.parse(JSON.stringify(metadata)) : null,
        },
      });
    } catch (error) {
      logError('Error saving chatbot message', error);
    }
  }

  /**
   * Create a new conversation
   */
  static async createConversation(
    userId?: string,
    sessionId?: string
  ): Promise<string> {
    try {
      if (!process.env.DATABASE_URL) {
        logError('DATABASE_URL not configured for conversation creation', {
          userId,
        });
        throw new Error('Database not configured');
      }

      const conversation = await prisma.chatbotConversation.create({
        data: {
          userId,
          sessionId:
            sessionId ||
            `session_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
          status: 'ACTIVE',
        },
      });

      logInfo('Created new chatbot conversation', {
        conversationId: conversation.id,
        userId,
      });

      return conversation.id;
    } catch (error) {
      logError('Error creating conversation', {
        userId,
        error: error instanceof Error ? error.message : String(error),
      });
      throw new Error('Failed to create conversation');
    }
  }

  /**
   * Get conversation history
   */
  static async getConversationHistory(
    conversationId: string
  ): Promise<ConversationContext['history']> {
    try {
      if (!process.env.DATABASE_URL) {
        logWarn('DATABASE_URL not configured, returning empty history', {
          conversationId,
        });
        return [];
      }

      const messages = await prisma.chatbotMessage.findMany({
        where: { conversationId },
        orderBy: { createdAt: 'asc' },
        take: 50, // Limit to recent messages
      });

      return messages.map(msg => ({
        role: msg.role.toLowerCase() as 'user' | 'assistant' | 'system',
        content: msg.content,
        timestamp: msg.createdAt,
      }));
    } catch (error) {
      logError('Error fetching conversation history', {
        conversationId,
        error: error instanceof Error ? error.message : String(error),
      });
      return [];
    }
  }

  /**
   * Close a conversation
   */
  static async closeConversation(
    conversationId: string,
    satisfaction?: number
  ): Promise<void> {
    try {
      await prisma.chatbotConversation.update({
        where: { id: conversationId },
        data: {
          status: 'CLOSED',
          resolvedAt: new Date(),
          satisfaction,
        },
      });

      logInfo('Closed chatbot conversation', {
        conversationId,
        satisfaction,
      });
    } catch (error) {
      logError('Error closing conversation', error);
    }
  }

  /**
   * Get active conversations for a user
   */
  static async getUserConversations(userId: string) {
    try {
      return await prisma.chatbotConversation.findMany({
        where: {
          userId,
          status: { in: ['ACTIVE', 'ESCALATED'] },
        },
        include: {
          messages: {
            orderBy: { createdAt: 'desc' },
            take: 1,
          },
        },
        orderBy: { updatedAt: 'desc' },
      });
    } catch (error) {
      logError('Error fetching user conversations', error);
      return [];
    }
  }
}
