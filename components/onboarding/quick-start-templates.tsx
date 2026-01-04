'use client';

/**
 * Quick Start Templates Component
 *
 * Provides pre-built templates for common API use cases.
 * Helps new users get started quickly with working examples.
 *
 * @module components/onboarding/quick-start-templates
 */

import { useState } from 'react';
import {
  Users,
  ShoppingCart,
  FileText,
  MessageSquare,
  Database,
  Shield,
  Zap,
  Copy,
  Check,
} from 'lucide-react';

export interface Template {
  id: string;
  name: string;
  description: string;
  icon: React.ComponentType<{ className?: string }>;
  category: 'auth' | 'crud' | 'integration' | 'security';
  prompt: string;
  framework?: string;
  language?: string;
  tags: string[];
}

export const QUICK_START_TEMPLATES: Template[] = [
  {
    id: 'user-auth',
    name: 'User Authentication API',
    description:
      'JWT-based authentication with login, register, and password reset',
    icon: Users,
    category: 'auth',
    prompt: `Create a REST API for user authentication with the following features:
- POST /auth/register - Register new users with email and password
- POST /auth/login - Login and receive JWT tokens
- POST /auth/refresh - Refresh access token
- POST /auth/forgot-password - Send password reset email
- POST /auth/reset-password - Reset password with token
- GET /auth/me - Get current user profile (protected)

Include:
- Password hashing with bcrypt
- JWT access and refresh tokens
- Rate limiting on auth endpoints
- Input validation with Zod
- OWASP security best practices`,
    framework: 'express',
    language: 'typescript',
    tags: ['authentication', 'jwt', 'security'],
  },
  {
    id: 'crud-api',
    name: 'CRUD REST API',
    description:
      'Full CRUD operations with pagination, filtering, and validation',
    icon: Database,
    category: 'crud',
    prompt: `Create a REST API with full CRUD operations for a resource management system:
- GET /items - List all items with pagination and filtering
- GET /items/:id - Get single item by ID
- POST /items - Create new item
- PUT /items/:id - Update item
- DELETE /items/:id - Delete item
- GET /items/search - Search items by query

Include:
- Pagination with page/limit params
- Sorting by any field
- Filtering by status, date range
- Input validation
- Proper error handling
- OpenAPI/Swagger documentation`,
    framework: 'express',
    language: 'typescript',
    tags: ['crud', 'rest', 'pagination'],
  },
  {
    id: 'ecommerce',
    name: 'E-Commerce API',
    description: 'Product catalog, cart, and checkout endpoints',
    icon: ShoppingCart,
    category: 'crud',
    prompt: `Create an e-commerce REST API with:
- Products: List, search, filter by category/price
- Cart: Add, update, remove items, get cart total
- Checkout: Create order, apply discount codes
- Orders: List user orders, get order details

Include:
- Product variants (size, color)
- Inventory tracking
- Price calculations with tax
- Input validation
- Authentication middleware for user-specific endpoints`,
    framework: 'express',
    language: 'typescript',
    tags: ['ecommerce', 'products', 'orders'],
  },
  {
    id: 'blog-cms',
    name: 'Blog/CMS API',
    description: 'Content management with posts, categories, and comments',
    icon: FileText,
    category: 'crud',
    prompt: `Create a blog/CMS REST API with:
- Posts: CRUD operations, publish/draft status
- Categories: Organize posts by category
- Comments: Add comments to posts, nested replies
- Tags: Tag posts for filtering
- Media: Upload and manage images

Include:
- Rich text content support
- SEO metadata fields
- Author information
- Pagination and search
- Role-based access (admin, editor, viewer)`,
    framework: 'express',
    language: 'typescript',
    tags: ['blog', 'cms', 'content'],
  },
  {
    id: 'chat-api',
    name: 'Chat/Messaging API',
    description: 'Real-time messaging with conversations and notifications',
    icon: MessageSquare,
    category: 'integration',
    prompt: `Create a chat/messaging REST API with:
- Conversations: Create, list, get messages
- Messages: Send, receive, mark as read
- Participants: Add/remove users from conversations
- Notifications: Unread count, push notification triggers

Include:
- Message pagination (infinite scroll)
- Typing indicators support
- Message status (sent, delivered, read)
- File attachments metadata
- WebSocket event hooks`,
    framework: 'express',
    language: 'typescript',
    tags: ['chat', 'messaging', 'realtime'],
  },
  {
    id: 'webhook-handler',
    name: 'Webhook Handler API',
    description: 'Secure webhook receiver with signature validation',
    icon: Zap,
    category: 'integration',
    prompt: `Create a webhook handler API with:
- POST /webhooks/:provider - Receive webhooks from various providers
- Signature validation for Stripe, GitHub, Slack
- Event logging and replay capability
- Async processing with queues
- Idempotency handling

Include:
- HMAC signature verification
- Request body raw access
- Retry logic for failed processing
- Event deduplication
- Audit logging`,
    framework: 'express',
    language: 'typescript',
    tags: ['webhooks', 'integrations', 'security'],
  },
  {
    id: 'api-gateway',
    name: 'API Gateway',
    description: 'Rate limiting, authentication, and request routing',
    icon: Shield,
    category: 'security',
    prompt: `Create an API gateway with:
- Rate limiting per user/IP
- API key authentication
- Request/response transformation
- Route aggregation
- Health checks

Include:
- Sliding window rate limiting
- Multiple auth strategies (API key, JWT, OAuth)
- Request logging and metrics
- Circuit breaker pattern
- CORS configuration`,
    framework: 'express',
    language: 'typescript',
    tags: ['gateway', 'security', 'rate-limiting'],
  },
];

interface QuickStartTemplatesProps {
  /**
   * Callback when a template is selected
   */
  onSelectTemplate: (template: Template) => void;

  /**
   * Currently selected template ID
   */
  selectedId?: string;

  /**
   * Show as compact cards
   */
  compact?: boolean;
}

export function QuickStartTemplates({
  onSelectTemplate,
  selectedId,
  compact = false,
}: QuickStartTemplatesProps) {
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const handleCopyPrompt = async (template: Template) => {
    await navigator.clipboard.writeText(template.prompt);
    setCopiedId(template.id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const categoryColors = {
    auth: 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400',
    crud: 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400',
    integration:
      'bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-400',
    security:
      'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400',
  };

  if (compact) {
    return (
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {QUICK_START_TEMPLATES.slice(0, 4).map(template => {
          const Icon = template.icon;
          return (
            <button
              key={template.id}
              onClick={() => onSelectTemplate(template)}
              className={`flex flex-col items-center gap-2 p-4 rounded-lg border transition-all ${
                selectedId === template.id
                  ? 'border-primary-500 bg-primary-50 dark:bg-primary-900/20'
                  : 'border-gray-200 dark:border-gray-700 hover:border-gray-300 dark:hover:border-gray-600'
              }`}
            >
              <Icon className="h-6 w-6 text-gray-600 dark:text-gray-400" />
              <span className="text-sm font-medium text-center">
                {template.name}
              </span>
            </button>
          );
        })}
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
          Quick Start Templates
        </h3>
        <span className="text-sm text-gray-500 dark:text-gray-400">
          {QUICK_START_TEMPLATES.length} templates
        </span>
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        {QUICK_START_TEMPLATES.map(template => {
          const Icon = template.icon;
          const isSelected = selectedId === template.id;
          const isCopied = copiedId === template.id;

          return (
            <div
              key={template.id}
              className={`relative p-4 rounded-lg border transition-all ${
                isSelected
                  ? 'border-primary-500 bg-primary-50 dark:bg-primary-900/20 ring-1 ring-primary-500'
                  : 'border-gray-200 dark:border-gray-700 hover:border-gray-300 dark:hover:border-gray-600'
              }`}
            >
              <div className="flex items-start gap-3">
                <div className="p-2 rounded-lg bg-gray-100 dark:bg-gray-800">
                  <Icon className="h-5 w-5 text-gray-600 dark:text-gray-400" />
                </div>

                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <h4 className="font-medium text-gray-900 dark:text-white">
                      {template.name}
                    </h4>
                    <span
                      className={`text-xs px-2 py-0.5 rounded-full ${categoryColors[template.category]}`}
                    >
                      {template.category}
                    </span>
                  </div>

                  <p className="text-sm text-gray-600 dark:text-gray-400 mb-3">
                    {template.description}
                  </p>

                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => onSelectTemplate(template)}
                      className="text-sm font-medium text-primary-600 hover:text-primary-700 dark:text-primary-400"
                    >
                      Use Template
                    </button>
                    <span className="text-gray-300 dark:text-gray-600">|</span>
                    <button
                      onClick={() => handleCopyPrompt(template)}
                      className="inline-flex items-center gap-1 text-sm text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-300"
                    >
                      {isCopied ? (
                        <>
                          <Check className="h-3 w-3 text-green-500" />
                          Copied!
                        </>
                      ) : (
                        <>
                          <Copy className="h-3 w-3" />
                          Copy Prompt
                        </>
                      )}
                    </button>
                  </div>
                </div>
              </div>

              {/* Tags */}
              <div className="flex flex-wrap gap-1 mt-3">
                {template.tags.map(tag => (
                  <span
                    key={tag}
                    className="text-xs px-2 py-0.5 bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-400 rounded"
                  >
                    {tag}
                  </span>
                ))}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

export default QuickStartTemplates;
