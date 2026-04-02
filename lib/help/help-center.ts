/**
 * Help Center Service
 * Manages knowledge base articles, FAQs, and documentation
 */

import { prisma } from '@core/lib/prisma';
import { logInfo, logError } from '@core/lib/logger';

enum ArticleCategory {
  GETTING_STARTED = 'GETTING_STARTED',
  API_GENERATION = 'API_GENERATION',
  SECURITY = 'SECURITY',
  HONEYPOTS = 'HONEYPOTS',
  MONITORING = 'MONITORING',
  BILLING = 'BILLING',
  TROUBLESHOOTING = 'TROUBLESHOOTING',
  TEAMS = 'TEAMS',
  INTEGRATIONS = 'INTEGRATIONS',
}

enum ArticleAudience {
  ALL = 'ALL',
  DEVELOPER = 'DEVELOPER',
  ADMIN = 'ADMIN',
  USER = 'USER',
}

interface Article {
  id: string;
  title: string;
  slug: string;
  content: string;
  category: ArticleCategory;
  audience: ArticleAudience;
  tags: string[];
  viewCount: number;
  helpful: number;
  notHelpful: number;
  createdAt: Date;
  updatedAt: Date;
}

interface FAQ {
  id: string;
  question: string;
  answer: string;
  category: ArticleCategory;
  order: number;
}

interface SearchResult {
  article: Article;
  relevance: number;
}

export class HelpCenterService {
  /**
   * Get all article categories
   */
  static getCategories() {
    return [
      {
        id: ArticleCategory.GETTING_STARTED,
        name: 'Getting Started',
        icon: '🚀',
      },
      {
        id: ArticleCategory.API_GENERATION,
        name: 'API Generation',
        icon: '🏗️',
      },
      { id: ArticleCategory.SECURITY, name: 'Security', icon: '🔒' },
      { id: ArticleCategory.HONEYPOTS, name: 'Honeypots', icon: '🍯' },
      { id: ArticleCategory.MONITORING, name: 'Monitoring', icon: '📊' },
      {
        id: ArticleCategory.BILLING,
        name: 'Billing & Subscriptions',
        icon: '💳',
      },
      {
        id: ArticleCategory.TROUBLESHOOTING,
        name: 'Troubleshooting',
        icon: '🔧',
      },
      { id: ArticleCategory.TEAMS, name: 'Team Collaboration', icon: '👥' },
      { id: ArticleCategory.INTEGRATIONS, name: 'Integrations', icon: '🔗' },
    ];
  }

  /**
   * Search articles
   */
  static async searchArticles(
    query: string,
    userRole?: string,
    category?: ArticleCategory
  ): Promise<SearchResult[]> {
    try {
      logInfo('Searching help articles', { query, userRole, category });

      // Determine audience based on role
      const audiences = [ArticleAudience.ALL];
      if (userRole === 'ADMIN' || userRole === 'OWNER') {
        audiences.push(
          ArticleAudience.ADMIN,
          ArticleAudience.DEVELOPER,
          ArticleAudience.USER
        );
      } else if (userRole === 'DEVELOPER') {
        audiences.push(ArticleAudience.DEVELOPER, ArticleAudience.USER);
      } else {
        audiences.push(ArticleAudience.USER);
      }

      const articles = await prisma.helpArticle.findMany({
        where: {
          published: true,
          audience: { in: audiences },
          ...(category && { category }),
        },
      });

      // Calculate relevance score
      const results = articles.map((article): SearchResult => {
        const titleMatch = article.title
          .toLowerCase()
          .includes(query.toLowerCase());
        const contentMatch = article.content
          .toLowerCase()
          .includes(query.toLowerCase());
        const tagMatch = article.tags.some((tag: string) =>
          tag.toLowerCase().includes(query.toLowerCase())
        );

        let relevance = 0;
        if (titleMatch) relevance += 10;
        if (contentMatch) relevance += 5;
        if (tagMatch) relevance += 3;

        return {
          article: article as Article,
          relevance,
        };
      });

      // Sort by relevance
      return results
        .filter(r => r.relevance > 0)
        .sort((a, b) => b.relevance - a.relevance);
    } catch (error) {
      logError('Failed to search articles', { error, query });
      return [];
    }
  }

  /**
   * Get articles by category
   */
  static async getArticlesByCategory(
    category: ArticleCategory,
    userRole?: string
  ): Promise<Article[]> {
    try {
      const audiences = [ArticleAudience.ALL];
      if (userRole === 'ADMIN' || userRole === 'OWNER') {
        audiences.push(
          ArticleAudience.ADMIN,
          ArticleAudience.DEVELOPER,
          ArticleAudience.USER
        );
      } else if (userRole === 'DEVELOPER') {
        audiences.push(ArticleAudience.DEVELOPER, ArticleAudience.USER);
      } else {
        audiences.push(ArticleAudience.USER);
      }

      const articles = await prisma.helpArticle.findMany({
        where: {
          category,
          published: true,
          audience: { in: audiences },
        },
        orderBy: { viewCount: 'desc' },
      });

      return articles as Article[];
    } catch (error) {
      logError('Failed to get articles by category', { error, category });
      return [];
    }
  }

  /**
   * Get article by slug
   */
  static async getArticleBySlug(slug: string): Promise<Article | null> {
    try {
      const article = await prisma.helpArticle.findUnique({
        where: { slug },
      });

      if (article) {
        // Increment view count
        await prisma.helpArticle.update({
          where: { slug },
          data: { viewCount: { increment: 1 } },
        });
      }

      return article as Article | null;
    } catch (error) {
      logError('Failed to get article', { error, slug });
      return null;
    }
  }

  /**
   * Get FAQs by category
   */
  static async getFAQs(category?: ArticleCategory): Promise<FAQ[]> {
    try {
      const faqs = await prisma.helpFAQ.findMany({
        where: category ? { category } : undefined,
        orderBy: { order: 'asc' },
      });

      return faqs as FAQ[];
    } catch (error) {
      logError('Failed to get FAQs', { error, category });
      return [];
    }
  }

  /**
   * Rate article as helpful/not helpful
   */
  static async rateArticle(articleId: string, helpful: boolean): Promise<void> {
    try {
      await prisma.helpArticle.update({
        where: { id: articleId },
        data: helpful
          ? { helpful: { increment: 1 } }
          : { notHelpful: { increment: 1 } },
      });

      logInfo('Article rated', { articleId, helpful });
    } catch (error) {
      logError('Failed to rate article', { error, articleId });
      throw error;
    }
  }

  /**
   * Get popular articles
   */
  static async getPopularArticles(limit = 5): Promise<Article[]> {
    try {
      const articles = await prisma.helpArticle.findMany({
        where: { published: true },
        orderBy: { viewCount: 'desc' },
        take: limit,
      });

      return articles as Article[];
    } catch (error) {
      logError('Failed to get popular articles', { error });
      return [];
    }
  }

  /**
   * Create seed data (for initial setup)
   */
  static getSeedArticles() {
    return [
      {
        title: 'Getting Started with VortexSecure',
        slug: 'getting-started',
        content: `# Welcome to VortexSecure!

VortexSecure is your all-in-one platform for API generation, security, and monitoring.

## Quick Start

1. **Sign in** with your GitHub or Google account
2. **Connect** your repository or upload code files
3. **Generate** your API with AI assistance
4. **Secure** your API with automatic security scans
5. **Monitor** your API with honeypots and threat detection

## Key Features

- 🏗️ **AI-Powered Generation**: Generate production-ready APIs from natural language
- 🔒 **Security First**: Automatic OWASP scans and vulnerability detection
- 🍯 **Honeypot Protection**: Deploy decoy endpoints to trap attackers
- 📊 **Real-time Monitoring**: Track API health and security threats
- 👥 **Team Collaboration**: Work together on API projects

## Next Steps

- [Create Your First API](#)
- [Set Up Security Scans](#)
- [Deploy a Honeypot](#)
- [Invite Team Members](#)`,
        category: ArticleCategory.GETTING_STARTED,
        audience: ArticleAudience.ALL,
        tags: ['quickstart', 'tutorial', 'basics'],
      },
      {
        title: 'How to Generate Your First API',
        slug: 'generate-first-api',
        content: `# Generating Your First API

Learn how to create a production-ready API in minutes with AIForge.

## Step 1: Describe Your API

Navigate to the Build section and describe what your API should do. Be specific!

Example: "Create a REST API for managing blog posts with CRUD operations, authentication, and PostgreSQL storage."

## Step 2: Choose a Framework

Select your preferred technology stack:
- Node.js with Express
- Python with FastAPI
- Go with Fiber
- Ruby on Rails
- And more!

## Step 3: Generate

Click "Generate API" and wait while our AI creates:
- Complete API code
- Security tests
- Documentation
- Docker configuration

## Step 4: Review & Deploy

Review the generated code, run security scans, and deploy to your infrastructure.`,
        category: ArticleCategory.API_GENERATION,
        audience: ArticleAudience.ALL,
        tags: ['api', 'generation', 'tutorial'],
      },
      {
        title: 'Understanding Security Scans',
        slug: 'security-scans',
        content: `# Security Scans

VortexSecure automatically scans your API for vulnerabilities.

## What We Check

- **OWASP Top 10**: All critical security risks
- **Authentication**: Secure auth implementation
- **Input Validation**: SQL injection, XSS prevention
- **Rate Limiting**: DDoS protection
- **Secrets Management**: No hardcoded credentials

## How to Read Reports

Security reports are color-coded:
- 🔴 **Critical**: Fix immediately
- 🟡 **Warning**: Address soon
- 🟢 **Pass**: All good!

## Best Practices

1. Run scans on every code change
2. Fix critical issues before deployment
3. Review warnings regularly
4. Enable automatic scanning`,
        category: ArticleCategory.SECURITY,
        audience: ArticleAudience.DEVELOPER,
        tags: ['security', 'owasp', 'scanning'],
      },
      {
        title: 'Setting Up Honeypots',
        slug: 'setup-honeypots',
        content: `# Honeypot Setup Guide

Honeypots are decoy endpoints that trap attackers.

## What Are Honeypots?

Fake API endpoints that:
- Look like real vulnerabilities
- Log all access attempts
- Alert you to attackers
- Collect threat intelligence

## Creating a Honeypot

1. Go to Defend > Honeypots
2. Click "Deploy Honeypot"
3. Choose honeypot type (fake admin, database, etc.)
4. Deploy to your infrastructure

## Monitoring

View all honeypot activity in real-time:
- Attack patterns
- Source IPs
- Attack types
- Threat severity`,
        category: ArticleCategory.HONEYPOTS,
        audience: ArticleAudience.DEVELOPER,
        tags: ['honeypot', 'security', 'monitoring'],
      },
      {
        title: 'Billing and Subscriptions',
        slug: 'billing-subscriptions',
        content: `# Billing & Subscriptions

All billing for developer plans is handled through Paddle. Enterprise plans use annual invoice/PO.

## Developer & Team Plans (Self-serve via Paddle)

- **Starter**: $99/month - 25 API generations, 1 honeypot, 50K events, alerts only
- **Pro**: $199/month - 60 API generations, 3 honeypots, 500K events, 500 automated actions
- **Team**: $499/month - 250 API generations, 10 honeypots, 5M events, 5K actions, SSO/SAML

## Enterprise Plans (Coming Soon — Annual billing)

- **Business**: From $2,000/month - 100 API endpoints, 25 honeypots, mTLS, SIEM, unlimited actions
- **Enterprise**: From $5,000/month - 500 API endpoints, dedicated CSM, PCI-DSS/HIPAA compliance
- **Enterprise Plus**: Custom pricing - On-premise, multi-region, dedicated security engineer

## Upgrading/Downgrading

Manage your subscription through Paddle or contact us:
1. Go to your DevFortress dashboard
2. Navigate to Settings → Subscription
3. Click "Manage Plan"
4. Choose new plan

## Subscription Required

VortexSecure requires an active subscription to use. All users must subscribe to at least the Starter plan. When approaching your monthly generation limit, we'll notify you. To continue generating APIs, upgrade to a higher plan through GitHub Marketplace.

## Managing Subscriptions

Upgrade, downgrade, or cancel anytime from Settings > Billing.`,
        category: ArticleCategory.BILLING,
        audience: ArticleAudience.ALL,
        tags: ['billing', 'subscription', 'pricing'],
      },
    ];
  }

  static getSeedFAQs() {
    return [
      {
        question: 'How do I reset my password?',
        answer:
          'VortexSecure uses OAuth authentication (GitHub/Google). Reset your password through your OAuth provider.',
        category: ArticleCategory.GETTING_STARTED,
        order: 1,
      },
      {
        question: 'Can I use my own infrastructure?',
        answer:
          'Yes! Enterprise plans include custom deployment options. Contact sales for details.',
        category: ArticleCategory.GETTING_STARTED,
        order: 2,
      },
      {
        question: 'What languages/frameworks do you support?',
        answer:
          'We support 10+ frameworks including Node.js, Python, Go, Ruby, Java, .NET, and more.',
        category: ArticleCategory.API_GENERATION,
        order: 1,
      },
      {
        question: 'How accurate is the AI generation?',
        answer:
          'Our AI generates production-ready code with 95%+ accuracy. Always review and test generated code.',
        category: ArticleCategory.API_GENERATION,
        order: 2,
      },
      {
        question: 'Are security scans automated?',
        answer:
          'Yes! Scans run automatically on generation and can be scheduled for deployed APIs.',
        category: ArticleCategory.SECURITY,
        order: 1,
      },
      {
        question: 'What if I find a security issue?',
        answer:
          'Report security issues through our contact form with "Security Issue" selected. We respond within 24 hours.',
        category: ArticleCategory.SECURITY,
        order: 2,
      },
    ];
  }
}

export { ArticleCategory, ArticleAudience };
export type { Article, FAQ, SearchResult };
