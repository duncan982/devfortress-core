/**
 * Developer Portal Service
 * Aggregates data from multiple sources for the internal developer portal
 */

import { Prisma } from '@prisma/client';
import { prisma } from '@core/lib/prisma';
import { logInfo, logError } from '@core/lib/logger';

interface PortalSection {
  id: string;
  title: string;
  description: string;
  icon: string;
  href: string;
  category: 'docs' | 'security' | 'monitoring' | 'data';
}

interface SecurityInsights {
  totalHoneypots: number;
  activeHoneypots: number;
  recentThreats: number;
  iacVulnerabilities: number;
  eolWarnings: number;
  securityScore: number;
}

interface MonitoringData {
  totalMonitors: number;
  activeMonitors: number;
  openIncidents: number;
  avgUptime: number;
  recentChecks: number;
}

interface FlywheelMetrics {
  totalAPIs: number;
  totalGenerations: number;
  activeUsers: number;
  revenueThisMonth: number;
  topAPIs: Array<{ name: string; count: number }>;
}

interface PortalData {
  sections: PortalSection[];
  securityInsights: SecurityInsights;
  monitoring: MonitoringData;
  flywheel: FlywheelMetrics;
  recentActivity: Array<{
    id: string;
    type: string;
    message: string;
    timestamp: Date;
    severity?: string;
  }>;
}

export class DeveloperPortalService {
  /**
   * Get all portal sections
   */
  static getPortalSections(): PortalSection[] {
    return [
      {
        id: 'api-docs',
        title: 'API Documentation',
        description:
          'Browse and search API documentation, endpoints, and examples',
        icon: 'book',
        href: '/portal/docs',
        category: 'docs',
      },
      {
        id: 'security-insights',
        title: 'Security Insights',
        description:
          'View security vulnerabilities, threats, and compliance status',
        icon: 'shield',
        href: '/portal/security',
        category: 'security',
      },
      {
        id: 'honeypot-logs',
        title: 'Honeypot Logs',
        description: 'Monitor honeypot activity and analyze threat patterns',
        icon: 'bug',
        href: '/portal/honeypots',
        category: 'security',
      },
      {
        id: 'api-monitoring',
        title: 'API Monitoring',
        description: 'Track API health, uptime, and performance metrics',
        icon: 'activity',
        href: '/portal/monitoring',
        category: 'monitoring',
      },
      {
        id: 'flywheel-data',
        title: 'Flywheel Analytics',
        description: 'View growth metrics, user engagement, and revenue data',
        icon: 'trending-up',
        href: '/portal/flywheel',
        category: 'data',
      },
      {
        id: 'infrastructure',
        title: 'Infrastructure',
        description: 'Monitor infrastructure health, costs, and resource usage',
        icon: 'server',
        href: '/portal/infrastructure',
        category: 'monitoring',
      },
      {
        id: 'team-management',
        title: 'Team Management',
        description: 'Manage team members, roles, and permissions',
        icon: 'users',
        href: '/portal/teams',
        category: 'docs',
      },
      {
        id: 'api-reference',
        title: 'API Reference',
        description: 'Complete API reference with authentication and examples',
        icon: 'code',
        href: '/portal/api-reference',
        category: 'docs',
      },
    ];
  }

  /**
   * Get security insights summary
   */
  static async getSecurityInsights(
    userId: string,
    teamId?: string
  ): Promise<SecurityInsights> {
    try {
      logInfo('Fetching security insights', { userId, teamId });

      // Get honeypot statistics
      const honeypotWhere: Prisma.HoneypotWhereInput = teamId
        ? {
            OR: [{ ownerId: userId }, { teamId }],
          }
        : { ownerId: userId };

      const honeypots = await prisma.honeypot.findMany({
        where: honeypotWhere,
        select: {
          status: true,
        },
      });

      const totalHoneypots = honeypots.length;
      const activeHoneypots = honeypots.filter(
        h => h.status === 'ACTIVE'
      ).length;

      // Get recent threats (last 7 days)
      const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
      const recentThreats = await prisma.threatEvent.count({
        where: {
          detectedAt: { gte: sevenDaysAgo },
        },
      });

      // Calculate security score (0-100)
      // Simple formula: base score - penalties
      let securityScore = 100;
      if (recentThreats > 10) securityScore -= 20;
      if (activeHoneypots === 0) securityScore -= 10;
      securityScore = Math.max(0, securityScore);

      return {
        totalHoneypots,
        activeHoneypots,
        recentThreats,
        iacVulnerabilities: 0, // TODO: Integrate with IaC scanner
        eolWarnings: 0, // TODO: Integrate with EOL tracker
        securityScore,
      };
    } catch (error) {
      logError('Failed to get security insights', { error, userId });
      return {
        totalHoneypots: 0,
        activeHoneypots: 0,
        recentThreats: 0,
        iacVulnerabilities: 0,
        eolWarnings: 0,
        securityScore: 0,
      };
    }
  }

  /**
   * Get monitoring data summary
   */
  static async getMonitoringData(
    userId: string,
    teamId?: string
  ): Promise<MonitoringData> {
    try {
      logInfo('Fetching monitoring data', { userId, teamId });

      const monitors = await prisma.aPIMonitor.findMany({
        where: {
          OR: [{ userId }, { teamId: teamId || undefined }],
        },
        include: {
          checks: {
            orderBy: { checkedAt: 'desc' },
            take: 100,
          },
          incidents: {
            where: { status: 'OPEN' },
          },
        },
      });

      const totalMonitors = monitors.length;
      const activeMonitors = monitors.filter(m => m.status === 'ACTIVE').length;
      const openIncidents = monitors.reduce(
        (sum, m) => sum + m.incidents.length,
        0
      );

      // Calculate average uptime
      let totalUptime = 0;
      let monitorsWithChecks = 0;
      for (const monitor of monitors) {
        if (monitor.checks.length > 0) {
          const successfulChecks = monitor.checks.filter(c => c.success).length;
          const uptime = (successfulChecks / monitor.checks.length) * 100;
          totalUptime += uptime;
          monitorsWithChecks++;
        }
      }
      const avgUptime =
        monitorsWithChecks > 0 ? totalUptime / monitorsWithChecks : 100;

      const recentChecks = monitors.reduce(
        (sum, m) => sum + Math.min(m.checks.length, 10),
        0
      );

      return {
        totalMonitors,
        activeMonitors,
        openIncidents,
        avgUptime: Math.round(avgUptime * 100) / 100,
        recentChecks,
      };
    } catch (error) {
      logError('Failed to get monitoring data', { error, userId });
      return {
        totalMonitors: 0,
        activeMonitors: 0,
        openIncidents: 0,
        avgUptime: 0,
        recentChecks: 0,
      };
    }
  }

  /**
   * Get flywheel metrics
   */
  static async getFlywheelMetrics(userId: string): Promise<FlywheelMetrics> {
    try {
      logInfo('Fetching flywheel metrics', { userId });

      // Get API projects
      const apiProjects = await prisma.apiProject.findMany({
        where: { createdById: userId },
        select: {
          name: true,
          createdAt: true,
        },
      });

      // Get active users in teams
      const teams = await prisma.team.findMany({
        where: {
          members: {
            some: { userId },
          },
        },
        include: {
          members: true,
        },
      });
      const activeUsers = teams.reduce(
        (sum, team) => sum + team.members.length,
        0
      );

      // Get revenue data (mock for now - integrate with payment service)
      const revenueThisMonth = 0; // TODO: Integrate with RevenueTracker

      // Top APIs by usage
      const topAPIs = apiProjects.slice(0, 5).map(api => ({
        name: api.name,
        count: 1, // TODO: Track actual usage
      }));

      return {
        totalAPIs: apiProjects.length,
        totalGenerations: apiProjects.length,
        activeUsers,
        revenueThisMonth,
        topAPIs,
      };
    } catch (error) {
      logError('Failed to get flywheel metrics', { error, userId });
      return {
        totalAPIs: 0,
        totalGenerations: 0,
        activeUsers: 0,
        revenueThisMonth: 0,
        topAPIs: [],
      };
    }
  }

  /**
   * Get recent activity across all systems
   */
  static async getRecentActivity(userId: string, limit = 20) {
    try {
      logInfo('Fetching recent activity', { userId, limit });

      const activities: Array<{
        id: string;
        type: string;
        message: string;
        timestamp: Date;
        severity?: string;
      }> = [];

      // Recent API creations
      const recentAPIs = await prisma.apiProject.findMany({
        where: { createdById: userId },
        orderBy: { createdAt: 'desc' },
        take: 5,
        select: {
          id: true,
          name: true,
          createdAt: true,
        },
      });

      for (const api of recentAPIs) {
        activities.push({
          id: api.id,
          type: 'api_created',
          message: `API "${api.name}" created`,
          timestamp: api.createdAt,
        });
      }

      // Recent threats
      const recentThreats = await prisma.threatEvent.findMany({
        orderBy: { detectedAt: 'desc' },
        take: 5,
        select: {
          id: true,
          tags: true,
          severity: true,
          detectedAt: true,
        },
      });

      for (const threat of recentThreats) {
        const threatLabel = threat.tags[0] || 'Security';
        activities.push({
          id: threat.id,
          type: 'threat_detected',
          message: `${threatLabel} threat detected`,
          timestamp: threat.detectedAt,
          severity: threat.severity,
        });
      }

      // Sort by timestamp and limit
      activities.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());
      return activities.slice(0, limit);
    } catch (error) {
      logError('Failed to get recent activity', { error, userId });
      return [];
    }
  }

  /**
   * Get complete portal data
   */
  static async getPortalData(
    userId: string,
    teamId?: string
  ): Promise<PortalData> {
    try {
      logInfo('Fetching complete portal data', { userId, teamId });

      const [sections, securityInsights, monitoring, flywheel, recentActivity] =
        await Promise.all([
          Promise.resolve(this.getPortalSections()),
          this.getSecurityInsights(userId, teamId),
          this.getMonitoringData(userId, teamId),
          this.getFlywheelMetrics(userId),
          this.getMonitoringData(userId, teamId),
          this.getFlywheelMetrics(userId),
          this.getRecentActivity(userId),
        ]);

// ... existing code ...

      return {
        sections,
        securityInsights,
        monitoring,
        flywheel,
        recentActivity: Array.isArray(recentActivity) ? recentActivity : [],
      };
    } catch (error) {
      logError('Failed to get portal data', { error, userId });
      throw error;
    }
  }

  /**
   * Search portal content
   */
  static async searchPortal(query: string, userId: string, category?: string) {
    try {
      logInfo('Searching portal content', { query, userId, category });

      const results: Array<{
        id: string;
        title: string;
        description: string;
        url: string;
        category: string;
        relevance: number;
      }> = [];

      const sections = this.getPortalSections();
      const lowerQuery = query.toLowerCase();

      // Search through sections
      for (const section of sections) {
        if (category && section.category !== category) continue;

        let relevance = 0;
        if (section.title.toLowerCase().includes(lowerQuery)) relevance += 10;
        if (section.description.toLowerCase().includes(lowerQuery))
          relevance += 5;

        if (relevance > 0) {
          results.push({
            id: section.id,
            title: section.title,
            description: section.description,
            url: section.href,
            category: section.category,
            relevance,
          });
        }
      }

      // Search through API projects
      const apiProjects = await prisma.apiProject.findMany({
        where: {
          createdById: userId,
          OR: [
            { name: { contains: query, mode: 'insensitive' } },
            { description: { contains: query, mode: 'insensitive' } },
          ],
        },
        take: 10,
      });

      for (const api of apiProjects) {
        results.push({
          id: api.id,
          title: api.name,
          description: api.description || 'API Project',
          url: `/build/${api.id}`,
          category: 'docs',
          relevance: 8,
        });
      }

      // Sort by relevance
      results.sort((a, b) => b.relevance - a.relevance);
      return results;
    } catch (error) {
      logError('Failed to search portal', { error, query });
      return [];
    }
  }
}

export type {
  PortalSection,
  SecurityInsights,
  MonitoringData,
  FlywheelMetrics,
  PortalData,
};
