/**
 * Continuous improvement sync service
 * Syncs flywheel insights back to BUILD tools to improve security rules and prompts
 */

import { PrismaClient } from '@prisma/client';
import { logInfo, logError, logWarn } from '../logger';
import { getOpenAIClient } from '../openai/client';

const prisma = new PrismaClient();

/**
 * Security rule derived from flywheel insights
 */
export interface SecurityRule {
  pattern: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  recommendation: string;
  category: string;
}

/**
 * Sync result for an API project
 */
export interface SyncResult {
  apiProjectId: string;
  rulesAdded: number;
  rulesUpdated: number;
  promptsUpdated: boolean;
  notificationsSent: number;
  error?: string;
}

/**
 * Extract security rules from flywheel insights
 */
export async function extractSecurityRules(
  insightId: string
): Promise<SecurityRule[]> {
  try {
    const insight = await prisma.flywheelInsight.findUnique({
      where: { id: insightId },
      include: {
        apiProject: {
          select: {
            id: true,
            name: true,
          },
        },
      },
    });

    if (!insight) {
      throw new Error('Insight not found');
    }

    const details = insight.details as {
      topPatterns?: Array<{
        pattern: string;
        count: number;
        severity: string;
      }>;
      recommendations?: string[];
    };

    const rules: SecurityRule[] = [];

    // Convert top attack patterns to security rules
    if (details.topPatterns) {
      for (const pattern of details.topPatterns) {
        // Map attack patterns to security categories
        let category = 'General Security';
        let recommendation = 'Implement input validation and sanitization';

        if (pattern.pattern.includes('sql-injection')) {
          category = 'SQL Injection';
          recommendation =
            'Use parameterized queries and prepared statements. Implement strict input validation.';
        } else if (pattern.pattern.includes('xss')) {
          category = 'Cross-Site Scripting';
          recommendation =
            'Encode output, validate input, and implement Content Security Policy headers.';
        } else if (pattern.pattern.includes('command-injection')) {
          category = 'Command Injection';
          recommendation =
            'Avoid system calls with user input. Use safe APIs and whitelist allowed commands.';
        } else if (pattern.pattern.includes('path-traversal')) {
          category = 'Path Traversal';
          recommendation =
            'Validate and sanitize file paths. Use allowlists for file access.';
        } else if (pattern.pattern.includes('auth-bypass')) {
          category = 'Authentication';
          recommendation =
            'Implement secure authentication mechanisms. Use multi-factor authentication.';
        } else if (pattern.pattern.includes('ssrf')) {
          category = 'Server-Side Request Forgery';
          recommendation =
            'Validate and sanitize URLs. Implement allowlists for external requests.';
        }

        rules.push({
          pattern: pattern.pattern,
          severity: pattern.severity.toLowerCase() as
            | 'low'
            | 'medium'
            | 'high'
            | 'critical',
          description: `Pattern detected from threat data: ${pattern.pattern} (${pattern.count} occurrences)`,
          recommendation,
          category,
        });
      }
    }

    // Add rules from AI recommendations
    if (details.recommendations) {
      for (const rec of details.recommendations.slice(0, 5)) {
        rules.push({
          pattern: 'ai-recommendation',
          severity: 'medium',
          description: `AI-generated recommendation: ${rec}`,
          recommendation: rec,
          category: 'Best Practices',
        });
      }
    }

    logInfo('Extracted security rules from insight', {
      insightId,
      rulesCount: rules.length,
    });

    return rules;
  } catch (error) {
    logError('Failed to extract security rules', { error, insightId });
    throw error;
  }
}

/**
 * Generate updated security prompt based on insights
 */
export async function generateUpdatedPrompt(
  apiProjectId: string,
  rules: SecurityRule[]
): Promise<string> {
  try {
    const openai = getOpenAIClient();

    const prompt = `You are a security expert. Based on recent threat intelligence, generate an updated security checklist and validation rules for API code generation.

Recent security rules learned from threat data:
${rules.map(r => `- ${r.category}: ${r.description}\n  Recommendation: ${r.recommendation}`).join('\n')}

Generate a comprehensive security prompt that includes:
1. Input validation requirements specific to these threats
2. Output encoding requirements
3. Authentication/authorization checks
4. Rate limiting and resource protection
5. Logging and monitoring requirements

Keep it concise (under 300 words) and actionable for code generation.`;

    const completion = await openai.chat.completions.create({
      model: process.env.OPENAI_MODEL || 'gpt-4o-mini',
      messages: [
        {
          role: 'system',
          content:
            'You are a cybersecurity expert specializing in secure API development.',
        },
        {
          role: 'user',
          content: prompt,
        },
      ],
      temperature: 0.3,
      max_tokens: 500,
    });

    const updatedPrompt =
      completion.choices[0]?.message?.content ||
      'Implement secure coding practices.';

    logInfo('Generated updated security prompt', {
      apiProjectId,
      promptLength: updatedPrompt.length,
    });

    return updatedPrompt;
  } catch (error) {
    logError('Failed to generate updated prompt', { error, apiProjectId });
    throw error;
  }
}

/**
 * Apply improvements to an API project
 */
export async function applyImprovements(
  apiProjectId: string,
  rules: SecurityRule[],
  updatedPrompt: string
): Promise<{
  rulesAdded: number;
  rulesUpdated: number;
  promptsUpdated: boolean;
}> {
  try {
    // Store updated security rules in project metadata
    const project = await prisma.apiProject.findUnique({
      where: { id: apiProjectId },
      select: { metadata: true },
    });

    if (!project) {
      throw new Error('API project not found');
    }

    const metadata = (project.metadata as Record<string, unknown>) || {};
    const existingRules = (metadata.securityRules as SecurityRule[]) || [];

    // Merge new rules with existing ones
    const ruleMap = new Map<string, SecurityRule>();

    // Add existing rules
    existingRules.forEach(rule => {
      ruleMap.set(`${rule.category}-${rule.pattern}`, rule);
    });

    let rulesAdded = 0;
    let rulesUpdated = 0;

    // Add/update new rules
    rules.forEach(rule => {
      const key = `${rule.category}-${rule.pattern}`;
      if (ruleMap.has(key)) {
        rulesUpdated++;
      } else {
        rulesAdded++;
      }
      ruleMap.set(key, rule);
    });

    // Update project metadata
    await prisma.apiProject.update({
      where: { id: apiProjectId },
      data: {
        metadata: {
          ...metadata,
          securityRules: Array.from(ruleMap.values()),
          securityPrompt: updatedPrompt,
          lastSyncedAt: new Date().toISOString(),
        } as never,
      },
    });

    logInfo('Applied improvements to API project', {
      apiProjectId,
      rulesAdded,
      rulesUpdated,
    });

    return {
      rulesAdded,
      rulesUpdated,
      promptsUpdated: true,
    };
  } catch (error) {
    logError('Failed to apply improvements', { error, apiProjectId });
    throw error;
  }
}

/**
 * Send notification to users about updates
 */
export async function notifyUsers(
  apiProjectId: string,
  updateSummary: string
): Promise<number> {
  try {
    const project = await prisma.apiProject.findUnique({
      where: { id: apiProjectId },
      select: {
        name: true,
        createdById: true,
        team: {
          select: {
            members: {
              select: {
                userId: true,
                user: {
                  select: {
                    email: true,
                    name: true,
                  },
                },
              },
            },
          },
        },
      },
    });

    if (!project) {
      throw new Error('API project not found');
    }

    // Collect user IDs to notify
    const userIds = new Set<string>([project.createdById]);

    if (project.team) {
      project.team.members.forEach(member => {
        userIds.add(member.userId);
      });
    }

    // Create audit logs for notifications
    const notificationLogs = Array.from(userIds).map(userId => ({
      userId,
      apiProjectId,
      action: 'PROJECT_UPDATED',
      resource: 'API_PROJECT',
      resourceId: apiProjectId,
      level: 'INFO' as const,
      message: `Security improvements applied to ${project.name}`,
      details: {
        updateSummary,
        timestamp: new Date().toISOString(),
      },
    }));

    await prisma.auditLog.createMany({
      data: notificationLogs,
    });

    logInfo('User notifications sent', {
      apiProjectId,
      notificationCount: userIds.size,
    });

    return userIds.size;
  } catch (error) {
    logError('Failed to notify users', { error, apiProjectId });
    throw error;
  }
}

/**
 * Sync insights to a specific API project
 */
export async function syncInsightsToProject(
  apiProjectId: string
): Promise<SyncResult> {
  try {
    logInfo('Starting continuous improvement sync', { apiProjectId });

    // Get latest insights for the project
    const insights = await prisma.flywheelInsight.findMany({
      where: { apiProjectId },
      orderBy: { generatedAt: 'desc' },
      take: 5, // Use last 5 insights
    });

    if (insights.length === 0) {
      logWarn('No insights available for sync', { apiProjectId });
      return {
        apiProjectId,
        rulesAdded: 0,
        rulesUpdated: 0,
        promptsUpdated: false,
        notificationsSent: 0,
        error: 'No insights available',
      };
    }

    // Extract rules from all insights
    const allRules: SecurityRule[] = [];
    for (const insight of insights) {
      const rules = await extractSecurityRules(insight.id);
      allRules.push(...rules);
    }

    // Generate updated prompt
    const updatedPrompt = await generateUpdatedPrompt(apiProjectId, allRules);

    // Apply improvements
    const result = await applyImprovements(
      apiProjectId,
      allRules,
      updatedPrompt
    );

    // Notify users
    const updateSummary = `Added ${result.rulesAdded} new security rules and updated ${result.rulesUpdated} existing rules based on threat intelligence.`;
    const notificationsSent = await notifyUsers(apiProjectId, updateSummary);

    logInfo('Continuous improvement sync completed', {
      apiProjectId,
      ...result,
      notificationsSent,
    });

    return {
      apiProjectId,
      ...result,
      notificationsSent,
    };
  } catch (error) {
    logError('Failed to sync insights to project', { error, apiProjectId });
    return {
      apiProjectId,
      rulesAdded: 0,
      rulesUpdated: 0,
      promptsUpdated: false,
      notificationsSent: 0,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}

/**
 * Sync insights to all API projects with recent insights
 */
export async function syncAllProjects(): Promise<{
  total: number;
  successful: number;
  failed: number;
  results: SyncResult[];
}> {
  try {
    logInfo('Starting continuous improvement sync for all projects');

    // Get all API projects that have insights from the last 7 days
    const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);

    const projects = await prisma.apiProject.findMany({
      where: {
        flywheelInsights: {
          some: {
            generatedAt: {
              gte: sevenDaysAgo,
            },
          },
        },
      },
      select: {
        id: true,
        name: true,
      },
    });

    logInfo('Found projects to sync', { count: projects.length });

    const results: SyncResult[] = [];
    let successful = 0;
    let failed = 0;

    for (const project of projects) {
      const result = await syncInsightsToProject(project.id);
      results.push(result);

      if (result.error) {
        failed++;
      } else {
        successful++;
      }
    }

    logInfo('Completed continuous improvement sync for all projects', {
      total: projects.length,
      successful,
      failed,
    });

    return {
      total: projects.length,
      successful,
      failed,
      results,
    };
  } catch (error) {
    logError('Failed to sync all projects', { error });
    throw error;
  }
}

/**
 * Allow teams to customize learning rules
 */
export async function updateTeamLearningRules(
  teamId: string,
  rules: {
    enableAutoSync: boolean;
    syncFrequency?: 'daily' | 'weekly' | 'monthly';
    minSeverity?: 'low' | 'medium' | 'high' | 'critical';
    excludedPatterns?: string[];
  }
): Promise<void> {
  try {
    const team = await prisma.team.findUnique({
      where: { id: teamId },
    });

    if (!team) {
      throw new Error('Team not found');
    }

    // Store learning rules in team metadata (would need to add to schema)
    // For now, we'll use audit log to track the configuration
    await prisma.auditLog.create({
      data: {
        userId: null,
        action: 'TEAM_CONFIG_UPDATED',
        resource: 'TEAM',
        resourceId: teamId,
        level: 'INFO',
        message: `Team learning rules updated for team ${teamId}`,
        details: {
          teamId,
          rules,
          timestamp: new Date().toISOString(),
        },
      },
    });

    logInfo('Team learning rules updated', { teamId, rules });
  } catch (error) {
    logError('Failed to update team learning rules', { error, teamId });
    throw error;
  }
}
