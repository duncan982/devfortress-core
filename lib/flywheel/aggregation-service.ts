/**
 * Flywheel aggregation service
 * Collects and aggregates threat data from both honeypots and live APIs,
 * analyzes patterns using AI, and stores insights in the database for
 * continuous improvement through the BUILD → DEFEND → LEARN feedback loop
 * 
 * Premium Integration: Includes LiveThreatEvent data (Premium A3) alongside
 * honeypot events for comprehensive threat intelligence
 */

import { PrismaClient, InsightType } from '@prisma/client';
import { logInfo, logError, logWarn } from '../logger';
import { getOpenAIClient } from '../openai/client';

const prisma = new PrismaClient();

export interface AggregationFilters {
  apiProjectId?: string;
  ownerId?: string;
  startDate?: Date;
  endDate?: Date;
  minSeverity?: string;
}

export interface TestResultAggregation {
  totalTests: number;
  successfulTests: number;
  failedTests: number;
  attackSuccessRate: number;
  topVulnerablePaths: Array<{
    path: string;
    successRate: number;
    attempts: number;
  }>;
  testCoverage: { attacksTested: number; uniquePaths: number };
  recentTestDate?: Date;
}

export interface ThreatPattern {
  pattern: string;
  count: number;
  severity: string;
  examples: string[];
}

export interface ThreatAggregation {
  totalThreats: number;
  criticalThreats: number;
  patterns: ThreatPattern[];
  topIPs: Array<{ ip: string; count: number }>;
  testResults: TestResultAggregation;
  timeRange: { start: Date; end: Date };
}

/**
 * Platform phases for the BUILD -> DEFEND -> LEARN feedback loop
 */
export type PlatformPhase = 'BUILD' | 'DEFEND' | 'LEARN';

/**
 * Actionable recommendation with phase categorization and context
 */
export interface ActionableRecommendation {
  id: string;
  recommendation: string;
  phase: PlatformPhase;
  context: string;
  priority: 'HIGH' | 'MEDIUM' | 'LOW';
  affectedEndpoints?: string[];
  relatedPatterns?: string[];
}

export interface InsightGenerationResult {
  id: string;
  summary: string;
  details: {
    totalThreats: number;
    criticalThreats: number;
    topPatterns: ThreatPattern[];
    topIPs: Array<{ ip: string; count: number }>;
    testResults: TestResultAggregation;
    recommendations: ActionableRecommendation[];
    trends: string[];
    phaseBreakdown: {
      BUILD: ActionableRecommendation[];
      DEFEND: ActionableRecommendation[];
      LEARN: ActionableRecommendation[];
    };
  };
  confidence: number;
  modelVersion: string;
}

/**
 * Aggregate honeypot test results for analytics
 */
export async function aggregateTestResults(
  filters: AggregationFilters
): Promise<TestResultAggregation> {
  try {
    const endDate = filters.endDate || new Date();
    const startDate =
      filters.startDate ||
      new Date(endDate.getTime() - 30 * 24 * 60 * 60 * 1000); // Last 30 days

     
    const where: any = {
      createdAt: {
        gte: startDate,
        lte: endDate,
      },
    };

    if (filters.ownerId) {
      where.honeypot = {
        ownerId: filters.ownerId,
      };
    }

    // Get all test results
    const testResults = await prisma.honeypotTestResult.findMany({
      where,
      select: {
        id: true,
        attacksSent: true,
        results: true,
        createdAt: true,
        honeypot: {
          select: {
            id: true,
            name: true,
          },
        },
      },
      orderBy: {
        createdAt: 'desc',
      },
    });

    if (testResults.length === 0) {
      return {
        totalTests: 0,
        successfulTests: 0,
        failedTests: 0,
        attackSuccessRate: 0,
        topVulnerablePaths: [],
        testCoverage: { attacksTested: 0, uniquePaths: 0 },
      };
    }

    let totalAttacks = 0;
    let successfulAttacks = 0;
    const pathSuccessMap = new Map<
      string,
      { success: number; total: number }
    >();
    const uniquePaths = new Set<string>();
    const uniqueAttacks = new Set<string>();

    testResults.forEach(testResult => {
      const results = testResult.results as Array<{
        attackName: string;
        path: string;
        statusCode: number | null;
        error: string | null;
      }>;

      results.forEach(result => {
        totalAttacks++;
        uniquePaths.add(result.path);
        uniqueAttacks.add(result.attackName);

        // Consider attack successful if it got a response (even error responses indicate the endpoint exists)
        if (result.statusCode !== null || !result.error) {
          successfulAttacks++;
        }

        // Track path vulnerability
        const pathKey = result.path;
        const existing = pathSuccessMap.get(pathKey) || {
          success: 0,
          total: 0,
        };
        existing.total++;
        if (result.statusCode !== null || !result.error) {
          existing.success++;
        }
        pathSuccessMap.set(pathKey, existing);
      });
    });

    // Calculate top vulnerable paths
    const topVulnerablePaths = Array.from(pathSuccessMap.entries())
      .map(([path, stats]) => ({
        path,
        successRate: stats.total > 0 ? (stats.success / stats.total) * 100 : 0,
        attempts: stats.total,
      }))
      .sort((a, b) => b.successRate - a.successRate)
      .slice(0, 10);

    const attackSuccessRate =
      totalAttacks > 0 ? (successfulAttacks / totalAttacks) * 100 : 0;

    logInfo('Aggregated test results', {
      totalTests: testResults.length,
      totalAttacks,
      successfulAttacks,
      attackSuccessRate: `${attackSuccessRate.toFixed(1)}%`,
      vulnerablePaths: topVulnerablePaths.length,
    });

    return {
      totalTests: testResults.length,
      successfulTests: successfulAttacks,
      failedTests: totalAttacks - successfulAttacks,
      attackSuccessRate,
      topVulnerablePaths,
      testCoverage: {
        attacksTested: uniqueAttacks.size,
        uniquePaths: uniquePaths.size,
      },
      recentTestDate: testResults[0]?.createdAt,
    };
  } catch (error) {
    logError('Failed to aggregate test results', { error, filters });
    throw error;
  }
}

export async function aggregateThreatData(
  filters: AggregationFilters = {}
): Promise<ThreatAggregation> {
  try {
    const endDate = filters.endDate || new Date();
    const startDate =
      filters.startDate ||
      new Date(endDate.getTime() - 30 * 24 * 60 * 60 * 1000); // Last 30 days

     
    const where: any = {
      detectedAt: {
        gte: startDate,
        lte: endDate,
      },
    };

    if (filters.apiProjectId) {
      where.apiProjectId = filters.apiProjectId;
    }

    if (filters.ownerId) {
      where.honeypot = {
        ownerId: filters.ownerId,
      };
    }

    if (filters.minSeverity) {
      // Severity hierarchy: LOW < MEDIUM < HIGH < CRITICAL
      const severityLevels = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
      const minIndex = severityLevels.indexOf(
        filters.minSeverity.toUpperCase()
      );
      if (minIndex !== -1) {
        where.severity = {
          in: severityLevels.slice(minIndex),
        };
      }
    }

    // Get all threat events from both honeypots and live APIs
    const [honeypotThreats, liveThreats] = await Promise.all([
      // Honeypot threat events
      prisma.threatEvent.findMany({
        where,
        select: {
          id: true,
          severity: true,
          tags: true,
          sourceIp: true,
          payload: true,
          detectedAt: true,
        },
        orderBy: {
          detectedAt: 'desc',
        },
      }),
      // Live API threat events (Premium A3 - Live Surveillance)
      // Handle gracefully if requestPath column doesn't exist yet
      prisma.liveThreatEvent.findMany({
        where: {
          ...(filters.apiProjectId && { projectId: filters.apiProjectId }),
          ...(filters.ownerId && {
            project: { is: { createdById: filters.ownerId } },
          }),
          timestamp: {
            ...(filters.startDate && { gte: filters.startDate }),
            ...(filters.endDate && { lte: filters.endDate }),
          },
        },
        select: {
          id: true,
          severity: true,
          eventType: true,
          ip: true,
          // requestPath: true, // May not exist yet in database
          timestamp: true,
          metadata: true,
        },
        orderBy: {
          timestamp: 'desc',
        },
      }).catch(error => {
        // Log error but continue - database schema may be migrating
        logWarn('Failed to fetch live threat events', { error: error instanceof Error ? error.message : 'Unknown error' });
        return [];
      }),
    ]);

    // Normalize both types of threats to a common format
    const threats = [
      ...honeypotThreats,
      ...liveThreats.map(lt => ({
        id: lt.id,
        severity: lt.severity,
        tags: [lt.eventType], // Event type as tag
        sourceIp: lt.ip,
        payload: { 
          path: '/', // Default path since requestPath may not exist
          ...(lt.metadata as Record<string, unknown> || {})
        },
        detectedAt: lt.timestamp,
      })),
    ];

    // Count critical threats
    const criticalThreats = threats.filter(
      t => t.severity === 'CRITICAL'
    ).length;

    // Aggregate patterns
    const patternMap = new Map<
      string,
      { count: number; severity: string; examples: string[] }
    >();

    threats.forEach(threat => {
      threat.tags.forEach(tag => {
        const existing = patternMap.get(tag);
        const example = (threat.payload as { path?: string })?.path || '/';

        if (existing) {
          existing.count++;
          if (existing.examples.length < 3) {
            existing.examples.push(example);
          }
          // Upgrade severity if this threat is more severe
          if (
            threat.severity === 'CRITICAL' ||
            (threat.severity === 'HIGH' && existing.severity !== 'CRITICAL')
          ) {
            existing.severity = threat.severity;
          }
        } else {
          patternMap.set(tag, {
            count: 1,
            severity: threat.severity,
            examples: [example],
          });
        }
      });
    });

    const patterns: ThreatPattern[] = Array.from(patternMap.entries())
      .map(([pattern, data]) => ({
        pattern,
        count: data.count,
        severity: data.severity,
        examples: data.examples,
      }))
      .sort((a, b) => b.count - a.count);

    // Aggregate top IPs
    const ipMap = new Map<string, number>();
    threats.forEach(threat => {
      const count = ipMap.get(threat.sourceIp) || 0;
      ipMap.set(threat.sourceIp, count + 1);
    });

    const topIPs = Array.from(ipMap.entries())
      .map(([ip, count]) => ({ ip, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);

    logInfo('Aggregated threat data', {
      totalThreats: threats.length,
      criticalThreats,
      patternsFound: patterns.length,
      topIPsCount: topIPs.length,
    });

    // Also aggregate test results
    const testResults = await aggregateTestResults(filters);

    return {
      totalThreats: threats.length,
      criticalThreats,
      patterns,
      topIPs,
      testResults,
      timeRange: { start: startDate, end: endDate },
    };
  } catch (error) {
    logError('Failed to aggregate test results', { error, filters });
    throw error;
  }
}

/**
 * Generate AI-powered insights from aggregated threat data
 * Creates actionable recommendations categorized by platform phase (BUILD/DEFEND/LEARN)
 * @param apiProjectId - Required API project ID for storing insights
 */
export async function generateInsights(
  aggregatedData: Awaited<ReturnType<typeof aggregateThreatData>>,
  apiProjectId: string
): Promise<InsightGenerationResult> {
  try {
    // Build enhanced analysis prompt for AI with phase categorization
    const prompt = `You are a security expert analyzing threat intelligence from honeypot deployments for an API security platform.

## Platform Context
This platform follows a BUILD -> DEFEND -> LEARN feedback loop:
- **BUILD**: Generate secure APIs with AI-powered code generation
- **DEFEND**: Deploy intelligent honeypots to detect and engage attackers  
- **LEARN**: Analyze threat data to improve both BUILD and DEFEND phases

## Threat Data to Analyze

**Overview:**
- Total Threats: ${aggregatedData.totalThreats}
- Critical Threats: ${aggregatedData.criticalThreats}
- Time Range: ${aggregatedData.timeRange.start.toISOString()} to ${aggregatedData.timeRange.end.toISOString()}

**Honeypot Testing Results:**
- Total Tests Run: ${aggregatedData.testResults.totalTests}
- Attack Success Rate: ${aggregatedData.testResults.attackSuccessRate.toFixed(1)}%
- Attacks Tested: ${aggregatedData.testResults.testCoverage.attacksTested}
- Unique Paths Tested: ${aggregatedData.testResults.testCoverage.uniquePaths}

**Top Vulnerable Paths:**
${aggregatedData.testResults.topVulnerablePaths
  .slice(0, 5)
  .map(
    p =>
      `- ${p.path}: ${p.successRate.toFixed(1)}% success rate (${p.attempts} attempts)`
  )
  .join('\n')}

**Top Attack Patterns:**
${aggregatedData.patterns
  .slice(0, 10)
  .map(
    p =>
      `- ${p.pattern}: ${p.count} occurrences (${p.severity} severity)\n  Examples: ${p.examples.join(', ')}`
  )
  .join('\n')}

**Top Attacking IPs:**
${aggregatedData.topIPs.map(ip => `- ${ip.ip}: ${ip.count} attempts`).join('\n')}

## Your Task

Generate actionable security recommendations that fit into the platform's feedback loop. Each recommendation MUST:
1. Be categorized into exactly one phase: BUILD, DEFEND, or LEARN
2. Include specific context explaining WHY this recommendation is being made based on the analyzed threat data
3. Have a priority level (HIGH/MEDIUM/LOW) based on severity and impact

**Phase Guidelines:**
- **BUILD recommendations**: Code changes, input validation, secure coding patterns to include in future API generations
- **DEFEND recommendations**: Honeypot configurations, rate limiting, blocking rules, detection improvements
- **LEARN recommendations**: Additional monitoring, pattern analysis, threat intelligence improvements

Respond with valid JSON in this exact format:
{
  "summary": "2-3 sentence overview of threat landscape and key insights",
  "recommendations": [
    {
      "id": "rec-1",
      "recommendation": "Specific actionable recommendation",
      "phase": "BUILD|DEFEND|LEARN",
      "context": "Explanation of why this is recommended based on the threat data",
      "priority": "HIGH|MEDIUM|LOW",
      "affectedEndpoints": ["/path1", "/path2"],
      "relatedPatterns": ["pattern1", "pattern2"]
    }
  ],
  "trends": ["trend observation 1", "trend observation 2"]
}

Generate 5-8 recommendations with a good mix across all three phases.`;

    logInfo('Generating AI insights with phase categorization', {
      totalThreats: aggregatedData.totalThreats,
      patternsCount: aggregatedData.patterns.length,
    });

    const openai = getOpenAIClient();
    const completion = await openai.chat.completions.create({
      model: 'gpt-4',
      messages: [
        {
          role: 'system',
          content:
            'You are a cybersecurity expert specializing in threat intelligence, API security, and the BUILD->DEFEND->LEARN security feedback loop. Always respond with valid JSON.',
        },
        {
          role: 'user',
          content: prompt,
        },
      ],
      temperature: 0.3,
      max_tokens: 2000,
      response_format: { type: 'json_object' },
    });

    const responseText = completion.choices[0]?.message?.content || '{}';

    // Parse AI response
    let aiInsights: {
      summary: string;
      recommendations: ActionableRecommendation[];
      trends: string[];
    };

    try {
      aiInsights = JSON.parse(responseText);

      // Ensure all recommendations have required fields
      aiInsights.recommendations = (aiInsights.recommendations || []).map(
        (rec, idx) => ({
          id: rec.id || `rec-${idx + 1}`,
          recommendation: rec.recommendation || 'Review security configuration',
          phase: (['BUILD', 'DEFEND', 'LEARN'].includes(rec.phase)
            ? rec.phase
            : 'DEFEND') as PlatformPhase,
          context: rec.context || 'Based on observed threat patterns',
          priority: (['HIGH', 'MEDIUM', 'LOW'].includes(rec.priority)
            ? rec.priority
            : 'MEDIUM') as 'HIGH' | 'MEDIUM' | 'LOW',
          affectedEndpoints: rec.affectedEndpoints || [],
          relatedPatterns: rec.relatedPatterns || [],
        })
      );
    } catch {
      // Fallback if AI didn't return valid JSON
      logWarn('AI response was not valid JSON, using fallback parsing');
      aiInsights = {
        summary:
          'Threat analysis completed. Review recommendations for security improvements.',
        recommendations: [
          {
            id: 'rec-1',
            recommendation:
              'Implement strict input validation on all API endpoints',
            phase: 'BUILD' as PlatformPhase,
            context: 'Multiple injection attempts detected in threat data',
            priority: 'HIGH' as const,
            affectedEndpoints: aggregatedData.testResults.topVulnerablePaths
              .slice(0, 3)
              .map(p => p.path),
            relatedPatterns: aggregatedData.patterns
              .slice(0, 2)
              .map(p => p.pattern),
          },
          {
            id: 'rec-2',
            recommendation:
              'Configure rate limiting to prevent brute-force attacks',
            phase: 'DEFEND' as PlatformPhase,
            context: `High volume of attempts from ${aggregatedData.topIPs.length} unique IPs detected`,
            priority: 'HIGH' as const,
            affectedEndpoints: ['/api/auth', '/api/login'],
            relatedPatterns: ['brute-force', 'credential-stuffing'],
          },
          {
            id: 'rec-3',
            recommendation: 'Expand honeypot coverage to additional endpoints',
            phase: 'LEARN' as PlatformPhase,
            context:
              'Current coverage may be missing attack vectors on unmonitored paths',
            priority: 'MEDIUM' as const,
            affectedEndpoints: [],
            relatedPatterns: [],
          },
        ],
        trends: [
          'Automated scanning tools detected',
          'Common attack patterns observed',
        ],
      };
    }

    // Categorize recommendations by phase
    const phaseBreakdown = {
      BUILD: aiInsights.recommendations.filter(r => r.phase === 'BUILD'),
      DEFEND: aiInsights.recommendations.filter(r => r.phase === 'DEFEND'),
      LEARN: aiInsights.recommendations.filter(r => r.phase === 'LEARN'),
    };

    // Store insight in database
    const insight = await prisma.flywheelInsight.create({
      data: {
        apiProjectId,
        type: InsightType.VULNERABILITY_TREND,
        summary: aiInsights.summary,
        details: JSON.parse(
          JSON.stringify({
            totalThreats: aggregatedData.totalThreats,
            criticalThreats: aggregatedData.criticalThreats,
            topPatterns: aggregatedData.patterns.slice(0, 10),
            topIPs: aggregatedData.topIPs,
            testResults: aggregatedData.testResults,
            recommendations: aiInsights.recommendations,
            trends: aiInsights.trends,
            phaseBreakdown,
            timeRange: {
              start: aggregatedData.timeRange.start.toISOString(),
              end: aggregatedData.timeRange.end.toISOString(),
            },
          })
        ),
        modelVersion: completion.model,
        confidence: 0.85,
      },
    });

    logInfo('Generated and stored flywheel insight with phase categorization', {
      insightId: insight.id,
      apiProjectId,
      totalThreats: aggregatedData.totalThreats,
      recommendationsByPhase: {
        BUILD: phaseBreakdown.BUILD.length,
        DEFEND: phaseBreakdown.DEFEND.length,
        LEARN: phaseBreakdown.LEARN.length,
      },
    });

    return {
      id: insight.id,
      summary: aiInsights.summary,
      details: {
        totalThreats: aggregatedData.totalThreats,
        criticalThreats: aggregatedData.criticalThreats,
        topPatterns: aggregatedData.patterns.slice(0, 10),
        topIPs: aggregatedData.topIPs,
        testResults: aggregatedData.testResults,
        recommendations: aiInsights.recommendations,
        trends: aiInsights.trends,
        phaseBreakdown,
      },
      confidence: 0.85,
      modelVersion: completion.model,
    };
  } catch (error) {
    logError('Failed to generate insights', { error, apiProjectId });
    throw error;
  }
}

/**
 * Get stored insights for an API project or owner
 */
export async function getInsights(
  filters: { apiProjectId?: string; ownerId?: string },
  limit: number = 10
) {
  try {
     
    const where: any = {};

    if (filters.apiProjectId) {
      where.apiProjectId = filters.apiProjectId;
    }

    if (filters.ownerId) {
      where.apiProject = {
        createdById: filters.ownerId,
      };
    }

    const insights = await prisma.flywheelInsight.findMany({
      where,
      include: {
        apiProject: {
          select: {
            id: true,
            name: true,
            slug: true,
          },
        },
      },
      orderBy: {
        generatedAt: 'desc',
      },
      take: limit,
    });

    return insights;
  } catch (error) {
    logError('Failed to get insights', { error, filters });
    throw error;
  }
}

/**
 * Trigger insight generation for all API projects with honeypots
 */
export async function generateInsightsForAllProjects(): Promise<{
  success: number;
  failed: number;
  results: Array<{
    projectId: string;
    status: 'success' | 'failed';
    error?: string;
  }>;
}> {
  try {
    // Get all API projects that have honeypots with threat data
    const projects = await prisma.apiProject.findMany({
      where: {
        honeypots: {
          some: {},
        },
      },
      select: {
        id: true,
        name: true,
      },
    });

    logInfo('Generating insights for all projects', {
      projectCount: projects.length,
    });

    const results: Array<{
      projectId: string;
      status: 'success' | 'failed';
      error?: string;
    }> = [];
    let success = 0;
    let failed = 0;

    for (const project of projects) {
      try {
        const aggregatedData = await aggregateThreatData({
          apiProjectId: project.id,
        });

        if (aggregatedData.totalThreats > 0) {
          await generateInsights(aggregatedData, project.id);
          results.push({ projectId: project.id, status: 'success' });
          success++;
        } else {
          results.push({
            projectId: project.id,
            status: 'failed',
            error: 'No threat data available',
          });
          failed++;
        }
      } catch (error) {
        logError('Failed to generate insights for project', {
          projectId: project.id,
          error,
        });
        results.push({
          projectId: project.id,
          status: 'failed',
          error: error instanceof Error ? error.message : 'Unknown error',
        });
        failed++;
      }
    }

    logInfo('Completed insight generation for all projects', {
      success,
      failed,
    });

    return { success, failed, results };
  } catch (error) {
    logError('Failed to generate insights for all projects', { error });
    throw error;
  }
}

/**
 * Fetch recent BUILD-phase insights for use in API generation
 * This closes the feedback loop: LEARN insights enhance BUILD security
 */
export async function getBuildPhaseInsights(
  userId: string,
  options?: {
    maxInsights?: number;
    maxAgeInDays?: number;
  }
): Promise<{
  securityRecommendations: string[];
  threatPatterns: string[];
  vulnerableEndpoints: string[];
}> {
  const maxInsights = options?.maxInsights ?? 5;
  const maxAgeInDays = options?.maxAgeInDays ?? 30;

  const startDate = new Date();
  startDate.setDate(startDate.getDate() - maxAgeInDays);

  try {
    // Fetch recent insights for user's projects
    const insights = await prisma.flywheelInsight.findMany({
      where: {
        apiProject: {
          createdById: userId,
        },
        generatedAt: {
          gte: startDate,
        },
        // Focus on insights with actionable recommendations
        type: {
          in: [InsightType.VULNERABILITY_TREND, InsightType.ATTACK_PATTERN],
        },
      },
      orderBy: {
        generatedAt: 'desc',
      },
      take: maxInsights * 2, // Fetch extra to filter
      select: {
        details: true,
        summary: true,
        type: true,
        confidence: true,
      },
    });

    const securityRecommendations: Set<string> = new Set();
    const threatPatterns: Set<string> = new Set();
    const vulnerableEndpoints: Set<string> = new Set();

    for (const insight of insights) {
      // Parse details JSON
      const details = insight.details as {
        recommendations?: ActionableRecommendation[];
        topPatterns?: ThreatPattern[];
        phaseBreakdown?: {
          BUILD?: ActionableRecommendation[];
        };
      } | null;

      if (!details) continue;

      // Extract BUILD-phase recommendations specifically
      const buildRecommendations = details.phaseBreakdown?.BUILD || [];
      for (const rec of buildRecommendations) {
        if (rec.priority === 'HIGH' || rec.priority === 'MEDIUM') {
          securityRecommendations.add(rec.recommendation);
          if (rec.affectedEndpoints) {
            rec.affectedEndpoints.forEach(ep => vulnerableEndpoints.add(ep));
          }
        }
      }

      // Also include high-priority general recommendations
      const generalRecs = details.recommendations || [];
      for (const rec of generalRecs) {
        if (rec.phase === 'BUILD' && rec.priority === 'HIGH') {
          securityRecommendations.add(rec.recommendation);
        }
      }

      // Extract threat patterns
      const patterns = details.topPatterns || [];
      for (const pattern of patterns) {
        if (pattern.severity === 'critical' || pattern.severity === 'high') {
          threatPatterns.add(`${pattern.pattern} (${pattern.severity})`);
        }
      }
    }

    logInfo('Fetched BUILD phase insights for API generation', {
      userId,
      insightsFound: insights.length,
      recommendationsExtracted: securityRecommendations.size,
      patternsExtracted: threatPatterns.size,
      endpointsIdentified: vulnerableEndpoints.size,
    });

    return {
      securityRecommendations: Array.from(securityRecommendations).slice(
        0,
        maxInsights
      ),
      threatPatterns: Array.from(threatPatterns).slice(0, maxInsights),
      vulnerableEndpoints: Array.from(vulnerableEndpoints).slice(0, 10),
    };
  } catch (error) {
    logWarn('Failed to fetch BUILD phase insights, continuing without them', {
      userId,
      error: error instanceof Error ? error.message : 'Unknown error',
    });

    // Return empty arrays on error - don't block API generation
    return {
      securityRecommendations: [],
      threatPatterns: [],
      vulnerableEndpoints: [],
    };
  }
}
