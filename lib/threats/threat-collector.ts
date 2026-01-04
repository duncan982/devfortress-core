/**
 * Threat data collector
 * Collects and processes attack data from honeypots
 */

import { PrismaClient, ThreatSeverity } from '@prisma/client';
import { logInfo, logError, logWarn } from '../logger';
import { threatFeedsService } from './threat-feeds';

const prisma = new PrismaClient();

/**
 * Attack data interface for incoming threats
 */
export interface AttackData {
  honeypotId: string;
  sourceIp: string;
  userAgent?: string;
  method?: string;
  path?: string;
  headers?: Record<string, string>;
  query?: Record<string, string>;
  body?: unknown;
  timestamp: Date;
  detectedPatterns?: string[];
}

/**
 * Threat analysis result
 */
export interface ThreatAnalysis {
  severity: ThreatSeverity;
  tags: string[];
  payload: Record<string, unknown>;
  confidence: number;
}

/**
 * Analyze attack data and determine severity
 */
export async function analyzeAttackData(
  data: AttackData
): Promise<ThreatAnalysis> {
  const tags: string[] = [];
  let severity: ThreatSeverity = ThreatSeverity.LOW;
  let confidence = 0.5;

  // Check for Vercel/AWS deployment health checks (not real attacks)
  // These IPs are from Vercel's infrastructure checking deployment health
  const vercelAwsIpRanges = [
    /^54\.(193|219|183|176|177|241|67|68)\./, // AWS US regions used by Vercel
    /^35\.(167|155|161|162)\./, // AWS US West
    /^52\.(8|9|10|11|24|25|26|27)\./, // AWS various
  ];

  const isVercelHealthCheck =
    data.path === '/' &&
    data.method === 'GET' &&
    vercelAwsIpRanges.some(range => range.test(data.sourceIp));

  if (isVercelHealthCheck) {
    tags.push('deployment-health-check');
    return {
      severity: ThreatSeverity.LOW,
      tags,
      payload: {
        method: data.method,
        path: data.path,
        headers: data.headers,
        query: data.query,
        body: data.body,
        userAgent: data.userAgent,
        note: 'Vercel deployment health check - not a real attack',
      },
      confidence: 0.95,
    };
  }

  // Check if this is a test request (from our test button)
  const isTestRequest =
    data.body &&
    typeof data.body === 'object' &&
    'isTest' in data.body &&
    (data.body as Record<string, unknown>).isTest === true;

  if (isTestRequest) {
    tags.push('test-attack');
  }

  // Pattern detection - separate text sources for different checks
  // Headers contain normal chars like ; | > < that trigger false positives
  const pathQueryBodyText = JSON.stringify({
    path: data.path,
    query: data.query,
    body: data.body,
  }).toLowerCase();

  // Full combined text for patterns that are less likely to false positive on headers
  const combinedText = JSON.stringify({
    path: data.path,
    query: data.query,
    body: data.body,
    headers: data.headers,
  }).toLowerCase();

  // SQL Injection patterns - check everywhere
  if (
    /(\bunion\b.*\bselect\b|select.*from|insert\s+into|delete\s+from|drop\s+table|exec\s*\()/i.test(
      combinedText
    )
  ) {
    tags.push('sql-injection');
    severity = ThreatSeverity.HIGH;
    confidence = 0.8;
  }

  // XSS patterns - check everywhere
  if (
    /(<script|javascript:|onerror=|onload=|eval\s*\(|alert\s*\()/i.test(
      combinedText
    )
  ) {
    tags.push('xss');
    severity = ThreatSeverity.HIGH;
    confidence = 0.85;
  }

  // Command injection patterns - ONLY check path, query, body (not headers)
  // Headers contain normal chars like ; | > < in cookies, forwarded, etc.
  if (/(\||;|`|\$\(|&&|>|<|\n|\r)/i.test(pathQueryBodyText)) {
    tags.push('command-injection');
    severity = ThreatSeverity.CRITICAL;
    confidence = 0.75;
  }

  // Path traversal patterns - check everywhere
  if (
    /(\.\.\/|\.\.\\|%2e%2e|etc\/passwd|windows\/system32)/i.test(combinedText)
  ) {
    tags.push('path-traversal');
    severity = ThreatSeverity.HIGH;
    confidence = 0.8;
  }

  // Authentication bypass patterns - only match suspicious access patterns, not just the word "admin"
  // Check for actual bypass attempts like accessing admin paths with bypass techniques
  const authBypassPatterns = [
    /' or '1'='1/i,
    /' or 1=1/i,
    /always\s+true/i,
    /\/admin\/(login|bypass|backdoor)/i, // Suspicious admin paths
    /admin['"]?\s*[:=]/i, // admin: or admin= in body
    /\broot\b.*\bpassword/i, // root password attempts
    /\bsu\s+root\b/i, // su root command
  ];

  for (const pattern of authBypassPatterns) {
    if (pattern.test(pathQueryBodyText)) {
      tags.push('auth-bypass');
      severity = ThreatSeverity.CRITICAL;
      confidence = 0.7;
      break;
    }
  }

  // Simple /admin path access is MEDIUM, not CRITICAL (common reconnaissance)
  if (data.path && /^\/admin\/?$/i.test(data.path)) {
    if (!tags.includes('auth-bypass')) {
      tags.push('admin-access-attempt');
      if (severity === ThreatSeverity.LOW) {
        severity = ThreatSeverity.MEDIUM;
      }
      confidence = 0.6;
    }
  }

  // SSRF patterns
  if (
    /(localhost|127\.0\.0\.1|169\.254|metadata\.google)/i.test(combinedText)
  ) {
    tags.push('ssrf');
    severity = ThreatSeverity.HIGH;
    confidence = 0.75;
  }

  // XXE patterns
  if (/(<!DOCTYPE|<!ENTITY|SYSTEM|PUBLIC)/i.test(combinedText)) {
    tags.push('xxe');
    severity = ThreatSeverity.HIGH;
    confidence = 0.8;
  }

  // Suspicious user agents
  if (data.userAgent) {
    const suspiciousAgents = [
      'sqlmap',
      'nikto',
      'nmap',
      'masscan',
      'metasploit',
      'burp',
      'zap',
      'w3af',
      'acunetix',
    ];
    if (
      suspiciousAgents.some(agent =>
        data.userAgent!.toLowerCase().includes(agent)
      )
    ) {
      tags.push('security-scanner');
      severity = ThreatSeverity.MEDIUM;
      confidence = 0.9;
    }
  }

  // Detect detected patterns from input
  if (data.detectedPatterns && data.detectedPatterns.length > 0) {
    tags.push(...data.detectedPatterns);
  }

  // If no specific patterns detected, mark as reconnaissance
  if (tags.length === 0) {
    tags.push('reconnaissance');
    severity = ThreatSeverity.LOW;
    confidence = 0.6;
  }

  // Check against threat feeds
  try {
    const feedResults = await threatFeedsService.checkAgainstFeeds(
      data.sourceIp,
      'ip'
    );
    if (feedResults.length > 0) {
      const highestSeverity = feedResults.reduce((max, entry) => {
        const severityOrder = { low: 1, medium: 2, high: 3, critical: 4 };
        return severityOrder[entry.severity] > severityOrder[max.severity]
          ? entry
          : max;
      });

      tags.push('threat-feed-match');
      tags.push(...highestSeverity.tags);
      if (
        highestSeverity.severity === 'critical' ||
        highestSeverity.severity === 'high'
      ) {
        severity = ThreatSeverity.HIGH;
      } else if (
        highestSeverity.severity === 'medium' &&
        severity === ThreatSeverity.LOW
      ) {
        severity = ThreatSeverity.MEDIUM;
      }
      confidence = Math.max(confidence, highestSeverity.confidence);
    }
  } catch (error) {
    logError('Error checking threat feeds', { error, sourceIp: data.sourceIp });
  }

  // Build payload for storage
  const payload: Record<string, unknown> = {
    method: data.method,
    path: data.path,
    headers: data.headers,
    query: data.query,
    body: data.body,
    userAgent: data.userAgent,
  };

  return {
    severity,
    tags,
    payload,
    confidence,
  };
}

/**
 * Log threat event to database
 */
export async function logThreatEvent(data: AttackData): Promise<string> {
  logInfo('logThreatEvent called', {
    honeypotId: data.honeypotId,
    sourceIp: data.sourceIp,
    path: data.path,
    method: data.method,
  });

  try {
    // Validate honeypot exists
    logInfo('Looking up honeypot in database', { honeypotId: data.honeypotId });
    const honeypot = await prisma.honeypot.findUnique({
      where: { id: data.honeypotId },
      select: { id: true, name: true, apiProjectId: true },
    });

    if (!honeypot) {
      logError('Honeypot not found for threat event', {
        honeypotId: data.honeypotId,
      });
      throw new Error('Honeypot not found');
    }

    logInfo('Honeypot found, analyzing attack', {
      honeypotId: data.honeypotId,
      honeypotName: honeypot.name,
    });

    // Analyze the attack
    const analysis = await analyzeAttackData(data);

    logInfo('Attack analyzed, creating threat event', {
      honeypotId: data.honeypotId,
      severity: analysis.severity,
      tags: analysis.tags,
    });

    // Create threat event
    const threatEvent = await prisma.threatEvent.create({
      data: {
        honeypotId: data.honeypotId,
        apiProjectId: honeypot.apiProjectId || undefined,
        sourceIp: data.sourceIp,
        userAgent: data.userAgent,
        payload: analysis.payload as never,
        detectedAt: data.timestamp,
        severity: analysis.severity,
        tags: analysis.tags,
        isFalsePositive: false,
      },
    });

    logInfo('Threat event created successfully', {
      threatEventId: threatEvent.id,
      honeypotId: data.honeypotId,
      honeypotName: honeypot.name,
      sourceIp: data.sourceIp,
      severity: analysis.severity,
      tags: analysis.tags,
      confidence: analysis.confidence,
    });

    // Log warning for high/critical threats
    if (
      analysis.severity === ThreatSeverity.HIGH ||
      analysis.severity === ThreatSeverity.CRITICAL
    ) {
      logWarn('High severity threat detected', {
        threatEventId: threatEvent.id,
        honeypotId: data.honeypotId,
        sourceIp: data.sourceIp,
        severity: analysis.severity,
        tags: analysis.tags,
      });
    }

    return threatEvent.id;
  } catch (error) {
    logError('Failed to log threat event', { error, data });
    throw error;
  }
}

/**
 * Aggregate threat data for a honeypot
 */
export interface ThreatAggregation {
  totalEvents: number;
  uniqueIPs: number;
  severityDistribution: Record<ThreatSeverity, number>;
  patternDistribution: Record<string, number>;
  topAttackIPs: Array<{ ip: string; count: number; severity: ThreatSeverity }>;
  recentTrends: Array<{
    date: string;
    count: number;
    severity: ThreatSeverity;
  }>;
}

/**
 * Aggregate threat data for analysis
 */
export async function aggregateThreatData(
  honeypotId: string,
  startDate?: Date,
  endDate?: Date
): Promise<ThreatAggregation> {
  try {
     
    const where: any = { honeypotId };

    if (startDate || endDate) {
      where.detectedAt = {};
      if (startDate) where.detectedAt.gte = startDate;
      if (endDate) where.detectedAt.lte = endDate;
    }

    // Total events
    const totalEvents = await prisma.threatEvent.count({ where });

    // Unique IPs
    const uniqueIPsResult = await prisma.threatEvent.findMany({
      where,
      select: { sourceIp: true },
      distinct: ['sourceIp'],
    });
    const uniqueIPs = uniqueIPsResult.length;

    // Severity distribution
    const severityGroups = await prisma.threatEvent.groupBy({
      by: ['severity'],
      where,
      _count: { id: true },
    });

    const severityDistribution: Record<ThreatSeverity, number> = {
      LOW: 0,
      MEDIUM: 0,
      HIGH: 0,
      CRITICAL: 0,
    };

    severityGroups.forEach(group => {
      severityDistribution[group.severity] = group._count.id;
    });

    // Pattern distribution
    const events = await prisma.threatEvent.findMany({
      where,
      select: { tags: true },
    });

    const patternDistribution: Record<string, number> = {};
    events.forEach(event => {
      if (event.tags && Array.isArray(event.tags)) {
        event.tags.forEach((tag: string) => {
          patternDistribution[tag] = (patternDistribution[tag] || 0) + 1;
        });
      }
    });

    // Top attack IPs
    const ipEvents = await prisma.threatEvent.findMany({
      where,
      select: { sourceIp: true, severity: true },
    });

    const ipCounts: Record<
      string,
      { count: number; maxSeverity: ThreatSeverity }
    > = {};
    ipEvents.forEach(event => {
      if (!ipCounts[event.sourceIp]) {
        ipCounts[event.sourceIp] = { count: 0, maxSeverity: event.severity };
      }
      ipCounts[event.sourceIp].count++;
      // Track highest severity for this IP
      const severityLevels = {
        LOW: 1,
        MEDIUM: 2,
        HIGH: 3,
        CRITICAL: 4,
      };
      if (
        severityLevels[event.severity] >
        severityLevels[ipCounts[event.sourceIp].maxSeverity]
      ) {
        ipCounts[event.sourceIp].maxSeverity = event.severity;
      }
    });

    const topAttackIPs = Object.entries(ipCounts)
      .map(([ip, data]) => ({
        ip,
        count: data.count,
        severity: data.maxSeverity,
      }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);

    // Recent trends (last 7 days by default)
    const trendStartDate =
      startDate || new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
    const trendEndDate = endDate || new Date();

    const trendEvents = await prisma.threatEvent.findMany({
      where: {
        honeypotId,
        detectedAt: {
          gte: trendStartDate,
          lte: trendEndDate,
        },
      },
      select: {
        detectedAt: true,
        severity: true,
      },
      orderBy: {
        detectedAt: 'asc',
      },
    });

    // Group by date
    const trendMap: Record<
      string,
      { count: number; severity: ThreatSeverity }
    > = {};
    trendEvents.forEach(event => {
      const dateKey = event.detectedAt.toISOString().split('T')[0];
      if (!trendMap[dateKey]) {
        trendMap[dateKey] = { count: 0, severity: ThreatSeverity.LOW };
      }
      trendMap[dateKey].count++;
      // Track highest severity for the day
      const severityLevels = {
        LOW: 1,
        MEDIUM: 2,
        HIGH: 3,
        CRITICAL: 4,
      };
      if (
        severityLevels[event.severity] >
        severityLevels[trendMap[dateKey].severity]
      ) {
        trendMap[dateKey].severity = event.severity;
      }
    });

    const recentTrends = Object.entries(trendMap).map(([date, data]) => ({
      date,
      count: data.count,
      severity: data.severity,
    }));

    logInfo('Threat data aggregated', {
      honeypotId,
      totalEvents,
      uniqueIPs,
      startDate,
      endDate,
    });

    return {
      totalEvents,
      uniqueIPs,
      severityDistribution,
      patternDistribution,
      topAttackIPs,
      recentTrends,
    };
  } catch (error) {
    logError('Failed to aggregate threat data', { error, honeypotId });
    throw error;
  }
}

/**
 * Get threat data for team dashboard
 */
export async function getTeamThreatData(
  teamId: string,
  startDate?: Date,
  endDate?: Date
) {
  try {
    // Get all honeypots for the team
    const honeypots = await prisma.honeypot.findMany({
      where: { teamId },
      select: { id: true, name: true },
    });

    // Aggregate data for each honeypot
    const aggregations = await Promise.all(
      honeypots.map(async honeypot => ({
        honeypotId: honeypot.id,
        honeypotName: honeypot.name,
        data: await aggregateThreatData(honeypot.id, startDate, endDate),
      }))
    );

    // Combine aggregations
    const combined: ThreatAggregation = {
      totalEvents: 0,
      uniqueIPs: 0,
      severityDistribution: {
        LOW: 0,
        MEDIUM: 0,
        HIGH: 0,
        CRITICAL: 0,
      },
      patternDistribution: {},
      topAttackIPs: [],
      recentTrends: [],
    };

    const uniqueIPsSet = new Set<string>();
    const allTopIPs: Array<{
      ip: string;
      count: number;
      severity: ThreatSeverity;
    }> = [];

    aggregations.forEach(agg => {
      combined.totalEvents += agg.data.totalEvents;

      // Track unique IPs
      agg.data.topAttackIPs.forEach(ipData => {
        uniqueIPsSet.add(ipData.ip);
        allTopIPs.push(ipData);
      });

      // Combine severity distributions
      Object.entries(agg.data.severityDistribution).forEach(
        ([severity, count]) => {
          combined.severityDistribution[severity as ThreatSeverity] += count;
        }
      );

      // Combine pattern distributions
      Object.entries(agg.data.patternDistribution).forEach(
        ([pattern, count]) => {
          combined.patternDistribution[pattern] =
            (combined.patternDistribution[pattern] || 0) + count;
        }
      );
    });

    combined.uniqueIPs = uniqueIPsSet.size;

    // Consolidate top IPs
    const ipMap: Record<string, { count: number; severity: ThreatSeverity }> =
      {};
    allTopIPs.forEach(item => {
      if (!ipMap[item.ip]) {
        ipMap[item.ip] = { count: 0, severity: item.severity };
      }
      ipMap[item.ip].count += item.count;

      // Keep highest severity
      const severityLevels = { LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };
      if (
        severityLevels[item.severity] > severityLevels[ipMap[item.ip].severity]
      ) {
        ipMap[item.ip].severity = item.severity;
      }
    });

    combined.topAttackIPs = Object.entries(ipMap)
      .map(([ip, data]) => ({ ip, count: data.count, severity: data.severity }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);

    logInfo('Team threat data aggregated', {
      teamId,
      totalEvents: combined.totalEvents,
      uniqueIPs: combined.uniqueIPs,
    });

    return {
      teamId,
      honeypots: aggregations,
      combined,
    };
  } catch (error) {
    logError('Failed to get team threat data', { error, teamId });
    throw error;
  }
}
