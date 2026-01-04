/**
 * Threat Intelligence Feeds Integration
 * Integrates with open-source threat intelligence feeds for enhanced honeypot protection
 */

import { config } from 'dotenv';
import { join } from 'path';
import { existsSync } from 'fs';
import { logError, logWarn } from '../logger';
import { cache } from '../cache';

// Load .env.local for standalone mode
const envLocalPath = join(process.cwd(), '.env.local');
const envLocalParentPath = join(process.cwd(), '../.env.local');

if (existsSync(envLocalPath)) {
  config({ path: envLocalPath, override: true });
} else if (existsSync(envLocalParentPath)) {
  config({ path: envLocalParentPath, override: true });
}

export interface ThreatFeedEntry {
  type: 'ip' | 'domain' | 'pattern' | 'botnet' | 'scanner';
  value: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  source: string;
  lastSeen: Date;
  confidence: number;
  tags: string[];
  metadata?: Record<string, unknown>;
}

export interface ThreatFeedResult {
  entries: ThreatFeedEntry[];
  lastUpdated: Date;
  source: string;
}

class ThreatFeedsService {
  private readonly CACHE_TTL = 3600000; // 1 hour
  private readonly ABUSEIPDB_API_KEY = process.env.ABUSEIPDB_API_KEY;
  private readonly ABUSEIPDB_BASE_URL = 'https://api.abuseipdb.com/api/v2';

  /**
   * Check if an IP is malicious using AbuseIPDB
   */
  async checkAbuseIPDB(ip: string): Promise<ThreatFeedEntry | null> {
    const cacheKey = `abuseipdb:${ip}`;

    // Check cache first
    const cached = await cache.get<ThreatFeedEntry>(cacheKey);
    if (cached) {
      return cached;
    }

    if (!this.ABUSEIPDB_API_KEY) {
      logWarn('AbuseIPDB API key not configured, skipping IP check');
      return null;
    }

    try {
      const response = await fetch(`${this.ABUSEIPDB_BASE_URL}/check`, {
        method: 'GET',
        headers: {
          Key: this.ABUSEIPDB_API_KEY,
          Accept: 'application/json',
        },
        body: new URLSearchParams({
          ipAddress: ip,
          maxAgeInDays: '90',
        }),
      });

      if (!response.ok) {
        throw new Error(`AbuseIPDB API error: ${response.status}`);
      }

      const data = await response.json();

      if (data.data.abuseConfidenceScore > 50) {
        const entry: ThreatFeedEntry = {
          type: 'ip',
          value: ip,
          severity: data.data.abuseConfidenceScore > 80 ? 'high' : 'medium',
          source: 'AbuseIPDB',
          lastSeen: new Date(data.data.lastReportedAt || Date.now()),
          confidence: data.data.abuseConfidenceScore / 100,
          tags: data.data.category || [],
        };

        // Cache for 1 hour
        await cache.set(cacheKey, entry, this.CACHE_TTL);

        return entry;
      }

      // Cache negative result for shorter time
      await cache.set(cacheKey, null, 1800000); // 30 min
      return null;
    } catch (error) {
      logError('Error checking AbuseIPDB', { ip, error });
      return null;
    }
  }

  /**
   * Get Emerging Threats rules (simplified - in practice would parse ET rules)
   * For demo purposes, return some common patterns
   */
  async getEmergingThreatsPatterns(): Promise<ThreatFeedEntry[]> {
    const cacheKey = 'emerging-threats:patterns';

    const cached = await cache.get<ThreatFeedEntry[]>(cacheKey);
    if (cached) {
      return cached;
    }

    // Simplified: return some common malicious patterns
    const patterns: ThreatFeedEntry[] = [
      {
        type: 'pattern',
        value: '/wp-admin/admin-ajax.php',
        severity: 'medium',
        source: 'Emerging Threats',
        lastSeen: new Date(),
        confidence: 0.7,
        tags: ['wordpress', 'brute-force'],
      },
      {
        type: 'pattern',
        value: '/.env',
        severity: 'high',
        source: 'Emerging Threats',
        lastSeen: new Date(),
        confidence: 0.9,
        tags: ['config-leak'],
      },
      {
        type: 'pattern',
        value: '/phpmyadmin/',
        severity: 'medium',
        source: 'Emerging Threats',
        lastSeen: new Date(),
        confidence: 0.6,
        tags: ['database-admin'],
      },
      {
        type: 'pattern',
        value: '/api/v1/admin',
        severity: 'high',
        source: 'Emerging Threats',
        lastSeen: new Date(),
        confidence: 0.8,
        tags: ['admin-access', 'reconnaissance'],
      },
      {
        type: 'pattern',
        value: '/../',
        severity: 'critical',
        source: 'Emerging Threats',
        lastSeen: new Date(),
        confidence: 0.95,
        tags: ['path-traversal', 'exploit'],
      },
      {
        type: 'scanner',
        value: 'sqlmap',
        severity: 'high',
        source: 'Emerging Threats',
        lastSeen: new Date(),
        confidence: 0.9,
        tags: ['sql-injection', 'automated-scanner'],
      },
      {
        type: 'scanner',
        value: 'nikto',
        severity: 'medium',
        source: 'Emerging Threats',
        lastSeen: new Date(),
        confidence: 0.85,
        tags: ['vulnerability-scanner', 'reconnaissance'],
      },
    ];

    await cache.set(cacheKey, patterns, this.CACHE_TTL);
    return patterns;
  }

  /**
   * Check user agent for known scanning tools and bots
   */
  async checkUserAgent(userAgent: string): Promise<ThreatFeedEntry | null> {
    const patterns = await this.getEmergingThreatsPatterns();
    const lowerUA = userAgent.toLowerCase();

    for (const pattern of patterns) {
      if (
        pattern.type === 'scanner' &&
        lowerUA.includes(pattern.value.toLowerCase())
      ) {
        return {
          ...pattern,
          metadata: { userAgent },
        };
      }
    }

    return null;
  }

  /**
   * Auto-flag and suggest blocking for suspicious patterns
   */
  async autoFlagSuspiciousActivity(params: {
    ip?: string;
    path?: string;
    userAgent?: string;
  }): Promise<{
    shouldBlock: boolean;
    threats: ThreatFeedEntry[];
    recommendation: string;
  }> {
    const threats: ThreatFeedEntry[] = [];

    // Check IP
    if (params.ip) {
      const ipThreats = await this.checkAgainstFeeds(params.ip, 'ip');
      threats.push(...ipThreats);
    }

    // Check path patterns
    if (params.path) {
      const pathThreats = await this.checkAgainstFeeds(params.path, 'pattern');
      threats.push(...pathThreats);
    }

    // Check user agent
    if (params.userAgent) {
      const uaThreat = await this.checkUserAgent(params.userAgent);
      if (uaThreat) {
        threats.push(uaThreat);
      }
    }

    // Determine if we should block
    const criticalThreats = threats.filter(t => t.severity === 'critical');
    const highThreats = threats.filter(t => t.severity === 'high');

    const shouldBlock = criticalThreats.length > 0 || highThreats.length >= 2;

    let recommendation = 'No action required';
    if (shouldBlock) {
      recommendation =
        'Immediate blocking recommended - Multiple high-severity threats detected';
    } else if (highThreats.length > 0) {
      recommendation = 'Monitor closely - High-severity threat detected';
    } else if (threats.length > 0) {
      recommendation = 'Continue monitoring - Low to medium severity threats';
    }

    return {
      shouldBlock,
      threats,
      recommendation,
    };
  }

  /**
   * Check if an IP or pattern matches known threats
   */
  async checkAgainstFeeds(
    value: string,
    type: 'ip' | 'domain' | 'pattern' = 'ip'
  ): Promise<ThreatFeedEntry[]> {
    const results: ThreatFeedEntry[] = [];

    if (type === 'ip') {
      const abuseResult = await this.checkAbuseIPDB(value);
      if (abuseResult) {
        results.push(abuseResult);
      }
    }

    // Check patterns if applicable
    if (type === 'pattern') {
      const patterns = await this.getEmergingThreatsPatterns();
      const matchingPattern = patterns.find(p => value.includes(p.value));
      if (matchingPattern) {
        results.push(matchingPattern);
      }
    }

    return results;
  }

  /**
   * Get all threat feed data
   */
  async getAllThreatData(): Promise<ThreatFeedResult[]> {
    const results: ThreatFeedResult[] = [];

    // AbuseIPDB doesn't provide bulk data in free tier
    // For demo, return patterns
    const patterns = await this.getEmergingThreatsPatterns();
    results.push({
      entries: patterns,
      lastUpdated: new Date(),
      source: 'Emerging Threats',
    });

    return results;
  }
}

export const threatFeedsService = new ThreatFeedsService();
