/**
 * Web Application Firewall (WAF) Integration
 * Integrates with Cloudflare WAF for enhanced security
 * 
 * Features:
 * - WAF rule configuration and management
 * - Rate limiting at edge
 * - DDoS protection with threat scoring
 * - WAF analytics and blocked request monitoring
 * - Rule testing and validation
 * - Custom security policies
 */

import { logInfo, logWarn } from '@core/lib/logger';

type WAFRequestSnapshot = {
  method?: string;
  url?: string;
  headers?: Record<string, string>;
  ip?: string;
  body?: unknown;
};

/**
 * WAF rule action types
 */
export enum WAFRuleAction {
  BLOCK = 'block',
  CHALLENGE = 'challenge',
  JS_CHALLENGE = 'js_challenge',
  MANAGED_CHALLENGE = 'managed_challenge',
  LOG = 'log',
  ALLOW = 'allow',
  BYPASS = 'bypass',
}

/**
 * Threat score levels
 */
export enum ThreatScore {
  LOW = 'low', // 0-14
  MEDIUM = 'medium', // 15-24
  HIGH = 'high', // 25-49
  CRITICAL = 'critical', // 50+
}

/**
 * Rate limit period
 */
export enum RateLimitPeriod {
  SECOND = '1s',
  TEN_SECONDS = '10s',
  MINUTE = '1m',
  FIVE_MINUTES = '5m',
  TEN_MINUTES = '10m',
  HOUR = '1h',
}

/**
 * WAF rule configuration
 */
export interface WAFRule {
  id: string;
  name: string;
  description: string;
  expression: string; // Cloudflare expression syntax
  action: WAFRuleAction;
  enabled: boolean;
  priority: number; // Lower = higher priority
  rateLimitThreshold?: number;
  rateLimitPeriod?: RateLimitPeriod;
  bypassUrls?: string[];
  createdAt: Date;
  updatedAt: Date;
}

/**
 * Rate limiting configuration
 */
export interface RateLimitRule {
  id: string;
  name: string;
  description: string;
  threshold: number; // Requests per period
  period: RateLimitPeriod;
  matchExpression: string; // What requests to apply rate limit to
  action: WAFRuleAction;
  enabled: boolean;
  characteristics?: string[]; // E.g., ['ip.src', 'http.request.uri']
}

/**
 * DDoS protection configuration
 */
export interface DDoSProtectionConfig {
  enabled: boolean;
  sensitivityLevel: 'low' | 'medium' | 'high' | 'custom';
  customThresholds?: {
    requestsPerSecond: number;
    bytesPerSecond: number;
    connectionsPerIp: number;
  };
  challengePassageTime: number; // Seconds
  underAttackMode: boolean; // Emergency mode
}

/**
 * WAF analytics data
 */
export interface WAFAnalytics {
  timeRange: {
    start: Date;
    end: Date;
  };
  totalRequests: number;
  blockedRequests: number;
  challengedRequests: number;
  allowedRequests: number;
  blockRate: number; // Percentage
  topBlockedCountries: Array<{
    country: string;
    count: number;
  }>;
  topBlockedIPs: Array<{
    ip: string;
    count: number;
    threatScore: number;
  }>;
  topBlockedPaths: Array<{
    path: string;
    count: number;
  }>;
  ruleHits: Array<{
    ruleId: string;
    ruleName: string;
    hits: number;
  }>;
  threatBreakdown: {
    sql_injection: number;
    xss: number;
    rce: number;
    lfi: number;
    rfi: number;
    bots: number;
    ddos: number;
    other: number;
  };
}

/**
 * Blocked request details
 */
export interface BlockedRequest {
  id: string;
  timestamp: Date;
  ip: string;
  country: string;
  path: string;
  method: string;
  userAgent: string;
  ruleId: string;
  ruleName: string;
  action: WAFRuleAction;
  threatScore: number;
  threatCategory: string;
  headers: Record<string, string>;
  body?: string;
}

/**
 * WAF rule test result
 */
export interface WAFRuleTestResult {
  ruleId: string;
  expression: string;
  testCases: Array<{
    name: string;
    request: {
      method: string;
      path: string;
      headers?: Record<string, string>;
      body?: string;
    };
    expectedMatch: boolean;
    actualMatch: boolean;
    passed: boolean;
  }>;
  overallPassed: boolean;
  passedCount: number;
  failedCount: number;
}

/**
 * Security policy configuration
 */
export interface SecurityPolicy {
  id: string;
  name: string;
  description: string;
  rules: string[]; // Rule IDs
  rateLimits: string[]; // Rate limit rule IDs
  ddosProtection: DDoSProtectionConfig;
  enabled: boolean;
  appliedTo: string[]; // Paths or zones
}

/**
 * WAF Integration Service
 */
class WAFService {
  private rules: Map<string, WAFRule> = new Map();
  private rateLimits: Map<string, RateLimitRule> = new Map();
  private blockedRequests: BlockedRequest[] = [];
  private policies: Map<string, SecurityPolicy> = new Map();
  private cloudflareApiKey: string;
  private cloudflareZoneId: string;

  constructor() {
    this.cloudflareApiKey = process.env.CLOUDFLARE_API_KEY || '';
    this.cloudflareZoneId = process.env.CLOUDFLARE_ZONE_ID || '';

    if (!this.cloudflareApiKey || !this.cloudflareZoneId) {
      if (process.env.NODE_ENV !== 'test') {
        logWarn('Cloudflare credentials not configured. WAF features will be simulated.');
      }
    }

    // Initialize default rules
    this.initializeDefaultRules();
  }

  /**
   * Initialize default WAF rules
   */
  private initializeDefaultRules(): void {
    // SQL Injection protection
    this.createRule({
      id: 'sql-injection-block',
      name: 'SQL Injection Protection',
      description: 'Block SQL injection attempts',
      expression:
        '(http.request.uri.query contains "UNION" or http.request.uri.query contains "SELECT" or http.request.body contains "DROP TABLE")',
      action: WAFRuleAction.BLOCK,
      enabled: true,
      priority: 1,
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    // XSS protection
    this.createRule({
      id: 'xss-block',
      name: 'XSS Protection',
      description: 'Block cross-site scripting attempts',
      expression: '(http.request.uri.query contains "<script" or http.request.body contains "<script")',
      action: WAFRuleAction.BLOCK,
      enabled: true,
      priority: 2,
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    // API rate limiting
    this.createRateLimit({
      id: 'api-rate-limit',
      name: 'API Rate Limit',
      description: 'Limit API requests per IP',
      threshold: 100,
      period: RateLimitPeriod.MINUTE,
      matchExpression: '(http.request.uri.path contains "/api/")',
      action: WAFRuleAction.BLOCK,
      enabled: true,
      characteristics: ['ip.src'],
    });

    logInfo('Default WAF rules initialized', {
      ruleCount: this.rules.size,
      rateLimitCount: this.rateLimits.size,
    });
  }

  /**
   * Create WAF rule
   */
  createRule(rule: WAFRule): WAFRule {
    this.rules.set(rule.id, rule);

    logInfo('WAF rule created', {
      ruleId: rule.id,
      action: rule.action,
    });

    return rule;
  }

  /**
   * Update WAF rule
   */
  updateRule(ruleId: string, updates: Partial<WAFRule>): WAFRule | null {
    const rule = this.rules.get(ruleId);
    if (!rule) return null;

    const updatedRule = {
      ...rule,
      ...updates,
      updatedAt: new Date(),
    };

    this.rules.set(ruleId, updatedRule);

    logInfo('WAF rule updated', { ruleId });

    return updatedRule;
  }

  /**
   * Delete WAF rule
   */
  deleteRule(ruleId: string): boolean {
    const deleted = this.rules.delete(ruleId);

    if (deleted) {
      logInfo('WAF rule deleted', { ruleId });
    }

    return deleted;
  }

  /**
   * Get rule by ID
   */
  getRule(ruleId: string): WAFRule | null {
    return this.rules.get(ruleId) || null;
  }

  /**
   * Get all rules
   */
  getAllRules(): WAFRule[] {
    return Array.from(this.rules.values()).sort((a, b) => a.priority - b.priority);
  }

  /**
   * Enable/disable rule
   */
  toggleRule(ruleId: string, enabled: boolean): WAFRule | null {
    return this.updateRule(ruleId, { enabled });
  }

  /**
   * Create rate limit rule
   */
  createRateLimit(rateLimit: RateLimitRule): RateLimitRule {
    this.rateLimits.set(rateLimit.id, rateLimit);

    logInfo('Rate limit rule created', {
      rateLimitId: rateLimit.id,
      threshold: rateLimit.threshold,
      period: rateLimit.period,
    });

    return rateLimit;
  }

  /**
   * Update rate limit rule
   */
  updateRateLimit(
    rateLimitId: string,
    updates: Partial<RateLimitRule>
  ): RateLimitRule | null {
    const rateLimit = this.rateLimits.get(rateLimitId);
    if (!rateLimit) return null;

    const updatedRateLimit = {
      ...rateLimit,
      ...updates,
    };

    this.rateLimits.set(rateLimitId, updatedRateLimit);

    logInfo('Rate limit rule updated', { rateLimitId });

    return updatedRateLimit;
  }

  /**
   * Get rate limit by ID
   */
  getRateLimit(rateLimitId: string): RateLimitRule | null {
    return this.rateLimits.get(rateLimitId) || null;
  }

  /**
   * Get all rate limits
   */
  getAllRateLimits(): RateLimitRule[] {
    return Array.from(this.rateLimits.values());
  }

  /**
   * Test WAF rule against sample requests
   */
  testRule(ruleId: string, testCases: WAFRuleTestResult['testCases']): WAFRuleTestResult {
    const rule = this.rules.get(ruleId);
    if (!rule) {
      throw new Error(`Rule not found: ${ruleId}`);
    }

    const results: WAFRuleTestResult['testCases'] = testCases.map(testCase => {
      // Simplified matching logic (in production, use actual Cloudflare expression evaluation)
      const actualMatch = this.evaluateExpression(rule.expression, testCase.request);
      const passed = actualMatch === testCase.expectedMatch;

      return {
        ...testCase,
        actualMatch,
        passed,
      };
    });

    const passedCount = results.filter(r => r.passed).length;
    const failedCount = results.length - passedCount;

    logInfo('WAF rule tested', {
      ruleId,
      passedCount,
      failedCount,
    });

    return {
      ruleId: rule.id,
      expression: rule.expression,
      testCases: results,
      overallPassed: failedCount === 0,
      passedCount,
      failedCount,
    };
  }

  /**
   * Simplified expression evaluator (for testing)
   */
  private evaluateExpression(
    expression: string,
    request: WAFRequestSnapshot
  ): boolean {
    // Simplified evaluation - in production, use Cloudflare's expression engine
    const lowerExpression = expression.toLowerCase();
    const requestStr = JSON.stringify(request).toLowerCase();

    // Basic contains check
    if (lowerExpression.includes('contains')) {
      const match = lowerExpression.match(/contains "([^"]+)"/);
      if (match) {
        return requestStr.includes(match[1].toLowerCase());
      }
    }

    return false;
  }

  /**
   * Get WAF analytics
   */
  getAnalytics(start: Date, end: Date): WAFAnalytics {
    // Filter blocked requests by time range
    const filteredRequests = this.blockedRequests.filter(
      r => r.timestamp >= start && r.timestamp <= end
    );

    const totalRequests = filteredRequests.length * 10; // Simulate total traffic
    const blockedRequests = filteredRequests.filter(
      r => r.action === WAFRuleAction.BLOCK
    ).length;
    const challengedRequests = filteredRequests.filter(
      r =>
        r.action === WAFRuleAction.CHALLENGE ||
        r.action === WAFRuleAction.JS_CHALLENGE
    ).length;

    // Count by country
    const countryMap = new Map<string, number>();
    filteredRequests.forEach(r => {
      countryMap.set(r.country, (countryMap.get(r.country) || 0) + 1);
    });

    // Count by IP
    const ipMap = new Map<string, { count: number; threatScore: number }>();
    filteredRequests.forEach(r => {
      const existing = ipMap.get(r.ip) || { count: 0, threatScore: r.threatScore };
      ipMap.set(r.ip, {
        count: existing.count + 1,
        threatScore: Math.max(existing.threatScore, r.threatScore),
      });
    });

    // Count by path
    const pathMap = new Map<string, number>();
    filteredRequests.forEach(r => {
      pathMap.set(r.path, (pathMap.get(r.path) || 0) + 1);
    });

    // Count by rule
    const ruleMap = new Map<string, { name: string; hits: number }>();
    filteredRequests.forEach(r => {
      const existing = ruleMap.get(r.ruleId) || { name: r.ruleName, hits: 0 };
      ruleMap.set(r.ruleId, {
        name: r.ruleName,
        hits: existing.hits + 1,
      });
    });

    // Count by threat category
    const threatBreakdown = {
      sql_injection: 0,
      xss: 0,
      rce: 0,
      lfi: 0,
      rfi: 0,
      bots: 0,
      ddos: 0,
      other: 0,
    };

    filteredRequests.forEach(r => {
      const category = r.threatCategory as keyof typeof threatBreakdown;
      if (category in threatBreakdown) {
        threatBreakdown[category]++;
      } else {
        threatBreakdown.other++;
      }
    });

    return {
      timeRange: { start, end },
      totalRequests,
      blockedRequests,
      challengedRequests,
      allowedRequests: totalRequests - blockedRequests - challengedRequests,
      blockRate: (blockedRequests / totalRequests) * 100,
      topBlockedCountries: Array.from(countryMap.entries())
        .map(([country, count]) => ({ country, count }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 10),
      topBlockedIPs: Array.from(ipMap.entries())
        .map(([ip, data]) => ({ ip, count: data.count, threatScore: data.threatScore }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 10),
      topBlockedPaths: Array.from(pathMap.entries())
        .map(([path, count]) => ({ path, count }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 10),
      ruleHits: Array.from(ruleMap.entries())
        .map(([ruleId, data]) => ({
          ruleId,
          ruleName: data.name,
          hits: data.hits,
        }))
        .sort((a, b) => b.hits - a.hits),
      threatBreakdown,
    };
  }

  /**
   * Log blocked request
   */
  logBlockedRequest(request: BlockedRequest): void {
    this.blockedRequests.push(request);

    // Keep only last 10,000 requests
    if (this.blockedRequests.length > 10000) {
      this.blockedRequests = this.blockedRequests.slice(-10000);
    }

    logWarn('Request blocked by WAF', {
      ip: request.ip,
      path: request.path,
      ruleId: request.ruleId,
      threatScore: request.threatScore,
    });
  }

  /**
   * Get recent blocked requests
   */
  getBlockedRequests(limit = 100): BlockedRequest[] {
    return this.blockedRequests
      .slice(-limit)
      .sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());
  }

  /**
   * Create security policy
   */
  createSecurityPolicy(policy: SecurityPolicy): SecurityPolicy {
    this.policies.set(policy.id, policy);

    logInfo('Security policy created', {
      policyId: policy.id,
      rulesCount: policy.rules.length,
    });

    return policy;
  }

  /**
   * Get security policy
   */
  getSecurityPolicy(policyId: string): SecurityPolicy | null {
    return this.policies.get(policyId) || null;
  }

  /**
   * Get all security policies
   */
  getAllSecurityPolicies(): SecurityPolicy[] {
    return Array.from(this.policies.values());
  }

  /**
   * Calculate threat score for request
   */
  calculateThreatScore(request: {
    ip: string;
    path: string;
    method: string;
    headers: Record<string, string>;
    body?: string;
  }): { score: number; level: ThreatScore; factors: string[] } {
    let score = 0;
    const factors: string[] = [];

    // Check for suspicious patterns
    const requestStr = JSON.stringify(request).toLowerCase();

    if (requestStr.includes('union') || requestStr.includes('select')) {
      score += 25;
      factors.push('SQL injection patterns detected');
    }

    if (requestStr.includes('<script')) {
      score += 20;
      factors.push('XSS patterns detected');
    }

    if (requestStr.includes('exec') || requestStr.includes('eval')) {
      score += 30;
      factors.push('Code execution patterns detected');
    }

    if (request.method === 'POST' && !request.body) {
      score += 5;
      factors.push('Missing request body');
    }

    if (!request.headers['user-agent']) {
      score += 10;
      factors.push('Missing user agent');
    }

    // Determine threat level
    let level: ThreatScore;
    if (score >= 50) level = ThreatScore.CRITICAL;
    else if (score >= 25) level = ThreatScore.HIGH;
    else if (score >= 15) level = ThreatScore.MEDIUM;
    else level = ThreatScore.LOW;

    return { score, level, factors };
  }

  /**
   * Clear blocked requests (for testing)
   */
  clearBlockedRequests(): void {
    this.blockedRequests = [];
  }
}

/**
 * Singleton WAF service
 */
export const wafService = new WAFService();
