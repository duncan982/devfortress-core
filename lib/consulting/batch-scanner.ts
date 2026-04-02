/**
 * Batch Scanner Service
 *
 * Orchestrates parallel security scanning across multiple endpoints.
 * Combines SecureForge, Code Analyzer, and IaC Scanner results into
 * a unified report structure.
 *
 * Used by both consulting (you run for clients) and DIY (subscribers run themselves).
 */

import { logInfo, logError, logWarn } from '@core/lib/logger';
import { performSecurityScan } from '@core/lib/build/secureforge';
import { IaCScannerService } from '@core/lib/security/iac-scanner';
import type { SecurityReport } from '@core/lib/build/secureforge';
import type { IaCScanResult } from '@core/lib/security/iac-scanner';
import type { CrawlResult, DiscoveredEndpoint } from './url-crawler';
import type { SubscriptionPlan } from '@prisma/client';

// ============================================================
// Types
// ============================================================

export interface EndpointScanResult {
  endpoint: DiscoveredEndpoint;
  securityReport?: SecurityReport;
  iacScanResult?: IaCScanResult;
  responseHeaders?: Record<string, string>;
  securityHeaders: SecurityHeaderCheck;
  error?: string;
}

export interface SecurityHeaderCheck {
  hasHSTS: boolean;
  hasCSP: boolean;
  hasXFrameOptions: boolean;
  hasXContentType: boolean;
  hasReferrerPolicy: boolean;
  hasPermissionsPolicy: boolean;
  score: number; // 0-100
  missing: string[];
}

export interface BatchScanResult {
  baseUrl: string;
  crawlResult: CrawlResult;
  endpointResults: EndpointScanResult[];
  overallScore: number; // 0-100
  summary: {
    totalEndpoints: number;
    scannedEndpoints: number;
    failedEndpoints: number;
    criticalIssues: number;
    highIssues: number;
    mediumIssues: number;
    lowIssues: number;
  };
  scanDuration: number;
}

// Security headers to check
const SECURITY_HEADERS = [
  {
    header: 'strict-transport-security',
    name: 'HSTS',
    key: 'hasHSTS' as const,
  },
  { header: 'content-security-policy', name: 'CSP', key: 'hasCSP' as const },
  {
    header: 'x-frame-options',
    name: 'X-Frame-Options',
    key: 'hasXFrameOptions' as const,
  },
  {
    header: 'x-content-type-options',
    name: 'X-Content-Type-Options',
    key: 'hasXContentType' as const,
  },
  {
    header: 'referrer-policy',
    name: 'Referrer-Policy',
    key: 'hasReferrerPolicy' as const,
  },
  {
    header: 'permissions-policy',
    name: 'Permissions-Policy',
    key: 'hasPermissionsPolicy' as const,
  },
];

// ============================================================
// Main Batch Scanner
// ============================================================

export interface ScanOptions {
  /**
   * Maximum wall-clock time (ms) the scan may use.
   * When exceeded the scanner returns results collected so far.
   * Default: 25 000 ms (25 s).
   */
  timeBudgetMs?: number;
  /**
   * Maximum number of endpoints to scan.
   * Extra endpoints are silently dropped to keep within time budget.
   * Default: 15.
   */
  maxEndpoints?: number;
  /**
   * Skip the expensive OpenAI-based body analysis during batch scanning.
   * Set to true for URL_SCAN jobs where the audit phase will do full analysis.
   * Default: false.
   */
  skipAIAnalysis?: boolean;
}

/**
 * Run security scans against all discovered endpoints from a crawl.
 * Uses Promise.allSettled() for parallel scanning with fault tolerance.
 *
 * @param crawlResult - Result from url-crawler
 * @param plan - Subscriber tier (affects AI analysis depth)
 * @param concurrency - Max parallel scans (tier-gated)
 * @param onProgress - Optional callback for progress updates
 * @param scanOptions - Time budget and endpoint cap options
 */
export async function batchScanEndpoints(
  crawlResult: CrawlResult,
  plan: SubscriptionPlan,
  concurrency: number = 5,
  onProgress?: (scanned: number, total: number) => void,
  scanOptions?: ScanOptions
): Promise<BatchScanResult> {
  const startTime = Date.now();
  const timeBudgetMs = scanOptions?.timeBudgetMs ?? 25_000;
  const maxEndpoints = scanOptions?.maxEndpoints ?? 15;
  const skipAI = scanOptions?.skipAIAnalysis ?? false;

  // Cap endpoints to prevent unbounded work
  const allEndpoints = crawlResult.endpoints;
  const endpoints = allEndpoints.slice(0, maxEndpoints);
  if (allEndpoints.length > maxEndpoints) {
    logInfo('Capping scanned endpoints for time budget', {
      total: allEndpoints.length,
      scanning: endpoints.length,
    });
  }

  logInfo('Starting batch scan', {
    baseUrl: crawlResult.baseUrl,
    endpointCount: endpoints.length,
    concurrency,
    timeBudgetMs,
    skipAI,
  });

  const endpointResults: EndpointScanResult[] = [];
  let scannedCount = 0;
  let budgetExceeded = false;

  // Process in batches of `concurrency` size
  for (let i = 0; i < endpoints.length; i += concurrency) {
    // Check time budget before starting next batch
    const elapsed = Date.now() - startTime;
    if (elapsed > timeBudgetMs) {
      logWarn('Batch scan time budget exceeded, returning partial results', {
        elapsed,
        timeBudgetMs,
        scanned: scannedCount,
        total: endpoints.length,
      });
      budgetExceeded = true;
      break;
    }

    const batch = endpoints.slice(i, i + concurrency);

    const results = await Promise.allSettled(
      batch.map(endpoint => scanSingleEndpoint(endpoint, plan, skipAI))
    );

    for (let j = 0; j < results.length; j++) {
      const result = results[j];
      if (result.status === 'fulfilled') {
        endpointResults.push(result.value);
      } else {
        endpointResults.push({
          endpoint: batch[j],
          securityHeaders: createEmptyHeaderCheck(),
          error:
            result.reason instanceof Error
              ? result.reason.message
              : String(result.reason),
        });
      }

      scannedCount++;
      if (onProgress) {
        onProgress(scannedCount, endpoints.length);
      }
    }
  }

  // Calculate summary
  const summary = calculateSummary(endpointResults);
  // Reflect total discovered endpoints (not just the ones we scanned)
  summary.totalEndpoints = allEndpoints.length;
  const overallScore = calculateOverallScore(endpointResults);
  const duration = Date.now() - startTime;

  logInfo('Batch scan completed', {
    baseUrl: crawlResult.baseUrl,
    ...summary,
    overallScore,
    duration,
    budgetExceeded,
  });

  return {
    baseUrl: crawlResult.baseUrl,
    crawlResult,
    endpointResults,
    overallScore,
    summary,
    scanDuration: duration,
  };
}

// ============================================================
// Single Endpoint Scanner
// ============================================================

/**
 * Scan a single endpoint for security issues.
 * When skipAI is true, only checks headers (no body fetch / OpenAI call).
 */
async function scanSingleEndpoint(
  endpoint: DiscoveredEndpoint,
  plan: SubscriptionPlan,
  skipAI: boolean = false
): Promise<EndpointScanResult> {
  const result: EndpointScanResult = {
    endpoint,
    securityHeaders: createEmptyHeaderCheck(),
  };

  try {
    // Fetch the endpoint to check headers — reduced timeout for serverless
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);

    const response = await fetch(endpoint.url, {
      method: 'HEAD', // Use HEAD to avoid downloading large bodies
      signal: controller.signal,
      headers: {
        'User-Agent': 'DevFortress-SecurityScanner/1.0',
      },
      redirect: 'follow',
    });

    clearTimeout(timeout);

    // Check security headers
    result.securityHeaders = checkSecurityHeaders(response.headers);
    result.responseHeaders = Object.fromEntries(response.headers.entries());

    // If endpoint returns JSON/HTML, fetch body for deeper analysis
    // Skip this expensive path when the caller only needs header checks
    const contentType = response.headers.get('content-type') || '';
    if (
      !skipAI &&
      (contentType.includes('json') ||
        contentType.includes('html') ||
        contentType.includes('javascript'))
    ) {
      try {
        const bodyResponse = await fetch(endpoint.url, {
          signal: AbortSignal.timeout(5000),
          headers: { 'User-Agent': 'DevFortress-SecurityScanner/1.0' },
          redirect: 'follow',
        });

        const body = await bodyResponse.text();

        // Only scan if body is reasonable size (< 500KB)
        if (body.length < 500_000) {
          const fileName = new URL(endpoint.url).pathname || 'response';
          const extension = contentType.includes('json')
            ? 'json'
            : contentType.includes('javascript')
              ? 'js'
              : 'html';

          result.securityReport = await performSecurityScan(
            [{ path: `${fileName}.${extension}`, contents: body }],
            plan
          );

          // Check for IaC content (Terraform, K8s manifests in responses)
          const iacType = IaCScannerService.detectIaCType(
            `${fileName}.${extension}`,
            body
          );
          if (iacType !== 'unknown') {
            result.iacScanResult = await IaCScannerService.scanFiles([
              {
                path: `${fileName}.${extension}`,
                type: iacType,
                content: body,
              },
            ]);
          }
        }
      } catch (fetchError) {
        logError('Failed to fetch endpoint body for scanning', {
          url: endpoint.url,
          error:
            fetchError instanceof Error
              ? fetchError.message
              : String(fetchError),
        });
      }
    }
  } catch (error) {
    result.error = error instanceof Error ? error.message : String(error);
  }

  return result;
}

// ============================================================
// Security Header Checker
// ============================================================

/**
 * Check for the presence and correctness of security headers.
 */
function checkSecurityHeaders(headers: Headers): SecurityHeaderCheck {
  const missing: string[] = [];
  const check: SecurityHeaderCheck = {
    hasHSTS: false,
    hasCSP: false,
    hasXFrameOptions: false,
    hasXContentType: false,
    hasReferrerPolicy: false,
    hasPermissionsPolicy: false,
    score: 0,
    missing,
  };

  let presentCount = 0;

  for (const { header, name, key } of SECURITY_HEADERS) {
    const value = headers.get(header);
    if (value) {
      check[key] = true;
      presentCount++;
    } else {
      missing.push(name);
    }
  }

  check.score = Math.round((presentCount / SECURITY_HEADERS.length) * 100);
  return check;
}

function createEmptyHeaderCheck(): SecurityHeaderCheck {
  return {
    hasHSTS: false,
    hasCSP: false,
    hasXFrameOptions: false,
    hasXContentType: false,
    hasReferrerPolicy: false,
    hasPermissionsPolicy: false,
    score: 0,
    missing: SECURITY_HEADERS.map(h => h.name),
  };
}

// ============================================================
// Score Calculation
// ============================================================

function calculateSummary(results: EndpointScanResult[]) {
  let criticalIssues = 0;
  let highIssues = 0;
  let mediumIssues = 0;
  let lowIssues = 0;
  let failedEndpoints = 0;

  for (const result of results) {
    if (result.error) {
      failedEndpoints++;
    }

    if (result.securityReport) {
      for (const issue of result.securityReport.issues) {
        switch (issue.severity) {
          case 'critical':
            criticalIssues++;
            break;
          case 'high':
            highIssues++;
            break;
          case 'medium':
            mediumIssues++;
            break;
          case 'low':
            lowIssues++;
            break;
        }
      }
    }

    if (result.iacScanResult) {
      criticalIssues += result.iacScanResult.summary.critical;
      highIssues += result.iacScanResult.summary.high;
      mediumIssues += result.iacScanResult.summary.medium;
      lowIssues += result.iacScanResult.summary.low;
    }
  }

  return {
    totalEndpoints: results.length,
    scannedEndpoints: results.length - failedEndpoints,
    failedEndpoints,
    criticalIssues,
    highIssues,
    mediumIssues,
    lowIssues,
  };
}

/**
 * Calculate an overall security score (0-100).
 * Weighted: critical=-25, high=-10, medium=-3, low=-1 per issue.
 * Header score contributes 30% of final score.
 */
function calculateOverallScore(results: EndpointScanResult[]): number {
  const summary = calculateSummary(results);

  // Issue penalty (out of 70 points)
  const issuePenalty =
    summary.criticalIssues * 25 +
    summary.highIssues * 10 +
    summary.mediumIssues * 3 +
    summary.lowIssues * 1;

  const issueScore = Math.max(0, 70 - issuePenalty);

  // Average header score (out of 30 points)
  const headerScores = results
    .filter(r => !r.error)
    .map(r => r.securityHeaders.score);
  const avgHeaderScore =
    headerScores.length > 0
      ? headerScores.reduce((a, b) => a + b, 0) / headerScores.length
      : 0;
  const headerPoints = (avgHeaderScore / 100) * 30;

  return Math.round(Math.min(100, issueScore + headerPoints));
}
