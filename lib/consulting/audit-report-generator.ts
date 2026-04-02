/**
 * Audit Report Generator Service
 *
 * Orchestrates SecureForge + Code Analyzer + IaC Scanner + Compliance
 * into a unified, structured security audit report.
 *
 * Generates both JSON (for API/DB storage) and HTML (for PDF rendering).
 * Used by consulting services and PRO+ DIY subscribers.
 */

import { prisma } from '@core/lib/prisma';
import { logInfo, logError } from '@core/lib/logger';
import { crawlUrl } from './url-crawler';
import type { CrawlOptions } from './url-crawler';
import { batchScanEndpoints, type BatchScanResult } from './batch-scanner';
import type { ScanOptions } from './batch-scanner';
import { updateJobProgress, completeJob, failJob } from './job-queue';
import type { SubscriptionPlan } from '@prisma/client';

// ============================================================
// Types
// ============================================================

export interface AuditReportInput {
  targetUrl?: string;
  codeSnippets?: Array<{ path: string; contents: string }>;
  userId: string;
  clientId?: string;
  jobId?: string;
  plan: SubscriptionPlan;
  /**
   * Total wall-clock time (ms) available for the entire audit.
   * When running inside a serverless function with a hard timeout,
   * pass the remaining budget here so the crawler + scanner stay
   * within limits.  Default: 45 000 ms.
   */
  timeBudgetMs?: number;
}

export interface AuditReportData {
  id: string;
  targetUrl?: string;
  generatedAt: string;
  overallScore: number;
  executiveSummary: string;
  scanResults?: BatchScanResult;
  issuesByCategory: Record<
    string,
    Array<{
      severity: string;
      description: string;
      location: string;
      recommendation: string;
    }>
  >;
  securityHeaderAnalysis: {
    averageScore: number;
    commonMissing: string[];
  };
  severityCounts: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  recommendations: string[];
  complianceNotes: string[];
}

// ============================================================
// Concurrency limits by tier
// ============================================================

const SCAN_CONCURRENCY: Record<SubscriptionPlan, number> = {
  STARTER: 1,
  PRO: 3,
  ENTERPRISE: 10, // Legacy alias for TEAM
  TEAM: 10,
  BUSINESS: 25,
  ENTERPRISE_PLUS: 50,
};

// ============================================================
// Main Generator
// ============================================================

/**
 * Generate a full security audit report.
 *
 * Pipeline:
 * 1. Crawl target URL (if provided) — 0-20% progress
 * 2. Batch scan all discovered endpoints — 20-70%
 * 3. Aggregate and categorize findings — 70-85%
 * 4. Generate executive summary — 85-95%
 * 5. Persist to database — 95-100%
 */
export async function generateAuditReport(
  input: AuditReportInput
): Promise<AuditReportData> {
  const { targetUrl, userId, clientId, jobId, plan } = input;
  const totalBudget = input.timeBudgetMs ?? 45_000;
  const auditStart = Date.now();

  /** ms remaining in the overall budget */
  const remaining = () => Math.max(0, totalBudget - (Date.now() - auditStart));

  try {
    // Step 1: Crawl URL if provided
    let scanResult: BatchScanResult | undefined;

    if (targetUrl) {
      if (jobId) await updateJobProgress(jobId, 5);
      logInfo('Audit: crawling target URL', {
        targetUrl,
        budgetRemaining: remaining(),
      });

      // Allocate ~40% of remaining budget to crawl, leave rest for scan + report
      const crawlBudget = Math.min(18_000, Math.floor(remaining() * 0.4));
      const crawlOptions: CrawlOptions = {
        timeBudgetMs: Math.max(5000, crawlBudget),
      };
      const crawlResult = await crawlUrl(targetUrl, crawlOptions);
      if (jobId) await updateJobProgress(jobId, 20);

      // Step 2: Batch scan endpoints
      const concurrency = SCAN_CONCURRENCY[plan] || 1;
      logInfo('Audit: scanning endpoints', {
        count: crawlResult.endpoints.length,
        concurrency,
        budgetRemaining: remaining(),
      });

      // Allocate ~70% of remaining budget to scan, keep 8 s for report generation + DB
      const scanBudget = Math.min(22_000, remaining() - 8_000);
      const scanOptions: ScanOptions = {
        timeBudgetMs: Math.max(5000, scanBudget),
        maxEndpoints: 15,
        // AI analysis is expensive (OpenAI call per endpoint) — skip for header-only pass
        skipAIAnalysis: plan === 'STARTER',
      };

      scanResult = await batchScanEndpoints(
        crawlResult,
        plan,
        concurrency,
        jobId
          ? (scanned, total) => {
              // Map scanning progress to 20-70% range
              const pct = 20 + Math.round((scanned / total) * 50);
              updateJobProgress(jobId, pct).catch(() => {});
            }
          : undefined,
        scanOptions
      );

      if (jobId) await updateJobProgress(jobId, 70);
    }

    // Step 3: Aggregate findings
    if (jobId) await updateJobProgress(jobId, 75);
    const issuesByCategory = aggregateIssues(scanResult);
    const severityCounts = countSeverities(scanResult);
    const securityHeaderAnalysis = analyzeHeaders(scanResult);

    // Step 4: Generate executive summary
    if (jobId) await updateJobProgress(jobId, 85);
    const overallScore = scanResult?.overallScore ?? 50;
    const executiveSummary = generateExecutiveSummary(
      targetUrl,
      overallScore,
      severityCounts,
      scanResult
    );
    const recommendations = generateRecommendations(
      issuesByCategory,
      securityHeaderAnalysis
    );
    const complianceNotes = generateComplianceNotes(scanResult);

    // Step 5: Persist to database
    if (jobId) await updateJobProgress(jobId, 95);

    const auditReport = await prisma.auditReport.create({
      data: {
        userId,
        clientId: clientId ?? null,
        jobId: jobId ?? null,
        targetUrl: targetUrl ?? null,
        status: 'COMPLETED',
        overallScore,
        executiveSummary,
        criticalCount: severityCounts.critical,
        highCount: severityCounts.high,
        mediumCount: severityCounts.medium,
        lowCount: severityCounts.low,
        reportJson: {
          issuesByCategory,
          securityHeaderAnalysis,
          recommendations,
          complianceNotes,
          scanSummary: scanResult?.summary ?? null,
          crawlDuration: scanResult?.crawlResult?.crawlDuration ?? null,
          scanDuration: scanResult?.scanDuration ?? null,
        },
        completedAt: new Date(),
      },
    });

    const reportData: AuditReportData = {
      id: auditReport.id,
      targetUrl,
      generatedAt: new Date().toISOString(),
      overallScore,
      executiveSummary,
      scanResults: scanResult,
      issuesByCategory,
      securityHeaderAnalysis,
      severityCounts,
      recommendations,
      complianceNotes,
    };

    // Mark job as complete
    if (jobId) {
      await completeJob(
        jobId,
        {
          reportId: auditReport.id,
          overallScore,
          severityCounts,
        },
        { userId, jobType: 'AUDIT' }
      );
    }

    logInfo('Audit report generated', {
      reportId: auditReport.id,
      overallScore,
      targetUrl,
    });

    return reportData;
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : String(error);

    logError('Audit report generation failed', {
      error: errorMsg,
      targetUrl,
      userId,
    });

    // Mark job as failed
    if (jobId) {
      await failJob(jobId, errorMsg, { userId, jobType: 'AUDIT' });
    }

    throw error;
  }
}

// ============================================================
// Aggregation Helpers
// ============================================================

function aggregateIssues(scanResult?: BatchScanResult): Record<
  string,
  Array<{
    severity: string;
    description: string;
    location: string;
    recommendation: string;
  }>
> {
  const categories: Record<
    string,
    Array<{
      severity: string;
      description: string;
      location: string;
      recommendation: string;
    }>
  > = {};

  if (!scanResult) return categories;

  for (const epResult of scanResult.endpointResults) {
    // Security report issues
    if (epResult.securityReport) {
      for (const issue of epResult.securityReport.issues) {
        const cat = issue.category || 'General';
        if (!categories[cat]) categories[cat] = [];
        categories[cat].push({
          severity: issue.severity,
          description: issue.description,
          location: `${epResult.endpoint.url} (${issue.file}${issue.line ? `:${issue.line}` : ''})`,
          recommendation: issue.suggestion,
        });
      }
    }

    // IaC scan issues
    if (epResult.iacScanResult) {
      for (const vuln of epResult.iacScanResult.vulnerabilities) {
        const cat = vuln.category || 'Infrastructure';
        if (!categories[cat]) categories[cat] = [];
        categories[cat].push({
          severity: vuln.severity,
          description: vuln.description,
          location: `${vuln.file}${vuln.line ? `:${vuln.line}` : ''}`,
          recommendation: vuln.recommendation,
        });
      }
    }

    // Missing security headers
    if (epResult.securityHeaders.missing.length > 0 && !epResult.error) {
      const cat = 'Security Headers';
      if (!categories[cat]) categories[cat] = [];
      categories[cat].push({
        severity: 'medium',
        description: `Missing security headers: ${epResult.securityHeaders.missing.join(', ')}`,
        location: epResult.endpoint.url,
        recommendation:
          'Add the missing security headers to improve protection against common attacks.',
      });
    }
  }

  return categories;
}

function countSeverities(scanResult?: BatchScanResult) {
  if (!scanResult) {
    return { critical: 0, high: 0, medium: 0, low: 0 };
  }
  return {
    critical: scanResult.summary.criticalIssues,
    high: scanResult.summary.highIssues,
    medium: scanResult.summary.mediumIssues,
    low: scanResult.summary.lowIssues,
  };
}

function analyzeHeaders(scanResult?: BatchScanResult) {
  if (!scanResult) {
    return { averageScore: 0, commonMissing: [] };
  }

  const headerScores = scanResult.endpointResults
    .filter(r => !r.error)
    .map(r => r.securityHeaders);

  if (headerScores.length === 0) {
    return { averageScore: 0, commonMissing: [] };
  }

  const averageScore = Math.round(
    headerScores.reduce((a, b) => a + b.score, 0) / headerScores.length
  );

  // Find most commonly missing headers
  const missingCount: Record<string, number> = {};
  for (const check of headerScores) {
    for (const header of check.missing) {
      missingCount[header] = (missingCount[header] || 0) + 1;
    }
  }

  const commonMissing = Object.entries(missingCount)
    .sort((a, b) => b[1] - a[1])
    .map(([header]) => header);

  return { averageScore, commonMissing };
}

// ============================================================
// Summary & Recommendations
// ============================================================

function generateExecutiveSummary(
  targetUrl: string | undefined,
  overallScore: number,
  severityCounts: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  },
  scanResult?: BatchScanResult
): string {
  const target = targetUrl || 'the provided codebase';
  const totalIssues =
    severityCounts.critical +
    severityCounts.high +
    severityCounts.medium +
    severityCounts.low;
  const endpointsScanned = scanResult?.summary.scannedEndpoints ?? 0;

  let riskLevel: string;
  if (overallScore >= 80) riskLevel = 'LOW';
  else if (overallScore >= 60) riskLevel = 'MODERATE';
  else if (overallScore >= 40) riskLevel = 'HIGH';
  else riskLevel = 'CRITICAL';

  return (
    `Security audit of ${target} completed on ${new Date().toISOString().split('T')[0]}. ` +
    `${endpointsScanned} endpoint(s) were discovered and scanned. ` +
    `Overall security score: ${overallScore}/100 (${riskLevel} risk). ` +
    `${totalIssues} security issue(s) were identified: ` +
    `${severityCounts.critical} critical, ${severityCounts.high} high, ` +
    `${severityCounts.medium} medium, ${severityCounts.low} low. ` +
    (severityCounts.critical > 0
      ? 'IMMEDIATE ACTION REQUIRED: Critical vulnerabilities detected that could lead to data breach or system compromise. '
      : '') +
    (severityCounts.high > 0
      ? 'High-severity issues should be addressed within 7 days. '
      : '') +
    `This report was generated by DevFortress VortexSecure engine.`
  );
}

function generateRecommendations(
  issuesByCategory: Record<string, Array<{ severity: string }>>,
  headerAnalysis: { averageScore: number; commonMissing: string[] }
): string[] {
  const recs: string[] = [];

  // Category-specific recommendations
  const categoryNames = Object.keys(issuesByCategory);

  if (categoryNames.includes('Sensitive Data Exposure')) {
    recs.push(
      'Move all hardcoded secrets to environment variables. Use a secrets manager (e.g., Vault, AWS Secrets Manager) for production.'
    );
  }

  if (
    categoryNames.some(
      c =>
        c.toLowerCase().includes('injection') || c.toLowerCase().includes('xss')
    )
  ) {
    recs.push(
      'Implement input validation and sanitization on all user inputs. Use parameterized queries for database operations.'
    );
  }

  if (categoryNames.some(c => c.toLowerCase().includes('authentication'))) {
    recs.push(
      'Review authentication implementation. Ensure strong password policies, MFA support, and secure session management.'
    );
  }

  // Header recommendations
  if (headerAnalysis.averageScore < 80) {
    recs.push(
      `Add missing security headers: ${headerAnalysis.commonMissing.slice(0, 3).join(', ')}. These protect against clickjacking, XSS, and MIME sniffing attacks.`
    );
  }

  // General best practices
  recs.push(
    'Enable HTTPS everywhere with HSTS preloading for all domains and subdomains.'
  );
  recs.push(
    'Implement rate limiting on all API endpoints to prevent abuse and brute-force attacks.'
  );
  recs.push(
    'Set up continuous security monitoring using DevFortress honeypots and live surveillance SDK.'
  );

  return recs;
}

function generateComplianceNotes(scanResult?: BatchScanResult): string[] {
  const notes: string[] = [];

  notes.push(
    'This automated security assessment covers OWASP Top 10 categories and common infrastructure misconfigurations.'
  );
  notes.push(
    'For formal compliance certification (SOC 2, HIPAA, GDPR), a manual review by a qualified auditor is recommended in addition to this automated scan.'
  );

  if (scanResult) {
    const hasCritical = scanResult.summary.criticalIssues > 0;
    if (hasCritical) {
      notes.push(
        'COMPLIANCE RISK: Critical vulnerabilities may violate data protection regulations (GDPR Article 32, HIPAA Security Rule).'
      );
    }

    const headerScore =
      scanResult.endpointResults
        .filter(r => !r.error)
        .reduce((sum, r) => sum + r.securityHeaders.score, 0) /
      Math.max(1, scanResult.endpointResults.filter(r => !r.error).length);

    if (headerScore < 50) {
      notes.push(
        'Security header coverage is below 50%. This may be flagged in PCI DSS and SOC 2 audits.'
      );
    }
  }

  return notes;
}
