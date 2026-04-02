'use client';

import { ReportExportButton } from '@core/components/reports/ReportExportButton';

interface InsightReportData {
  totalThreats: number;
  criticalThreats: number;
  patterns: Array<{ pattern: string; count: number; severity: string }>;
  recommendations: Array<{
    phase: string;
    recommendation: string;
    priority: string;
    context?: string;
  }>;
  trends: string[];
  dataSource: string;
  honeypotThreats?: number;
  liveApiThreats?: number;
}

interface InsightsReportExportProps {
  data: InsightReportData;
  className?: string;
}

/**
 * Insights-specific report export that builds structured report data
 * from the insights page's current state
 */
export function InsightsReportExport({ data, className }: InsightsReportExportProps) {
  const sourceLabel =
    data.dataSource === 'all'
      ? 'All Sources (Honeypots + Live APIs)'
      : data.dataSource === 'honeypots'
        ? 'Honeypots Only'
        : data.dataSource === 'apis'
          ? 'Deployed APIs Only'
          : data.dataSource;

  const sections = [
    {
      heading: 'Executive Summary',
      content: `This report contains ${data.totalThreats.toLocaleString()} total threat events analyzed across ${sourceLabel}. ${data.criticalThreats} critical threats were identified requiring immediate attention. The analysis covers honeypot deception data${data.liveApiThreats ? ` and ${data.liveApiThreats.toLocaleString()} live API surveillance events` : ''}, providing a comprehensive view of your security posture.`,
    },
    {
      heading: 'Threat Overview',
      content: [
        `Total Threats Detected: ${data.totalThreats.toLocaleString()}`,
        `Critical Threats: ${data.criticalThreats}`,
        `Honeypot Threats: ${(data.honeypotThreats ?? 0).toLocaleString()}`,
        `Live API Events: ${(data.liveApiThreats ?? 0).toLocaleString()}`,
        `Unique Attack Patterns: ${data.patterns.length}`,
      ],
    },
  ];

  if (data.patterns.length > 0) {
    sections.push({
      heading: 'Top Attack Patterns',
      content: data.patterns.slice(0, 10).map(
        (p) => `${p.pattern} — ${p.count} occurrences (${p.severity} severity)`
      ),
    });
  }

  // Group recommendations by phase
  const byPhase: Record<string, typeof data.recommendations> = {};
  for (const rec of data.recommendations) {
    if (!byPhase[rec.phase]) byPhase[rec.phase] = [];
    byPhase[rec.phase].push(rec);
  }

  for (const [phase, recs] of Object.entries(byPhase)) {
    const phaseLabels: Record<string, string> = {
      BUILD: '🔨 BUILD Phase Recommendations',
      DEFEND: '🛡️ DEFEND Phase Recommendations',
      COLLECT: '📥 COLLECT Phase Recommendations',
      LEARN: '📊 LEARN Phase Recommendations',
    };
    sections.push({
      heading: phaseLabels[phase] || `${phase} Recommendations`,
      content: recs.map(
        (r) => `[${r.priority}] ${r.recommendation}${r.context ? ` — ${r.context}` : ''}`
      ),
    });
  }

  if (data.trends.length > 0) {
    sections.push({
      heading: 'Trend Analysis',
      content: data.trends,
    });
  }

  sections.push({
    heading: 'Next Steps',
    content: [
      'Review and address all HIGH priority recommendations immediately',
      'Deploy additional honeypots to increase threat intelligence coverage',
      'Install the Devfortress SDK on production APIs for live surveillance',
      'Generate new insights regularly to track security posture improvements',
      'Use the BUILD phase to apply security recommendations to API generation',
    ],
  });

  return (
    <ReportExportButton
      reportData={{
        title: 'Devfortress Security Insights Report',
        generatedAt: new Date().toISOString(),
        dataSource: sourceLabel,
        sections,
      }}
      className={className}
    />
  );
}
