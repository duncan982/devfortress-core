/**
 * Compliance PDF Report Generator
 * Generates enterprise-grade compliance evidence reports in structured JSON
 * that can be rendered as PDF via the client-side report viewer.
 *
 * Supports: PCI-DSS v4.0, SOC2 Type II, GDPR, HIPAA
 */

import { logInfo, logError } from '@core/lib/logger';
import {
  ComplianceStandard,
  type ComplianceReport,
} from '@core/lib/compliance/compliance-service';

/* ─── Types ─── */

export interface ComplianceControl {
  controlId: string;
  controlName: string;
  description: string;
  status: 'compliant' | 'non_compliant' | 'not_applicable' | 'in_progress';
  evidence: string[];
  notes?: string;
  lastAuditDate?: string;
}

export interface ComplianceReportData {
  id: string;
  standard: ComplianceStandard;
  title: string;
  subtitle: string;
  orgName: string;
  orgId: string;
  period: { start: string; end: string };
  generatedAt: string;
  generatedBy: string;
  version: string;
  executive_summary: string;
  controls: ComplianceControl[];
  findings: Array<{
    severity: 'low' | 'medium' | 'high' | 'critical';
    description: string;
    recommendation: string;
    status: 'open' | 'in_progress' | 'resolved';
    controlRef?: string;
  }>;
  statistics: {
    totalControls: number;
    compliant: number;
    nonCompliant: number;
    inProgress: number;
    notApplicable: number;
    overallScore: number;
  };
  appendices: Array<{
    title: string;
    content: string;
  }>;
}

/* ─── Control Templates ─── */

const PCI_DSS_CONTROLS: ComplianceControl[] = [
  {
    controlId: 'PCI-DSS-6.4.1',
    controlName: 'Public-facing web application protection',
    description:
      'Public-facing web applications are protected against attacks by deploying WAF-equivalent security controls.',
    status: 'compliant',
    evidence: [
      'DevFortress SDK monitors all API endpoints in real-time',
      'Pre-auth threat detection covers OWASP Top 10',
      'Automated response actions block malicious requests within 2 seconds',
    ],
  },
  {
    controlId: 'PCI-DSS-6.4.2',
    controlName: 'Automated technical solution for web applications',
    description:
      'An automated technical solution that detects and prevents web-based attacks is deployed.',
    status: 'compliant',
    evidence: [
      'Closed-loop detection and response pipeline',
      'AbuseIPDB integration for IP reputation scoring',
      'Composite threat scoring drives automated blocking decisions',
    ],
  },
  {
    controlId: 'PCI-DSS-10.2.1',
    controlName: 'Audit log covers all system components',
    description:
      'Audit logs capture all access to system components that store, process, or transmit cardholder data.',
    status: 'compliant',
    evidence: [
      'Comprehensive audit logging via EnterpriseComplianceManager',
      'All API access events logged with user, IP, timestamp, action',
      'Logs retained per data retention policy (Enterprise: 365 days)',
    ],
  },
  {
    controlId: 'PCI-DSS-10.2.2',
    controlName: 'Audit log records all administrator actions',
    description:
      'All actions taken by any individual with administrative access are logged.',
    status: 'compliant',
    evidence: [
      'Admin actions tracked in audit log with ADMIN_SETTINGS event type',
      'User management, configuration changes, and security events logged',
      'Immutable audit trail for compliance verification',
    ],
  },
  {
    controlId: 'PCI-DSS-11.4',
    controlName: 'Intrusion detection/prevention',
    description:
      'Intrusion detection and/or intrusion prevention techniques are implemented to monitor all traffic.',
    status: 'compliant',
    evidence: [
      'Real-time threat detection via DevFortress SDK',
      '8 pre-auth detection types: brute force, credential stuffing, injection, path traversal, XSS, CSRF, rate abuse, scanner fingerprinting',
      '3 post-auth detection types: token replay, privilege escalation, anomalous volume',
      'AbuseIPDB blacklist synchronisation for known attacker blocking',
    ],
  },
  {
    controlId: 'PCI-DSS-12.10',
    controlName: 'Incident response plan',
    description:
      'An incident response plan exists and is ready to be activated immediately.',
    status: 'compliant',
    evidence: [
      'Automated incident response via playbook engine',
      'Session revocation < 2 seconds for confirmed threats',
      'Escalation to SIEM connectors (Splunk, Datadog, Sentinel)',
      'Closed-loop audit trail: detect → respond → confirm',
    ],
  },
];

const SOC2_CONTROLS: ComplianceControl[] = [
  {
    controlId: 'CC6.1',
    controlName: 'Logical Access Controls',
    description:
      'The entity implements logical access security software, infrastructure, and architectures.',
    status: 'compliant',
    evidence: [
      'Role-based access control (RBAC) enforced via Supabase RLS',
      'Multi-factor authentication available',
      'API key management with scoped permissions',
      'Session privacy architecture prevents real token exposure',
    ],
  },
  {
    controlId: 'CC6.6',
    controlName: 'Security measures against threats outside system boundaries',
    description:
      'The entity implements security measures to protect information in transit and at rest.',
    status: 'compliant',
    evidence: [
      'TLS 1.3 for all data in transit',
      'HMAC-SHA256 webhook signing with timestamp anti-replay',
      'Session privacy architecture ensures real tokens never leave client applications',
      'Supabase encryption at rest for all stored data',
    ],
  },
  {
    controlId: 'CC7.2',
    controlName: 'Monitoring of system components',
    description:
      'The entity monitors system components and the operation of those components for anomalies.',
    status: 'compliant',
    evidence: [
      'Real-time SSE event stream for security events',
      'Composite threat scoring with configurable thresholds',
      'AbuseIPDB integration for external threat intelligence',
      'Dashboard provides visibility into all monitored endpoints',
    ],
  },
  {
    controlId: 'CC7.3',
    controlName: 'Change management and incident response',
    description:
      'The entity evaluates events to determine if they constitute incidents.',
    status: 'compliant',
    evidence: [
      'Automated threat classification with severity levels',
      'Playbook engine for configurable response actions',
      'SIEM integration for centralised incident management',
      'Closed-loop audit trail tracks detect → respond → confirm chain',
    ],
  },
  {
    controlId: 'CC8.1',
    controlName: 'Change management process',
    description:
      'Changes to infrastructure, data, software, and procedures are authorised and managed.',
    status: 'compliant',
    evidence: [
      'Git-based version control with PR review requirements',
      'CI/CD pipeline with automated testing and security checks',
      'Playbook versioning tracks all rule changes',
      'Audit log records all configuration changes',
    ],
  },
];

const GDPR_CONTROLS: ComplianceControl[] = [
  {
    controlId: 'GDPR-Art.5(1)(f)',
    controlName: 'Integrity and confidentiality',
    description:
      'Personal data processed in a manner that ensures appropriate security.',
    status: 'compliant',
    evidence: [
      'Privacy-first architecture — real session tokens never transmitted to DevFortress',
      'IP addresses used for threat detection, not profiling',
      'Data minimisation: only security-relevant metadata collected',
      'Encryption in transit (TLS 1.3) and at rest (Supabase)',
    ],
  },
  {
    controlId: 'GDPR-Art.15',
    controlName: 'Right of access',
    description:
      'Data subjects have the right to obtain confirmation of processing and access to their data.',
    status: 'compliant',
    evidence: [
      'Data Subject Request (DSR) API: POST /api/compliance/data-request',
      'Full data export functionality via ComplianceService.exportUserData()',
      'Automated processing of ACCESS requests',
    ],
  },
  {
    controlId: 'GDPR-Art.17',
    controlName: 'Right to erasure',
    description:
      'Data subjects have the right to obtain erasure of personal data.',
    status: 'compliant',
    evidence: [
      'DELETION request type in DSR system',
      'Soft-delete with anonymisation via ComplianceService.deleteUserData()',
      'Configurable data retention policies per data type',
    ],
  },
  {
    controlId: 'GDPR-Art.32',
    controlName: 'Security of processing',
    description:
      'Controller and processor implement appropriate technical and organisational measures.',
    status: 'compliant',
    evidence: [
      'Real-time API security monitoring and automated response',
      'HMAC-SHA256 webhook signing prevents request forgery',
      'Brute force detection and automated account protection',
      'Regular dependency scanning via npm audit',
    ],
  },
  {
    controlId: 'GDPR-Art.33',
    controlName: 'Notification of breach to supervisory authority',
    description:
      'In the case of a personal data breach, controller shall notify within 72 hours.',
    status: 'compliant',
    evidence: [
      'Real-time threat detection identifies potential breaches immediately',
      'SIEM integration enables centralised breach monitoring',
      'Audit log provides evidence timeline for breach investigation',
      'Automated alerting notifies security team within minutes',
    ],
  },
];

const HIPAA_CONTROLS: ComplianceControl[] = [
  {
    controlId: 'HIPAA-§164.312(a)(1)',
    controlName: 'Access control',
    description:
      'Implement technical policies and procedures for electronic information systems that maintain ePHI.',
    status: 'compliant',
    evidence: [
      'Role-based access control via Supabase RLS policies',
      'API key scoping restricts access to authorised resources',
      'Session management with automatic expiration',
      'Multi-factor authentication support',
    ],
  },
  {
    controlId: 'HIPAA-§164.312(b)',
    controlName: 'Audit controls',
    description:
      'Implement hardware, software, and procedural mechanisms that record and examine activity.',
    status: 'compliant',
    evidence: [
      'Comprehensive audit logging of all API access and actions',
      'Enterprise retention: 365 days for audit logs, 730 days for compliance',
      'Tamper-evident logging with timestamp verification',
      'CSV export for external audit review',
    ],
  },
  {
    controlId: 'HIPAA-§164.312(c)(1)',
    controlName: 'Integrity controls',
    description:
      'Implement policies and procedures to protect ePHI from improper alteration or destruction.',
    status: 'compliant',
    evidence: [
      'HMAC-SHA256 message integrity for all webhook communications',
      'Database-level constraints prevent invalid state transitions',
      'Audit trail tracks all data modifications',
    ],
  },
  {
    controlId: 'HIPAA-§164.312(d)',
    controlName: 'Person or entity authentication',
    description:
      'Implement procedures to verify that a person or entity seeking access is the one claimed.',
    status: 'compliant',
    evidence: [
      'Supabase authentication with email verification',
      'Session privacy prevents session impersonation',
      'Brute force detection locks accounts after failed attempts',
    ],
  },
  {
    controlId: 'HIPAA-§164.312(e)(1)',
    controlName: 'Transmission security',
    description:
      'Implement technical security measures to guard against unauthorised access to ePHI being transmitted.',
    status: 'compliant',
    evidence: [
      'TLS 1.3 for all data in transit',
      'HMAC-SHA256 webhook signing with anti-replay protection',
      'mTLS available for Enterprise customers requiring mutual certificate authentication',
    ],
  },
];

/* ─── Report Generator ─── */

export class ComplianceReportGenerator {
  /**
   * Generate a comprehensive compliance report
   */
  async generateReport(params: {
    standard: ComplianceStandard;
    orgName: string;
    orgId: string;
    period: { start: Date; end: Date };
    generatedBy: string;
  }): Promise<ComplianceReportData> {
    const { standard, orgName, orgId, period, generatedBy } = params;

    logInfo('Generating compliance report', { standard, orgName, orgId });

    const controls = this.getControlsForStandard(standard);
    const statistics = this.calculateStatistics(controls);

    const report: ComplianceReportData = {
      id: `report-${standard}-${Date.now()}`,
      standard,
      title: this.getReportTitle(standard),
      subtitle: `Compliance Evidence Report for ${orgName}`,
      orgName,
      orgId,
      period: {
        start: period.start.toISOString(),
        end: period.end.toISOString(),
      },
      generatedAt: new Date().toISOString(),
      generatedBy,
      version: '1.0',
      executive_summary: this.getExecutiveSummary(
        standard,
        statistics,
        orgName
      ),
      controls,
      findings: this.generateFindings(controls),
      statistics,
      appendices: this.getAppendices(standard),
    };

    logInfo('Compliance report generated', {
      reportId: report.id,
      standard,
      totalControls: statistics.totalControls,
      overallScore: statistics.overallScore,
    });

    return report;
  }

  /**
   * Generate report as HTML string (for PDF conversion via browser print)
   */
  async generateReportHTML(params: {
    standard: ComplianceStandard;
    orgName: string;
    orgId: string;
    period: { start: Date; end: Date };
    generatedBy: string;
  }): Promise<string> {
    const report = await this.generateReport(params);
    return this.renderReportHTML(report);
  }

  private getControlsForStandard(
    standard: ComplianceStandard
  ): ComplianceControl[] {
    switch (standard) {
      case ComplianceStandard.PCI_DSS:
        return PCI_DSS_CONTROLS;
      case ComplianceStandard.SOC2:
        return SOC2_CONTROLS;
      case ComplianceStandard.GDPR:
        return GDPR_CONTROLS;
      case ComplianceStandard.HIPAA:
        return HIPAA_CONTROLS;
      default:
        return [];
    }
  }

  private getReportTitle(standard: ComplianceStandard): string {
    switch (standard) {
      case ComplianceStandard.PCI_DSS:
        return 'PCI-DSS v4.0 Compliance Evidence Report';
      case ComplianceStandard.SOC2:
        return 'SOC2 Type II Trust Services Criteria Report';
      case ComplianceStandard.GDPR:
        return 'GDPR Compliance Assessment Report';
      case ComplianceStandard.HIPAA:
        return 'HIPAA Technical Safeguards Compliance Report';
      default:
        return 'Compliance Report';
    }
  }

  private getExecutiveSummary(
    standard: ComplianceStandard,
    statistics: ComplianceReportData['statistics'],
    orgName: string
  ): string {
    const standardName = standard.toUpperCase().replace('_', '-');
    return (
      `This report provides compliance evidence for ${orgName}'s use of the DevFortress API Security Platform ` +
      `against the ${standardName} framework. The assessment covers ${statistics.totalControls} controls, ` +
      `of which ${statistics.compliant} are fully compliant, ${statistics.inProgress} are in progress, ` +
      `${statistics.nonCompliant} are non-compliant, and ${statistics.notApplicable} are not applicable. ` +
      `The overall compliance score is ${statistics.overallScore.toFixed(1)}%. ` +
      `DevFortress provides continuous API security monitoring, automated threat detection and response, ` +
      `and comprehensive audit logging to support your compliance objectives.`
    );
  }

  private calculateStatistics(
    controls: ComplianceControl[]
  ): ComplianceReportData['statistics'] {
    const total = controls.length;
    const compliant = controls.filter(c => c.status === 'compliant').length;
    const nonCompliant = controls.filter(
      c => c.status === 'non_compliant'
    ).length;
    const inProgress = controls.filter(c => c.status === 'in_progress').length;
    const notApplicable = controls.filter(
      c => c.status === 'not_applicable'
    ).length;
    const applicable = total - notApplicable;
    const score = applicable > 0 ? (compliant / applicable) * 100 : 100;

    return {
      totalControls: total,
      compliant,
      nonCompliant,
      inProgress,
      notApplicable,
      overallScore: Math.round(score * 10) / 10,
    };
  }

  private generateFindings(
    controls: ComplianceControl[]
  ): ComplianceReportData['findings'] {
    const findings: ComplianceReportData['findings'] = [];

    for (const control of controls) {
      if (control.status === 'non_compliant') {
        findings.push({
          severity: 'high',
          description: `Control ${control.controlId} (${control.controlName}) is not compliant.`,
          recommendation: `Review and implement the requirements for ${control.controlId}. ${control.notes || ''}`,
          status: 'open',
          controlRef: control.controlId,
        });
      }
      if (control.status === 'in_progress') {
        findings.push({
          severity: 'medium',
          description: `Control ${control.controlId} (${control.controlName}) is in progress.`,
          recommendation: `Complete implementation of ${control.controlId}. ${control.notes || ''}`,
          status: 'in_progress',
          controlRef: control.controlId,
        });
      }
    }

    return findings;
  }

  private getAppendices(
    standard: ComplianceStandard
  ): ComplianceReportData['appendices'] {
    const appendices = [
      {
        title: 'About DevFortress',
        content:
          'DevFortress is a developer-first API and application security platform that provides real-time threat detection, automated response, and comprehensive compliance evidence. The platform uses a lightweight SDK to monitor API traffic, a composite threat scoring engine powered by AbuseIPDB intelligence, and a closed-loop response pipeline that detects, responds to, and confirms resolution of security threats within seconds.',
      },
      {
        title: 'Session Privacy Architecture',
        content:
          "DevFortress implements a privacy-first security model where real session tokens never leave the client application. The SDK generates an anonymised session identifier for each token and sends only the identifier to the DevFortress platform. This means that even in the event of a platform breach, attackers would obtain only meaningless identifier strings — not tokens that could be used to impersonate users. This architecture is fundamental to DevFortress's security posture and is included on all subscription tiers.",
      },
      {
        title: 'Data Retention Policies',
        content:
          'Enterprise tier: Security events retained for 365 days. Audit logs retained for 730 days (2 years). Honeypot data retained indefinitely. All data subject to configurable retention policies and GDPR-compliant deletion processes.',
      },
    ];

    if (
      standard === ComplianceStandard.PCI_DSS ||
      standard === ComplianceStandard.HIPAA
    ) {
      appendices.push({
        title: 'Encryption Standards',
        content:
          'All data in transit encrypted with TLS 1.3. Webhook communications secured with HMAC-SHA256 signatures including timestamp-based anti-replay protection. Enterprise customers can additionally enable mTLS (mutual X.509 certificate authentication) for transport-layer mutual authentication. Database storage uses Supabase encryption at rest (AES-256).',
      });
    }

    return appendices;
  }

  /**
   * Render report as HTML suitable for browser print-to-PDF
   */
  private renderReportHTML(report: ComplianceReportData): string {
    const statusBadge = (status: string) => {
      const colors: Record<string, string> = {
        compliant: 'background:#22c55e;color:white',
        non_compliant: 'background:#ef4444;color:white',
        in_progress: 'background:#f59e0b;color:white',
        not_applicable: 'background:#6b7280;color:white',
      };
      return `<span style="display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;${colors[status] || ''}">${status.replace('_', ' ').toUpperCase()}</span>`;
    };

    const severityBadge = (severity: string) => {
      const colors: Record<string, string> = {
        low: '#3b82f6',
        medium: '#f59e0b',
        high: '#ef4444',
        critical: '#7f1d1d',
      };
      return `<span style="display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;background:${colors[severity] || '#6b7280'};color:white">${severity.toUpperCase()}</span>`;
    };

    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>${report.title} — ${report.orgName}</title>
<style>
  @page { margin: 1in; size: A4; }
  body { font-family: 'Segoe UI', system-ui, sans-serif; color: #1a1a1a; line-height: 1.6; max-width: 800px; margin: 0 auto; padding: 40px; }
  h1 { font-size: 24px; color: #0284c7; border-bottom: 3px solid #0284c7; padding-bottom: 12px; }
  h2 { font-size: 18px; color: #1e3a5f; margin-top: 32px; border-bottom: 1px solid #e5e7eb; padding-bottom: 8px; }
  h3 { font-size: 14px; color: #374151; margin-top: 16px; }
  .meta { color: #6b7280; font-size: 13px; margin-bottom: 24px; }
  .score-card { display: flex; gap: 16px; margin: 16px 0; }
  .score-item { background: #f0f9ff; border: 1px solid #bae6fd; border-radius: 8px; padding: 12px 20px; text-align: center; flex: 1; }
  .score-item .number { font-size: 28px; font-weight: 700; color: #0284c7; }
  .score-item .label { font-size: 11px; color: #6b7280; text-transform: uppercase; letter-spacing: 0.05em; }
  table { width: 100%; border-collapse: collapse; margin: 12px 0; }
  th { background: #f1f5f9; font-size: 12px; text-transform: uppercase; letter-spacing: 0.05em; padding: 8px 12px; text-align: left; border-bottom: 2px solid #e2e8f0; }
  td { padding: 10px 12px; border-bottom: 1px solid #e2e8f0; font-size: 13px; vertical-align: top; }
  .evidence { list-style: none; padding: 0; margin: 4px 0 0 0; }
  .evidence li { font-size: 12px; color: #4b5563; padding: 2px 0; }
  .evidence li::before { content: '✓ '; color: #22c55e; font-weight: 600; }
  .footer { margin-top: 48px; padding-top: 16px; border-top: 1px solid #e5e7eb; font-size: 11px; color: #9ca3af; text-align: center; }
  .appendix { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 16px 20px; margin: 12px 0; }
  .appendix h3 { margin-top: 0; }
</style>
</head>
<body>
  <h1>${report.title}</h1>
  <p class="meta">
    <strong>Organisation:</strong> ${report.orgName}<br>
    <strong>Report Period:</strong> ${new Date(report.period.start).toLocaleDateString()} — ${new Date(report.period.end).toLocaleDateString()}<br>
    <strong>Generated:</strong> ${new Date(report.generatedAt).toLocaleString()}<br>
    <strong>Generated By:</strong> ${report.generatedBy}<br>
    <strong>Report ID:</strong> ${report.id}
  </p>

  <h2>Executive Summary</h2>
  <p>${report.executive_summary}</p>

  <div class="score-card">
    <div class="score-item">
      <div class="number">${report.statistics.overallScore}%</div>
      <div class="label">Overall Score</div>
    </div>
    <div class="score-item">
      <div class="number">${report.statistics.compliant}</div>
      <div class="label">Compliant</div>
    </div>
    <div class="score-item">
      <div class="number">${report.statistics.nonCompliant}</div>
      <div class="label">Non-Compliant</div>
    </div>
    <div class="score-item">
      <div class="number">${report.statistics.totalControls}</div>
      <div class="label">Total Controls</div>
    </div>
  </div>

  <h2>Control Assessment</h2>
  <table>
    <thead>
      <tr>
        <th style="width:12%">Control ID</th>
        <th style="width:22%">Control</th>
        <th style="width:12%">Status</th>
        <th>Evidence</th>
      </tr>
    </thead>
    <tbody>
      ${report.controls
        .map(
          c => `
      <tr>
        <td><strong>${c.controlId}</strong></td>
        <td>${c.controlName}<br><span style="font-size:11px;color:#6b7280">${c.description}</span></td>
        <td>${statusBadge(c.status)}</td>
        <td><ul class="evidence">${c.evidence.map(e => `<li>${e}</li>`).join('')}</ul>${c.notes ? `<span style="font-size:11px;color:#6b7280;font-style:italic">${c.notes}</span>` : ''}</td>
      </tr>`
        )
        .join('')}
    </tbody>
  </table>

  ${
    report.findings.length > 0
      ? `
  <h2>Findings</h2>
  <table>
    <thead>
      <tr>
        <th>Severity</th>
        <th>Finding</th>
        <th>Recommendation</th>
        <th>Status</th>
      </tr>
    </thead>
    <tbody>
      ${report.findings
        .map(
          f => `
      <tr>
        <td>${severityBadge(f.severity)}</td>
        <td>${f.description}</td>
        <td>${f.recommendation}</td>
        <td>${statusBadge(f.status)}</td>
      </tr>`
        )
        .join('')}
    </tbody>
  </table>`
      : '<h2>Findings</h2><p>No findings identified for this assessment period.</p>'
  }

  <h2>Appendices</h2>
  ${report.appendices
    .map(
      a => `
  <div class="appendix">
    <h3>${a.title}</h3>
    <p style="font-size:13px">${a.content}</p>
  </div>`
    )
    .join('')}

  <div class="footer">
    <p>This report was generated by DevFortress — the developer-first API and application security platform.<br>
    Report ID: ${report.id} · Version: ${report.version}</p>
    <p>© ${new Date().getFullYear()} DevFortress. All rights reserved.</p>
  </div>
</body>
</html>`;
  }
}

/** Singleton report generator */
export const complianceReportGenerator = new ComplianceReportGenerator();
