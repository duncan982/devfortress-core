/**
 * OWASP ZAP Security Scanner Integration
 * Automates security scanning with OWASP ZAP
 */

import { exec } from 'child_process';
import { promisify } from 'util';
import { logInfo, logError, logWarn } from '../logger';
import { prisma } from '../prisma';
import fs from 'fs/promises';
import path from 'path';

const execAsync = promisify(exec);

export interface ZAPScanConfig {
  targetUrl: string;
  scanType: 'baseline' | 'full' | 'api';
  apiDefinitionUrl?: string; // For API scans (OpenAPI/Swagger)
  maxDuration?: number; // Max scan duration in minutes
  alertThreshold?: 'high' | 'medium' | 'low' | 'informational';
}

export interface ZAPAlert {
  alert: string;
  risk: 'High' | 'Medium' | 'Low' | 'Informational';
  confidence: 'High' | 'Medium' | 'Low';
  url: string;
  description: string;
  solution: string;
  reference: string;
  cweid?: string;
  wascid?: string;
}

export interface ZAPScanResult {
  scanId: string;
  targetUrl: string;
  scanType: string;
  startTime: Date;
  endTime: Date;
  duration: number; // seconds
  alertCounts: {
    high: number;
    medium: number;
    low: number;
    informational: number;
  };
  alerts: ZAPAlert[];
  reportPath?: string;
}

export class OWASPZAPScanner {
  private zapDockerImage = 'ghcr.io/zaproxy/zaproxy:stable';
  private reportsDir = path.join(process.cwd(), 'reports', 'security');

  /**
   * Check if ZAP is available (via Docker)
   */
  async isAvailable(): Promise<boolean> {
    try {
      await execAsync('docker --version');
      logInfo('Docker is available for ZAP scanning');
      return true;
    } catch (error) {
      logWarn('Docker not available - ZAP scanning disabled', { error });
      return false;
    }
  }

  /**
   * Run OWASP ZAP baseline scan
   */
  async runBaselineScan(config: ZAPScanConfig): Promise<ZAPScanResult> {
    try {
      logInfo('Starting OWASP ZAP baseline scan', {
        targetUrl: config.targetUrl,
      });

      const scanId = `scan-${Date.now()}`;
      const reportPath = path.join(this.reportsDir, `${scanId}.json`);
      const startTime = new Date();

      // Ensure reports directory exists
      await fs.mkdir(this.reportsDir, { recursive: true });

      // Run ZAP baseline scan
      const cmd = this.buildZAPCommand(config, reportPath);

      try {
        const { stdout, stderr } = await execAsync(cmd, {
          maxBuffer: 10 * 1024 * 1024, // 10MB buffer
          timeout: (config.maxDuration || 30) * 60 * 1000,
        });

        logInfo('ZAP scan output', {
          stdout: stdout.substring(0, 500),
          stderr: stderr.substring(0, 500),
        });
      } catch (execError: unknown) {
        // ZAP may exit with non-zero status if it finds vulnerabilities
        // This is expected behavior, so we continue
        const error = execError as {
          code?: number;
          stdout?: string;
          stderr?: string;
        };
        if (error.code !== 2 && error.code !== 1) {
          // Exit codes 1-2 are expected (vulnerabilities found)
          throw execError;
        }
        logInfo('ZAP scan completed with findings', { exitCode: error.code });
      }

      const endTime = new Date();
      const duration = Math.floor(
        (endTime.getTime() - startTime.getTime()) / 1000
      );

      // Parse report
      const result = await this.parseReport(
        reportPath,
        scanId,
        config,
        startTime,
        endTime,
        duration
      );

      // Store in database
      await this.storeScanResult(result);

      logInfo('OWASP ZAP scan completed', {
        scanId,
        duration,
        alertCounts: result.alertCounts,
      });

      return result;
    } catch (error) {
      logError('Error running OWASP ZAP scan', { error, config });
      throw error;
    }
  }

  /**
   * Build ZAP Docker command
   */
  private buildZAPCommand(config: ZAPScanConfig, reportPath: string): string {
    const reportDir = path.dirname(reportPath);
    const reportFileName = path.basename(reportPath);

    let cmd = `docker run --rm `;

    // Mount report directory
    cmd += `-v "${reportDir}:/zap/wrk:rw" `;

    // Add ZAP image
    cmd += `${this.zapDockerImage} `;

    // Choose scan type
    switch (config.scanType) {
      case 'baseline':
        cmd += `zap-baseline.py -t ${config.targetUrl} -J ${reportFileName}`;
        break;
      case 'full':
        cmd += `zap-full-scan.py -t ${config.targetUrl} -J ${reportFileName}`;
        break;
      case 'api':
        if (config.apiDefinitionUrl) {
          cmd += `zap-api-scan.py -t ${config.targetUrl} -f openapi -O ${config.apiDefinitionUrl} -J ${reportFileName}`;
        } else {
          cmd += `zap-baseline.py -t ${config.targetUrl} -J ${reportFileName}`;
        }
        break;
    }

    // Add additional flags
    cmd += ` -I`; // Ignore warning about not being able to access GUI

    return cmd;
  }

  /**
   * Parse ZAP JSON report
   */
  private async parseReport(
    reportPath: string,
    scanId: string,
    config: ZAPScanConfig,
    startTime: Date,
    endTime: Date,
    duration: number
  ): Promise<ZAPScanResult> {
    try {
      const reportContent = await fs.readFile(reportPath, 'utf-8');
      const report = JSON.parse(reportContent);

      const alerts: ZAPAlert[] = [];
      const alertCounts = {
        high: 0,
        medium: 0,
        low: 0,
        informational: 0,
      };

      // Parse site alerts
      if (report.site && Array.isArray(report.site)) {
        for (const site of report.site) {
          if (site.alerts && Array.isArray(site.alerts)) {
            for (const alert of site.alerts) {
              const zapAlert: ZAPAlert = {
                alert: alert.name || alert.alert,
                risk: alert.riskdesc?.split(' ')[0] || alert.risk,
                confidence: alert.confidence,
                url: alert.url || site['@host'],
                description: alert.desc || alert.description,
                solution: alert.solution,
                reference: alert.reference,
                cweid: alert.cweid,
                wascid: alert.wascid,
              };

              alerts.push(zapAlert);

              // Count by risk level
              const risk = zapAlert.risk.toLowerCase();
              if (risk.includes('high')) alertCounts.high++;
              else if (risk.includes('medium')) alertCounts.medium++;
              else if (risk.includes('low')) alertCounts.low++;
              else alertCounts.informational++;
            }
          }
        }
      }

      return {
        scanId,
        targetUrl: config.targetUrl,
        scanType: config.scanType,
        startTime,
        endTime,
        duration,
        alertCounts,
        alerts,
        reportPath,
      };
    } catch (error) {
      logError('Error parsing ZAP report', { error, reportPath });

      // Return minimal result on parse error
      return {
        scanId,
        targetUrl: config.targetUrl,
        scanType: config.scanType,
        startTime,
        endTime,
        duration,
        alertCounts: {
          high: 0,
          medium: 0,
          low: 0,
          informational: 0,
        },
        alerts: [],
        reportPath,
      };
    }
  }

  /**
   * Store scan result in database
   */
  private async storeScanResult(result: ZAPScanResult): Promise<void> {
    try {
       
      const prismaAny = prisma as any;
      await prismaAny.securityScan.create({
        data: {
          scanId: result.scanId,
          targetUrl: result.targetUrl,
          scanType: result.scanType,
          startTime: result.startTime,
          endTime: result.endTime,
          duration: result.duration,
          highAlerts: result.alertCounts.high,
          mediumAlerts: result.alertCounts.medium,
          lowAlerts: result.alertCounts.low,
          infoAlerts: result.alertCounts.informational,
          alerts: result.alerts,
          reportPath: result.reportPath,
        },
      });

      logInfo('Stored security scan result in database', {
        scanId: result.scanId,
      });
    } catch (error) {
      logError('Error storing security scan result', {
        error,
        scanId: result.scanId,
      });
      // Don't throw - scan was successful even if storage failed
    }
  }

  /**
   * Get scan results from database
   */
  async getScanResults(filters: {
    limit?: number;
    targetUrl?: string;
    minSeverity?: 'high' | 'medium' | 'low';
  }): Promise<ZAPScanResult[]> {
    try {
       
      const prismaAny = prisma as any;
       
      const where: any = {};

      if (filters.targetUrl) {
        where.targetUrl = filters.targetUrl;
      }

      if (filters.minSeverity === 'high') {
        where.highAlerts = { gt: 0 };
      } else if (filters.minSeverity === 'medium') {
        where.OR = [{ highAlerts: { gt: 0 } }, { mediumAlerts: { gt: 0 } }];
      }

      const scans = await prismaAny.securityScan.findMany({
        where,
        orderBy: { startTime: 'desc' },
        take: filters.limit || 10,
      });

      return scans.map(
        (scan: {
          scanId: string;
          targetUrl: string;
          scanType: string;
          startTime: Date;
          endTime: Date;
          duration: number;
          highAlerts: number;
          mediumAlerts: number;
          lowAlerts: number;
          infoAlerts: number;
          alerts: ZAPAlert[];
          reportPath: string;
        }) => ({
          scanId: scan.scanId,
          targetUrl: scan.targetUrl,
          scanType: scan.scanType,
          startTime: scan.startTime,
          endTime: scan.endTime,
          duration: scan.duration,
          alertCounts: {
            high: scan.highAlerts,
            medium: scan.mediumAlerts,
            low: scan.lowAlerts,
            informational: scan.infoAlerts,
          },
          alerts: scan.alerts,
          reportPath: scan.reportPath,
        })
      );
    } catch (error) {
      logError('Error fetching security scan results', { error });
      return [];
    }
  }
}

// Singleton instance
export const owaspScanner = new OWASPZAPScanner();
