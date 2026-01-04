/**
 * Infrastructure as Code (IaC) Scanner Service
 * Scans Terraform, CloudFormation, Kubernetes, and other IaC files for security vulnerabilities
 */

import { logInfo, logError, logWarn } from '@core/lib/logger';
import { getOpenAIClient, ensureOpenAIAvailability } from '@core/lib/openai/client';

export interface IaCFile {
  path: string;
  type:
    | 'terraform'
    | 'cloudformation'
    | 'kubernetes'
    | 'ansible'
    | 'docker'
    | 'unknown';
  content: string;
}

export interface IaCVulnerability {
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  description: string;
  file: string;
  line?: number;
  recommendation: string;
  category: string;
  cwe?: string;
}

export interface IaCScanResult {
  scanId: string;
  timestamp: Date;
  filesScanned: number;
  vulnerabilities: IaCVulnerability[];
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  duration: number;
}

export class IaCScannerService {
  /**
   * Detect IaC file type based on content and path
   */
  static detectIaCType(filePath: string, content: string): IaCFile['type'] {
    const lowerPath = filePath.toLowerCase();
    const lowerContent = content.toLowerCase();

    // Terraform
    if (lowerPath.endsWith('.tf') || lowerPath.endsWith('.tfvars')) {
      return 'terraform';
    }
    if (
      lowerContent.includes('resource "') ||
      lowerContent.includes('provider "')
    ) {
      return 'terraform';
    }

    // CloudFormation
    if (lowerPath.endsWith('.yaml') || lowerPath.endsWith('.yml')) {
      if (
        lowerContent.includes('awscloudformation') ||
        lowerContent.includes('resources:')
      ) {
        return 'cloudformation';
      }
    }
    if (lowerPath.endsWith('.json')) {
      if (
        lowerContent.includes('awscloudformation') ||
        lowerContent.includes('"resources"')
      ) {
        return 'cloudformation';
      }
    }

    // Kubernetes
    if (
      lowerContent.includes('apiversion:') &&
      lowerContent.includes('kind:')
    ) {
      return 'kubernetes';
    }

    // Docker
    if (lowerPath === 'dockerfile' || lowerPath.startsWith('dockerfile.')) {
      return 'docker';
    }

    // Ansible
    if (lowerPath.endsWith('.yml') || lowerPath.endsWith('.yaml')) {
      if (
        lowerContent.includes('- hosts:') ||
        lowerContent.includes('ansible')
      ) {
        return 'ansible';
      }
    }

    return 'unknown';
  }

  /**
   * Scan IaC files for vulnerabilities using static analysis rules
   */
  static async scanWithStaticAnalysis(
    iacFile: IaCFile
  ): Promise<IaCVulnerability[]> {
    const vulnerabilities: IaCVulnerability[] = [];
    const lines = iacFile.content.split('\n');

    try {
      logInfo('Running static analysis on IaC file', {
        path: iacFile.path,
        type: iacFile.type,
      });

      // Common security checks across all IaC types
      this.checkForHardcodedSecrets(iacFile, lines, vulnerabilities);
      this.checkForInsecureProtocols(iacFile, lines, vulnerabilities);
      this.checkForPublicExposure(iacFile, lines, vulnerabilities);

      // Type-specific checks
      switch (iacFile.type) {
        case 'terraform':
          this.scanTerraform(iacFile, lines, vulnerabilities);
          break;
        case 'cloudformation':
          this.scanCloudFormation(iacFile, lines, vulnerabilities);
          break;
        case 'kubernetes':
          this.scanKubernetes(iacFile, lines, vulnerabilities);
          break;
        case 'docker':
          this.scanDocker(iacFile, lines, vulnerabilities);
          break;
      }

      return vulnerabilities;
    } catch (error) {
      logError('Static analysis failed', { error, file: iacFile.path });
      throw error;
    }
  }

  /**
   * Check for hardcoded secrets
   */
  private static checkForHardcodedSecrets(
    file: IaCFile,
    lines: string[],
    vulnerabilities: IaCVulnerability[]
  ): void {
    const secretPatterns = [
      { pattern: /password\s*=\s*["'][^"']+["']/i, name: 'password' },
      { pattern: /api[_-]?key\s*=\s*["'][^"']+["']/i, name: 'API key' },
      { pattern: /secret[_-]?key\s*=\s*["'][^"']+["']/i, name: 'secret key' },
      { pattern: /access[_-]?key\s*=\s*["'][^"']+["']/i, name: 'access key' },
      { pattern: /token\s*=\s*["'][^"']+["']/i, name: 'token' },
    ];

    lines.forEach((line, index) => {
      secretPatterns.forEach(secret => {
        if (secret.pattern.test(line)) {
          vulnerabilities.push({
            severity: 'critical',
            title: `Hardcoded ${secret.name} detected`,
            description: `${secret.name} appears to be hardcoded in the configuration. This is a critical security risk.`,
            file: file.path,
            line: index + 1,
            recommendation: `Use environment variables, secret management services (AWS Secrets Manager, HashiCorp Vault, etc.), or encrypted configuration files instead.`,
            category: 'Secrets Management',
            cwe: 'CWE-798',
          });
        }
      });
    });
  }

  /**
   * Check for insecure protocols
   */
  private static checkForInsecureProtocols(
    file: IaCFile,
    lines: string[],
    vulnerabilities: IaCVulnerability[]
  ): void {
    const insecurePatterns = [
      { pattern: /http:\/\//i, protocol: 'HTTP', secure: 'HTTPS' },
      { pattern: /ftp:\/\//i, protocol: 'FTP', secure: 'SFTP or FTPS' },
      { pattern: /telnet/i, protocol: 'Telnet', secure: 'SSH' },
    ];

    lines.forEach((line, index) => {
      insecurePatterns.forEach(check => {
        if (check.pattern.test(line)) {
          vulnerabilities.push({
            severity: 'high',
            title: `Insecure protocol ${check.protocol} used`,
            description: `Using ${check.protocol} can expose data to man-in-the-middle attacks.`,
            file: file.path,
            line: index + 1,
            recommendation: `Replace ${check.protocol} with ${check.secure} for encrypted communication.`,
            category: 'Network Security',
            cwe: 'CWE-319',
          });
        }
      });
    });
  }

  /**
   * Check for public exposure
   */
  private static checkForPublicExposure(
    file: IaCFile,
    lines: string[],
    vulnerabilities: IaCVulnerability[]
  ): void {
    const exposurePatterns = [
      { pattern: /0\.0\.0\.0\/0/, name: 'all IP addresses (0.0.0.0/0)' },
      { pattern: /::\/0/, name: 'all IPv6 addresses (::/0)' },
      { pattern: /\*\.\*\.\*\.\*/, name: 'wildcard IP' },
    ];

    lines.forEach((line, index) => {
      exposurePatterns.forEach(check => {
        if (check.pattern.test(line)) {
          vulnerabilities.push({
            severity: 'high',
            title: 'Overly permissive network access',
            description: `Configuration allows access from ${check.name}, which may expose resources to the public internet.`,
            file: file.path,
            line: index + 1,
            recommendation:
              'Restrict access to specific IP ranges or use security groups with principle of least privilege.',
            category: 'Network Security',
            cwe: 'CWE-284',
          });
        }
      });
    });
  }

  /**
   * Terraform-specific security checks
   */
  private static scanTerraform(
    file: IaCFile,
    lines: string[],
    vulnerabilities: IaCVulnerability[]
  ): void {
    lines.forEach((line, index) => {
      // Check for unencrypted storage
      if (line.includes('encrypted') && line.includes('false')) {
        vulnerabilities.push({
          severity: 'high',
          title: 'Unencrypted storage detected',
          description: 'Storage resource is configured without encryption.',
          file: file.path,
          line: index + 1,
          recommendation:
            'Enable encryption at rest for all storage resources.',
          category: 'Data Protection',
          cwe: 'CWE-311',
        });
      }

      // Check for default VPC usage
      if (line.includes('default') && line.includes('vpc')) {
        vulnerabilities.push({
          severity: 'medium',
          title: 'Using default VPC',
          description: 'Default VPC may have insecure default settings.',
          file: file.path,
          line: index + 1,
          recommendation:
            'Create and use custom VPCs with properly configured security groups.',
          category: 'Network Security',
          cwe: 'CWE-1188',
        });
      }
    });
  }

  /**
   * CloudFormation-specific security checks
   */
  private static scanCloudFormation(
    file: IaCFile,
    lines: string[],
    vulnerabilities: IaCVulnerability[]
  ): void {
    lines.forEach((line, index) => {
      // Check for wildcard IAM permissions
      if (line.includes('Action') && line.includes('*')) {
        vulnerabilities.push({
          severity: 'high',
          title: 'Overly permissive IAM permissions',
          description: 'IAM policy grants wildcard (*) permissions.',
          file: file.path,
          line: index + 1,
          recommendation:
            'Follow principle of least privilege and specify exact actions needed.',
          category: 'Access Control',
          cwe: 'CWE-732',
        });
      }

      // Check for public S3 buckets
      if (line.includes('PublicReadWrite') || line.includes('PublicRead')) {
        vulnerabilities.push({
          severity: 'critical',
          title: 'Publicly accessible S3 bucket',
          description: 'S3 bucket configured with public access.',
          file: file.path,
          line: index + 1,
          recommendation:
            'Remove public access and use IAM policies or pre-signed URLs for controlled access.',
          category: 'Data Protection',
          cwe: 'CWE-266',
        });
      }
    });
  }

  /**
   * Kubernetes-specific security checks
   */
  private static scanKubernetes(
    file: IaCFile,
    lines: string[],
    vulnerabilities: IaCVulnerability[]
  ): void {
    lines.forEach((line, index) => {
      // Check for privileged containers
      if (line.includes('privileged') && line.includes('true')) {
        vulnerabilities.push({
          severity: 'critical',
          title: 'Privileged container detected',
          description: 'Container is configured to run in privileged mode.',
          file: file.path,
          line: index + 1,
          recommendation:
            'Avoid privileged mode. Use specific capabilities instead if elevated permissions are needed.',
          category: 'Container Security',
          cwe: 'CWE-250',
        });
      }

      // Check for host network usage
      if (line.includes('hostNetwork') && line.includes('true')) {
        vulnerabilities.push({
          severity: 'high',
          title: 'Host network mode enabled',
          description: 'Pod uses host network namespace.',
          file: file.path,
          line: index + 1,
          recommendation:
            'Avoid hostNetwork mode unless absolutely necessary. Use service networking instead.',
          category: 'Container Security',
          cwe: 'CWE-653',
        });
      }
    });
  }

  /**
   * Docker-specific security checks
   */
  private static scanDocker(
    file: IaCFile,
    lines: string[],
    vulnerabilities: IaCVulnerability[]
  ): void {
    lines.forEach((line, index) => {
      // Check for running as root
      if (line.toUpperCase().startsWith('USER') && line.includes('root')) {
        vulnerabilities.push({
          severity: 'medium',
          title: 'Container runs as root user',
          description: 'Dockerfile explicitly sets user to root.',
          file: file.path,
          line: index + 1,
          recommendation:
            'Create and use a non-root user for running the application.',
          category: 'Container Security',
          cwe: 'CWE-250',
        });
      }

      // Check for latest tag usage
      if (line.toUpperCase().startsWith('FROM') && line.includes(':latest')) {
        vulnerabilities.push({
          severity: 'low',
          title: 'Using :latest tag',
          description:
            'Base image uses :latest tag which can lead to unpredictable builds.',
          file: file.path,
          line: index + 1,
          recommendation:
            'Pin to specific image versions for reproducible builds.',
          category: 'Container Security',
          cwe: 'CWE-494',
        });
      }
    });
  }

  /**
   * Use AI to analyze IaC for complex vulnerabilities
   */
  static async scanWithAI(iacFile: IaCFile): Promise<IaCVulnerability[]> {
    try {
      logInfo('Running AI analysis on IaC file', {
        path: iacFile.path,
        type: iacFile.type,
      });

      const prompt = `Analyze the following ${iacFile.type} configuration for security vulnerabilities and misconfigurations. Focus on:
1. Security vulnerabilities (access control, encryption, exposure)
2. Compliance issues (best practices, standards)
3. Potential misconfigurations that could lead to security incidents
4. EOL or deprecated resources

File: ${iacFile.path}
Content:
\`\`\`
${iacFile.content}
\`\`\`

Return a JSON array of vulnerabilities with this structure:
[
  {
    "severity": "critical|high|medium|low|info",
    "title": "Short title",
    "description": "Detailed description",
    "line": <line number if applicable>,
    "recommendation": "How to fix",
    "category": "Category name",
    "cwe": "CWE ID if applicable"
  }
]

Only return valid JSON, no additional text.`;

      ensureOpenAIAvailability();
      const client = getOpenAIClient();

      const response = await client.chat.completions.create({
        model: 'gpt-4o-mini',
        messages: [
          {
            role: 'system',
            content:
              'You are a security expert specializing in Infrastructure as Code analysis. Provide accurate, actionable security findings in valid JSON format.',
          },
          { role: 'user', content: prompt },
        ],
        temperature: 0.3,
        max_tokens: 2000,
      });

      const content = response.choices[0].message.content || '[]';
      const aiVulnerabilities = JSON.parse(content) as IaCVulnerability[];

      // Add file path to each vulnerability
      return aiVulnerabilities.map(vuln => ({
        ...vuln,
        file: iacFile.path,
      }));
    } catch (error) {
      logError('AI analysis failed', { error, file: iacFile.path });
      // Return empty array on failure, don't block the scan
      return [];
    }
  }

  /**
   * Comprehensive scan combining static analysis and AI
   */
  static async scanFiles(
    files: IaCFile[],
    useAI: boolean = true
  ): Promise<IaCScanResult> {
    const startTime = Date.now();
    const scanId = `iac-scan-${Date.now()}`;

    logInfo('Starting IaC scan', { scanId, filesCount: files.length, useAI });

    const allVulnerabilities: IaCVulnerability[] = [];

    for (const file of files) {
      // Static analysis (always run)
      const staticVulns = await this.scanWithStaticAnalysis(file);
      allVulnerabilities.push(...staticVulns);

      // AI analysis (optional, for deeper insights)
      if (useAI && file.type !== 'unknown') {
        try {
          const aiVulns = await this.scanWithAI(file);
          // Merge AI findings, avoiding duplicates
          aiVulns.forEach(aiVuln => {
            const isDuplicate = allVulnerabilities.some(
              existing =>
                existing.title === aiVuln.title &&
                existing.file === aiVuln.file &&
                existing.line === aiVuln.line
            );
            if (!isDuplicate) {
              allVulnerabilities.push(aiVuln);
            }
          });
        } catch (error) {
          logWarn(
            'AI scan failed for file, continuing with static analysis only',
            {
              file: file.path,
              error,
            }
          );
        }
      }
    }

    const duration = Date.now() - startTime;

    const summary = {
      critical: allVulnerabilities.filter(v => v.severity === 'critical')
        .length,
      high: allVulnerabilities.filter(v => v.severity === 'high').length,
      medium: allVulnerabilities.filter(v => v.severity === 'medium').length,
      low: allVulnerabilities.filter(v => v.severity === 'low').length,
      info: allVulnerabilities.filter(v => v.severity === 'info').length,
    };

    logInfo('IaC scan completed', {
      scanId,
      filesScanned: files.length,
      vulnerabilitiesFound: allVulnerabilities.length,
      duration,
    });

    return {
      scanId,
      timestamp: new Date(),
      filesScanned: files.length,
      vulnerabilities: allVulnerabilities,
      summary,
      duration,
    };
  }
}
