/**
 * End-of-Life (EOL) Tracking Service
 * Tracks and alerts on EOL/deprecated dependencies and infrastructure components
 */

import { logInfo, logError } from '@core/lib/logger';

export interface EOLPackage {
  name: string;
  version: string;
  type: 'dependency' | 'runtime' | 'infrastructure' | 'framework';
  eolDate?: Date;
  status: 'active' | 'approaching_eol' | 'eol' | 'deprecated';
  latestVersion?: string;
  migrationPath?: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
}

export interface EOLScanResult {
  scanId: string;
  timestamp: Date;
  packagesChecked: number;
  eolPackages: EOLPackage[];
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
}

/**
 * EOL database - in production, this would be fetched from an API like endoflife.date
 */
const EOL_DATABASE: Record<string, { eolDate: Date; latestVersion: string }> = {
  // Node.js versions
  'node-14': { eolDate: new Date('2023-04-30'), latestVersion: '20.x' },
  'node-16': { eolDate: new Date('2024-09-11'), latestVersion: '20.x' },
  'node-18': { eolDate: new Date('2025-04-30'), latestVersion: '20.x' },

  // Python versions
  'python-3.7': { eolDate: new Date('2023-06-27'), latestVersion: '3.12' },
  'python-3.8': { eolDate: new Date('2024-10-14'), latestVersion: '3.12' },
  'python-3.9': { eolDate: new Date('2025-10-05'), latestVersion: '3.12' },

  // Java versions
  'java-8': { eolDate: new Date('2030-12-31'), latestVersion: '21' },
  'java-11': { eolDate: new Date('2026-09-30'), latestVersion: '21' },

  // Databases
  'postgresql-11': { eolDate: new Date('2023-11-09'), latestVersion: '16' },
  'postgresql-12': { eolDate: new Date('2024-11-14'), latestVersion: '16' },
  'mysql-5.7': { eolDate: new Date('2023-10-31'), latestVersion: '8.0' },

  // Frameworks
  'express-4': { eolDate: new Date('2025-12-31'), latestVersion: '5.x' },
  'django-3.2': { eolDate: new Date('2024-04-01'), latestVersion: '5.0' },
  'react-17': { eolDate: new Date('2024-06-01'), latestVersion: '18.x' },

  // Infrastructure
  'ubuntu-18.04': { eolDate: new Date('2023-05-31'), latestVersion: '22.04' },
  'ubuntu-20.04': { eolDate: new Date('2025-04-02'), latestVersion: '22.04' },
  'debian-10': { eolDate: new Date('2024-06-30'), latestVersion: '12' },
};

export class EOLTrackerService {
  /**
   * Check if a package is EOL or approaching EOL
   */
  static checkEOLStatus(
    name: string,
    version: string,
    type: EOLPackage['type']
  ): EOLPackage {
    const key = `${name}-${version.split('.')[0]}`;
    const eolInfo = EOL_DATABASE[key];

    const now = new Date();
    const threeMonthsFromNow = new Date();
    threeMonthsFromNow.setMonth(now.getMonth() + 3);

    let status: EOLPackage['status'] = 'active';
    let severity: EOLPackage['severity'] = 'low';

    if (eolInfo) {
      if (eolInfo.eolDate < now) {
        status = 'eol';
        severity = 'critical';
      } else if (eolInfo.eolDate < threeMonthsFromNow) {
        status = 'approaching_eol';
        severity = 'high';
      }
    }

    return {
      name,
      version,
      type,
      eolDate: eolInfo?.eolDate,
      status,
      latestVersion: eolInfo?.latestVersion,
      severity,
      migrationPath: this.getMigrationPath(
        name,
        version,
        eolInfo?.latestVersion
      ),
    };
  }

  /**
   * Generate migration guidance
   */
  private static getMigrationPath(
    name: string,
    currentVersion: string,
    latestVersion?: string
  ): string {
    if (!latestVersion) {
      return 'Check official documentation for latest version.';
    }

    const migrations: Record<string, string> = {
      node: 'Update package.json engines field and run npm install. Test thoroughly before deploying.',
      python:
        'Update Dockerfile or runtime configuration. Check for deprecated syntax and libraries.',
      postgresql:
        'Plan database migration with pg_dump and restore. Test queries for compatibility.',
      mysql:
        'Use MySQL Workbench migration tool or mysqldump. Verify stored procedures and triggers.',
      express:
        'Review Express.js migration guide. Update middleware and error handling.',
      django:
        'Follow Django upgrade guide. Update settings and deprecated APIs.',
      react:
        'Update React and ReactDOM. Migrate class components to hooks if needed.',
      ubuntu:
        'Plan OS upgrade with do-release-upgrade. Backup data and test applications.',
      debian:
        'Follow Debian upgrade guide. Update /etc/apt/sources.list and run apt dist-upgrade.',
    };

    const baseName = name.split('-')[0];
    return (
      migrations[baseName] ||
      `Upgrade from ${currentVersion} to ${latestVersion}. Check official documentation for breaking changes.`
    );
  }

  /**
   * Parse package.json for Node.js dependencies
   */
  static parsePackageJson(content: string): EOLPackage[] {
    const packages: EOLPackage[] = [];

    try {
      const packageJson = JSON.parse(content);

      // Check Node.js engine version
      if (packageJson.engines?.node) {
        const nodeVersion = packageJson.engines.node.replace(/[^0-9.]/g, '');
        packages.push(this.checkEOLStatus('node', nodeVersion, 'runtime'));
      }

      // Check dependencies (sample - in production, check all)
      const deps = {
        ...packageJson.dependencies,
        ...packageJson.devDependencies,
      };
      const knownFrameworks = ['express', 'react', 'django', 'fastapi'];

      Object.entries(deps).forEach(([name, version]) => {
        if (knownFrameworks.includes(name)) {
          const versionStr = String(version).replace(/[^0-9.]/g, '');
          packages.push(this.checkEOLStatus(name, versionStr, 'framework'));
        }
      });
    } catch (error) {
      logError('Failed to parse package.json', { error });
    }

    return packages;
  }

  /**
   * Parse requirements.txt for Python dependencies
   */
  static parseRequirementsTxt(content: string): EOLPackage[] {
    const packages: EOLPackage[] = [];
    const lines = content.split('\n');

    lines.forEach(line => {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) return;

      const match = trimmed.match(/^([a-zA-Z0-9-_]+)[>=<~]+([0-9.]+)/);
      if (match) {
        const [, name, version] = match;
        if (['django', 'fastapi', 'flask'].includes(name.toLowerCase())) {
          packages.push(
            this.checkEOLStatus(name.toLowerCase(), version, 'framework')
          );
        }
      }
    });

    return packages;
  }

  /**
   * Parse Dockerfile for base images
   */
  static parseDockerfile(content: string): EOLPackage[] {
    const packages: EOLPackage[] = [];
    const lines = content.split('\n');

    lines.forEach(line => {
      if (line.toUpperCase().startsWith('FROM')) {
        const match = line.match(/FROM\s+([a-z-]+):([0-9.]+)/i);
        if (match) {
          const [, name, version] = match;
          if (['node', 'python', 'ubuntu', 'debian'].includes(name)) {
            packages.push(this.checkEOLStatus(name, version, 'infrastructure'));
          }
        }
      }
    });

    return packages;
  }

  /**
   * Comprehensive EOL scan across multiple file types
   */
  static async scanProject(
    files: Record<string, string>
  ): Promise<EOLScanResult> {
    const scanId = `eol-scan-${Date.now()}`;
    const timestamp = new Date();

    logInfo('Starting EOL scan', {
      scanId,
      filesCount: Object.keys(files).length,
    });

    const allPackages: EOLPackage[] = [];

    // Scan each file type
    Object.entries(files).forEach(([path, content]) => {
      if (path.endsWith('package.json')) {
        allPackages.push(...this.parsePackageJson(content));
      } else if (path.endsWith('requirements.txt')) {
        allPackages.push(...this.parseRequirementsTxt(content));
      } else if (path.toLowerCase().includes('dockerfile')) {
        allPackages.push(...this.parseDockerfile(content));
      }
    });

    // Filter to only EOL or approaching EOL packages
    const eolPackages = allPackages.filter(
      pkg => pkg.status === 'eol' || pkg.status === 'approaching_eol'
    );

    const summary = {
      critical: eolPackages.filter(p => p.severity === 'critical').length,
      high: eolPackages.filter(p => p.severity === 'high').length,
      medium: eolPackages.filter(p => p.severity === 'medium').length,
      low: eolPackages.filter(p => p.severity === 'low').length,
    };

    logInfo('EOL scan completed', {
      scanId,
      packagesChecked: allPackages.length,
      eolPackagesFound: eolPackages.length,
    });

    return {
      scanId,
      timestamp,
      packagesChecked: allPackages.length,
      eolPackages,
      summary,
    };
  }

  /**
   * Get EOL status for specific package
   */
  static getPackageEOLInfo(name: string, version: string): EOLPackage | null {
    const key = `${name}-${version.split('.')[0]}`;
    const eolInfo = EOL_DATABASE[key];

    if (!eolInfo) {
      return null;
    }

    return this.checkEOLStatus(name, version, 'dependency');
  }

  /**
   * Check if package should trigger alert
   */
  static shouldAlert(pkg: EOLPackage): boolean {
    return (
      pkg.status === 'eol' ||
      (pkg.status === 'approaching_eol' && pkg.severity === 'high')
    );
  }
}
