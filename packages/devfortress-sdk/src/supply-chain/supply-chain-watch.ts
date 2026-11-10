import * as fs from 'fs';
import * as path from 'path';

export interface CveDatabaseEntry {
  cveId: string;
  packageName: string;
  vulnerableVersionRange: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  description: string;
}

export interface VulnerabilityAlert {
  packageName: string;
  installedVersion: string;
  cveId: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  description: string;
}

export interface SupplyChainConfig {
  enableRuntimeScanning: boolean;
  enableContinuousMonitoring: boolean;
  alertOnSeverity: Array<'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'>;
  blockOnSeverity?: Array<'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'>; // If set, block execution (e.g. by throwing)
  cveDatabasePath?: string; // Path to a local JSON CVE DB, optional
}

export class SupplyChainWatch {
  private readonly config: SupplyChainConfig;
  private cveDatabase: CveDatabaseEntry[] = [];
  private installedPackages: Map<string, string> = new Map();
  private scanInterval: NodeJS.Timeout | null = null;

  constructor(
    config: SupplyChainConfig = {
      enableRuntimeScanning: true,
      enableContinuousMonitoring: true,
      alertOnSeverity: ['HIGH', 'CRITICAL'],
    }
  ) {
    this.config = config;
    if (this.config.enableRuntimeScanning) {
      this.loadMockCveDatabase(); // In reality, fetch from an OSV/NVD API or load local file
      this.scanDependencies();

      if (this.config.enableContinuousMonitoring) {
        // Scan every hour
        this.scanInterval = setInterval(
          () => this.scanDependencies(),
          60 * 60 * 1000
        );
      }
    }
  }

  // Very basic mock DB for demonstration. Real implementation would use semver checking.
  private loadMockCveDatabase() {
    this.cveDatabase = [
      {
        cveId: 'CVE-2023-XXXX1',
        packageName: 'lodash',
        vulnerableVersionRange: '<4.17.21', // Simplified
        severity: 'HIGH',
        description: 'Prototype pollution in lodash',
      },
      {
        cveId: 'CVE-2024-XXXX2',
        packageName: 'express',
        vulnerableVersionRange: '<4.19.2',
        severity: 'CRITICAL',
        description: 'Path traversal in express',
      },
    ];
  }

  public scanDependencies(): VulnerabilityAlert[] {
    const alerts: VulnerabilityAlert[] = [];
    this.installedPackages.clear();

    try {
      // Attempt to read package.json in the current working directory
      const pkgJsonPath = path.resolve(process.cwd(), 'package.json');
      if (fs.existsSync(pkgJsonPath)) {
        const pkgData = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'));
        const deps = { ...pkgData.dependencies, ...pkgData.devDependencies };

        for (const [name, version] of Object.entries(deps)) {
          const cleanVersion = (version as string).replace(/[\^~]/g, ''); // Naive semver clean
          this.installedPackages.set(name, cleanVersion);

          // Check against DB
          const vulnerability = this.checkPackage(name, cleanVersion);
          if (vulnerability) {
            alerts.push(vulnerability);
            this.handleVulnerability(vulnerability);
          }
        }
      }
    } catch (e) {
      console.error(
        '[DevFortress SupplyChainWatch] Error scanning dependencies:',
        e
      );
    }

    return alerts;
  }

  private checkPackage(
    name: string,
    version: string
  ): VulnerabilityAlert | null {
    // Very naive check for demonstration purposes. Needs actual semver library.
    for (const entry of this.cveDatabase) {
      if (entry.packageName === name) {
        // Simplified: just assuming it matches if the name matches for this demo
        if (this.config.alertOnSeverity.includes(entry.severity)) {
          return {
            packageName: name,
            installedVersion: version,
            cveId: entry.cveId,
            severity: entry.severity,
            description: entry.description,
          };
        }
      }
    }
    return null;
  }

  private handleVulnerability(alert: VulnerabilityAlert) {
    console.warn(
      `[DevFortress SECURITY ALERT] Vulnerable package detected: ${alert.packageName}@${alert.installedVersion} (${alert.cveId}) - ${alert.severity}`
    );

    if (this.config.blockOnSeverity?.includes(alert.severity)) {
      throw new Error(
        `[DevFortress] Execution blocked due to ${alert.severity} vulnerability in ${alert.packageName}`
      );
    }
    // In a real implementation, this would also send telemetry to the DevFortress ECL
  }

  public generateSbom(): any {
    const sbom: any = {
      bomFormat: 'CycloneDX',
      specVersion: '1.4',
      version: 1,
      components: [],
    };

    for (const [name, version] of this.installedPackages.entries()) {
      sbom.components.push({
        type: 'library',
        name: name,
        version: version,
        purl: `pkg:npm/${name}@${version}`,
      });
    }
    return sbom;
  }

  public stopMonitoring() {
    if (this.scanInterval) {
      clearInterval(this.scanInterval);
      this.scanInterval = null;
    }
  }
}
