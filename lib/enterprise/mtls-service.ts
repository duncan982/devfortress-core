/**
 * mTLS (Mutual TLS) Certificate Authentication Service
 * Enterprise-tier feature: Client certificate-based API authentication
 * Provides certificate generation, validation, rotation, and revocation
 */

import { logInfo, logError, logWarn } from '@core/lib/logger';

/* ─── Types ─── */

export enum CertificateStatus {
  ACTIVE = 'active',
  PENDING = 'pending',
  REVOKED = 'revoked',
  EXPIRED = 'expired',
  ROTATING = 'rotating',
}

export enum CertificateType {
  ROOT_CA = 'root_ca',
  INTERMEDIATE_CA = 'intermediate_ca',
  CLIENT = 'client',
  SERVER = 'server',
}

export interface CertificateRecord {
  id: string;
  orgId: string;
  type: CertificateType;
  status: CertificateStatus;
  commonName: string;
  serialNumber: string;
  fingerprint: string;
  issuer: string;
  subject: string;
  validFrom: Date;
  validUntil: Date;
  createdAt: Date;
  revokedAt: Date | null;
  revocationReason: string | null;
  /** The certificate chain (PEM) — only included in provisioning response */
  certificatePEM?: string;
  metadata: Record<string, unknown>;
}

export interface CertificateRequest {
  orgId: string;
  commonName: string;
  validityDays: number;
  type: CertificateType;
  allowedEndpoints?: string[];
  ipRestrictions?: string[];
  metadata?: Record<string, unknown>;
}

export interface CertificateProvisionResult {
  success: boolean;
  certificate: CertificateRecord | null;
  /** Base64-encoded PKCS12 bundle (cert + key) — returned only once */
  pkcs12Bundle?: string;
  message: string;
}

export interface CertificateValidationResult {
  valid: boolean;
  certificate: CertificateRecord | null;
  reason: string;
  checks: {
    exists: boolean;
    notRevoked: boolean;
    notExpired: boolean;
    chainValid: boolean;
    orgMatch: boolean;
  };
}

export interface mTLSConfig {
  orgId: string;
  enabled: boolean;
  enforceForAllEndpoints: boolean;
  /** Endpoints that require mTLS (if not enforcing globally) */
  requiredEndpoints: string[];
  /** Certificate auto-rotation settings */
  autoRotation: {
    enabled: boolean;
    daysBeforeExpiry: number;
    notifyDays: number[];
  };
  /** Maximum certificate validity */
  maxValidityDays: number;
  /** Allowed key algorithms */
  allowedKeyAlgorithms: string[];
  createdAt: Date;
  updatedAt: Date;
}

/* ─── Default Configuration ─── */

const DEFAULT_MTLS_CONFIG: Omit<
  mTLSConfig,
  'orgId' | 'createdAt' | 'updatedAt'
> = {
  enabled: false,
  enforceForAllEndpoints: false,
  requiredEndpoints: [],
  autoRotation: {
    enabled: true,
    daysBeforeExpiry: 30,
    notifyDays: [90, 60, 30, 14, 7, 1],
  },
  maxValidityDays: 365,
  allowedKeyAlgorithms: ['RSA-2048', 'RSA-4096', 'ECDSA-P256', 'ECDSA-P384'],
};

/* ─── Service ─── */

class MTLSService {
  private certificates: Map<string, CertificateRecord> = new Map();
  private configs: Map<string, mTLSConfig> = new Map();
  private serialCounter = 1000;

  constructor() {
    logInfo('MTLSService initialized', {
      defaultMaxValidity: DEFAULT_MTLS_CONFIG.maxValidityDays,
      allowedAlgorithms: DEFAULT_MTLS_CONFIG.allowedKeyAlgorithms,
    });
  }

  /**
   * Configure mTLS for an organization
   */
  configureOrg(
    orgId: string,
    config?: Partial<Omit<mTLSConfig, 'orgId' | 'createdAt' | 'updatedAt'>>
  ): mTLSConfig {
    const now = new Date();
    const fullConfig: mTLSConfig = {
      ...DEFAULT_MTLS_CONFIG,
      ...config,
      orgId,
      createdAt: this.configs.get(orgId)?.createdAt || now,
      updatedAt: now,
    };

    this.configs.set(orgId, fullConfig);
    logInfo('mTLS configuration updated', {
      orgId,
      enabled: fullConfig.enabled,
    });
    return fullConfig;
  }

  /**
   * Get mTLS configuration for an organization
   */
  getConfig(orgId: string): mTLSConfig | null {
    return this.configs.get(orgId) || null;
  }

  /**
   * Provision a new client certificate
   */
  provisionCertificate(
    request: CertificateRequest
  ): CertificateProvisionResult {
    try {
      const config = this.configs.get(request.orgId);
      if (!config?.enabled) {
        return {
          success: false,
          certificate: null,
          message: 'mTLS is not enabled for this organization',
        };
      }

      if (request.validityDays > config.maxValidityDays) {
        return {
          success: false,
          certificate: null,
          message: `Validity exceeds maximum of ${config.maxValidityDays} days`,
        };
      }

      this.serialCounter += 1;
      const serialNumber = `DF${this.serialCounter.toString(16).toUpperCase().padStart(8, '0')}`;
      const id = `cert_${request.orgId}_${Date.now()}_${this.serialCounter}`;
      const now = new Date();
      const validUntil = new Date(
        now.getTime() + request.validityDays * 24 * 60 * 60 * 1000
      );

      // Generate fingerprint (simulated - in production, derived from actual cert)
      const fingerprint = this.generateFingerprint();

      const certificate: CertificateRecord = {
        id,
        orgId: request.orgId,
        type: request.type,
        status: CertificateStatus.ACTIVE,
        commonName: request.commonName,
        serialNumber,
        fingerprint,
        issuer: 'CN=DevFortress CA,O=DevFortress,C=US',
        subject: `CN=${request.commonName},O=Org-${request.orgId}`,
        validFrom: now,
        validUntil,
        createdAt: now,
        revokedAt: null,
        revocationReason: null,
        metadata: {
          ...request.metadata,
          allowedEndpoints: request.allowedEndpoints || [],
          ipRestrictions: request.ipRestrictions || [],
          algorithm: 'ECDSA-P256',
          keySize: 256,
        },
      };

      this.certificates.set(id, certificate);

      logInfo('Client certificate provisioned', {
        id,
        orgId: request.orgId,
        commonName: request.commonName,
        serialNumber,
        validUntil: validUntil.toISOString(),
        type: request.type,
      });

      return {
        success: true,
        certificate,
        // In production, this would be a real PKCS12 bundle
        pkcs12Bundle: Buffer.from(`simulated-pkcs12-bundle-${id}`).toString(
          'base64'
        ),
        message: `Certificate provisioned successfully. Valid until ${validUntil.toISOString()}`,
      };
    } catch (error) {
      logError('Failed to provision certificate', { request, error });
      return {
        success: false,
        certificate: null,
        message: `Failed to provision certificate: ${error instanceof Error ? error.message : 'Unknown error'}`,
      };
    }
  }

  /**
   * Validate an incoming client certificate
   */
  validateCertificate(
    fingerprint: string,
    orgId: string
  ): CertificateValidationResult {
    const certificate = Array.from(this.certificates.values()).find(
      c => c.fingerprint === fingerprint
    );

    const checks = {
      exists: !!certificate,
      notRevoked:
        !!certificate && certificate.status !== CertificateStatus.REVOKED,
      notExpired: !!certificate && new Date() < certificate.validUntil,
      chainValid: !!certificate, // Simplified — in production, verify full chain
      orgMatch: !!certificate && certificate.orgId === orgId,
    };

    const valid = Object.values(checks).every(Boolean);

    if (!valid && certificate) {
      logWarn('Certificate validation failed', {
        fingerprint,
        orgId,
        certificateOrg: certificate.orgId,
        status: certificate.status,
        checks,
      });
    }

    return {
      valid,
      certificate: certificate || null,
      reason: valid
        ? 'Certificate is valid'
        : !checks.exists
          ? 'Certificate not found'
          : !checks.notRevoked
            ? 'Certificate has been revoked'
            : !checks.notExpired
              ? 'Certificate has expired'
              : !checks.orgMatch
                ? 'Certificate does not belong to this organization'
                : 'Certificate chain validation failed',
      checks,
    };
  }

  /**
   * Revoke a certificate
   */
  revokeCertificate(id: string, reason: string): boolean {
    const cert = this.certificates.get(id);
    if (!cert) return false;

    cert.status = CertificateStatus.REVOKED;
    cert.revokedAt = new Date();
    cert.revocationReason = reason;
    this.certificates.set(id, cert);

    logWarn('Certificate revoked', {
      id,
      orgId: cert.orgId,
      commonName: cert.commonName,
      serialNumber: cert.serialNumber,
      reason,
    });

    return true;
  }

  /**
   * Rotate a certificate (provision new, mark old for revocation)
   */
  rotateCertificate(id: string): CertificateProvisionResult {
    const oldCert = this.certificates.get(id);
    if (!oldCert) {
      return {
        success: false,
        certificate: null,
        message: 'Certificate not found',
      };
    }

    // Mark old cert as rotating
    oldCert.status = CertificateStatus.ROTATING;
    this.certificates.set(id, oldCert);

    // Provision new certificate with same parameters
    const result = this.provisionCertificate({
      orgId: oldCert.orgId,
      commonName: oldCert.commonName,
      validityDays: this.configs.get(oldCert.orgId)?.maxValidityDays || 365,
      type: oldCert.type,
      metadata: {
        ...oldCert.metadata,
        rotatedFrom: id,
      },
    });

    if (result.success) {
      // Revoke old certificate after grace period would be applied in production
      logInfo('Certificate rotation initiated', {
        oldCertId: id,
        newCertId: result.certificate?.id,
        orgId: oldCert.orgId,
      });
    }

    return result;
  }

  /**
   * Get certificates for an organization
   */
  getCertificatesByOrg(orgId: string): CertificateRecord[] {
    return Array.from(this.certificates.values())
      .filter(c => c.orgId === orgId)
      .map(c => ({ ...c, certificatePEM: undefined })); // Strip PEM from listings
  }

  /**
   * Get certificates approaching expiry
   */
  getExpiringCertificates(daysThreshold: number = 30): CertificateRecord[] {
    const threshold = new Date(
      Date.now() + daysThreshold * 24 * 60 * 60 * 1000
    );
    return Array.from(this.certificates.values()).filter(
      c => c.status === CertificateStatus.ACTIVE && c.validUntil <= threshold
    );
  }

  /**
   * Get service statistics
   */
  getStats(): {
    totalCertificates: number;
    activeCertificates: number;
    revokedCertificates: number;
    expiredCertificates: number;
    orgsWithMTLS: number;
    certsByType: Record<string, number>;
  } {
    const certsByType: Record<string, number> = {};
    let active = 0,
      revoked = 0,
      expired = 0;

    for (const cert of this.certificates.values()) {
      certsByType[cert.type] = (certsByType[cert.type] || 0) + 1;
      if (cert.status === CertificateStatus.ACTIVE) active++;
      else if (cert.status === CertificateStatus.REVOKED) revoked++;
      else if (cert.status === CertificateStatus.EXPIRED) expired++;
    }

    return {
      totalCertificates: this.certificates.size,
      activeCertificates: active,
      revokedCertificates: revoked,
      expiredCertificates: expired,
      orgsWithMTLS: this.configs.size,
      certsByType,
    };
  }

  /* ─── Private Helpers ─── */

  private generateFingerprint(): string {
    const chars = '0123456789ABCDEF';
    const parts: string[] = [];
    for (let i = 0; i < 20; i++) {
      let byte = '';
      for (let j = 0; j < 2; j++) {
        byte += chars.charAt(Math.floor(Math.random() * 16));
      }
      parts.push(byte);
    }
    return `SHA256:${parts.join(':')}`;
  }
}

/* ─── Singleton Export ─── */

export const mtlsService = new MTLSService();
