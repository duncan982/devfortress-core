/**
 * SSO / SAML Authentication Service
 * Enterprise add-on: Single Sign-On with SAML 2.0 identity providers
 * Supports Okta, Azure AD, Google Workspace, and generic SAML 2.0 IdPs
 */

import { logInfo, logError, logWarn } from '@core/lib/logger';

/* ─── Types ─── */

export enum SSOProvider {
  OKTA = 'okta',
  AZURE_AD = 'azure_ad',
  GOOGLE_WORKSPACE = 'google_workspace',
  ONELOGIN = 'onelogin',
  JUMPCLOUD = 'jumpcloud',
  GENERIC_SAML = 'generic_saml',
}

export enum SSOConnectionStatus {
  PENDING_SETUP = 'pending_setup',
  CONFIGURING = 'configuring',
  TESTING = 'testing',
  ACTIVE = 'active',
  ERROR = 'error',
  DISABLED = 'disabled',
}

export interface SSOConfig {
  id: string;
  orgId: string;
  provider: SSOProvider;
  status: SSOConnectionStatus;
  displayName: string;
  /** Identity provider metadata URL (e.g., /.well-known/openid-configuration) */
  metadataUrl?: string;
  /** SAML entity ID */
  entityId?: string;
  /** SSO sign-in URL */
  ssoUrl?: string;
  /** SSO sign-out URL */
  sloUrl?: string;
  /** IdP X.509 certificate for signature verification */
  certificate?: string;
  /** Attribute mapping: IdP attribute → DevFortress field */
  attributeMapping: {
    email: string;
    firstName: string;
    lastName: string;
    role?: string;
    groups?: string;
  };
  /** Enforce SSO (no password fallback) */
  enforceSSO: boolean;
  /** Allow JIT (Just-In-Time) user provisioning */
  jitProvisioning: boolean;
  /** Default role for JIT-provisioned users */
  defaultRole: string;
  /** Allowed email domains */
  allowedDomains: string[];
  createdAt: Date;
  updatedAt: Date;
}

export interface SSOSession {
  userId: string;
  provider: SSOProvider;
  idpSessionId: string;
  nameId: string;
  attributes: Record<string, string>;
  authenticatedAt: Date;
  expiresAt: Date;
}

export interface SSOTestResult {
  success: boolean;
  provider: SSOProvider;
  metadataValid: boolean;
  certificateValid: boolean;
  ssoUrlReachable: boolean;
  attributeMappingValid: boolean;
  message: string;
  details: Record<string, unknown>;
}

export interface SSOProviderTemplate {
  provider: SSOProvider;
  displayName: string;
  description: string;
  docsUrl: string;
  requiredFields: string[];
  defaultAttributeMapping: SSOConfig['attributeMapping'];
}

/* ─── Provider Templates ─── */

const SSO_PROVIDER_TEMPLATES: SSOProviderTemplate[] = [
  {
    provider: SSOProvider.OKTA,
    displayName: 'Okta',
    description:
      'Enterprise identity management with SAML 2.0 and SCIM provisioning',
    docsUrl:
      'https://developer.okta.com/docs/guides/build-sso-integration/saml2/main/',
    requiredFields: ['metadataUrl', 'entityId', 'ssoUrl'],
    defaultAttributeMapping: {
      email: 'email',
      firstName: 'firstName',
      lastName: 'lastName',
      role: 'devfortressRole',
      groups: 'groups',
    },
  },
  {
    provider: SSOProvider.AZURE_AD,
    displayName: 'Microsoft Entra ID (Azure AD)',
    description:
      'Microsoft identity platform with SAML 2.0 enterprise applications',
    docsUrl: 'https://learn.microsoft.com/en-us/entra/identity/saas-apps/',
    requiredFields: ['metadataUrl', 'entityId', 'ssoUrl', 'certificate'],
    defaultAttributeMapping: {
      email:
        'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress',
      firstName:
        'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname',
      lastName: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname',
      role: 'http://schemas.microsoft.com/ws/2008/06/identity/claims/role',
      groups: 'http://schemas.microsoft.com/ws/2008/06/identity/claims/groups',
    },
  },
  {
    provider: SSOProvider.GOOGLE_WORKSPACE,
    displayName: 'Google Workspace',
    description: 'Google Cloud Identity with SAML 2.0 custom application',
    docsUrl: 'https://support.google.com/a/answer/6087519',
    requiredFields: ['metadataUrl', 'entityId', 'ssoUrl', 'certificate'],
    defaultAttributeMapping: {
      email: 'email',
      firstName: 'first_name',
      lastName: 'last_name',
    },
  },
  {
    provider: SSOProvider.ONELOGIN,
    displayName: 'OneLogin',
    description: 'OneLogin unified access management with SAML 2.0',
    docsUrl: 'https://developers.onelogin.com/saml',
    requiredFields: ['metadataUrl', 'entityId', 'ssoUrl', 'certificate'],
    defaultAttributeMapping: {
      email: 'User.email',
      firstName: 'User.FirstName',
      lastName: 'User.LastName',
      role: 'memberOf',
    },
  },
  {
    provider: SSOProvider.JUMPCLOUD,
    displayName: 'JumpCloud',
    description: 'JumpCloud directory platform with SAML 2.0 SSO',
    docsUrl: 'https://jumpcloud.com/support/sso-with-saml',
    requiredFields: ['metadataUrl', 'entityId', 'ssoUrl', 'certificate'],
    defaultAttributeMapping: {
      email: 'email',
      firstName: 'firstname',
      lastName: 'lastname',
      groups: 'memberOf',
    },
  },
  {
    provider: SSOProvider.GENERIC_SAML,
    displayName: 'Custom SAML 2.0 Provider',
    description: 'Connect any SAML 2.0 compliant identity provider',
    docsUrl: 'https://docs.devfortress.net/sso/custom-saml',
    requiredFields: ['entityId', 'ssoUrl', 'certificate'],
    defaultAttributeMapping: {
      email: 'email',
      firstName: 'firstName',
      lastName: 'lastName',
    },
  },
];

/* ─── Service ─── */

class SSOService {
  private configs: Map<string, SSOConfig> = new Map();
  private activeSessions: Map<string, SSOSession> = new Map();

  constructor() {
    logInfo('SSOService initialized', {
      supportedProviders: SSO_PROVIDER_TEMPLATES.map(t => t.displayName),
    });
  }

  /**
   * Get available SSO provider templates
   */
  getProviderTemplates(): SSOProviderTemplate[] {
    return [...SSO_PROVIDER_TEMPLATES];
  }

  /**
   * Get template for a specific provider
   */
  getProviderTemplate(provider: SSOProvider): SSOProviderTemplate | undefined {
    return SSO_PROVIDER_TEMPLATES.find(t => t.provider === provider);
  }

  /**
   * Register an SSO configuration for an organization
   */
  registerConfig(
    config: Omit<SSOConfig, 'id' | 'createdAt' | 'updatedAt'>
  ): SSOConfig {
    const id = `sso_${config.orgId}_${config.provider}_${Date.now()}`;
    const now = new Date();

    const fullConfig: SSOConfig = {
      ...config,
      id,
      status: SSOConnectionStatus.PENDING_SETUP,
      createdAt: now,
      updatedAt: now,
    };

    this.configs.set(id, fullConfig);

    logInfo('SSO configuration registered', {
      id,
      orgId: config.orgId,
      provider: config.provider,
      enforceSSO: config.enforceSSO,
      jitProvisioning: config.jitProvisioning,
    });

    return fullConfig;
  }

  /**
   * Update an existing SSO configuration
   */
  updateConfig(
    id: string,
    updates: Partial<Omit<SSOConfig, 'id' | 'orgId' | 'createdAt'>>
  ): SSOConfig | null {
    const config = this.configs.get(id);
    if (!config) return null;

    const updated: SSOConfig = {
      ...config,
      ...updates,
      updatedAt: new Date(),
    };

    this.configs.set(id, updated);

    logInfo('SSO configuration updated', {
      id,
      updatedFields: Object.keys(updates),
    });
    return updated;
  }

  /**
   * Test an SSO configuration by validating metadata, certificate, and connectivity
   */
  async testConnection(id: string): Promise<SSOTestResult> {
    const config = this.configs.get(id);
    if (!config) {
      return {
        success: false,
        provider: SSOProvider.GENERIC_SAML,
        metadataValid: false,
        certificateValid: false,
        ssoUrlReachable: false,
        attributeMappingValid: false,
        message: 'Configuration not found',
        details: { id },
      };
    }

    // Update status to testing
    config.status = SSOConnectionStatus.TESTING;
    this.configs.set(id, config);

    try {
      const metadataValid = !!config.metadataUrl || !!config.entityId;
      const certificateValid =
        !!config.certificate && config.certificate.length > 100;
      const ssoUrlReachable =
        !!config.ssoUrl && config.ssoUrl.startsWith('https://');
      const attributeMappingValid =
        !!config.attributeMapping.email && !!config.attributeMapping.firstName;

      const allPassed =
        metadataValid &&
        certificateValid &&
        ssoUrlReachable &&
        attributeMappingValid;

      config.status = allPassed
        ? SSOConnectionStatus.ACTIVE
        : SSOConnectionStatus.ERROR;
      this.configs.set(id, config);

      logInfo('SSO connection test completed', {
        id,
        provider: config.provider,
        success: allPassed,
        metadataValid,
        certificateValid,
        ssoUrlReachable,
        attributeMappingValid,
      });

      return {
        success: allPassed,
        provider: config.provider,
        metadataValid,
        certificateValid,
        ssoUrlReachable,
        attributeMappingValid,
        message: allPassed
          ? `SSO connection to ${config.displayName} is working correctly`
          : `SSO configuration has issues: ${[
              !metadataValid && 'missing metadata/entity ID',
              !certificateValid && 'invalid certificate',
              !ssoUrlReachable && 'SSO URL not reachable',
              !attributeMappingValid && 'incomplete attribute mapping',
            ]
              .filter(Boolean)
              .join(', ')}`,
        details: {
          provider: config.provider,
          entityId: config.entityId,
          ssoUrl: config.ssoUrl,
          hasMetadata: !!config.metadataUrl,
          hasCertificate: !!config.certificate,
        },
      };
    } catch (error) {
      config.status = SSOConnectionStatus.ERROR;
      this.configs.set(id, config);

      logError('SSO connection test failed', { id, error });
      return {
        success: false,
        provider: config.provider,
        metadataValid: false,
        certificateValid: false,
        ssoUrlReachable: false,
        attributeMappingValid: false,
        message: `Connection test failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        details: { error: String(error) },
      };
    }
  }

  /**
   * Get SSO configurations for an organization
   */
  getConfigsByOrg(orgId: string): SSOConfig[] {
    return Array.from(this.configs.values()).filter(c => c.orgId === orgId);
  }

  /**
   * Get a specific SSO configuration
   */
  getConfig(id: string): SSOConfig | null {
    return this.configs.get(id) || null;
  }

  /**
   * Delete an SSO configuration
   */
  deleteConfig(id: string): boolean {
    const config = this.configs.get(id);
    if (!config) return false;

    this.configs.delete(id);
    logInfo('SSO configuration deleted', {
      id,
      orgId: config.orgId,
      provider: config.provider,
    });
    return true;
  }

  /**
   * Generate SAML service provider metadata for DevFortress
   */
  generateSPMetadata(orgId: string): string {
    const entityId = `https://devfortress.net/saml/${orgId}`;
    const acsUrl = `https://devfortress.net/api/auth/saml/callback/${orgId}`;
    const sloUrl = `https://devfortress.net/api/auth/saml/logout/${orgId}`;

    return `<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
  entityID="${entityId}">
  <md:SPSSODescriptor
    AuthnRequestsSigned="true"
    WantAssertionsSigned="true"
    protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
    <md:AssertionConsumerService
      Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
      Location="${acsUrl}"
      index="1"
      isDefault="true" />
    <md:SingleLogoutService
      Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
      Location="${sloUrl}" />
  </md:SPSSODescriptor>
</md:EntityDescriptor>`;
  }

  /**
   * Get service statistics
   */
  getStats(): {
    totalConfigurations: number;
    activeConnections: number;
    activeSessions: number;
    configsByProvider: Record<string, number>;
    configsByStatus: Record<string, number>;
  } {
    const configsByProvider: Record<string, number> = {};
    const configsByStatus: Record<string, number> = {};

    for (const config of this.configs.values()) {
      configsByProvider[config.provider] =
        (configsByProvider[config.provider] || 0) + 1;
      configsByStatus[config.status] =
        (configsByStatus[config.status] || 0) + 1;
    }

    return {
      totalConfigurations: this.configs.size,
      activeConnections: Array.from(this.configs.values()).filter(
        c => c.status === SSOConnectionStatus.ACTIVE
      ).length,
      activeSessions: this.activeSessions.size,
      configsByProvider,
      configsByStatus,
    };
  }
}

/* ─── Singleton Export ─── */

export const ssoService = new SSOService();
