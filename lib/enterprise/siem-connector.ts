/**
 * SIEM Integration Service
 * Provides connectors for Splunk, Datadog, and Microsoft Sentinel
 * Enterprise-tier feature for forwarding security events in CEF/JSON format
 */

import { logInfo, logError, logWarn } from '@core/lib/logger';

/* ─── Types ─── */

export enum SIEMProvider {
  SPLUNK = 'splunk',
  DATADOG = 'datadog',
  SENTINEL = 'sentinel',
  GENERIC_WEBHOOK = 'generic_webhook',
  GENERIC_SYSLOG = 'generic_syslog',
}

export enum SIEMEventSeverity {
  LOW = 1,
  MEDIUM = 4,
  HIGH = 7,
  CRITICAL = 10,
}

export enum MITREAttackTechnique {
  BRUTE_FORCE = 'T1110',
  CREDENTIAL_STUFFING = 'T1110.004',
  SQL_INJECTION = 'T1190',
  PATH_TRAVERSAL = 'T1083',
  XSS = 'T1059.007',
  CSRF = 'T1185',
  PRIVILEGE_ESCALATION = 'T1068',
  TOKEN_REPLAY = 'T1550.001',
  RATE_ABUSE = 'T1498',
  SCANNER_FINGERPRINTING = 'T1595',
  ANOMALOUS_VOLUME = 'T1499',
}

export interface SIEMConfig {
  id: string;
  orgId: string;
  provider: SIEMProvider;
  enabled: boolean;
  endpoint: string;
  authToken?: string;
  apiKey?: string;
  /** Splunk HEC token */
  hecToken?: string;
  /** Datadog API key */
  ddApiKey?: string;
  /** Datadog site (e.g. datadoghq.com) */
  ddSite?: string;
  /** Microsoft Sentinel workspace ID */
  sentinelWorkspaceId?: string;
  /** Microsoft Sentinel shared key */
  sentinelSharedKey?: string;
  /** Custom HTTP headers */
  customHeaders?: Record<string, string>;
  /** Minimum severity to forward */
  minSeverity: SIEMEventSeverity;
  /** Threat types to include (empty = all) */
  threatTypeFilter: string[];
  createdAt: Date;
  updatedAt: Date;
}

export interface SIEMEvent {
  id: string;
  timestamp: string;
  orgId: string;
  severity: SIEMEventSeverity;
  threatType: string;
  mitreAttackId?: string;
  sourceIp: string;
  destinationEndpoint: string;
  httpMethod: string;
  userId?: string;
  sessionAlias?: string;
  actionTaken: string;
  description: string;
  threatScore: number;
  details: Record<string, unknown>;
}

export interface CEFEvent {
  version: string;
  deviceVendor: string;
  deviceProduct: string;
  deviceVersion: string;
  signatureId: string;
  name: string;
  severity: number;
  extensions: Record<string, string>;
}

export interface SIEMDeliveryResult {
  success: boolean;
  provider: SIEMProvider;
  eventId: string;
  statusCode?: number;
  error?: string;
  retryable: boolean;
  deliveredAt?: Date;
}

/* ─── CEF Formatter ─── */

function formatCEF(event: SIEMEvent): string {
  const cef: CEFEvent = {
    version: '0',
    deviceVendor: 'DevFortress',
    deviceProduct: 'API Security Platform',
    deviceVersion: '3.0',
    signatureId: event.threatType,
    name: event.description,
    severity: event.severity,
    extensions: {
      src: event.sourceIp,
      dst: event.destinationEndpoint,
      requestMethod: event.httpMethod,
      act: event.actionTaken,
      msg: event.description,
      cs1: event.orgId,
      cs1Label: 'OrganizationId',
      cs2: event.mitreAttackId || 'N/A',
      cs2Label: 'MITREAttackId',
      cs3: event.sessionAlias || 'N/A',
      cs3Label: 'SessionAlias',
      cn1: String(event.threatScore),
      cn1Label: 'ThreatScore',
      rt: event.timestamp,
      externalId: event.id,
    },
  };

  const extStr = Object.entries(cef.extensions)
    .map(([k, v]) => `${k}=${v}`)
    .join(' ');

  return `CEF:${cef.version}|${cef.deviceVendor}|${cef.deviceProduct}|${cef.deviceVersion}|${cef.signatureId}|${cef.name}|${cef.severity}|${extStr}`;
}

/* ─── MITRE ATT&CK Mapping ─── */

const THREAT_TO_MITRE: Record<string, MITREAttackTechnique> = {
  brute_force: MITREAttackTechnique.BRUTE_FORCE,
  credential_stuffing: MITREAttackTechnique.CREDENTIAL_STUFFING,
  sql_injection: MITREAttackTechnique.SQL_INJECTION,
  path_traversal: MITREAttackTechnique.PATH_TRAVERSAL,
  xss: MITREAttackTechnique.XSS,
  csrf: MITREAttackTechnique.CSRF,
  privilege_escalation: MITREAttackTechnique.PRIVILEGE_ESCALATION,
  token_replay: MITREAttackTechnique.TOKEN_REPLAY,
  rate_abuse: MITREAttackTechnique.RATE_ABUSE,
  scanner_fingerprinting: MITREAttackTechnique.SCANNER_FINGERPRINTING,
  anomalous_volume: MITREAttackTechnique.ANOMALOUS_VOLUME,
};

export function mapThreatToMITRE(threatType: string): string | undefined {
  return THREAT_TO_MITRE[threatType.toLowerCase()];
}

/* ─── Connector Implementations ─── */

/**
 * Splunk HTTP Event Collector (HEC) connector
 */
async function deliverToSplunk(
  config: SIEMConfig,
  event: SIEMEvent
): Promise<SIEMDeliveryResult> {
  const payload = {
    time: new Date(event.timestamp).getTime() / 1000,
    host: 'devfortress-platform',
    source: 'devfortress:api-security',
    sourcetype: '_json',
    event: {
      ...event,
      cef: formatCEF(event),
      mitre_attack_id: event.mitreAttackId,
    },
  };

  try {
    const response = await fetch(config.endpoint, {
      method: 'POST',
      headers: {
        Authorization: `Splunk ${config.hecToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(payload),
    });

    return {
      success: response.ok,
      provider: SIEMProvider.SPLUNK,
      eventId: event.id,
      statusCode: response.status,
      retryable: response.status >= 500,
      deliveredAt: response.ok ? new Date() : undefined,
      error: response.ok ? undefined : `Splunk HEC returned ${response.status}`,
    };
  } catch (error) {
    return {
      success: false,
      provider: SIEMProvider.SPLUNK,
      eventId: event.id,
      retryable: true,
      error: error instanceof Error ? error.message : 'Unknown Splunk error',
    };
  }
}

/**
 * Datadog Logs API connector
 */
async function deliverToDatadog(
  config: SIEMConfig,
  event: SIEMEvent
): Promise<SIEMDeliveryResult> {
  const site = config.ddSite || 'datadoghq.com';
  const endpoint = `https://http-intake.logs.${site}/api/v2/logs`;

  const payload = [
    {
      ddsource: 'devfortress',
      ddtags: `env:production,threat_type:${event.threatType},severity:${event.severity}`,
      hostname: 'devfortress-platform',
      service: 'api-security',
      message: JSON.stringify({
        ...event,
        mitre_attack_id: event.mitreAttackId,
      }),
    },
  ];

  try {
    const response = await fetch(endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'DD-API-KEY': config.ddApiKey || '',
      },
      body: JSON.stringify(payload),
    });

    return {
      success: response.ok,
      provider: SIEMProvider.DATADOG,
      eventId: event.id,
      statusCode: response.status,
      retryable: response.status >= 500,
      deliveredAt: response.ok ? new Date() : undefined,
      error: response.ok ? undefined : `Datadog returned ${response.status}`,
    };
  } catch (error) {
    return {
      success: false,
      provider: SIEMProvider.DATADOG,
      eventId: event.id,
      retryable: true,
      error: error instanceof Error ? error.message : 'Unknown Datadog error',
    };
  }
}

/**
 * Microsoft Sentinel Log Analytics connector
 */
async function deliverToSentinel(
  config: SIEMConfig,
  event: SIEMEvent
): Promise<SIEMDeliveryResult> {
  const logType = 'DevFortress_SecurityEvent';
  const dateString = new Date().toUTCString();

  const body = JSON.stringify([
    {
      TimeGenerated: event.timestamp,
      ThreatType: event.threatType,
      MITREAttackId: event.mitreAttackId || '',
      Severity: event.severity,
      SourceIP: event.sourceIp,
      Endpoint: event.destinationEndpoint,
      HttpMethod: event.httpMethod,
      ActionTaken: event.actionTaken,
      ThreatScore: event.threatScore,
      Description: event.description,
      SessionAlias: event.sessionAlias || '',
      OrgId: event.orgId,
    },
  ]);

  // Build HMAC-SHA256 signature for Sentinel
  const stringToSign = `POST\n${body.length}\napplication/json\nx-ms-date:${dateString}\n/api/logs`;

  try {
    // Use Web Crypto API for HMAC
    const encoder = new TextEncoder();
    const keyData = Uint8Array.from(atob(config.sentinelSharedKey || ''), c =>
      c.charCodeAt(0)
    );
    const key = await crypto.subtle.importKey(
      'raw',
      keyData,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );
    const signature = await crypto.subtle.sign(
      'HMAC',
      key,
      encoder.encode(stringToSign)
    );
    const signatureBase64 = btoa(
      String.fromCharCode(...new Uint8Array(signature))
    );
    const authorization = `SharedKey ${config.sentinelWorkspaceId}:${signatureBase64}`;

    const endpoint = `https://${config.sentinelWorkspaceId}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01`;

    const response = await fetch(endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Log-Type': logType,
        'x-ms-date': dateString,
        Authorization: authorization,
      },
      body,
    });

    return {
      success: response.ok,
      provider: SIEMProvider.SENTINEL,
      eventId: event.id,
      statusCode: response.status,
      retryable: response.status >= 500,
      deliveredAt: response.ok ? new Date() : undefined,
      error: response.ok ? undefined : `Sentinel returned ${response.status}`,
    };
  } catch (error) {
    return {
      success: false,
      provider: SIEMProvider.SENTINEL,
      eventId: event.id,
      retryable: true,
      error: error instanceof Error ? error.message : 'Unknown Sentinel error',
    };
  }
}

/**
 * Generic webhook connector
 */
async function deliverToWebhook(
  config: SIEMConfig,
  event: SIEMEvent
): Promise<SIEMDeliveryResult> {
  try {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...(config.authToken
        ? { Authorization: `Bearer ${config.authToken}` }
        : {}),
      ...(config.customHeaders || {}),
    };

    const response = await fetch(config.endpoint, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        ...event,
        cef: formatCEF(event),
        mitre_attack_id: event.mitreAttackId,
      }),
    });

    return {
      success: response.ok,
      provider: SIEMProvider.GENERIC_WEBHOOK,
      eventId: event.id,
      statusCode: response.status,
      retryable: response.status >= 500,
      deliveredAt: response.ok ? new Date() : undefined,
      error: response.ok ? undefined : `Webhook returned ${response.status}`,
    };
  } catch (error) {
    return {
      success: false,
      provider: SIEMProvider.GENERIC_WEBHOOK,
      eventId: event.id,
      retryable: true,
      error: error instanceof Error ? error.message : 'Unknown webhook error',
    };
  }
}

/* ─── Main Service ─── */

export class SIEMConnectorService {
  private configs: Map<string, SIEMConfig> = new Map();
  private deliveryQueue: Array<{
    config: SIEMConfig;
    event: SIEMEvent;
    attempts: number;
  }> = [];
  private deadLetterQueue: SIEMDeliveryResult[] = [];
  private maxRetries = 3;

  /**
   * Register a SIEM configuration for an org
   */
  registerConfig(config: SIEMConfig): void {
    this.configs.set(config.id, config);
    logInfo('SIEM connector registered', {
      configId: config.id,
      orgId: config.orgId,
      provider: config.provider,
    });
  }

  /**
   * Get all SIEM configs for an org
   */
  getOrgConfigs(orgId: string): SIEMConfig[] {
    return Array.from(this.configs.values()).filter(c => c.orgId === orgId);
  }

  /**
   * Remove a SIEM configuration
   */
  removeConfig(configId: string): boolean {
    const removed = this.configs.delete(configId);
    if (removed) {
      logInfo('SIEM connector removed', { configId });
    }
    return removed;
  }

  /**
   * Deliver a security event to all configured SIEM providers for an org
   */
  async deliverEvent(event: SIEMEvent): Promise<SIEMDeliveryResult[]> {
    const configs = this.getOrgConfigs(event.orgId).filter(c => c.enabled);

    if (configs.length === 0) {
      return [];
    }

    // Enrich event with MITRE ATT&CK mapping
    if (!event.mitreAttackId) {
      event.mitreAttackId = mapThreatToMITRE(event.threatType);
    }

    const results: SIEMDeliveryResult[] = [];

    for (const config of configs) {
      // Check severity filter
      if (event.severity < config.minSeverity) {
        continue;
      }

      // Check threat type filter
      if (
        config.threatTypeFilter.length > 0 &&
        !config.threatTypeFilter.includes(event.threatType)
      ) {
        continue;
      }

      const result = await this.deliverToProvider(config, event);
      results.push(result);

      if (!result.success && result.retryable) {
        this.deliveryQueue.push({ config, event, attempts: 1 });
        logWarn('SIEM delivery queued for retry', {
          provider: config.provider,
          eventId: event.id,
          error: result.error,
        });
      } else if (!result.success) {
        this.deadLetterQueue.push(result);
        logError('SIEM delivery failed permanently', {
          provider: config.provider,
          eventId: event.id,
          error: result.error,
        });
      }
    }

    return results;
  }

  /**
   * Route delivery to the correct provider connector
   */
  private async deliverToProvider(
    config: SIEMConfig,
    event: SIEMEvent
  ): Promise<SIEMDeliveryResult> {
    switch (config.provider) {
      case SIEMProvider.SPLUNK:
        return deliverToSplunk(config, event);
      case SIEMProvider.DATADOG:
        return deliverToDatadog(config, event);
      case SIEMProvider.SENTINEL:
        return deliverToSentinel(config, event);
      case SIEMProvider.GENERIC_WEBHOOK:
        return deliverToWebhook(config, event);
      default:
        return {
          success: false,
          provider: config.provider,
          eventId: event.id,
          retryable: false,
          error: `Unsupported SIEM provider: ${config.provider}`,
        };
    }
  }

  /**
   * Process retry queue — call periodically
   */
  async processRetryQueue(): Promise<SIEMDeliveryResult[]> {
    const results: SIEMDeliveryResult[] = [];
    const remaining: typeof this.deliveryQueue = [];

    for (const item of this.deliveryQueue) {
      const result = await this.deliverToProvider(item.config, item.event);
      results.push(result);

      if (
        !result.success &&
        result.retryable &&
        item.attempts < this.maxRetries
      ) {
        remaining.push({ ...item, attempts: item.attempts + 1 });
      } else if (!result.success) {
        this.deadLetterQueue.push(result);
        logError('SIEM delivery exhausted retries', {
          provider: item.config.provider,
          eventId: item.event.id,
          attempts: item.attempts,
        });
      }
    }

    this.deliveryQueue = remaining;
    return results;
  }

  /**
   * Get dead letter queue items
   */
  getDeadLetterQueue(): SIEMDeliveryResult[] {
    return [...this.deadLetterQueue];
  }

  /**
   * Clear dead letter queue
   */
  clearDeadLetterQueue(): number {
    const count = this.deadLetterQueue.length;
    this.deadLetterQueue = [];
    return count;
  }

  /**
   * Send a synthetic test event to verify SIEM configuration
   */
  async testConnection(configId: string): Promise<SIEMDeliveryResult> {
    const config = this.configs.get(configId);
    if (!config) {
      return {
        success: false,
        provider: SIEMProvider.GENERIC_WEBHOOK,
        eventId: 'test',
        retryable: false,
        error: 'Configuration not found',
      };
    }

    const testEvent: SIEMEvent = {
      id: `test-${Date.now()}`,
      timestamp: new Date().toISOString(),
      orgId: config.orgId,
      severity: SIEMEventSeverity.LOW,
      threatType: 'test_event',
      sourceIp: '127.0.0.1',
      destinationEndpoint: '/api/siem/test',
      httpMethod: 'POST',
      actionTaken: 'test_delivery',
      description:
        'DevFortress SIEM integration test — if you see this event, your connector is working.',
      threatScore: 0,
      details: { isTest: true, configId },
    };

    const result = await this.deliverToProvider(config, testEvent);

    logInfo('SIEM test event sent', {
      configId,
      provider: config.provider,
      success: result.success,
    });

    return result;
  }

  /**
   * Format event as CEF string (for display/export)
   */
  formatAsCEF(event: SIEMEvent): string {
    return formatCEF(event);
  }
}

/** Singleton SIEM service */
export const siemService = new SIEMConnectorService();
