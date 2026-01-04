/**
 * VortexSecure Deployment Configuration
 *
 * Environment-aware configuration for local vs production deployment modes.
 * Controls behavior of all 4 phases: BUILD, DEFEND, COLLECT, LEARN
 */

import { logInfo, logWarn } from '../logger';

export type DeploymentMode = 'local' | 'production';

/**
 * Configuration for each VortexSecure phase
 */
export interface PhaseConfig {
  // PHASE 1: BUILD - API Generation
  build: {
    enabled: boolean;
    openaiMock: boolean;
  };

  // PHASE 2: DEFEND - Honeypots & Surveillance
  defend: {
    honeypotMode: DeploymentMode;
    honeypotLocalPort: number;
    honeypotLocalHost: string;
    vercelEnabled: boolean;
    githubEnabled: boolean;
    surveillanceMode: DeploymentMode;
  };

  // PHASE 3: COLLECT - Threat Event Ingestion
  collect: {
    mode: DeploymentMode;
    retentionDays: number;
    rateLimitPerMinute: number;
    localDatabase: boolean;
  };

  // PHASE 4: LEARN - Threat Intelligence
  learn: {
    mode: DeploymentMode;
    analysisSchedule: string;
    minThreatsForInsights: number;
    lookbackDays: number;
  };
}

/**
 * Get current deployment mode from environment
 */
export function getDeploymentMode(): DeploymentMode {
  const mode = process.env.DEPLOYMENT_MODE?.toLowerCase() || 'local';

  if (mode !== 'local' && mode !== 'production') {
    logWarn('Invalid DEPLOYMENT_MODE, defaulting to local', { mode });
    return 'local';
  }

  return mode as DeploymentMode;
}

/**
 * Check if running in local development mode
 */
export function isLocalMode(): boolean {
  return getDeploymentMode() === 'local';
}

/**
 * Check if running in production mode
 */
export function isProductionMode(): boolean {
  return getDeploymentMode() === 'production';
}

/**
 * Get phase-specific configuration based on deployment mode
 */
export function getPhaseConfig(): PhaseConfig {
  const mode = getDeploymentMode();
  const isLocal = mode === 'local';

  const config: PhaseConfig = {
    // PHASE 1: BUILD
    build: {
      enabled: true,
      openaiMock: isLocal && process.env.MOCK_OPENAI_API === 'true',
    },

    // PHASE 2: DEFEND
    defend: {
      honeypotMode:
        (process.env.HONEYPOT_DEPLOYMENT_MODE as DeploymentMode) || mode,
      honeypotLocalPort: parseInt(
        process.env.HONEYPOT_LOCAL_PORT || '4000',
        10
      ),
      honeypotLocalHost: process.env.HONEYPOT_LOCAL_HOST || 'localhost',
      vercelEnabled: !isLocal && !!process.env.VERCEL_ACCESS_TOKEN,
      githubEnabled: !isLocal && !!process.env.GITHUB_TOKEN,
      surveillanceMode:
        (process.env.SURVEILLANCE_MODE as DeploymentMode) || mode,
    },

    // PHASE 3: COLLECT
    collect: {
      mode: (process.env.COLLECTION_MODE as DeploymentMode) || mode,
      retentionDays: parseInt(process.env.EVENT_RETENTION_DAYS_FREE || '7', 10),
      rateLimitPerMinute: parseInt(
        process.env.EVENT_INGESTION_RATE_LIMIT || '1000',
        10
      ),
      localDatabase:
        isLocal || (process.env.DATABASE_URL?.includes('localhost') ?? false),
    },

    // PHASE 4: LEARN
    learn: {
      mode: (process.env.ANALYSIS_MODE as DeploymentMode) || mode,
      analysisSchedule: isLocal
        ? process.env.ANALYSIS_CRON_SCHEDULE || '*/5 * * * *' // Every 5 minutes
        : process.env.ANALYSIS_CRON_PRODUCTION || '0 */1 * * *', // Every hour
      minThreatsForInsights: parseInt(
        process.env.INSIGHTS_MIN_THREATS || '5',
        10
      ),
      lookbackDays: parseInt(process.env.INSIGHTS_LOOKBACK_DAYS || '30', 10),
    },
  };

  logInfo('Phase configuration loaded', {
    deploymentMode: mode,
    honeypotMode: config.defend.honeypotMode,
    collectionMode: config.collect.mode,
    analysisMode: config.learn.mode,
  });

  return config;
}

/**
 * Get honeypot deployment URL based on mode
 */
export function getHoneypotDeploymentUrl(honeypotId: string): string {
  const config = getPhaseConfig();

  if (config.defend.honeypotMode === 'local') {
    return `http://${config.defend.honeypotLocalHost}:${config.defend.honeypotLocalPort}/honeypot/${honeypotId}`;
  }

  // Production mode - use Vercel deployment
  const baseUrl =
    process.env.VERCEL_PROJECT_URL || process.env.NEXT_PUBLIC_API_URL;
  return `${baseUrl}/api/honeypot/${honeypotId}`;
}

/**
 * Get surveillance webhook URL for SDK
 */
export function getSurveillanceWebhookUrl(): string {
  const config = getPhaseConfig();

  if (config.defend.surveillanceMode === 'local') {
    return process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3002';
  }

  // Production mode
  return process.env.NEXT_PUBLIC_API_URL || process.env.VERCEL_URL || '';
}

/**
 * Get threat event ingestion endpoint
 */
export function getThreatIngestionUrl(): string {
  const config = getPhaseConfig();
  const baseUrl =
    config.collect.mode === 'local'
      ? process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3002'
      : process.env.NEXT_PUBLIC_API_URL || process.env.VERCEL_URL || '';

  return `${baseUrl}/api/events/ingest`;
}

/**
 * Check if local testing mode is enabled
 */
export function isLocalTestingMode(): boolean {
  return process.env.LOCAL_TESTING_MODE === 'true';
}

/**
 * Check if external API should be mocked (for local testing)
 */
export function shouldMockExternalAPI(
  service: 'vercel' | 'github' | 'openai'
): boolean {
  if (!isLocalTestingMode()) {
    return false;
  }

  const mockMap = {
    vercel: process.env.MOCK_VERCEL_API === 'true',
    github: process.env.MOCK_GITHUB_API === 'true',
    openai: process.env.MOCK_OPENAI_API === 'true',
  };

  return mockMap[service] || false;
}

/**
 * Get database connection string based on mode
 */
export function getDatabaseUrl(): string {
  return (
    process.env.DATABASE_URL ||
    'postgresql://postgres:postgres@localhost:5432/vortexsecure'
  );
}

/**
 * Validate environment configuration on startup
 */
export function validateEnvironmentConfig(): {
  valid: boolean;
  errors: string[];
  warnings: string[];
} {
  const errors: string[] = [];
  const warnings: string[] = [];
  const mode = getDeploymentMode();

  // Required in all modes
  if (!process.env.DATABASE_URL) {
    errors.push('DATABASE_URL is required');
  }

  if (!process.env.NEXT_PUBLIC_SUPABASE_URL) {
    errors.push('NEXT_PUBLIC_SUPABASE_URL is required');
  }

  if (!process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY) {
    errors.push('NEXT_PUBLIC_SUPABASE_ANON_KEY is required');
  }

  // Production-specific requirements
  if (mode === 'production') {
    if (!process.env.VERCEL_ACCESS_TOKEN) {
      warnings.push(
        'VERCEL_ACCESS_TOKEN not set - honeypot deployment will be limited'
      );
    }

    if (!process.env.GITHUB_TOKEN) {
      warnings.push(
        'GITHUB_TOKEN not set - GitHub integration will be disabled'
      );
    }

    if (!process.env.OPENAI_API_KEY) {
      errors.push('OPENAI_API_KEY is required in production mode');
    }

    if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) {
      errors.push(
        'SESSION_SECRET must be at least 32 characters in production'
      );
    }
  }

  // Local mode recommendations
  if (mode === 'local') {
    if (!process.env.OPENAI_API_KEY && process.env.MOCK_OPENAI_API !== 'true') {
      warnings.push(
        'OPENAI_API_KEY not set - set MOCK_OPENAI_API=true for testing'
      );
    }
  }

  // Log results
  if (errors.length > 0) {
    logWarn('Environment validation errors', { errors });
  }

  if (warnings.length > 0) {
    logWarn('Environment validation warnings', { warnings });
  }

  return {
    valid: errors.length === 0,
    errors,
    warnings,
  };
}

/**
 * Export configuration summary for logging/debugging
 */
export function getConfigSummary() {
  const mode = getDeploymentMode();
  const config = getPhaseConfig();

  return {
    deploymentMode: mode,
    isLocal: isLocalMode(),
    isProduction: isProductionMode(),
    localTestingEnabled: isLocalTestingMode(),
    phases: {
      build: {
        enabled: config.build.enabled,
        mockAI: config.build.openaiMock,
      },
      defend: {
        honeypotMode: config.defend.honeypotMode,
        honeypotUrl:
          config.defend.honeypotMode === 'local'
            ? `${config.defend.honeypotLocalHost}:${config.defend.honeypotLocalPort}`
            : 'vercel',
        surveillanceMode: config.defend.surveillanceMode,
      },
      collect: {
        mode: config.collect.mode,
        database: config.collect.localDatabase ? 'local' : 'remote',
        retention: `${config.collect.retentionDays} days`,
      },
      learn: {
        mode: config.learn.mode,
        schedule: config.learn.analysisSchedule,
        minThreats: config.learn.minThreatsForInsights,
      },
    },
  };
}
