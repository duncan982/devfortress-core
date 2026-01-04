/**
 * Infrastructure Monitoring Service
 * Monitors Vercel and Supabase usage metrics for free tier limits
 * Alerts admins at 80% usage thresholds
 */

import { logInfo, logWarn, logError } from '@core/lib/logger';

// Vercel API types
interface VercelUsage {
  bandwidth: {
    used: number;
    limit: number;
    percentage: number;
  };
  builds: {
    used: number;
    limit: number;
    percentage: number;
  };
  functions: {
    invocations: number;
    limit: number;
    percentage: number;
  };
  edgeFunctions: {
    invocations: number;
    limit: number;
    percentage: number;
  };
}

// Supabase usage types
interface SupabaseUsage {
  database: {
    size: number; // in MB
    limit: number; // in MB
    percentage: number;
  };
  storage: {
    size: number; // in MB
    limit: number; // in MB
    percentage: number;
  };
  bandwidth: {
    used: number; // in GB
    limit: number; // in GB
    percentage: number;
  };
  auth: {
    users: number;
    limit: number;
    percentage: number;
  };
}

// Alert threshold (80%)
const ALERT_THRESHOLD = 80;

// Free tier limits (Vercel Hobby)
const VERCEL_FREE_LIMITS = {
  bandwidth: 100 * 1024 * 1024 * 1024, // 100GB in bytes
  builds: 6000, // 6000 minutes
  functions: 1000000, // 1M invocations
  edgeFunctions: 1000000, // 1M invocations
};

// Free tier limits (Supabase Free)
const SUPABASE_FREE_LIMITS = {
  database: 500, // 500MB
  storage: 1024, // 1GB
  bandwidth: 2, // 2GB
  auth: 50000, // 50k users
};

/**
 * Get Vercel usage metrics via API
 * Requires VERCEL_TOKEN environment variable
 */
export async function getVercelUsage(): Promise<VercelUsage | null> {
  const vercelToken = process.env.VERCEL_TOKEN;
  const vercelTeamId = process.env.VERCEL_TEAM_ID;

  if (!vercelToken) {
    logWarn('VERCEL_TOKEN not configured, skipping Vercel monitoring');
    return null;
  }

  try {
    const endpoint = vercelTeamId
      ? `https://api.vercel.com/v1/teams/${vercelTeamId}/usage`
      : 'https://api.vercel.com/v1/usage';

    const response = await fetch(endpoint, {
      headers: {
        Authorization: `Bearer ${vercelToken}`,
      },
    });

    if (!response.ok) {
      throw new Error(`Vercel API error: ${response.status}`);
    }

    const data = await response.json();

    // Calculate usage percentages
    const usage: VercelUsage = {
      bandwidth: {
        used: data.bandwidth?.used || 0,
        limit: VERCEL_FREE_LIMITS.bandwidth,
        percentage:
          ((data.bandwidth?.used || 0) / VERCEL_FREE_LIMITS.bandwidth) * 100,
      },
      builds: {
        used: data.builds?.used || 0,
        limit: VERCEL_FREE_LIMITS.builds,
        percentage:
          ((data.builds?.used || 0) / VERCEL_FREE_LIMITS.builds) * 100,
      },
      functions: {
        invocations: data.functions?.invocations || 0,
        limit: VERCEL_FREE_LIMITS.functions,
        percentage:
          ((data.functions?.invocations || 0) / VERCEL_FREE_LIMITS.functions) *
          100,
      },
      edgeFunctions: {
        invocations: data.edgeFunctions?.invocations || 0,
        limit: VERCEL_FREE_LIMITS.edgeFunctions,
        percentage:
          ((data.edgeFunctions?.invocations || 0) /
            VERCEL_FREE_LIMITS.edgeFunctions) *
          100,
      },
    };

    logInfo('Vercel usage metrics retrieved', { usage });
    return usage;
  } catch (error) {
    logError('Failed to get Vercel usage metrics', { error });
    return null;
  }
}

/**
 * Get Supabase usage metrics via Management API
 * Requires SUPABASE_SERVICE_ROLE_KEY and SUPABASE_PROJECT_ID
 */
export async function getSupabaseUsage(): Promise<SupabaseUsage | null> {
  const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
  const supabaseProjectId = process.env.SUPABASE_PROJECT_ID;

  if (!supabaseServiceKey || !supabaseProjectId) {
    logWarn(
      'Supabase credentials not configured, skipping Supabase monitoring'
    );
    return null;
  }

  try {
    // Note: Supabase Management API endpoint
    const endpoint = `https://api.supabase.com/v1/projects/${supabaseProjectId}/usage`;

    const response = await fetch(endpoint, {
      headers: {
        Authorization: `Bearer ${supabaseServiceKey}`,
      },
    });

    if (!response.ok) {
      throw new Error(`Supabase API error: ${response.status}`);
    }

    const data = await response.json();

    // Calculate usage percentages
    const usage: SupabaseUsage = {
      database: {
        size: data.db_size_mb || 0,
        limit: SUPABASE_FREE_LIMITS.database,
        percentage:
          ((data.db_size_mb || 0) / SUPABASE_FREE_LIMITS.database) * 100,
      },
      storage: {
        size: data.storage_size_mb || 0,
        limit: SUPABASE_FREE_LIMITS.storage,
        percentage:
          ((data.storage_size_mb || 0) / SUPABASE_FREE_LIMITS.storage) * 100,
      },
      bandwidth: {
        used: data.bandwidth_gb || 0,
        limit: SUPABASE_FREE_LIMITS.bandwidth,
        percentage:
          ((data.bandwidth_gb || 0) / SUPABASE_FREE_LIMITS.bandwidth) * 100,
      },
      auth: {
        users: data.auth_users || 0,
        limit: SUPABASE_FREE_LIMITS.auth,
        percentage: ((data.auth_users || 0) / SUPABASE_FREE_LIMITS.auth) * 100,
      },
    };

    logInfo('Supabase usage metrics retrieved', { usage });
    return usage;
  } catch (error) {
    logError('Failed to get Supabase usage metrics', { error });
    return null;
  }
}

/**
 * Check if any usage metric exceeds threshold
 */
export function checkUsageAlerts(
  vercelUsage: VercelUsage | null,
  supabaseUsage: SupabaseUsage | null
): {
  alerts: string[];
  critical: boolean;
} {
  const alerts: string[] = [];
  let critical = false;

  // Check Vercel usage
  if (vercelUsage) {
    if (vercelUsage.bandwidth.percentage >= ALERT_THRESHOLD) {
      alerts.push(
        `Vercel bandwidth at ${vercelUsage.bandwidth.percentage.toFixed(1)}% (${(vercelUsage.bandwidth.used / (1024 * 1024 * 1024)).toFixed(2)}GB / ${VERCEL_FREE_LIMITS.bandwidth / (1024 * 1024 * 1024)}GB)`
      );
      if (vercelUsage.bandwidth.percentage >= 95) critical = true;
    }

    if (vercelUsage.builds.percentage >= ALERT_THRESHOLD) {
      alerts.push(
        `Vercel builds at ${vercelUsage.builds.percentage.toFixed(1)}% (${vercelUsage.builds.used} / ${VERCEL_FREE_LIMITS.builds} minutes)`
      );
      if (vercelUsage.builds.percentage >= 95) critical = true;
    }

    if (vercelUsage.functions.percentage >= ALERT_THRESHOLD) {
      alerts.push(
        `Vercel functions at ${vercelUsage.functions.percentage.toFixed(1)}% (${vercelUsage.functions.invocations.toLocaleString()} / ${VERCEL_FREE_LIMITS.functions.toLocaleString()} invocations)`
      );
      if (vercelUsage.functions.percentage >= 95) critical = true;
    }

    if (vercelUsage.edgeFunctions.percentage >= ALERT_THRESHOLD) {
      alerts.push(
        `Vercel Edge Functions at ${vercelUsage.edgeFunctions.percentage.toFixed(1)}% (${vercelUsage.edgeFunctions.invocations.toLocaleString()} / ${VERCEL_FREE_LIMITS.edgeFunctions.toLocaleString()} invocations)`
      );
      if (vercelUsage.edgeFunctions.percentage >= 95) critical = true;
    }
  }

  // Check Supabase usage
  if (supabaseUsage) {
    if (supabaseUsage.database.percentage >= ALERT_THRESHOLD) {
      alerts.push(
        `Supabase database at ${supabaseUsage.database.percentage.toFixed(1)}% (${supabaseUsage.database.size}MB / ${SUPABASE_FREE_LIMITS.database}MB)`
      );
      if (supabaseUsage.database.percentage >= 95) critical = true;
    }

    if (supabaseUsage.storage.percentage >= ALERT_THRESHOLD) {
      alerts.push(
        `Supabase storage at ${supabaseUsage.storage.percentage.toFixed(1)}% (${supabaseUsage.storage.size}MB / ${SUPABASE_FREE_LIMITS.storage}MB)`
      );
      if (supabaseUsage.storage.percentage >= 95) critical = true;
    }

    if (supabaseUsage.bandwidth.percentage >= ALERT_THRESHOLD) {
      alerts.push(
        `Supabase bandwidth at ${supabaseUsage.bandwidth.percentage.toFixed(1)}% (${supabaseUsage.bandwidth.used}GB / ${SUPABASE_FREE_LIMITS.bandwidth}GB)`
      );
      if (supabaseUsage.bandwidth.percentage >= 95) critical = true;
    }

    if (supabaseUsage.auth.percentage >= ALERT_THRESHOLD) {
      alerts.push(
        `Supabase auth users at ${supabaseUsage.auth.percentage.toFixed(1)}% (${supabaseUsage.auth.users.toLocaleString()} / ${SUPABASE_FREE_LIMITS.auth.toLocaleString()} users)`
      );
      if (supabaseUsage.auth.percentage >= 95) critical = true;
    }
  }

  if (alerts.length > 0) {
    logWarn('Infrastructure usage alerts', { alerts, critical });
  }

  return { alerts, critical };
}

/**
 * Get aggregated infrastructure status
 */
export async function getInfrastructureStatus() {
  const vercelUsage = await getVercelUsage();
  const supabaseUsage = await getSupabaseUsage();
  const { alerts, critical } = checkUsageAlerts(vercelUsage, supabaseUsage);

  return {
    vercel: vercelUsage,
    supabase: supabaseUsage,
    alerts,
    critical,
    timestamp: new Date().toISOString(),
  };
}
