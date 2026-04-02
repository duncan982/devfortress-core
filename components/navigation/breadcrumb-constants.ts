/**
 * Breadcrumb Navigation Constants
 * Shared breadcrumb paths for consistent navigation
 *
 * Active Defense Feedback Loop (5-Phase Architecture):
 * 1. BUILD - Generate secure APIs and honeypots
 * 2. DEFEND - Deploy surveillance and monitor threats
 * 3. COLLECT - Aggregate threat data from production APIs
 * 4. LEARN - AI analysis and pattern recognition
 * 5. PATCH - Apply learned insights to improve protection
 */

export interface BreadcrumbItem {
  label: string;
  href: string;
}

/**
 * Predefined breadcrumb paths for common pages
 */
export const BREADCRUMB_PATHS = {
  dashboard: { label: 'Dashboard', href: '/dashboard' },
  build: { label: 'BUILD Phase', href: '/build' },
  defend: { label: 'DEFEND Phase', href: '/defend' },
  learn: { label: 'LEARN Phase', href: '/learn' },
  collect: { label: 'COLLECT Phase', href: '/collect' },
  patch: { label: 'PATCH Phase', href: '/patch' },
  accountManagement: { label: 'Account & Management', href: '/dashboard' },

  // DEFEND Phase sub-pages - unified navigation
  defendAlerts: { label: 'DEFEND Phase', href: '/defend' },
  defendSurveillance: { label: 'DEFEND Phase', href: '/defend' },
  defendEvents: { label: 'DEFEND Phase', href: '/defend' },
  honeypots: { label: 'DEFEND Phase', href: '/defend' },
  threats: { label: 'COLLECT Phase', href: '/collect' },

  // BUILD Phase sub-pages
  buildAdvanced: { label: 'Advanced Features', href: '/build' },

  // Insights
  insights: { label: 'Insights', href: '/dashboard/insights' },

  // Teams
  teams: { label: 'Teams', href: '/dashboard/teams' },
  teamMonitoring: { label: 'Team Monitoring', href: '/dashboard/monitoring' },
} as const;
