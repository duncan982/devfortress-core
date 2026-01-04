/**
 * Breadcrumb Navigation Constants
 * Shared breadcrumb paths for consistent navigation
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
  accountManagement: { label: 'Account & Management', href: '/dashboard' },

  // DEFEND Phase sub-pages - unified navigation
  defendAlerts: { label: 'DEFEND Phase', href: '/defend' },
  defendSurveillance: { label: 'COLLECT Phase', href: '/collect' },
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
