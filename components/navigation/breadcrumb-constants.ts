/**
 * Shared breadcrumb paths for consistent navigation
 * MVP Focus: Collect Phase — SDK Surveillance, Token Aliasing, CL Protection
 * Other phases (BUILD, DEFEND, LEARN, PATCH) are commented out for post-MVP reinstatement.
 */

export interface BreadcrumbItem {
  label: string;
  href: string;
}

export const BREADCRUMB_PATHS = {
  dashboard: { label: 'Dashboard', href: '/dashboard' },
  accountManagement: { label: 'Account & Management', href: '/dashboard' },

  // MVP: Collect Phase
  collect: { label: 'COLLECT Phase', href: '/dashboard/collect/surveillance' },
  collectSurveillance: {
    label: 'Surveillance',
    href: '/dashboard/collect/surveillance',
  },
  collectSecurity: {
    label: 'Security Overview',
    href: '/dashboard/collect/security',
  },
  credentials: { label: 'SDK Credentials', href: '/dashboard/credentials' },
  projects: { label: 'Projects', href: '/dashboard/projects' },
  insights: { label: 'Insights', href: '/dashboard/insights' },
  teams: { label: 'Teams', href: '/dashboard/teams' },
  teamMonitoring: { label: 'Team Monitoring', href: '/dashboard/monitoring' },

  // POST-MVP deprecated aliases — all redirect to /dashboard until phases are reinstated
  build: { label: 'BUILD Phase', href: '/dashboard' },
  defend: { label: 'DEFEND Phase', href: '/dashboard' },
  learn: { label: 'LEARN Phase', href: '/dashboard' },
  patch: { label: 'PATCH Phase', href: '/dashboard' },
  defendAlerts: { label: 'Alerts', href: '/dashboard' },
  defendSurveillance: { label: 'Surveillance', href: '/dashboard/credentials' },
  defendEvents: { label: 'Events', href: '/dashboard/collect/surveillance' },
  honeypots: { label: 'Projects', href: '/dashboard/projects' },
  threats: { label: 'COLLECT Phase', href: '/dashboard/collect/surveillance' },
  buildAdvanced: { label: 'Advanced Features', href: '/dashboard' },
} as const;
