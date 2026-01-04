/**
 * Onboarding tour steps definition
 * Matches the database onboarding steps with UI tour guidance
 */

import { TourStep } from './OnboardingTour';

export const DASHBOARD_TOUR_STEPS: TourStep[] = [
  {
    target: '[data-tour="github-connect"]',
    title: 'Connect Your GitHub Account',
    content:
      'Start by connecting your GitHub account. This allows VortexSecure to access your repositories and generate APIs from your code.',
    placement: 'bottom',
  },
  {
    target: '[data-tour="repository-selector"]',
    title: 'Select a Repository',
    content:
      'Choose which repository you want to work with. You can switch repositories at any time.',
    placement: 'right',
  },
  {
    target: '[data-tour="credits-balance"]',
    title: 'Your Credit Balance',
    content:
      'Each API generation uses credits. You start with 10 free credits. You can purchase more anytime.',
    placement: 'bottom',
  },
];

export const BUILD_TOUR_STEPS: TourStep[] = [
  {
    target: '[data-tour="api-generator"]',
    title: 'API Generator',
    content:
      'This is where you generate new APIs. You can create APIs from scratch or from existing code.',
    placement: 'right',
  },
  {
    target: '[data-tour="framework-selector"]',
    title: 'Choose Your Framework',
    content:
      'Select your preferred framework (Node.js/Express, Python/FastAPI, Java/Spring, etc.). VortexSecure will generate framework-specific code.',
    placement: 'top',
  },
  {
    target: '[data-tour="generation-prompt"]',
    title: 'Describe Your API',
    content:
      'Describe what you want to build. Be specific about endpoints, data models, and functionality. The AI will generate production-ready code.',
    placement: 'left',
  },
  {
    target: '[data-tour="credit-cost"]',
    title: 'Credit Cost Preview',
    content:
      'See how many credits your generation will cost before you submit. Complex APIs may require more credits.',
    placement: 'top',
  },
  {
    target: '[data-tour="generate-button"]',
    title: 'Generate Your API',
    content:
      'Click here to start generating. The process takes 30-60 seconds depending on complexity.',
    placement: 'top',
  },
];

export const DEFEND_TOUR_STEPS: TourStep[] = [
  {
    target: '[data-tour="security-scanner"]',
    title: 'Security Scanner',
    content:
      'Run comprehensive security scans on your APIs. Detects OWASP Top 10 vulnerabilities and more.',
    placement: 'right',
  },
  {
    target: '[data-tour="scan-results"]',
    title: 'Scan Results',
    content:
      'View detailed security findings with severity ratings and remediation guidance.',
    placement: 'bottom',
  },
  {
    target: '[data-tour="honeypots"]',
    title: 'Deploy Honeypots',
    content:
      'Set up decoy endpoints to detect and track attackers. Learn from real attack patterns.',
    placement: 'left',
  },
  {
    target: '[data-tour="threat-intelligence"]',
    title: 'Threat Intelligence',
    content:
      'View real-time threat data from your honeypots. See attack patterns, IP addresses, and techniques.',
    placement: 'bottom',
  },
];

export const LEARN_TOUR_STEPS: TourStep[] = [
  {
    target: '[data-tour="flywheel"]',
    title: 'Learning Flywheel',
    content:
      'VortexSecure learns from every interaction. The more you use it, the smarter it gets.',
    placement: 'right',
  },
  {
    target: '[data-tour="insights"]',
    title: 'AI Insights',
    content:
      'Get personalized recommendations based on your API usage patterns and security posture.',
    placement: 'bottom',
  },
  {
    target: '[data-tour="analytics"]',
    title: 'Analytics Dashboard',
    content:
      'Track your API generation metrics, security improvements, and cost savings over time.',
    placement: 'left',
  },
];

/**
 * Complete onboarding tour combining all phases
 */
export const COMPLETE_ONBOARDING_TOUR: TourStep[] = [
  ...DASHBOARD_TOUR_STEPS,
  ...BUILD_TOUR_STEPS.slice(0, 3), // Just the basics
  ...DEFEND_TOUR_STEPS.slice(0, 2), // Security intro
  {
    target: '[data-tour="help-center"]',
    title: 'Need Help?',
    content:
      'Access our help center, documentation, and support anytime from the top menu.',
    placement: 'bottom',
  },
  {
    target: '[data-tour="settings"]',
    title: 'Your Settings',
    content:
      'Customize your preferences, manage billing, and configure integrations in Settings.',
    placement: 'left',
  },
];
