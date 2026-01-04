/**
 * Dashboard Tutorial
 * Interactive tutorial for dashboard features
 */

import { TutorialStep } from './tutorial-provider';

export const dashboardTutorial: TutorialStep[] = [
  {
    target: '[data-tutorial="nav-build"]',
    title: 'Build APIs',
    content:
      'Click here to generate secure APIs from your codebase. Connect your GitHub repo and let AI do the heavy lifting.',
    position: 'bottom',
    helpArticle: '/help/article/getting-started',
  },
  {
    target: '[data-tutorial="nav-defend"]',
    title: 'Deploy Honeypots',
    content:
      'Set up honeypots to detect and analyze threats. Protect your applications with intelligent decoys.',
    position: 'bottom',
  },
  {
    target: '[data-tutorial="nav-portal"]',
    title: 'Developer Portal',
    content:
      'Access your customized developer portal with security reports, monitoring dashboards, and team collaboration tools.',
    position: 'bottom',
  },
  {
    target: '[data-tutorial="api-projects"]',
    title: 'API Projects',
    content:
      'View all your generated APIs here. Track status, documentation, and deployment information.',
    position: 'right',
  },
  {
    target: '[data-tutorial="recent-activity"]',
    title: 'Recent Activity',
    content:
      'Stay updated with the latest events, API generations, security scans, and team activities.',
    position: 'left',
  },
  {
    target: '[data-tutorial="profile-menu"]',
    title: 'Profile & Settings',
    content:
      'Manage your account, subscription, and preferences. Access settings for theme, notifications, and more.',
    position: 'bottom',
  },
];

export const buildTutorial: TutorialStep[] = [
  {
    target: '[data-tutorial="repo-connect"]',
    title: 'Connect Repository',
    content:
      "Select or connect a GitHub repository containing your API codebase. We'll analyze it automatically.",
    position: 'bottom',
  },
  {
    target: '[data-tutorial="framework-select"]',
    title: 'Choose Framework',
    content:
      'Select the framework for your API. We support Next.js, Express, FastAPI, Spring Boot, and more.',
    position: 'bottom',
  },
  {
    target: '[data-tutorial="security-scan"]',
    title: 'Security Scanning',
    content:
      'Enable security scanning to identify vulnerabilities in your code and infrastructure before deployment.',
    position: 'right',
  },
  {
    target: '[data-tutorial="generate-button"]',
    title: 'Generate API',
    content:
      "Click to start AI-powered API generation. We'll create comprehensive documentation, test suites, and deployment configs.",
    position: 'top',
  },
];

export const portalTutorial: TutorialStep[] = [
  {
    target: '[data-tutorial="security-overview"]',
    title: 'Security Dashboard',
    content:
      'View real-time security metrics, vulnerability scans, and threat intelligence from your honeypots.',
    position: 'right',
  },
  {
    target: '[data-tutorial="monitoring"]',
    title: 'API Monitoring',
    content:
      'Monitor your APIs with uptime tracking, performance metrics, and incident management.',
    position: 'right',
  },
  {
    target: '[data-tutorial="flywheel-data"]',
    title: 'Flywheel Intelligence',
    content:
      'Explore aggregated threat data and intelligence patterns to improve your API security.',
    position: 'left',
  },
  {
    target: '[data-tutorial="team-members"]',
    title: 'Team Collaboration',
    content:
      'Invite team members, manage roles, and collaborate on API projects and security responses.',
    position: 'left',
  },
];

export const onboardingTutorial: TutorialStep[] = [
  {
    target: '[data-tutorial="step-indicator"]',
    title: 'Onboarding Progress',
    content:
      'Track your onboarding progress here. Complete each step to unlock all VortexSecure features.',
    position: 'bottom',
  },
  {
    target: '[data-tutorial="connect-github"]',
    title: 'Connect GitHub',
    content:
      'Link your GitHub account to access repositories and enable seamless code integration.',
    position: 'bottom',
  },
  {
    target: '[data-tutorial="choose-plan"]',
    title: 'Select Subscription',
    content:
      'Choose a plan that fits your needs. Start with our Free tier or upgrade for advanced features.',
    position: 'bottom',
  },
  {
    target: '[data-tutorial="skip-button"]',
    title: 'Skip Anytime',
    content:
      'You can skip onboarding and return later. Access it from your profile menu.',
    position: 'top',
  },
];
