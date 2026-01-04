/**
 * Pre-defined UAT Test Scenarios
 * Comprehensive test cases for beta testing program
 */

import {
  TestScenario,
  TestScenarioCategory,
  TestScenarioPriority,
  TestScenarioStatus,
} from './beta-user-service';

const CATEGORY_MAP = {
  api_generation: TestScenarioCategory.API_GENERATION,
  security_scan: TestScenarioCategory.SECURITY_SCAN,
  deployment: TestScenarioCategory.DEPLOYMENT,
  monitoring: TestScenarioCategory.MONITORING,
  general: TestScenarioCategory.GENERAL,
} as const;

const PRIORITY_MAP = {
  high: TestScenarioPriority.HIGH,
  medium: TestScenarioPriority.MEDIUM,
  low: TestScenarioPriority.LOW,
} as const;

const STATUS_MAP = {
  active: TestScenarioStatus.ACTIVE,
  draft: TestScenarioStatus.DRAFT,
  completed: TestScenarioStatus.COMPLETED,
  deprecated: TestScenarioStatus.DEPRECATED,
} as const;

type ScenarioDefinition = Omit<
  TestScenario,
  'id' | 'createdAt' | 'updatedAt' | 'category' | 'priority' | 'status'
> & {
  category: keyof typeof CATEGORY_MAP;
  priority: keyof typeof PRIORITY_MAP;
  status: keyof typeof STATUS_MAP;
};

const SCENARIO_DEFINITIONS: ScenarioDefinition[] = [
  // API Generation Scenarios
  {
    name: 'Basic API Generation',
    description:
      'Test generating a simple REST API from natural language prompt',
    category: 'api_generation',
    priority: 'high',
    status: 'active',
    steps: [
      'Navigate to /build page',
      'Enter prompt: "Create a user management API with CRUD operations"',
      'Select framework: Node.js/Express',
      'Click "Generate API"',
      'Wait for generation to complete',
      'Review generated code and documentation',
    ],
    expectedOutcome:
      'API code is generated with proper structure, endpoints, and documentation. Code is syntactically correct and follows best practices.',
  },
  {
    name: 'API Generation with Authentication',
    description: 'Test generating an API with JWT authentication',
    category: 'api_generation',
    priority: 'high',
    status: 'active',
    steps: [
      'Navigate to /build page',
      'Enter prompt: "Create a blog API with JWT authentication"',
      'Select "Include authentication" option',
      'Select framework: Python/FastAPI',
      'Click "Generate API"',
      'Verify authentication middleware is included',
    ],
    expectedOutcome:
      'Generated API includes JWT authentication setup, protected routes, and proper error handling.',
  },
  {
    name: 'Multi-Framework API Generation',
    description:
      'Test generating the same API in different frameworks to ensure flexibility',
    category: 'api_generation',
    priority: 'medium',
    status: 'active',
    steps: [
      'Generate API with prompt: "E-commerce product catalog API"',
      'First generation: Node.js/Express',
      'Second generation: Python/FastAPI',
      'Third generation: Java/Spring Boot',
      'Compare outputs for consistency',
    ],
    expectedOutcome:
      'All three APIs have similar structure and functionality, adapted to framework conventions.',
  },

  // Security Scan Scenarios
  {
    name: 'Security Vulnerability Detection',
    description: 'Test security scanning for common vulnerabilities',
    category: 'security_scan',
    priority: 'high',
    status: 'active',
    steps: [
      'Navigate to /defend page',
      'Connect GitHub repository with sample API code',
      'Run security scan',
      'Wait for scan to complete',
      'Review vulnerability report',
      'Check for OWASP Top 10 issues',
    ],
    expectedOutcome:
      'Security scan identifies common vulnerabilities (SQL injection, XSS, etc.) with severity levels and fix suggestions.',
  },
  {
    name: 'IaC Security Scanning',
    description: 'Test scanning infrastructure-as-code files',
    category: 'security_scan',
    priority: 'high',
    status: 'active',
    steps: [
      'Upload repository with Terraform/CloudFormation files',
      'Select IaC scanning option',
      'Run scan',
      'Review IaC-specific vulnerabilities',
      'Check for misconfigurations (open ports, weak encryption)',
    ],
    expectedOutcome:
      'IaC scan detects infrastructure vulnerabilities and provides remediation steps.',
  },
  {
    name: 'EOL Dependency Detection',
    description: 'Test end-of-life dependency tracking',
    category: 'security_scan',
    priority: 'medium',
    status: 'active',
    steps: [
      'Upload project with outdated dependencies',
      'Run dependency scan',
      'View EOL warnings',
      'Check for upgrade recommendations',
    ],
    expectedOutcome:
      'System identifies EOL dependencies and suggests current alternatives.',
  },

  // Deployment Scenarios
  {
    name: 'GitHub Integration and Deployment',
    description: 'Test pushing generated code to GitHub repository',
    category: 'deployment',
    priority: 'high',
    status: 'active',
    steps: [
      'Generate an API',
      'Connect GitHub account via OAuth',
      'Select target repository',
      'Push generated code',
      'Verify code appears in GitHub',
      'Check commit message and structure',
    ],
    expectedOutcome:
      'Generated code is successfully pushed to GitHub with proper folder structure and commit message.',
  },
  {
    name: 'API Documentation Generation',
    description: 'Test automatic OpenAPI/Swagger documentation generation',
    category: 'deployment',
    priority: 'medium',
    status: 'active',
    steps: [
      'Generate API with documentation option enabled',
      'Navigate to documentation preview',
      'Verify OpenAPI spec is generated',
      'Test interactive API documentation',
      'Export documentation',
    ],
    expectedOutcome:
      'Complete OpenAPI specification is generated with interactive documentation viewer.',
  },

  // Monitoring Scenarios
  {
    name: 'Honeypot Deployment and Monitoring',
    description: 'Test deploying and monitoring honeypots',
    category: 'monitoring',
    priority: 'high',
    status: 'active',
    steps: [
      'Navigate to honeypot section',
      'Deploy a new honeypot',
      'Simulate attack traffic',
      'Monitor honeypot logs in real-time',
      'Review threat intelligence data',
      'Check alerts and notifications',
    ],
    expectedOutcome:
      'Honeypot captures attack attempts and provides actionable threat intelligence.',
  },
  {
    name: 'Real-Time API Monitoring',
    description: 'Test monitoring API performance and health',
    category: 'monitoring',
    priority: 'medium',
    status: 'active',
    steps: [
      'Deploy monitored API',
      'Generate test traffic',
      'View real-time metrics dashboard',
      'Check response times and error rates',
      'Test alert thresholds',
    ],
    expectedOutcome:
      'Dashboard displays accurate real-time metrics with working alert system.',
  },
  {
    name: 'Threat Intelligence Aggregation',
    description: 'Test flywheel data collection and analysis',
    category: 'monitoring',
    priority: 'medium',
    status: 'active',
    steps: [
      'Collect data from multiple honeypots',
      'Navigate to threat intelligence dashboard',
      'Review aggregated attack patterns',
      'Check AI-generated insights',
      'Export threat report',
    ],
    expectedOutcome:
      'System aggregates data from multiple sources and provides actionable insights.',
  },

  // General UX Scenarios
  {
    name: 'User Onboarding Flow',
    description: 'Test complete onboarding experience for new users',
    category: 'general',
    priority: 'high',
    status: 'active',
    steps: [
      'Create new account',
      'Complete profile setup',
      'Follow onboarding tutorial',
      'Connect GitHub account',
      'Generate first API',
      'Review dashboard overview',
    ],
    expectedOutcome:
      'Smooth onboarding experience with clear instructions and no blocking issues.',
  },
  {
    name: 'Subscription and Credit Management',
    description: 'Test subscription upgrade and credit usage',
    category: 'general',
    priority: 'high',
    status: 'active',
    steps: [
      'View pricing page',
      'Select subscription tier',
      'Complete payment via GitHub Marketplace',
      'Verify subscription activation',
      'Generate APIs to consume credits',
      'Monitor credit balance',
      'Test credit overage handling',
    ],
    expectedOutcome:
      'Subscription flow works smoothly with accurate credit tracking and overage notifications.',
  },
  {
    name: 'Help Center and Support Access',
    description: 'Test help center functionality and support contact',
    category: 'general',
    priority: 'medium',
    status: 'active',
    steps: [
      'Navigate to /help page',
      'Search for topics',
      'Read documentation articles',
      'Access contact support form',
      'Submit test support request',
      'Verify confirmation email',
    ],
    expectedOutcome:
      'Help center is searchable and comprehensive. Support form submits successfully.',
  },
  {
    name: 'Multi-Device Responsiveness',
    description: 'Test application on different screen sizes',
    category: 'general',
    priority: 'medium',
    status: 'active',
    steps: [
      'Access application on desktop',
      'Test on tablet view',
      'Test on mobile phone',
      'Verify all features work on each device',
      'Check navigation and forms',
    ],
    expectedOutcome:
      'Application is fully responsive and functional on all device sizes.',
  },
  {
    name: 'Accessibility Testing',
    description: 'Test WCAG compliance and keyboard navigation',
    category: 'general',
    priority: 'medium',
    status: 'active',
    steps: [
      'Navigate site using keyboard only',
      'Test with screen reader',
      'Check color contrast ratios',
      'Verify alt text on images',
      'Test form labels and ARIA attributes',
    ],
    expectedOutcome:
      'Site meets WCAG 2.1 AA standards with full keyboard navigation.',
  },
  {
    name: 'Error Handling and Recovery',
    description: 'Test application behavior during errors',
    category: 'general',
    priority: 'high',
    status: 'active',
    steps: [
      'Trigger API generation failure (invalid input)',
      'Test network disconnection scenario',
      'Submit forms with invalid data',
      'Access non-existent pages',
      'Test concurrent API generation requests',
      'Verify error messages are user-friendly',
    ],
    expectedOutcome:
      'Application handles errors gracefully with clear messages and recovery options.',
  },
  {
    name: 'Performance Under Load',
    description: 'Test application performance with multiple concurrent users',
    category: 'general',
    priority: 'low',
    status: 'active',
    steps: [
      'Simulate 10+ concurrent API generations',
      'Monitor response times',
      'Check for memory leaks',
      'Verify data consistency',
      'Test queue management',
    ],
    expectedOutcome:
      'Application maintains performance with multiple concurrent operations.',
  },
];

export const DEFAULT_TEST_SCENARIOS: Omit<
  TestScenario,
  'id' | 'createdAt' | 'updatedAt'
>[] = SCENARIO_DEFINITIONS.map(def => ({
  ...def,
  category: CATEGORY_MAP[def.category],
  priority: PRIORITY_MAP[def.priority],
  status: STATUS_MAP[def.status],
}));
