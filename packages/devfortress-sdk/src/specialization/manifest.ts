// packages/devfortress-sdk/src/specialization/manifest.ts

export type SpecializationModeId =
  | 'app_security'
  | 'api_key_aliasing_service'
  | 'account_takeover_defense'
  | 'commerce_abuse_defense'
  | 'ai_agent_security'
  | 'runtime_supply_chain_watch'
  | 'regulated_industry_security'
  | 'fintech_security'
  | 'healthcare_security'
  | 'mcp_protection'
  | 'llm_protection'
  | 'web3_protection';

export interface SpecializationManifest {
  mode: SpecializationModeId;
  displayName: string;
  description: string;
  requiredTier: 'starter' | 'pro' | 'team' | 'enterprise';
  phase: 'mvp' | 'post-patent' | 'post-revenue';
  detectorRules: string[]; // rule IDs activated by this mode
  dashboardModules: string[]; // dashboard widget IDs to enable
  validationSuites: string[]; // validation script phases to run
  isActive: boolean;
}

export const SPECIALIZATION_MANIFESTS: Record<
  SpecializationModeId,
  SpecializationManifest
> = {
  app_security: {
    mode: 'app_security',
    displayName: 'Application Security',
    description:
      'Baseline SDK and platform protection for all applications. Always active.',
    requiredTier: 'starter',
    phase: 'mvp',
    detectorRules: [
      'sql_injection',
      'path_traversal',
      'rate_limit',
      'anomaly_baseline',
    ],
    dashboardModules: ['threat-feed', 'event-counts', 'top-ips'],
    validationSuites: ['PHASE 1', 'PHASE 2', 'PHASE 3'],
    isActive: true,
  },
  api_key_aliasing_service: {
    mode: 'api_key_aliasing_service',
    displayName: 'API Key Aliasing Service',
    description:
      'Credential isolation via cryptographic aliasing. Real keys never leave your infrastructure.',
    requiredTier: 'pro',
    phase: 'mvp',
    detectorRules: [
      'alias_enumeration',
      'alias_rotation_anomaly',
      'credential_reuse',
    ],
    dashboardModules: ['alias-manager', 'alias-analytics', 'rotation-history'],
    validationSuites: ['PHASE 11', 'PHASE 11g'],
    isActive: true,
  },
  account_takeover_defense: {
    mode: 'account_takeover_defense',
    displayName: 'Account Takeover Defense',
    description:
      'Multi-signal ATO detection covering credential stuffing, session hijacking, and MFA fatigue.',
    requiredTier: 'pro',
    phase: 'mvp',
    detectorRules: [
      'credential_stuffing',
      'session_anomaly',
      'mfa_fatigue',
      'impossible_travel',
      'oauth_redirect',
    ],
    dashboardModules: ['ato-feed', 'session-map', 'credential-alerts'],
    validationSuites: ['PHASE 5', 'PHASE 6'],
    isActive: false,
  },
  commerce_abuse_defense: {
    mode: 'commerce_abuse_defense',
    displayName: 'Commerce Abuse Defense',
    description:
      'Cart manipulation, payment fraud, coupon stacking, and business logic abuse detection.',
    requiredTier: 'pro',
    phase: 'mvp',
    detectorRules: [
      'cart_manipulation',
      'coupon_stacking',
      'checkout_velocity',
      'gift_card_fraud',
    ],
    dashboardModules: ['abuse-feed', 'fraud-score-chart'],
    validationSuites: ['PHASE 7'],
    isActive: false,
  },
  ai_agent_security: {
    mode: 'ai_agent_security',
    displayName: 'AI Agent Security',
    description:
      'Tool-call validation, agent behavior monitoring, and agentic threat detection.',
    requiredTier: 'pro',
    phase: 'post-patent',
    detectorRules: [
      'tool_call_sequence',
      'agent_anomaly',
      'indirect_prompt_injection',
      'feedback_poisoning',
    ],
    dashboardModules: ['agent-feed', 'tool-usage-heatmap'],
    validationSuites: ['PHASE 9'],
    isActive: false,
  },
  runtime_supply_chain_watch: {
    mode: 'runtime_supply_chain_watch',
    displayName: 'Runtime Supply Chain Watch',
    description:
      'Runtime CVE detection across loaded packages and agent tool chains.',
    requiredTier: 'team',
    phase: 'mvp',
    detectorRules: ['config_integrity', 'cve_detection', 'dependency_anomaly'],
    dashboardModules: ['cve-feed', 'sbom-view'],
    validationSuites: [],
    isActive: false,
  },
  regulated_industry_security: {
    mode: 'regulated_industry_security',
    displayName: 'Regulated Industry Security',
    description:
      'Consent governance, audit trails, and compliance-focused controls.',
    requiredTier: 'enterprise',
    phase: 'post-revenue',
    detectorRules: ['consent_violation', 'audit_gap', 'policy_breach'],
    dashboardModules: ['consent-dashboard', 'compliance-report'],
    validationSuites: [],
    isActive: false,
  },
  fintech_security: {
    mode: 'fintech_security',
    displayName: 'Fintech Security',
    description:
      'Transaction velocity monitoring, PCI-DSS field detection, and AML heuristics.',
    requiredTier: 'enterprise',
    phase: 'post-revenue',
    detectorRules: [
      'transaction_velocity',
      'pci_field_detection',
      'aml_structuring',
    ],
    dashboardModules: ['transaction-feed', 'pci-alerts'],
    validationSuites: [],
    isActive: false,
  },
  healthcare_security: {
    mode: 'healthcare_security',
    displayName: 'Healthcare Security',
    description:
      'HIPAA-aware access logging, PHI detection, and break-the-glass tracking.',
    requiredTier: 'enterprise',
    phase: 'post-revenue',
    detectorRules: ['phi_detection', 'break_the_glass', 'minimum_necessary'],
    dashboardModules: ['hipaa-feed', 'phi-alerts'],
    validationSuites: [],
    isActive: false,
  },
  mcp_protection: {
    mode: 'mcp_protection',
    displayName: 'MCP Server Protection',
    description:
      'Model Context Protocol request validation, tool ACLs, and exfiltration detection.',
    requiredTier: 'enterprise',
    phase: 'post-patent',
    detectorRules: ['mcp_request_validation', 'tool_acl', 'mcp_exfiltration'],
    dashboardModules: ['mcp-sessions', 'tool-heatmap'],
    validationSuites: [],
    isActive: false,
  },
  llm_protection: {
    mode: 'llm_protection',
    displayName: 'LLM Protection',
    description:
      'Prompt injection detection, output sanitization, and token cost anomaly alerting.',
    requiredTier: 'pro',
    phase: 'post-patent',
    detectorRules: [
      'prompt_injection',
      'output_sanitization',
      'token_cost_anomaly',
    ],
    dashboardModules: ['llm-feed', 'injection-chart'],
    validationSuites: [],
    isActive: false,
  },
  web3_protection: {
    mode: 'web3_protection',
    displayName: 'Web3 Protection',
    description:
      'Transaction validation, drainer wallet detection, and smart contract interaction controls.',
    requiredTier: 'enterprise',
    phase: 'post-revenue',
    detectorRules: [
      'drainer_detection',
      'token_approval_anomaly',
      'gas_price_anomaly',
    ],
    dashboardModules: ['web3-feed', 'wallet-alerts'],
    validationSuites: [],
    isActive: false,
  },
};
