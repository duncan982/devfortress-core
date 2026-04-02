/**
 * Enterprise module barrel file
 */

export {
  siemService,
  SIEMProvider,
  SIEMEventSeverity,
  MITREAttackTechnique,
  mapThreatToMITRE,
} from './siem-connector';
export type {
  SIEMConfig,
  SIEMEvent,
  SIEMDeliveryResult,
} from './siem-connector';

export {
  playbookEngine,
  PlaybookAction,
  PlaybookConditionField,
  ConditionOperator,
} from './playbook-engine';
export type {
  Playbook,
  PlaybookRule,
  PlaybookCondition,
  PlaybookEvaluationContext,
  PlaybookExecutionResult,
} from './playbook-engine';

export { complianceReportGenerator } from './compliance-report-generator';
export type {
  ComplianceReportData,
  ComplianceControl,
} from './compliance-report-generator';

export {
  accountLockService,
  AccountLockReason,
  AccountLockStatus,
} from './account-lock-service';
export type {
  AccountLockRecord,
  LockPolicy,
  LockResult,
  UnlockResult,
} from './account-lock-service';

export {
  ssoService,
  SSOProvider,
  SSOConnectionStatus,
} from './sso-saml-service';
export type {
  SSOConfig,
  SSOSession,
  SSOTestResult,
  SSOProviderTemplate,
} from './sso-saml-service';

export {
  mtlsService,
  CertificateStatus,
  CertificateType,
} from './mtls-service';
export type {
  CertificateRecord,
  CertificateRequest,
  CertificateProvisionResult,
  CertificateValidationResult,
  mTLSConfig,
} from './mtls-service';

// 7. Endpoint Metering
export {
  endpointMeteringService,
  normalisePath,
} from './endpoint-metering-service';
export type {
  EndpointRecord,
  UsagePeriod,
  MeteringConfig,
} from './endpoint-metering-service';

// 8. Tier Enforcement
export {
  enforceTier,
  checkFeatureLimit,
  getTierFeatures,
  FEATURE_GATES,
} from './tier-enforcement';
export type { FeatureGate, SubscriptionTier } from './tier-enforcement';

// 9. Enterprise Onboarding
export {
  enterpriseOnboardingService,
  OnboardingPhase,
  StepStatus,
} from './enterprise-onboarding-service';
export type {
  EnterpriseOnboarding,
  OnboardingStep,
  CSMAssignment,
} from './enterprise-onboarding-service';

// 10. Enterprise Billing
export {
  enterpriseBillingService,
  BillingCurrency,
  InvoiceStatus,
  ContractStatus,
} from './enterprise-billing-service';
export type { Invoice, Contract, LineItem } from './enterprise-billing-service';

// 11. Usage Metering
export {
  usageMeteringService,
  UsageMeteringService,
} from './usage-metering-service';
export type {
  UsagePeriod as UsageMeteringPeriod,
  UsageCheckResult,
  UsageSummary,
} from './usage-metering-service';
