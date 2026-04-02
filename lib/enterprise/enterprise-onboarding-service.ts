/**
 * Enterprise Onboarding Service
 *
 * Manages the structured 4-week enterprise onboarding process:
 * - 14-step checklist with assigned owners
 * - CSM assignment and tracking
 * - Weekly milestone targets
 * - Progress reporting for enterprise dashboard
 */

import { logInfo, logWarn } from '@core/lib/logger';

/* ─── Types ─── */

export enum OnboardingPhase {
  WEEK_1 = 'Week 1: Foundation',
  WEEK_2 = 'Week 2: Integration',
  WEEK_3 = 'Week 3: Security Hardening',
  WEEK_4 = 'Week 4: Go-Live',
}

export enum StepStatus {
  NOT_STARTED = 'not_started',
  IN_PROGRESS = 'in_progress',
  COMPLETED = 'completed',
  BLOCKED = 'blocked',
  SKIPPED = 'skipped',
}

export interface OnboardingStep {
  id: string;
  phase: OnboardingPhase;
  order: number;
  title: string;
  description: string;
  owner: 'customer' | 'devfortress' | 'shared';
  status: StepStatus;
  completedAt?: string;
  completedBy?: string;
  notes?: string;
  blockerReason?: string;
  dependencies?: string[]; // step IDs
  estimatedMinutes: number;
}

export interface CSMAssignment {
  csmId: string;
  csmName: string;
  csmEmail: string;
  assignedAt: string;
  nextCheckIn: string;
  checkInCadence: 'weekly' | 'biweekly' | 'monthly';
}

export interface EnterpriseOnboarding {
  id: string;
  orgId: string;
  orgName: string;
  contractSignedAt: string;
  kickoffDate: string;
  targetGoLiveDate: string;
  csm: CSMAssignment;
  steps: OnboardingStep[];
  currentPhase: OnboardingPhase;
  overallProgress: number; // 0–100
  createdAt: string;
  updatedAt: string;
}

/* ─── Default 14-Step Checklist ─── */

const DEFAULT_STEPS: Omit<OnboardingStep, 'status'>[] = [
  // Week 1: Foundation
  {
    id: 'kickoff_call',
    phase: OnboardingPhase.WEEK_1,
    order: 1,
    title: 'Kickoff Call',
    description:
      'Introductions, review contract scope, define success criteria, agree on timeline.',
    owner: 'shared',
    estimatedMinutes: 60,
  },
  {
    id: 'account_setup',
    phase: OnboardingPhase.WEEK_1,
    order: 2,
    title: 'Account & Workspace Setup',
    description:
      'Create enterprise organisation, invite initial admin users, configure SSO/SAML if applicable.',
    owner: 'devfortress',
    estimatedMinutes: 30,
    dependencies: ['kickoff_call'],
  },
  {
    id: 'api_key_provisioning',
    phase: OnboardingPhase.WEEK_1,
    order: 3,
    title: 'API Key Provisioning',
    description:
      'Generate production API keys, configure rate limits, set up key rotation schedule.',
    owner: 'devfortress',
    estimatedMinutes: 15,
    dependencies: ['account_setup'],
  },
  {
    id: 'architecture_review',
    phase: OnboardingPhase.WEEK_1,
    order: 4,
    title: 'Architecture Review',
    description:
      'Map customer API architecture, identify endpoints to monitor, review data flow.',
    owner: 'shared',
    estimatedMinutes: 90,
    dependencies: ['kickoff_call'],
  },

  // Week 2: Integration
  {
    id: 'sdk_integration',
    phase: OnboardingPhase.WEEK_2,
    order: 5,
    title: 'SDK Installation & Integration',
    description:
      'Install devfortress-sdk in customer application(s), configure observe() hooks, verify first events in dashboard.',
    owner: 'customer',
    estimatedMinutes: 120,
    dependencies: ['api_key_provisioning'],
  },
  {
    id: 'siem_setup',
    phase: OnboardingPhase.WEEK_2,
    order: 6,
    title: 'SIEM Integration',
    description:
      'Configure SIEM connector (Splunk/Datadog/Sentinel), verify event delivery, tune severity filters.',
    owner: 'shared',
    estimatedMinutes: 60,
    dependencies: ['sdk_integration'],
  },
  {
    id: 'compliance_config',
    phase: OnboardingPhase.WEEK_2,
    order: 7,
    title: 'Compliance Framework Configuration',
    description:
      'Select applicable frameworks (PCI-DSS, SOC2, GDPR, HIPAA), configure evidence collection, schedule first report.',
    owner: 'shared',
    estimatedMinutes: 45,
    dependencies: ['account_setup'],
  },
  {
    id: 'mtls_setup',
    phase: OnboardingPhase.WEEK_2,
    order: 8,
    title: 'mTLS Certificate Setup',
    description:
      'Provision client certificates, configure certificate pinning, test mutual authentication.',
    owner: 'shared',
    estimatedMinutes: 60,
    dependencies: ['sdk_integration'],
  },

  // Week 3: Security Hardening
  {
    id: 'playbook_creation',
    phase: OnboardingPhase.WEEK_3,
    order: 9,
    title: 'Response Playbook Configuration',
    description:
      'Create custom response playbooks for identified threat scenarios, test with dry-run mode.',
    owner: 'shared',
    estimatedMinutes: 90,
    dependencies: ['sdk_integration'],
  },
  {
    id: 'honeypot_deployment',
    phase: OnboardingPhase.WEEK_3,
    order: 10,
    title: 'Honeypot Deployment',
    description:
      'Deploy decoy endpoints matching customer API patterns, configure alerting thresholds.',
    owner: 'devfortress',
    estimatedMinutes: 45,
    dependencies: ['architecture_review'],
  },
  {
    id: 'threat_tuning',
    phase: OnboardingPhase.WEEK_3,
    order: 11,
    title: 'Threat Detection Tuning',
    description:
      'Review initial detections, adjust thresholds to reduce false positives, configure allowlists.',
    owner: 'shared',
    estimatedMinutes: 60,
    dependencies: ['sdk_integration'],
  },

  // Week 4: Go-Live
  {
    id: 'load_test',
    phase: OnboardingPhase.WEEK_4,
    order: 12,
    title: 'Load Testing & Performance Validation',
    description:
      'Verify SDK impact on application latency under production-like load. Target: < 2ms overhead per request.',
    owner: 'shared',
    estimatedMinutes: 90,
    dependencies: ['sdk_integration', 'playbook_creation'],
  },
  {
    id: 'runbook_handoff',
    phase: OnboardingPhase.WEEK_4,
    order: 13,
    title: 'Runbook & Escalation Handoff',
    description:
      'Deliver operational runbook, configure PagerDuty/Slack integrations, test escalation flow.',
    owner: 'devfortress',
    estimatedMinutes: 60,
    dependencies: ['threat_tuning'],
  },
  {
    id: 'go_live',
    phase: OnboardingPhase.WEEK_4,
    order: 14,
    title: 'Production Go-Live',
    description:
      'Switch to production mode, enable automated responses, confirm all dashboards operational.',
    owner: 'shared',
    estimatedMinutes: 30,
    dependencies: ['load_test', 'runbook_handoff'],
  },
];

/* ─── In-Memory Store ─── */
const onboardingStore = new Map<string, EnterpriseOnboarding>();

/* ─── Service ─── */

export class EnterpriseOnboardingService {
  /* ─── Create a new onboarding ─── */
  createOnboarding(params: {
    orgId: string;
    orgName: string;
    contractSignedAt: string;
    csmName: string;
    csmEmail: string;
  }): EnterpriseOnboarding {
    const now = new Date();
    const kickoffDate = new Date(
      now.getTime() + 3 * 24 * 60 * 60 * 1000
    ).toISOString(); // 3 days from now
    const targetGoLive = new Date(
      now.getTime() + 28 * 24 * 60 * 60 * 1000
    ).toISOString(); // 4 weeks

    const onboarding: EnterpriseOnboarding = {
      id: `onb_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
      orgId: params.orgId,
      orgName: params.orgName,
      contractSignedAt: params.contractSignedAt,
      kickoffDate,
      targetGoLiveDate: targetGoLive,
      csm: {
        csmId: `csm_${Math.random().toString(36).slice(2, 8)}`,
        csmName: params.csmName,
        csmEmail: params.csmEmail,
        assignedAt: now.toISOString(),
        nextCheckIn: kickoffDate,
        checkInCadence: 'weekly',
      },
      steps: DEFAULT_STEPS.map(s => ({
        ...s,
        status: StepStatus.NOT_STARTED,
      })),
      currentPhase: OnboardingPhase.WEEK_1,
      overallProgress: 0,
      createdAt: now.toISOString(),
      updatedAt: now.toISOString(),
    };

    onboardingStore.set(onboarding.id, onboarding);
    logInfo('Enterprise onboarding created', {
      onboardingId: onboarding.id,
      orgId: params.orgId,
      orgName: params.orgName,
      csm: params.csmName,
    });
    return onboarding;
  }

  /* ─── Update step status ─── */
  updateStep(
    onboardingId: string,
    stepId: string,
    update: {
      status: StepStatus;
      completedBy?: string;
      notes?: string;
      blockerReason?: string;
    }
  ): EnterpriseOnboarding | null {
    const onboarding = onboardingStore.get(onboardingId);
    if (!onboarding) return null;

    const step = onboarding.steps.find(s => s.id === stepId);
    if (!step) return null;

    // Check dependencies
    if (update.status === StepStatus.IN_PROGRESS && step.dependencies) {
      const unmet = step.dependencies.filter(depId => {
        const dep = onboarding.steps.find(s => s.id === depId);
        return dep && dep.status !== StepStatus.COMPLETED;
      });
      if (unmet.length > 0) {
        logWarn('Cannot start step — unmet dependencies', {
          stepId,
          unmet,
        });
        return null;
      }
    }

    step.status = update.status;
    if (update.status === StepStatus.COMPLETED) {
      step.completedAt = new Date().toISOString();
      step.completedBy = update.completedBy;
    }
    if (update.notes) step.notes = update.notes;
    if (update.blockerReason) step.blockerReason = update.blockerReason;

    // Recalculate progress
    const completed = onboarding.steps.filter(
      s => s.status === StepStatus.COMPLETED || s.status === StepStatus.SKIPPED
    ).length;
    onboarding.overallProgress = Math.round(
      (completed / onboarding.steps.length) * 100
    );

    // Update current phase
    const phases = Object.values(OnboardingPhase);
    for (const phase of phases) {
      const phaseSteps = onboarding.steps.filter(s => s.phase === phase);
      const allDone = phaseSteps.every(
        s =>
          s.status === StepStatus.COMPLETED || s.status === StepStatus.SKIPPED
      );
      if (!allDone) {
        onboarding.currentPhase = phase;
        break;
      }
    }

    onboarding.updatedAt = new Date().toISOString();
    onboardingStore.set(onboardingId, onboarding);

    logInfo('Onboarding step updated', {
      onboardingId,
      stepId,
      status: update.status,
      progress: onboarding.overallProgress,
    });
    return onboarding;
  }

  /* ─── Get onboarding by ID ─── */
  getOnboarding(onboardingId: string): EnterpriseOnboarding | null {
    return onboardingStore.get(onboardingId) ?? null;
  }

  /* ─── Get onboarding by org ID ─── */
  getOnboardingByOrg(orgId: string): EnterpriseOnboarding | null {
    for (const [, ob] of onboardingStore) {
      if (ob.orgId === orgId) return ob;
    }
    return null;
  }

  /* ─── List all onboardings ─── */
  listOnboardings(): EnterpriseOnboarding[] {
    return Array.from(onboardingStore.values()).sort(
      (a, b) =>
        new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()
    );
  }

  /* ─── Get phase summary ─── */
  getPhaseSummary(onboardingId: string): Array<{
    phase: OnboardingPhase;
    total: number;
    completed: number;
    blocked: number;
  }> | null {
    const ob = onboardingStore.get(onboardingId);
    if (!ob) return null;

    return Object.values(OnboardingPhase).map(phase => {
      const steps = ob.steps.filter(s => s.phase === phase);
      return {
        phase,
        total: steps.length,
        completed: steps.filter(
          s =>
            s.status === StepStatus.COMPLETED || s.status === StepStatus.SKIPPED
        ).length,
        blocked: steps.filter(s => s.status === StepStatus.BLOCKED).length,
      };
    });
  }

  /* ─── Stats ─── */
  getStats(): {
    total: number;
    active: number;
    completed: number;
    averageProgress: number;
  } {
    const all = Array.from(onboardingStore.values());
    const completed = all.filter(ob => ob.overallProgress === 100);
    const avgProgress =
      all.length > 0
        ? Math.round(
            all.reduce((sum, ob) => sum + ob.overallProgress, 0) / all.length
          )
        : 0;
    return {
      total: all.length,
      active: all.length - completed.length,
      completed: completed.length,
      averageProgress: avgProgress,
    };
  }
}

/* ─── Singleton ─── */
export const enterpriseOnboardingService = new EnterpriseOnboardingService();
