import { Prisma } from '@prisma/client';
import { prisma } from '@core/lib/prisma';
import { logInfo, logError } from '@core/lib/logger';

/**
 * User Onboarding Service
 * Manages user onboarding flow, progress tracking, and feature tutorials
 */

export interface OnboardingStep {
  id: string;
  title: string;
  description: string;
  completed: boolean;
  optional: boolean;
  order: number;
}

export interface OnboardingProgress {
  userId: string;
  currentStep: number;
  completedSteps: string[];
  skipped: boolean;
  completedAt: Date | null;
}

/**
 * Default onboarding steps for all users
 */
export const ONBOARDING_STEPS: Omit<OnboardingStep, 'completed'>[] = [
  {
    id: 'setup-mfa',
    title: 'Set Up Two-Factor Authentication',
    description:
      'Enable 2FA to secure your account with an additional layer of protection',
    optional: true,
    order: 1,
  },
  {
    id: 'connect-repo',
    title: 'Connect Your Repository',
    description:
      'Link your GitHub account to start generating APIs from your codebase',
    optional: true,
    order: 2,
  },
  {
    id: 'generate-api',
    title: 'Generate Your First API',
    description:
      'Use VortexSecure to automatically generate secure API documentation',
    optional: false,
    order: 3,
  },
  {
    id: 'security-scan',
    title: 'Run Security Scan',
    description: 'Scan your APIs for vulnerabilities and security issues',
    optional: false,
    order: 3,
  },
  {
    id: 'deploy-honeypot',
    title: 'Deploy a Honeypot',
    description:
      'Set up threat detection to monitor attackers targeting your APIs',
    optional: true,
    order: 4,
  },
  {
    id: 'explore-insights',
    title: 'Explore Threat Insights',
    description: 'Learn from real-world attack patterns and vulnerabilities',
    optional: true,
    order: 5,
  },
];

/**
 * Get user's onboarding progress
 */
export async function getOnboardingProgress(
  userId: string
): Promise<OnboardingProgress | null> {
  try {
    const progress = await prisma.userOnboarding.findUnique({
      where: { userId },
    });

    if (!progress) {
      return null;
    }

    return {
      userId: progress.userId,
      currentStep: progress.currentStep,
      completedSteps: progress.completedSteps as string[],
      skipped: progress.skipped,
      completedAt: progress.completedAt,
    };
  } catch (error) {
    logError('Failed to get onboarding progress', { userId, error });
    throw error;
  }
}

/**
 * Initialize onboarding for a new user
 */
export async function initializeOnboarding(
  userId: string
): Promise<OnboardingProgress> {
  try {
    const existing = await prisma.userOnboarding.findUnique({
      where: { userId },
    });

    if (existing) {
      logInfo('User already has onboarding progress', { userId });
      return {
        userId: existing.userId,
        currentStep: existing.currentStep,
        completedSteps: existing.completedSteps as string[],
        skipped: existing.skipped,
        completedAt: existing.completedAt,
      };
    }

    const onboarding = await prisma.userOnboarding.create({
      data: {
        userId,
        currentStep: 1,
        completedSteps: [],
        skipped: false,
      },
    });

    logInfo('Initialized onboarding for user', { userId });

    return {
      userId: onboarding.userId,
      currentStep: onboarding.currentStep,
      completedSteps: onboarding.completedSteps as string[],
      skipped: onboarding.skipped,
      completedAt: onboarding.completedAt,
    };
  } catch (error) {
    if (
      error instanceof Prisma.PrismaClientKnownRequestError &&
      error.code === 'P2002'
    ) {
      logInfo(
        'Onboarding already exists due to race condition, fetching existing record',
        {
          userId,
        }
      );

      // Race condition: record was created between our check and create
      // Retry fetching the existing record
      const existing = await prisma.userOnboarding.findUnique({
        where: { userId },
      });

      if (existing) {
        return {
          userId: existing.userId,
          currentStep: existing.currentStep,
          completedSteps: existing.completedSteps as string[],
          skipped: existing.skipped,
          completedAt: existing.completedAt,
        };
      }

      // If still not found, something is very wrong
      logError('P2002 error but record not found - database inconsistency', {
        userId,
      });
      throw new Error(
        'Database inconsistency: unique constraint violation without existing record'
      );
    }

    logError('Failed to initialize onboarding', { userId, error });
    throw error;
  }
}

/**
 * Mark an onboarding step as completed
 */
export async function completeOnboardingStep(
  userId: string,
  stepId: string
): Promise<OnboardingProgress> {
  try {
    const progress = await getOnboardingProgress(userId);

    if (!progress) {
      throw new Error('User onboarding not initialized');
    }

    if (progress.completedSteps.includes(stepId)) {
      logInfo('Step already completed', { userId, stepId });
      return progress;
    }

    const completedSteps = [...progress.completedSteps, stepId];
    const step = ONBOARDING_STEPS.find(s => s.id === stepId);
    const nextStep = step ? step.order + 1 : progress.currentStep + 1;

    // Check if all required steps are completed
    const requiredSteps = ONBOARDING_STEPS.filter(s => !s.optional);
    const allRequiredCompleted = requiredSteps.every(s =>
      completedSteps.includes(s.id)
    );

    const updated = await prisma.userOnboarding.update({
      where: { userId },
      data: {
        completedSteps,
        currentStep: nextStep,
        completedAt: allRequiredCompleted ? new Date() : null,
      },
    });

    logInfo('Completed onboarding step', {
      userId,
      stepId,
      totalCompleted: completedSteps.length,
    });

    return {
      userId: updated.userId,
      currentStep: updated.currentStep,
      completedSteps: updated.completedSteps as string[],
      skipped: updated.skipped,
      completedAt: updated.completedAt,
    };
  } catch (error) {
    logError('Failed to complete onboarding step', { userId, stepId, error });
    throw error;
  }
}

/**
 * Skip onboarding
 */
export async function skipOnboarding(userId: string): Promise<void> {
  try {
    await prisma.userOnboarding.update({
      where: { userId },
      data: {
        skipped: true,
        completedAt: new Date(),
      },
    });

    logInfo('User skipped onboarding', { userId });
  } catch (error) {
    logError('Failed to skip onboarding', { userId, error });
    throw error;
  }
}

/**
 * Reset onboarding progress
 */
export async function resetOnboarding(userId: string): Promise<void> {
  try {
    await prisma.userOnboarding.update({
      where: { userId },
      data: {
        currentStep: 1,
        completedSteps: [],
        skipped: false,
        completedAt: null,
      },
    });

    logInfo('Reset onboarding for user', { userId });
  } catch (error) {
    logError('Failed to reset onboarding', { userId, error });
    throw error;
  }
}

/**
 * Get onboarding steps with completion status
 */
export async function getOnboardingSteps(
  userId: string
): Promise<OnboardingStep[]> {
  try {
    const progress = await getOnboardingProgress(userId);
    const completedSteps = progress?.completedSteps || [];

    return ONBOARDING_STEPS.map(step => ({
      ...step,
      completed: completedSteps.includes(step.id),
    }));
  } catch (error) {
    logError('Failed to get onboarding steps', { userId, error });
    throw error;
  }
}

/**
 * Check if user should see onboarding
 */
export async function shouldShowOnboarding(userId: string): Promise<boolean> {
  try {
    // Skip onboarding for admin users to avoid MFA setup issues
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { role: true },
    });
    if (user?.role === 'ADMIN') {
      return false;
    }

    const progress = await getOnboardingProgress(userId);

    // Show onboarding if:
    // 1. User has never started onboarding
    // 2. User started but hasn't completed all required steps or skipped
    if (!progress) {
      return true;
    }

    if (progress.skipped) {
      return false;
    }

    // Check if all required steps are completed
    const requiredSteps = ONBOARDING_STEPS.filter(step => !step.optional).map(
      step => step.id
    );
    const hasCompletedAllRequired = requiredSteps.every(stepId =>
      progress.completedSteps.includes(stepId)
    );

    if (hasCompletedAllRequired) {
      // Mark onboarding as completed if not already
      if (!progress.completedAt) {
        await prisma.userOnboarding.update({
          where: { userId },
          data: { completedAt: new Date() },
        });
      }
      return false;
    }

    return true;
  } catch (error) {
    logError('Failed to check onboarding status', { userId, error });
    return false;
  }
}
