'use client';

import { useEffect, useMemo, useState } from 'react';
import { useRouter } from 'next/navigation';
import { OnboardingStep } from '@core/lib/onboarding/onboarding-service';
import { logError } from '@core/lib/logger/client';

interface OnboardingWizardProps {
  userId: string;
  steps: OnboardingStep[];
  currentStep: number;
}

/**
 * Onboarding Wizard Component
 * Interactive step-by-step guide for new users
 */
export function OnboardingWizard({
  userId: _userId,
  steps,
  currentStep,
}: OnboardingWizardProps) {
  const router = useRouter();
  const [stepsState, setStepsState] = useState<OnboardingStep[]>(steps);
  const [activeStep, setActiveStep] = useState(currentStep);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    setStepsState(steps);
  }, [steps]);

  useEffect(() => {
    setActiveStep(currentStep);
  }, [currentStep]);

  const currentStepData = useMemo(() => {
    if (!stepsState.length) {
      return undefined;
    }
    return (
      stepsState.find(step => step.order === activeStep) ||
      stepsState[stepsState.length - 1]
    );
  }, [activeStep, stepsState]);

  const progress = useMemo(() => {
    if (!stepsState.length) {
      return 0;
    }
    const completedCount = stepsState.filter(step => step.completed).length;
    return (completedCount / stepsState.length) * 100;
  }, [stepsState]);

  const handleNext = async () => {
    if (!currentStepData || loading) {
      return;
    }

    setLoading(true);

    try {
      const response = await fetch('/api/onboarding/complete', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ stepId: currentStepData.id }),
      });

      if (!response.ok) {
        throw new Error(`Failed to complete step ${currentStepData.id}`);
      }

      const data = await response.json();
      const completedSteps = new Set<string>(
        data?.progress?.completedSteps ?? []
      );
      const completedAt: string | null = data?.progress?.completedAt ?? null;
      const nextStep: number = data?.progress?.currentStep ?? activeStep + 1;
      const maxOrder = stepsState.length
        ? stepsState.reduce((max, step) => Math.max(max, step.order), 1)
        : nextStep;

      setStepsState(prev =>
        prev.map(step => ({
          ...step,
          completed: completedSteps.has(step.id),
        }))
      );

      // If onboarding is complete, redirect to dashboard
      if (completedAt) {
        router.push('/dashboard');
        router.refresh();
        return;
      }

      const safeNext = Math.max(1, Math.min(nextStep, maxOrder));
      setActiveStep(safeNext);
    } catch (error) {
      logError('Failed to advance onboarding step', { error });
    } finally {
      setLoading(false);
    }
  };

  const handlePrevious = () => {
    if (activeStep > 1) {
      setActiveStep(activeStep - 1);
    }
  };

  const handleSkip = async () => {
    setLoading(true);
    try {
      await fetch('/api/onboarding/skip', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      });
      router.push('/dashboard');
    } catch (error) {
      logError('Failed to skip onboarding', { error });
    } finally {
      setLoading(false);
    }
  };

  const getStepContent = (step: OnboardingStep) => {
    switch (step.id) {
      case 'setup-mfa':
        return (
          <div className="space-y-4">
            <p className="text-neutral-600 dark:text-neutral-400">
              Two-factor authentication adds an extra layer of security to your
              account. You can set this up later in your account settings.
            </p>
            <button
              onClick={() => router.push('/dashboard/settings')}
              className="inline-flex items-center px-6 py-3 bg-neutral-900 dark:bg-white text-white dark:text-neutral-900 font-semibold rounded-lg hover:bg-neutral-800 dark:hover:bg-neutral-100 transition-colors"
            >
              Set Up Later
            </button>
          </div>
        );

      case 'connect-repo':
        return (
          <div className="space-y-4">
            <p className="text-neutral-600 dark:text-neutral-400">
              Optionally connect your GitHub account later in the repositories
              page to access your repositories and start generating APIs.
            </p>
            <button
              onClick={() => router.push('/dashboard/repositories')}
              className="inline-flex items-center px-6 py-3 bg-neutral-900 dark:bg-white text-white dark:text-neutral-900 font-semibold rounded-lg hover:bg-neutral-800 dark:hover:bg-neutral-100 transition-colors"
            >
              <svg
                className="w-5 h-5 mr-2"
                fill="currentColor"
                viewBox="0 0 24 24"
                aria-hidden="true"
              >
                <path
                  fillRule="evenodd"
                  d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z"
                  clipRule="evenodd"
                />
              </svg>
              Connect GitHub
            </button>
          </div>
        );

      case 'generate-api':
        return (
          <div className="space-y-4">
            <p className="text-neutral-600 dark:text-neutral-400">
              Generate comprehensive API documentation from your codebase
              automatically.
            </p>
            <button
              onClick={() => router.push('/build')}
              className="inline-flex items-center px-6 py-3 bg-primary-600 text-white font-semibold rounded-lg hover:bg-primary-700 transition-colors"
            >
              Go to API Generator
            </button>
          </div>
        );

      case 'security-scan':
        return (
          <div className="space-y-4">
            <p className="text-neutral-600 dark:text-neutral-400">
              Scan your APIs for vulnerabilities and get actionable security
              recommendations.
            </p>
            <button
              onClick={() => router.push('/defend')}
              className="inline-flex items-center px-6 py-3 bg-error-600 text-white font-semibold rounded-lg hover:bg-error-700 transition-colors"
            >
              Run Security Scan
            </button>
          </div>
        );

      case 'deploy-honeypot':
        return (
          <div className="space-y-4">
            <p className="text-neutral-600 dark:text-neutral-400">
              Deploy honeypots to detect and monitor attackers targeting your
              APIs.
            </p>
            <button
              onClick={() => router.push('/dashboard/honeypots')}
              className="inline-flex items-center px-6 py-3 bg-purple-600 text-white font-semibold rounded-lg hover:bg-purple-700 transition-colors"
            >
              Deploy Honeypot
            </button>
          </div>
        );

      case 'explore-insights':
        return (
          <div className="space-y-4">
            <p className="text-neutral-600 dark:text-neutral-400">
              Learn from real-world attack patterns and threat intelligence.
            </p>
            <button
              onClick={() => router.push('/learn')}
              className="inline-flex items-center px-6 py-3 bg-success-600 text-white font-semibold rounded-lg hover:bg-success-700 transition-colors"
            >
              Explore Insights
            </button>
          </div>
        );

      default:
        return null;
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-primary-50 to-indigo-100 dark:from-neutral-900 dark:to-neutral-800 flex items-center justify-center p-6">
      <div className="max-w-3xl w-full bg-white dark:bg-neutral-800 rounded-2xl shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="bg-gradient-to-r from-primary-600 to-indigo-600 px-8 py-6 text-white">
          <h1 className="text-3xl font-bold mb-2">Welcome to DevFortress! 🚀</h1>
          <p className="text-primary-100">
            Let&apos;s get you started with building secure APIs
          </p>
        </div>

        {/* Progress Bar */}
        <div className="px-8 pt-6">
          <div className="flex justify-between items-center mb-2">
            <span className="text-sm font-medium text-neutral-700 dark:text-neutral-300">
              Progress
            </span>
            <span className="text-sm font-medium text-neutral-700 dark:text-neutral-300">
              {Math.round(progress)}%
            </span>
          </div>
          <div className="w-full bg-neutral-200 dark:bg-neutral-700 rounded-full h-2">
            <div
              className="bg-gradient-to-r from-primary-600 to-indigo-600 h-2 rounded-full transition-all duration-300"
              style={{ width: `${progress}%` }}
            />
          </div>
        </div>

        {/* Steps Navigation */}
        <div className="px-8 py-6">
          <div className="flex items-center justify-between mb-8">
            {stepsState.map((step, index) => (
              <div key={step.id} className="flex items-center">
                <button
                  onClick={() => setActiveStep(step.order)}
                  className={`w-10 h-10 rounded-full flex items-center justify-center font-semibold transition-all ${
                    step.completed
                      ? 'bg-success-500 text-white'
                      : step.order === activeStep
                        ? 'bg-primary-600 text-white'
                        : 'bg-neutral-200 dark:bg-neutral-700 text-neutral-600 dark:text-neutral-400'
                  }`}
                  aria-label={`Step ${step.order}: ${step.title}`}
                >
                  {step.completed ? '✓' : step.order}
                </button>
                {index < stepsState.length - 1 && (
                  <div
                    className={`w-12 h-1 mx-2 ${
                      step.completed
                        ? 'bg-success-500'
                        : 'bg-neutral-200 dark:bg-neutral-700'
                    }`}
                  />
                )}
              </div>
            ))}
          </div>

          {/* Step Content */}
          <div className="mb-8">
            <div className="flex items-center gap-2 mb-4">
              <h2 className="text-2xl font-bold text-neutral-900 dark:text-white">
                {currentStepData?.title || 'Getting Started'}
              </h2>
              {currentStepData?.optional && (
                <span className="px-2 py-1 text-xs font-medium bg-neutral-100 dark:bg-neutral-700 text-neutral-600 dark:text-neutral-400 rounded-full">
                  Optional
                </span>
              )}
            </div>
            <p className="text-neutral-700 dark:text-neutral-300 mb-6">
              {currentStepData?.description ||
                'Let&apos;s get started with your DevFortress journey'}
            </p>
            {currentStepData ? getStepContent(currentStepData) : null}
          </div>

          {/* Actions */}
          <div className="flex justify-between items-center pt-6 border-t border-neutral-200 dark:border-neutral-700">
            <button
              onClick={handleSkip}
              disabled={loading}
              className="px-4 py-2 text-neutral-600 dark:text-neutral-400 hover:text-neutral-900 dark:hover:text-white transition-colors disabled:opacity-50"
            >
              Skip for now
            </button>
            <div className="flex gap-3">
              {activeStep > 1 && (
                <button
                  onClick={handlePrevious}
                  disabled={loading}
                  className="px-6 py-2 border border-neutral-300 dark:border-neutral-600 text-neutral-700 dark:text-neutral-300 rounded-lg hover:bg-neutral-50 dark:hover:bg-neutral-700 transition-colors disabled:opacity-50"
                >
                  Previous
                </button>
              )}
              <button
                onClick={handleNext}
                disabled={loading}
                className="px-6 py-2 bg-primary-600 text-white font-semibold rounded-lg hover:bg-primary-700 transition-colors disabled:opacity-50"
              >
                {activeStep < stepsState.length ? 'Next' : 'Finish'}
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
