/**
 * Onboarding Provider
 * Manages global onboarding state and tour activation
 */

'use client';

import {
  createContext,
  useContext,
  useState,
  useEffect,
  ReactNode,
} from 'react';
import { OnboardingTour, TourStep } from './OnboardingTour';
import { COMPLETE_ONBOARDING_TOUR } from './tour-steps';
import { logError } from '@core/lib/logger/client';

interface OnboardingContextValue {
  isOnboarding: boolean;
  currentStep: number;
  startTour: (steps?: TourStep[]) => void;
  completeTour: () => void;
  skipTour: () => void;
}

const OnboardingContext = createContext<OnboardingContextValue | null>(null);

export function useOnboarding() {
  const context = useContext(OnboardingContext);
  if (!context) {
    throw new Error('useOnboarding must be used within OnboardingProvider');
  }
  return context;
}

interface OnboardingProviderProps {
  children: ReactNode;
  userId?: string;
  autoStart?: boolean;
}

export function OnboardingProvider({
  children,
  userId,
  autoStart = true,
}: OnboardingProviderProps) {
  const [isOnboarding, setIsOnboarding] = useState(false);
  const [currentStep, setCurrentStep] = useState(0);
  const [tourSteps, setTourSteps] = useState<TourStep[]>(
    COMPLETE_ONBOARDING_TOUR
  );

  useEffect(() => {
    let isMounted = true;

    async function checkStatus() {
      if (!autoStart || !userId) return;

      try {
        const response = await fetch('/api/onboarding/status');
        if (response.ok) {
          const data = await response.json();
          // Only update state if component is still mounted
          if (isMounted && !data.completed && !data.skipped) {
            setIsOnboarding(true);
          }
        }
      } catch (error) {
        if (isMounted) {
          logError('Failed to check onboarding status', { error });
        }
      }
    }

    void checkStatus();

    return () => {
      isMounted = false;
    };
  }, [autoStart, userId]);

  function startTour(steps?: TourStep[]) {
    if (steps) {
      setTourSteps(steps);
    }
    setCurrentStep(0);
    setIsOnboarding(true);
  }

  async function completeTour() {
    setIsOnboarding(false);

    // Update server-side onboarding status
    try {
      await fetch('/api/onboarding/complete', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ completed: true }),
      });
    } catch (error) {
      logError('Failed to update onboarding status', { error });
    }
  }

  async function skipTour() {
    setIsOnboarding(false);

    // Update server-side onboarding status
    try {
      await fetch('/api/onboarding/skip', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      });
    } catch (error) {
      logError('Failed to skip onboarding', { error });
    }
  }

  return (
    <OnboardingContext.Provider
      value={{
        isOnboarding,
        currentStep,
        startTour,
        completeTour,
        skipTour,
      }}
    >
      {children}
      {isOnboarding && (
        <OnboardingTour
          steps={tourSteps}
          onComplete={completeTour}
          onSkip={skipTour}
          storageKey={`onboarding-tour-${userId}`}
        />
      )}
    </OnboardingContext.Provider>
  );
}
