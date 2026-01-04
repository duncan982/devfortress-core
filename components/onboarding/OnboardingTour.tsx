/**
 * Onboarding Tour Component
 * Custom guided tour for DevFortress onboarding
 */

'use client';

import { useState, useEffect } from 'react';
import { logInfo } from '@core/lib/logger/client';

export interface TourStep {
  target: string; // CSS selector
  title: string;
  content: string;
  placement?: 'top' | 'bottom' | 'left' | 'right';
  action?: () => void;
}

interface OnboardingTourProps {
  steps: TourStep[];
  onComplete: () => void;
  onSkip: () => void;
  storageKey: string;
}

export function OnboardingTour({
  steps,
  onComplete,
  onSkip,
  storageKey,
}: OnboardingTourProps) {
  const [currentStep, setCurrentStep] = useState(0);
  const [isActive, setIsActive] = useState(false);
  const [position, setPosition] = useState({ top: 0, left: 0 });

  useEffect(() => {
    // Check if tour was already completed
    const completed = localStorage.getItem(storageKey);
    if (!completed) {
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setIsActive(true);
      logInfo('Starting onboarding tour', { storageKey });
    }
  }, [storageKey]);

  useEffect(() => {
    if (!isActive || currentStep >= steps.length) return;

    // Position the tooltip near the target element
    const step = steps[currentStep];
    const target = document.querySelector(step.target);

    if (target) {
      const rect = target.getBoundingClientRect();
      const placement = step.placement || 'bottom';

      let top = 0;
      let left = 0;

      switch (placement) {
        case 'top':
          top = rect.top - 150;
          left = rect.left + rect.width / 2 - 150;
          break;
        case 'bottom':
          top = rect.bottom + 10;
          left = rect.left + rect.width / 2 - 150;
          break;
        case 'left':
          top = rect.top + rect.height / 2 - 75;
          left = rect.left - 310;
          break;
        case 'right':
          top = rect.top + rect.height / 2 - 75;
          left = rect.right + 10;
          break;
      }

      // eslint-disable-next-line react-hooks/set-state-in-effect
      setPosition({ top, left });

      // Highlight the target element
      target.classList.add('onboarding-highlight');

      // Scroll to element
      target.scrollIntoView({ behavior: 'smooth', block: 'center' });

      return () => {
        target.classList.remove('onboarding-highlight');
      };
    }
  }, [currentStep, isActive, steps]);

  const handleNext = () => {
    if (currentStep < steps.length - 1) {
      const step = steps[currentStep];
      if (step.action) step.action();
      setCurrentStep(currentStep + 1);
    } else {
      handleComplete();
    }
  };

  const handlePrevious = () => {
    if (currentStep > 0) {
      setCurrentStep(currentStep - 1);
    }
  };

  const handleSkip = () => {
    setIsActive(false);
    localStorage.setItem(storageKey, 'skipped');
    onSkip();
    logInfo('Onboarding tour skipped', { step: currentStep });
  };

  const handleComplete = () => {
    setIsActive(false);
    localStorage.setItem(storageKey, 'completed');
    onComplete();
    logInfo('Onboarding tour completed');
  };

  if (!isActive || currentStep >= steps.length) return null;

  const step = steps[currentStep];

  return (
    <>
      {/* Overlay */}
      <div className="fixed inset-0 bg-black/50 z-40" onClick={handleSkip} />

      {/* Tooltip */}
      <div
        className="fixed z-50 bg-white dark:bg-gray-800 rounded-lg shadow-2xl w-80 p-6"
        style={{
          top: `${position.top}px`,
          left: `${position.left}px`,
          maxWidth: '90vw',
        }}
      >
        {/* Header */}
        <div className="flex items-start justify-between mb-4">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100">
            {step.title}
          </h3>
          <button
            onClick={handleSkip}
            className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
            aria-label="Close"
          >
            <svg
              className="w-5 h-5"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M6 18L18 6M6 6l12 12"
              />
            </svg>
          </button>
        </div>

        {/* Content */}
        <p className="text-sm text-gray-600 dark:text-gray-400 mb-6">
          {step.content}
        </p>

        {/* Progress */}
        <div className="mb-4">
          <div className="flex justify-between text-xs text-gray-500 dark:text-gray-400 mb-2">
            <span>
              Step {currentStep + 1} of {steps.length}
            </span>
            <span>{Math.round(((currentStep + 1) / steps.length) * 100)}%</span>
          </div>
          <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
            <div
              className="bg-blue-600 h-2 rounded-full transition-all duration-300"
              style={{ width: `${((currentStep + 1) / steps.length) * 100}%` }}
            />
          </div>
        </div>

        {/* Actions */}
        <div className="flex justify-between">
          <button
            onClick={handleSkip}
            className="px-4 py-2 text-sm text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-100"
          >
            Skip Tour
          </button>
          <div className="flex space-x-2">
            {currentStep > 0 && (
              <button
                onClick={handlePrevious}
                className="px-4 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700"
              >
                Previous
              </button>
            )}
            <button
              onClick={handleNext}
              className="px-4 py-2 text-sm bg-blue-600 text-white rounded-lg hover:bg-blue-700"
            >
              {currentStep === steps.length - 1 ? 'Finish' : 'Next'}
            </button>
          </div>
        </div>
      </div>

      {/* Global styles for highlighted elements */}
      <style jsx global>{`
        .onboarding-highlight {
          position: relative;
          z-index: 45;
          box-shadow: 0 0 0 4px rgba(59, 130, 246, 0.5);
          border-radius: 4px;
        }
      `}</style>
    </>
  );
}
