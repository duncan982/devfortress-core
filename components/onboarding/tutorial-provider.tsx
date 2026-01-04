/**
 * Interactive Tutorial System
 * Provides step-by-step tutorials with tooltips and highlights
 */

'use client';

import { useState, useEffect, useRef } from 'react';
import { X, ChevronLeft, ChevronRight } from 'lucide-react';

export interface TutorialStep {
  target: string; // CSS selector for element to highlight
  title: string;
  content: string;
  position?: 'top' | 'bottom' | 'left' | 'right';
  action?: () => void;
  helpArticle?: string; // Link to help center article for deeper learning
}

interface TutorialProviderProps {
  steps: TutorialStep[];
  onComplete: () => void;
  onSkip: () => void;
  enabled: boolean;
}

export function TutorialProvider({
  steps,
  onComplete,
  onSkip,
  enabled,
}: TutorialProviderProps) {
  const [currentStep, setCurrentStep] = useState(0);
  const [position, setPosition] = useState({ top: 0, left: 0 });
  const [tooltipPosition, setTooltipPosition] = useState<
    'top' | 'bottom' | 'left' | 'right'
  >('bottom');
  const tooltipRef = useRef<HTMLDivElement>(null);

  const step = steps[currentStep];
  const isLastStep = currentStep === steps.length - 1;
  const isFirstStep = currentStep === 0;

  useEffect(() => {
    if (!enabled || !step) return;

    // Find target element and calculate position
    const updatePosition = () => {
      const target = document.querySelector(step.target);
      if (!target) return;

      const rect = target.getBoundingClientRect();
      const tooltipRect = tooltipRef.current?.getBoundingClientRect();

      let top = rect.bottom + window.scrollY + 10;
      let left = rect.left + window.scrollX + rect.width / 2;

      // Adjust position based on preference
      const preferredPosition = step.position || 'bottom';
      setTooltipPosition(preferredPosition);

      switch (preferredPosition) {
        case 'top':
          top = rect.top + window.scrollY - (tooltipRect?.height || 0) - 10;
          break;
        case 'bottom':
          top = rect.bottom + window.scrollY + 10;
          break;
        case 'left':
          top = rect.top + window.scrollY + rect.height / 2;
          left = rect.left + window.scrollX - (tooltipRect?.width || 0) - 10;
          break;
        case 'right':
          top = rect.top + window.scrollY + rect.height / 2;
          left = rect.right + window.scrollX + 10;
          break;
      }

      setPosition({ top, left });

      // Add highlight to target element
      target.classList.add('tutorial-highlight');
      target.scrollIntoView({ behavior: 'smooth', block: 'center' });

      return () => {
        target.classList.remove('tutorial-highlight');
      };
    };

    updatePosition();
    window.addEventListener('resize', updatePosition);

    return () => {
      window.removeEventListener('resize', updatePosition);
      const target = document.querySelector(step.target);
      target?.classList.remove('tutorial-highlight');
    };
  }, [currentStep, enabled, step]);

  const handleNext = () => {
    if (step.action) {
      step.action();
    }

    if (isLastStep) {
      onComplete();
    } else {
      setCurrentStep(currentStep + 1);
    }
  };

  const handlePrevious = () => {
    if (!isFirstStep) {
      setCurrentStep(currentStep - 1);
    }
  };

  if (!enabled || !step) return null;

  return (
    <>
      {/* Backdrop overlay */}
      <div className="fixed inset-0 bg-black bg-opacity-50 z-modalBackdrop pointer-events-none" />

      {/* Tutorial tooltip */}
      <div
        ref={tooltipRef}
        className="fixed z-tooltip bg-white dark:bg-neutral-900 rounded-lg shadow-2xl border-2 border-primary-500 dark:border-primary-400 max-w-sm"
        style={{
          top: `${position.top}px`,
          left: `${position.left}px`,
          transform:
            tooltipPosition === 'left' || tooltipPosition === 'right'
              ? 'translateY(-50%)'
              : 'translateX(-50%)',
        }}
      >
        {/* Arrow indicator */}
        <div
          className={`absolute w-3 h-3 bg-white dark:bg-neutral-900 border-2 border-primary-500 dark:border-primary-400 transform rotate-45 ${
            tooltipPosition === 'top'
              ? 'bottom-[-8px] left-1/2 -translate-x-1/2'
              : tooltipPosition === 'bottom'
                ? 'top-[-8px] left-1/2 -translate-x-1/2'
                : tooltipPosition === 'left'
                  ? 'right-[-8px] top-1/2 -translate-y-1/2'
                  : 'left-[-8px] top-1/2 -translate-y-1/2'
          }`}
        />

        <div className="p-4">
          {/* Header */}
          <div className="flex items-start justify-between mb-3">
            <div className="flex-1">
              <h3 className="text-lg font-semibold text-neutral-900 dark:text-white">
                {step.title}
              </h3>
              <p className="text-xs text-neutral-500 dark:text-neutral-400 mt-1">
                Step {currentStep + 1} of {steps.length}
              </p>
            </div>
            <button
              onClick={onSkip}
              className="p-1 rounded-md hover:bg-neutral-100 dark:hover:bg-neutral-800 transition-colors"
              aria-label="Skip tutorial"
            >
              <X className="w-5 h-5 text-neutral-500" />
            </button>
          </div>

          {/* Content */}
          <p className="text-sm text-neutral-600 dark:text-neutral-400 mb-3">
            {step.content}
          </p>

          {/* Help Center Link */}
          {step.helpArticle && (
            <a
              href={step.helpArticle}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 text-xs text-primary-600 dark:text-primary-400 hover:underline mb-3"
            >
              Learn more in Help Center →
            </a>
          )}

          {/* Progress bar */}
          <div className="w-full bg-neutral-200 dark:bg-neutral-800 rounded-full h-1.5 mb-4">
            <div
              className="bg-primary-600 dark:bg-primary-500 h-1.5 rounded-full transition-all duration-300"
              style={{ width: `${((currentStep + 1) / steps.length) * 100}%` }}
            />
          </div>

          {/* Navigation buttons */}
          <div className="flex items-center justify-between gap-2">
            <button
              onClick={onSkip}
              className="text-sm text-neutral-600 dark:text-neutral-400 hover:text-neutral-900 dark:hover:text-white transition-colors"
            >
              Skip
            </button>

            <div className="flex items-center gap-2">
              {!isFirstStep && (
                <button
                  onClick={handlePrevious}
                  className="flex items-center gap-1 px-3 py-1.5 text-sm font-medium text-neutral-700 dark:text-neutral-300 border border-neutral-300 dark:border-neutral-700 rounded-md hover:bg-neutral-100 dark:hover:bg-neutral-800 transition-colors"
                >
                  <ChevronLeft className="w-4 h-4" />
                  Back
                </button>
              )}

              <button
                onClick={handleNext}
                className="flex items-center gap-1 px-4 py-1.5 text-sm font-medium text-white bg-primary-600 dark:bg-primary-500 rounded-md hover:bg-primary-700 dark:hover:bg-primary-600 transition-colors"
              >
                {isLastStep ? 'Finish' : 'Next'}
                {!isLastStep && <ChevronRight className="w-4 h-4" />}
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Highlight styles */}
      <style jsx global>{`
        .tutorial-highlight {
          position: relative;
          z-index: 1041;
          box-shadow: 0 0 0 4px rgba(14, 165, 233, 0.5);
          border-radius: 0.375rem;
        }
      `}</style>
    </>
  );
}

/**
 * Tutorial hook for managing tutorial state
 */
export function useTutorial(tutorialId: string) {
  const [enabled, setEnabled] = useState(false);
  const [completed, setCompleted] = useState(() => {
    // Initialize from localStorage
    if (typeof window !== 'undefined') {
      const completedTutorials = JSON.parse(
        localStorage.getItem('completedTutorials') || '[]'
      );
      return completedTutorials.includes(tutorialId);
    }
    return false;
  });

  const start = () => setEnabled(true);

  const complete = async () => {
    setEnabled(false);
    setCompleted(true);

    // Save completion status
    const completedTutorials = JSON.parse(
      localStorage.getItem('completedTutorials') || '[]'
    );
    if (!completedTutorials.includes(tutorialId)) {
      completedTutorials.push(tutorialId);
      localStorage.setItem(
        'completedTutorials',
        JSON.stringify(completedTutorials)
      );
    }

    // Track tutorial completion
    try {
      await fetch('/api/analytics/tutorial-completion', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ tutorialId }),
      });
    } catch {
      // Silently fail
    }
  };

  const skip = async () => {
    setEnabled(false);

    // Track tutorial skip
    try {
      await fetch('/api/analytics/tutorial-skip', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ tutorialId }),
      });
    } catch {
      // Silently fail
    }
  };

  const reset = () => {
    const completedTutorials = JSON.parse(
      localStorage.getItem('completedTutorials') || '[]'
    );
    const filtered = completedTutorials.filter(
      (id: string) => id !== tutorialId
    );
    localStorage.setItem('completedTutorials', JSON.stringify(filtered));
    setCompleted(false);
  };

  return {
    enabled,
    completed,
    start,
    complete,
    skip,
    reset,
  };
}
