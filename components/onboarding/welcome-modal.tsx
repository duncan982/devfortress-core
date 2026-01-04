'use client';

/**
 * Welcome Modal Component
 *
 * Shows a guided welcome experience for first-time users.
 * Introduces key features and helps users get started quickly.
 *
 * @module components/onboarding/welcome-modal
 */

import { useState } from 'react';
import {
  X,
  Rocket,
  Shield,
  Lightbulb,
  ChevronRight,
  Check,
} from 'lucide-react';

interface WelcomeModalProps {
  /**
   * User's name for personalization
   */
  userName?: string;

  /**
   * Whether to show the modal
   */
  isOpen: boolean;

  /**
   * Callback when modal is closed
   */
  onClose: () => void;

  /**
   * Callback when onboarding is completed
   */
  onComplete?: () => void;
}

const STEPS = [
  {
    id: 'welcome',
    title: 'Welcome to DevFortress! 🎉',
    description:
      'Build secure APIs with AI assistance and protect them with intelligent honeypots.',
    icon: Rocket,
    color: 'text-blue-500',
  },
  {
    id: 'build',
    title: 'BUILD: Generate Secure APIs',
    description:
      'Describe your API in plain English. Our AI generates production-ready code with built-in security best practices (OWASP Top 10 protection).',
    icon: Rocket,
    color: 'text-green-500',
    action: 'Try: "Create a REST API for user authentication with JWT tokens"',
  },
  {
    id: 'defend',
    title: 'DEFEND: Deploy Honeypots',
    description:
      'Deploy decoy APIs that look like your real endpoints. Attackers waste time on fakes while you collect intelligence.',
    icon: Shield,
    color: 'text-orange-500',
    action: 'Deploy a honeypot from any generated API project',
  },
  {
    id: 'learn',
    title: 'LEARN: Get Threat Insights',
    description:
      'View attack patterns, threat intelligence, and actionable recommendations to improve your security posture.',
    icon: Lightbulb,
    color: 'text-purple-500',
    action: 'Check the Insights tab after your honeypot captures traffic',
  },
];

export function WelcomeModal({
  userName,
  isOpen,
  onClose,
  onComplete,
}: WelcomeModalProps) {
  // Initialize state based on isOpen prop - reset on each open
  const [currentStep, setCurrentStep] = useState(0);
  // Track completed steps (used for potential future progress indicators)
   
  const [completedSteps, setCompletedSteps] = useState<Set<number>>(new Set());
  const [prevIsOpen, setPrevIsOpen] = useState(isOpen);

  // Reset state when modal opens (using derived state pattern)
  if (isOpen && !prevIsOpen) {
    setCurrentStep(0);
    setCompletedSteps(new Set());
    setPrevIsOpen(true);
  } else if (!isOpen && prevIsOpen) {
    setPrevIsOpen(false);
  }

  if (!isOpen) return null;

  const currentStepData = STEPS[currentStep];
  const isLastStep = currentStep === STEPS.length - 1;
  const Icon = currentStepData.icon;

  const handleNext = () => {
    setCompletedSteps(prev => new Set([...prev, currentStep]));
    if (isLastStep) {
      onComplete?.();
      onClose();
    } else {
      setCurrentStep(prev => prev + 1);
    }
  };

  const handleSkip = () => {
    onClose();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      {/* Backdrop */}
      <div
        className="absolute inset-0 bg-black/50 backdrop-blur-sm"
        onClick={handleSkip}
      />

      {/* Modal */}
      <div className="relative bg-white dark:bg-gray-900 rounded-2xl shadow-2xl max-w-lg w-full mx-4 overflow-hidden">
        {/* Close button */}
        <button
          onClick={handleSkip}
          className="absolute top-4 right-4 p-2 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 rounded-full hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors z-10"
          aria-label="Close"
        >
          <X className="h-5 w-5" />
        </button>

        {/* Progress indicator */}
        <div className="flex gap-1 p-4 pb-0">
          {STEPS.map((_, index) => (
            <div
              key={index}
              className={`h-1 flex-1 rounded-full transition-colors ${
                index <= currentStep
                  ? 'bg-primary-500'
                  : 'bg-gray-200 dark:bg-gray-700'
              }`}
            />
          ))}
        </div>

        {/* Content */}
        <div className="p-8 pt-6">
          {/* Step indicator */}
          <div className="flex items-center gap-2 mb-6">
            <div
              className={`p-3 rounded-xl bg-gray-100 dark:bg-gray-800 ${currentStepData.color}`}
            >
              <Icon className="h-6 w-6" />
            </div>
            <span className="text-sm text-gray-500 dark:text-gray-400">
              Step {currentStep + 1} of {STEPS.length}
            </span>
          </div>

          {/* Title */}
          <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-3">
            {currentStep === 0 && userName
              ? `Welcome, ${userName}! 🎉`
              : currentStepData.title}
          </h2>

          {/* Description */}
          <p className="text-gray-600 dark:text-gray-300 mb-4">
            {currentStepData.description}
          </p>

          {/* Action hint */}
          {currentStepData.action && (
            <div className="bg-gray-50 dark:bg-gray-800 rounded-lg p-4 mb-6">
              <p className="text-sm font-medium text-gray-700 dark:text-gray-300">
                💡 {currentStepData.action}
              </p>
            </div>
          )}

          {/* Quick start options for first step */}
          {currentStep === 0 && (
            <div className="grid grid-cols-2 gap-3 mb-6">
              <a
                href="/dashboard/build"
                className="flex items-center gap-2 p-3 rounded-lg border border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors"
              >
                <Rocket className="h-5 w-5 text-green-500" />
                <span className="text-sm font-medium">Generate API</span>
              </a>
              <a
                href="/docs/self-hosting"
                className="flex items-center gap-2 p-3 rounded-lg border border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors"
              >
                <Shield className="h-5 w-5 text-blue-500" />
                <span className="text-sm font-medium">Self-Host Guide</span>
              </a>
            </div>
          )}

          {/* Navigation buttons */}
          <div className="flex items-center justify-between">
            <button
              onClick={handleSkip}
              className="text-sm text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200"
            >
              Skip tour
            </button>

            <button
              onClick={handleNext}
              className="inline-flex items-center gap-2 px-6 py-2.5 bg-primary-600 text-white rounded-lg font-medium hover:bg-primary-700 transition-colors"
            >
              {isLastStep ? (
                <>
                  <Check className="h-4 w-4" />
                  Get Started
                </>
              ) : (
                <>
                  Next
                  <ChevronRight className="h-4 w-4" />
                </>
              )}
            </button>
          </div>
        </div>

        {/* Bottom feature highlight */}
        {currentStep === STEPS.length - 1 && (
          <div className="bg-gradient-to-r from-primary-500 to-primary-600 px-8 py-4 text-white">
            <p className="text-sm opacity-90">
              🚀 <strong>Pro tip:</strong> Start by generating an API, then
              deploy a honeypot to see the full security flywheel in action!
            </p>
          </div>
        )}
      </div>
    </div>
  );
}

/**
 * Hook to manage welcome modal state
 */
export function useWelcomeModal() {
  // Check localStorage synchronously on mount to avoid flash
  const getInitialState = () => {
    if (typeof window === 'undefined') return { seen: true, open: false };
    const seen = localStorage.getItem('devfortress_welcome_seen');
    return { seen: !!seen, open: !seen };
  };

  const initial = getInitialState();
  const [isOpen, setIsOpen] = useState(initial.open);
  const [hasSeenWelcome, setHasSeenWelcome] = useState(initial.seen);

  const markAsSeen = () => {
    if (typeof window !== 'undefined') {
      localStorage.setItem('devfortress_welcome_seen', 'true');
    }
    setHasSeenWelcome(true);
  };

  const handleClose = () => {
    setIsOpen(false);
    markAsSeen();
  };

  const handleComplete = () => {
    markAsSeen();
  };

  const resetWelcome = () => {
    if (typeof window !== 'undefined') {
      localStorage.removeItem('devfortress_welcome_seen');
    }
    setHasSeenWelcome(false);
    setIsOpen(true);
  };

  return {
    isOpen,
    hasSeenWelcome,
    openWelcome: () => setIsOpen(true),
    closeWelcome: handleClose,
    completeWelcome: handleComplete,
    resetWelcome,
  };
}

export default WelcomeModal;
