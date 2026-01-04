/**
 * Phase Tabs Component
 * Reusable tabbed navigation for Core Services and Premium Features
 * Implements filing cabinet/binder tab metaphor with active state management
 */

'use client';

import { useState } from 'react';

export type TabId = 'core' | 'premium';

interface PhaseTabsProps {
  /** Title for the Core Services tab */
  coreTitle?: string;
  /** Title for the Premium Features tab */
  premiumTitle?: string;
  /** Content to display in Core Services tab */
  coreContent: React.ReactNode;
  /** Content to display in Premium Features tab */
  premiumContent: React.ReactNode;
  /** Default active tab */
  defaultTab?: TabId;
  /** Color theme for the phase (affects tab highlighting) */
  theme?: 'primary' | 'red' | 'amber' | 'purple';
}

export function PhaseTabs({
  coreTitle = 'Core Services',
  premiumTitle = 'Premium Features',
  coreContent,
  premiumContent,
  defaultTab = 'core',
  theme = 'primary',
}: PhaseTabsProps) {
  const [activeTab, setActiveTab] = useState<TabId>(defaultTab);

  // Theme-specific colors
  const themeColors = {
    primary: {
      activeBg: 'bg-primary-600 dark:bg-primary-500',
      activeText: 'text-white',
      inactiveBg: 'bg-neutral-200 dark:bg-neutral-800',
      inactiveText: 'text-neutral-700 dark:text-neutral-300',
      hoverBg: 'hover:bg-neutral-300 dark:hover:bg-neutral-700',
    },
    red: {
      activeBg: 'bg-red-600 dark:bg-red-500',
      activeText: 'text-white',
      inactiveBg: 'bg-neutral-200 dark:bg-neutral-800',
      inactiveText: 'text-neutral-700 dark:text-neutral-300',
      hoverBg: 'hover:bg-neutral-300 dark:hover:bg-neutral-700',
    },
    amber: {
      activeBg: 'bg-amber-600 dark:bg-amber-500',
      activeText: 'text-white',
      inactiveBg: 'bg-neutral-200 dark:bg-neutral-800',
      inactiveText: 'text-neutral-700 dark:text-neutral-300',
      hoverBg: 'hover:bg-neutral-300 dark:hover:bg-neutral-700',
    },
    purple: {
      activeBg: 'bg-purple-600 dark:bg-purple-500',
      activeText: 'text-white',
      inactiveBg: 'bg-neutral-200 dark:bg-neutral-800',
      inactiveText: 'text-neutral-700 dark:text-neutral-300',
      hoverBg: 'hover:bg-neutral-300 dark:hover:bg-neutral-700',
    },
  };

  const colors = themeColors[theme];

  return (
    <div className="space-y-6">
      {/* Tab Navigation - Filing Cabinet Style */}
      <div className="flex gap-2 border-b-2 border-neutral-200 dark:border-neutral-700">
        {/* Core Services Tab */}
        <button
          onClick={() => setActiveTab('core')}
          className={`
            relative px-6 py-3 font-semibold transition-all duration-200
            rounded-t-lg -mb-0.5 border-b-2
            ${
              activeTab === 'core'
                ? `${colors.activeBg} ${colors.activeText} border-transparent shadow-lg scale-105`
                : `${colors.inactiveBg} ${colors.inactiveText} border-transparent ${colors.hoverBg}`
            }
          `}
        >
          {coreTitle}
          {activeTab === 'core' && (
            <div className="absolute bottom-0 left-0 right-0 h-0.5 bg-green-500" />
          )}
        </button>

        {/* Premium Features Tab */}
        <button
          onClick={() => setActiveTab('premium')}
          className={`
            relative px-6 py-3 font-semibold transition-all duration-200
            rounded-t-lg -mb-0.5 border-b-2
            ${
              activeTab === 'premium'
                ? `${colors.activeBg} ${colors.activeText} border-transparent shadow-lg scale-105`
                : `${colors.inactiveBg} ${colors.inactiveText} border-transparent ${colors.hoverBg}`
            }
          `}
        >
          {premiumTitle}
          {activeTab === 'premium' && (
            <div className="absolute bottom-0 left-0 right-0 h-0.5 bg-amber-500" />
          )}
        </button>
      </div>

      {/* Tab Content */}
      <div className="transition-all duration-300 ease-in-out">
        {activeTab === 'core' && (
          <div className="animate-fade-in">
            {coreContent}
          </div>
        )}
        {activeTab === 'premium' && (
          <div className="animate-fade-in">
            {premiumContent}
          </div>
        )}
      </div>
    </div>
  );
}
