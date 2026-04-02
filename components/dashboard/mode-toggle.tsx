'use client';

import { useState, useCallback, useEffect } from 'react';

export type SurveillanceMode = 'all' | 'agents' | 'api';

interface ModeToggleProps {
  defaultMode?: SurveillanceMode;
  onChange?: (mode: SurveillanceMode) => void;
  className?: string;
  /** Persist mode selection in localStorage */
  persistKey?: string;
}

const modeLabels: Record<SurveillanceMode, string> = {
  all: 'All Events',
  agents: 'Agents',
  api: 'API',
};

const modeDescriptions: Record<SurveillanceMode, string> = {
  all: 'Show all security events from both agents and APIs',
  agents: 'Show only events from AI agents (LangChain, OpenAI, etc.)',
  api: 'Show only events from traditional API endpoints',
};

const modeIcons: Record<SurveillanceMode, React.ReactNode> = {
  all: (
    <svg
      className="w-4 h-4"
      fill="none"
      viewBox="0 0 24 24"
      stroke="currentColor"
    >
      <path
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth={2}
        d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zM14 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zM14 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z"
      />
    </svg>
  ),
  agents: (
    <svg
      className="w-4 h-4"
      fill="none"
      viewBox="0 0 24 24"
      stroke="currentColor"
    >
      <path
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth={2}
        d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"
      />
    </svg>
  ),
  api: (
    <svg
      className="w-4 h-4"
      fill="none"
      viewBox="0 0 24 24"
      stroke="currentColor"
    >
      <path
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth={2}
        d="M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z"
      />
    </svg>
  ),
};

/**
 * Get initial mode from localStorage (for use in useState initializer)
 */
function getPersistedMode(persistKey?: string, defaultMode: SurveillanceMode = 'all'): SurveillanceMode {
  if (persistKey && typeof window !== 'undefined') {
    const saved = localStorage.getItem(persistKey);
    if (saved === 'all' || saved === 'agents' || saved === 'api') {
      return saved;
    }
  }
  return defaultMode;
}

/**
 * Mode Toggle Component
 * Allows users to filter dashboard views between All, Agents, and API events
 */
export function ModeToggle({
  defaultMode = 'all',
  onChange,
  className = '',
  persistKey,
}: ModeToggleProps) {
  const [mode, setMode] = useState<SurveillanceMode>(() => 
    getPersistedMode(persistKey, defaultMode)
  );

  // Notify parent of initial persisted mode if different from default
  useEffect(() => {
    const persisted = getPersistedMode(persistKey, defaultMode);
    if (persisted !== defaultMode) {
      onChange?.(persisted);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleModeChange = useCallback(
    (newMode: SurveillanceMode) => {
      setMode(newMode);
      onChange?.(newMode);
      if (persistKey && typeof window !== 'undefined') {
        localStorage.setItem(persistKey, newMode);
      }
    },
    [onChange, persistKey]
  );

  const modes: SurveillanceMode[] = ['all', 'agents', 'api'];

  return (
    <div className={`flex items-center gap-1 ${className}`}>
      <span className="text-sm font-medium text-neutral-600 dark:text-neutral-400 mr-2">
        View:
      </span>
      <div className="inline-flex rounded-lg border border-neutral-200 dark:border-neutral-700 bg-neutral-100 dark:bg-neutral-800 p-1">
        {modes.map(m => (
          <button
            key={m}
            onClick={() => handleModeChange(m)}
            title={modeDescriptions[m]}
            className={`
              inline-flex items-center gap-1.5 px-3 py-1.5 text-sm font-medium rounded-md transition-all
              ${
                mode === m
                  ? 'bg-white dark:bg-neutral-700 text-brand-600 dark:text-brand-400 shadow-sm'
                  : 'text-neutral-600 dark:text-neutral-400 hover:text-neutral-900 dark:hover:text-neutral-200'
              }
            `}
          >
            {modeIcons[m]}
            {modeLabels[m]}
          </button>
        ))}
      </div>
    </div>
  );
}

/**
 * Compact Mode Toggle for space-constrained areas
 */
export function ModeToggleCompact({
  defaultMode = 'all',
  onChange,
  className = '',
  persistKey,
}: ModeToggleProps) {
  const [mode, setMode] = useState<SurveillanceMode>(() => 
    getPersistedMode(persistKey, defaultMode)
  );

  // Notify parent of initial persisted mode if different from default
  useEffect(() => {
    const persisted = getPersistedMode(persistKey, defaultMode);
    if (persisted !== defaultMode) {
      onChange?.(persisted);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleModeChange = useCallback(
    (newMode: SurveillanceMode) => {
      setMode(newMode);
      onChange?.(newMode);
      if (persistKey && typeof window !== 'undefined') {
        localStorage.setItem(persistKey, newMode);
      }
    },
    [onChange, persistKey]
  );

  return (
    <select
      value={mode}
      onChange={e => handleModeChange(e.target.value as SurveillanceMode)}
      className={`
        px-3 py-1.5 text-sm font-medium rounded-md border
        border-neutral-200 dark:border-neutral-700
        bg-white dark:bg-neutral-800
        text-neutral-700 dark:text-neutral-300
        focus:outline-none focus:ring-2 focus:ring-brand-500
        ${className}
      `}
    >
      <option value="all">All Events</option>
      <option value="agents">Agents Only</option>
      <option value="api">API Only</option>
    </select>
  );
}

/**
 * Hook to manage surveillance mode state
 */
export function useSurveillanceMode(
  persistKey?: string
): [SurveillanceMode, (mode: SurveillanceMode) => void] {
  const [mode, setMode] = useState<SurveillanceMode>(() => getPersistedMode(persistKey));

  const updateMode = useCallback(
    (newMode: SurveillanceMode) => {
      setMode(newMode);
      if (persistKey && typeof window !== 'undefined') {
        localStorage.setItem(persistKey, newMode);
      }
    },
    [persistKey]
  );

  return [mode, updateMode];
}

/**
 * Check if an event originated from an AI agent
 */
export function isAgentEvent<T extends { 
  metadata?: Record<string, unknown>;
  eventType?: string;
  userAgent?: string;
}>(event: T): boolean {
  // Check metadata flags
  if (event.metadata?.isAgent === true) return true;
  if (event.metadata?.agentId) return true;
  
  // Check metadata source
  const source = String(event.metadata?.source || '').toLowerCase();
  if (source.includes('agent') || source.includes('langchain') || source.includes('openai') || source.includes('ai')) {
    return true;
  }
  
  // Check event type
  const eventType = String(event.eventType || '').toLowerCase();
  if (eventType.includes('agent') || eventType.includes('ai_')) {
    return true;
  }
  
  // Check user agent for common AI agent signatures
  const userAgent = String(event.userAgent || '').toLowerCase();
  const agentPatterns = [
    'langchain',
    'openai',
    'anthropic',
    'gpt',
    'claude',
    'llama',
    'ai-agent',
    'chatgpt',
    'copilot',
    'autogpt',
  ];
  
  return agentPatterns.some(pattern => userAgent.includes(pattern));
}

/**
 * Utility to filter events based on surveillance mode
 * Detects agent events by checking:
 * - metadata.isAgent flag
 * - metadata.agentId presence
 * - metadata.source containing 'agent'
 * - eventType containing 'agent'
 * - userAgent containing agent identifiers
 */
export function filterEventsByMode<
  T extends { 
    metadata?: Record<string, unknown>;
    eventType?: string;
    userAgent?: string;
  },
>(events: T[], mode: SurveillanceMode): T[] {
  if (mode === 'all') return events;

  return events.filter(event => {
    const isAgent = isAgentEvent(event);
    return mode === 'agents' ? isAgent : !isAgent;
  });
}

export default ModeToggle;
