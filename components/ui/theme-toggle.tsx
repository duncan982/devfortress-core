/**
 * Theme Toggle Component
 * Allows users to switch between light, dark, and system theme preferences
 *
 * Note: setState in useEffect for hasMounted is a valid hydration fix pattern
 */

'use client';

import { useTheme } from '@core/components/providers/theme-provider';
import { useEffect, useState } from 'react';

/**
 * Theme Toggle Component
 * Allows users to switch between light, dark, and system theme preferences
 */
export function ThemeToggle() {
  const { theme, setTheme } = useTheme();
  const [isOpen, setIsOpen] = useState(false);
  const [mounted, setMounted] = useState(false);

  // Prevent hydration mismatch by only rendering after mount
  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setMounted(true);
  }, []);

  const themes = [
    { value: 'light' as const, label: 'Light', icon: '☀️' },
    { value: 'dark' as const, label: 'Dark', icon: '🌙' },
    { value: 'system' as const, label: 'System', icon: '💻' },
  ];

  const currentTheme = themes.find(t => t.value === theme) || themes[2]; // Default to system

  // Show placeholder during SSR to prevent hydration mismatch
  if (!mounted) {
    return (
      <div className="relative">
        <button
          className="flex items-center gap-2 px-3 py-2 rounded-lg hover:bg-neutral-100 dark:hover:bg-neutral-800 transition-colors"
          aria-label="Toggle theme"
          disabled
        >
          <span className="text-xl" aria-hidden="true">
            💻
          </span>
          <span className="text-sm font-medium text-neutral-700 dark:text-neutral-300">
            System
          </span>
          <svg
            className="w-4 h-4 text-neutral-500"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
            aria-hidden="true"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M19 9l-7 7-7-7"
            />
          </svg>
        </button>
      </div>
    );
  }

  return (
    <div className="relative">
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="flex items-center gap-2 px-3 py-2 rounded-lg hover:bg-neutral-100 dark:hover:bg-neutral-800 transition-colors"
        aria-label="Toggle theme"
        aria-expanded={isOpen}
      >
        <span className="text-xl" aria-hidden="true">
          {currentTheme.icon}
        </span>
        <span className="text-sm font-medium text-neutral-700 dark:text-neutral-300">
          {currentTheme.label}
        </span>
        <svg
          className={`w-4 h-4 text-neutral-500 transition-transform ${
            isOpen ? 'rotate-180' : ''
          }`}
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
          aria-hidden="true"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={2}
            d="M19 9l-7 7-7-7"
          />
        </svg>
      </button>

      {isOpen && (
        <>
          {/* Backdrop */}
          <div
            className="fixed inset-0 z-10"
            onClick={() => setIsOpen(false)}
            aria-hidden="true"
          />

          {/* Dropdown menu */}
          <div className="absolute right-0 mt-2 w-48 bg-white dark:bg-neutral-800 border border-neutral-200 dark:border-neutral-700 rounded-lg shadow-lg z-20">
            <div className="py-1" role="menu" aria-orientation="vertical">
              {themes.map(themeOption => (
                <button
                  key={themeOption.value}
                  onClick={() => {
                    setTheme(themeOption.value);
                    setIsOpen(false);
                  }}
                  className={`w-full flex items-center gap-3 px-4 py-2 text-sm hover:bg-neutral-100 dark:hover:bg-neutral-700 transition-colors ${
                    theme === themeOption.value
                      ? 'bg-primary-50 dark:bg-primary-900/20 text-primary-700 dark:text-primary-300'
                      : 'text-neutral-700 dark:text-neutral-300'
                  }`}
                  role="menuitem"
                >
                  <span className="text-lg" aria-hidden="true">
                    {themeOption.icon}
                  </span>
                  <span className="flex-1 text-left">{themeOption.label}</span>
                  {theme === themeOption.value && (
                    <svg
                      className="w-4 h-4 text-primary-600 dark:text-primary-400"
                      fill="currentColor"
                      viewBox="0 0 20 20"
                      aria-hidden="true"
                    >
                      <path
                        fillRule="evenodd"
                        d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z"
                        clipRule="evenodd"
                      />
                    </svg>
                  )}
                </button>
              ))}
            </div>
          </div>
        </>
      )}
    </div>
  );
}

/**
 * Simple Theme Toggle Button (Compact Version)
 * For use in navigation bars or toolbars
 */
export function ThemeToggleButton() {
  const { theme, setTheme, resolvedTheme } = useTheme();
  const [hasMounted, setHasMounted] = useState(false);

  // This is a valid hydration fix pattern - mount detection
  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setHasMounted(true);
  }, []);

  const toggleTheme = () => {
    // Always toggle based on what's currently displayed (resolvedTheme)
    const nextTheme = resolvedTheme === 'dark' ? 'light' : 'dark';
    setTheme(nextTheme);
  };

  // Prevent hydration mismatch by not rendering dynamic content until mounted
  if (!hasMounted) {
    return (
      <button
        className="p-2 rounded-lg hover:bg-neutral-100 dark:hover:bg-neutral-800 transition-colors"
        aria-label="Toggle theme"
        disabled
      >
        <svg
          className="w-5 h-5 text-neutral-700 dark:text-neutral-300"
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
          aria-hidden="true"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={2}
            d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z"
          />
        </svg>
      </button>
    );
  }

  return (
    <button
      onClick={toggleTheme}
      className="p-2 rounded-lg hover:bg-neutral-100 dark:hover:bg-neutral-800 transition-colors"
      aria-label={`Current theme: ${resolvedTheme}. Click to switch.`}
      title={`Theme: ${theme} (${resolvedTheme})`}
    >
      {resolvedTheme === 'dark' ? (
        <svg
          className="w-5 h-5 text-neutral-700 dark:text-neutral-300"
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
          aria-hidden="true"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={2}
            d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z"
          />
        </svg>
      ) : (
        <svg
          className="w-5 h-5 text-neutral-700 dark:text-neutral-300"
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
          aria-hidden="true"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={2}
            d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z"
          />
        </svg>
      )}
    </button>
  );
}
