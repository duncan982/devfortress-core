/**
 * Language Selector Component
 * Allows users to switch between supported languages
 */

'use client';

import { useState } from 'react';

export const locales = [
  { code: 'en', name: 'English', flag: '🇬🇧' },
  { code: 'fr', name: 'Français', flag: '🇫🇷' },
  { code: 'es', name: 'Español', flag: '🇪🇸' },
  { code: 'de', name: 'Deutsch', flag: '🇩🇪' },
] as const;

export type LocaleCode = (typeof locales)[number]['code'];

interface LanguageSelectorProps {
  currentLocale?: LocaleCode;
  onLocaleChange?: (locale: LocaleCode) => void;
}

export function LanguageSelector({
  currentLocale = 'en',
  onLocaleChange,
}: LanguageSelectorProps) {
  const [isOpen, setIsOpen] = useState(false);
  const [selectedLocale, setSelectedLocale] = useState(currentLocale);

  const handleLocaleChange = (localeCode: LocaleCode) => {
    setSelectedLocale(localeCode);
    setIsOpen(false);

    // Store preference in localStorage
    if (typeof window !== 'undefined') {
      localStorage.setItem('locale', localeCode);
    }

    // Call callback if provided
    if (onLocaleChange) {
      onLocaleChange(localeCode);
    }

    // Reload page to apply new locale
    window.location.reload();
  };

  const currentLocaleData = locales.find(l => l.code === selectedLocale);

  return (
    <div className="relative">
      <button
        type="button"
        onClick={() => setIsOpen(!isOpen)}
        className="flex items-center space-x-2 rounded-lg border border-neutral-300 bg-white px-3 py-2 text-sm font-medium text-neutral-700 hover:bg-neutral-50 dark:border-neutral-700 dark:bg-neutral-900 dark:text-neutral-300 dark:hover:bg-neutral-800"
        aria-expanded={isOpen}
        aria-haspopup="true"
      >
        <span className="text-lg">{currentLocaleData?.flag}</span>
        <span>{currentLocaleData?.name}</span>
        <svg
          className={`h-4 w-4 transition-transform ${isOpen ? 'rotate-180' : ''}`}
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
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

          {/* Dropdown */}
          <div className="absolute right-0 z-20 mt-2 w-48 rounded-lg border border-neutral-200 bg-white shadow-lg dark:border-neutral-800 dark:bg-neutral-950">
            <div className="py-1">
              {locales.map(locale => (
                <button
                  key={locale.code}
                  onClick={() => handleLocaleChange(locale.code)}
                  className={`flex w-full items-center space-x-3 px-4 py-2 text-sm ${
                    locale.code === selectedLocale
                      ? 'bg-primary-50 text-primary-600 dark:bg-primary-950 dark:text-primary-400'
                      : 'text-neutral-700 hover:bg-neutral-50 dark:text-neutral-300 dark:hover:bg-neutral-900'
                  }`}
                >
                  <span className="text-lg">{locale.flag}</span>
                  <span className="flex-1 text-left">{locale.name}</span>
                  {locale.code === selectedLocale && (
                    <svg
                      className="h-4 w-4"
                      fill="currentColor"
                      viewBox="0 0 20 20"
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
 * Get locale from localStorage or browser
 */
export function getStoredLocale(): LocaleCode {
  if (typeof window === 'undefined') return 'en';

  const stored = localStorage.getItem('locale') as LocaleCode;
  if (stored && locales.some(l => l.code === stored)) {
    return stored;
  }

  // Try to get from browser language
  const browserLang = navigator.language.split('-')[0] as LocaleCode;
  if (locales.some(l => l.code === browserLang)) {
    return browserLang;
  }

  return 'en';
}
