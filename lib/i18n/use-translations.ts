/**
 * Translation Utility
 * Simple i18n implementation for client-side translations
 */

'use client';

import { useState, useEffect, useCallback } from 'react';
import { LocaleCode } from '@core/components/ui/language-selector';

type Messages = Record<string, unknown>;

// Cache for loaded messages
const messagesCache: Record<string, Messages> = {};

/**
 * Custom hook for translations
 */
export function useTranslations() {
  const [locale, setLocale] = useState<LocaleCode>('en');
  const [messages, setMessages] = useState<Messages>({});
  const [loading, setLoading] = useState(true);

  // Load messages for current locale
  useEffect(() => {
    async function loadMessages() {
      try {
        setLoading(true);

        // Get locale from localStorage or browser
        const storedLocale =
          (localStorage.getItem('locale') as LocaleCode) || 'en';
        setLocale(storedLocale);

        // Check cache first
        if (messagesCache[storedLocale]) {
          setMessages(messagesCache[storedLocale]);
          setLoading(false);
          return;
        }

        // Load messages from file
        const response = await fetch(`/messages/${storedLocale}.json`);
        if (!response.ok) {
          throw new Error('Failed to load messages');
        }

        const loadedMessages = await response.json();
        messagesCache[storedLocale] = loadedMessages;
        setMessages(loadedMessages);
      } catch {
        // Fallback to English on error
        if (locale !== 'en') {
          const fallbackResponse = await fetch('/messages/en.json');
          const fallbackMessages = await fallbackResponse.json();
          setMessages(fallbackMessages);
        }
      } finally {
        setLoading(false);
      }
    }

    loadMessages();
  }, [locale]);

  /**
   * Get translation by key with interpolation support
   */
  const t = useCallback(
    (key: string, params?: Record<string, string | number>): string => {
      const keys = key.split('.');
      let value: unknown = messages;

      // Navigate through nested keys
      for (const k of keys) {
        if (value && typeof value === 'object' && k in value) {
          value = (value as Record<string, unknown>)[k];
        } else {
          return key; // Return key if not found
        }
      }

      let translation = String(value);

      // Interpolate parameters
      if (params) {
        Object.entries(params).forEach(([param, val]) => {
          translation = translation.replace(`{${param}}`, String(val));
        });
      }

      return translation;
    },
    [messages]
  );

  return { t, locale, loading };
}

/**
 * Simple translation function for static usage
 */
export function translate(
  messages: Messages,
  key: string,
  params?: Record<string, string | number>
): string {
  const keys = key.split('.');
  let value: unknown = messages;

  for (const k of keys) {
    if (value && typeof value === 'object' && k in value) {
      value = (value as Record<string, unknown>)[k];
    } else {
      return key;
    }
  }

  let translation = String(value);

  if (params) {
    Object.entries(params).forEach(([param, val]) => {
      translation = translation.replace(`{${param}}`, String(val));
    });
  }

  return translation;
}
