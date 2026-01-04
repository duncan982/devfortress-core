/**
 * Notification Preferences Component
 * Allows users to manage email notification settings
 */
'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { logError } from '@core/lib/logger/client';

interface NotificationPreferences {
  emailNotifications: boolean;
  securityAlertsEnabled: boolean;
  marketingOptIn: boolean;
  creditAlertsEnabled: boolean;
}

interface NotificationSettingsProps {
  initialPreferences: NotificationPreferences;
}

export function NotificationSettings({
  initialPreferences,
}: NotificationSettingsProps) {
  const router = useRouter();
  const [preferences, setPreferences] = useState(initialPreferences);
  const [isLoading, setIsLoading] = useState(false);
  const [message, setMessage] = useState('');

  const handleToggle = async (key: keyof NotificationPreferences) => {
    const newPreferences = {
      ...preferences,
      [key]: !preferences[key],
    };
    setPreferences(newPreferences);
    setIsLoading(true);
    setMessage('');

    // Map frontend keys to API keys
    const apiPayload = {
      securityAlertsEnabled: newPreferences.securityAlertsEnabled,
      marketingOptIn: newPreferences.marketingOptIn,
      creditAlertsEnabled: newPreferences.creditAlertsEnabled,
    };

    try {
      const response = await fetch('/api/user/preferences', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ notifications: apiPayload }),
      });

      if (!response.ok) {
        throw new Error('Failed to update preferences');
      }

      setMessage('Preferences updated!');
      router.refresh();
    } catch (error) {
      logError('Failed to update notification preferences', error);
      setMessage('Failed to update preferences. Please try again.');
      // Revert the change on error
      setPreferences(initialPreferences);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="space-y-4">
      {message && (
        <div
          className={`p-3 rounded-md text-sm ${
            message.includes('updated')
              ? 'bg-success-50 dark:bg-success-900/20 text-success-700 dark:text-success-400'
              : 'bg-error-50 dark:bg-error-900/20 text-error-700 dark:text-error-400'
          }`}
        >
          {message}
        </div>
      )}

      <div className="flex items-center justify-between">
        <div>
          <p className="font-medium text-neutral-900 dark:text-white mb-1">
            Email Notifications
          </p>
          <p className="text-sm text-neutral-600 dark:text-neutral-400">
            Receive email updates about your account
          </p>
        </div>
        <label className="relative inline-flex items-center cursor-pointer">
          <input
            type="checkbox"
            className="sr-only peer"
            checked={preferences.emailNotifications}
            onChange={() => handleToggle('emailNotifications')}
            disabled={isLoading}
          />
          <div className="w-11 h-6 bg-neutral-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-primary-300 dark:peer-focus:ring-primary-800 rounded-full peer dark:bg-neutral-700 peer-checked:after:translate-x-full rtl:peer-checked:after:-translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:start-[2px] after:bg-white after:border-neutral-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all dark:border-neutral-600 peer-checked:bg-primary-600 peer-disabled:opacity-50 peer-disabled:cursor-not-allowed"></div>
        </label>
      </div>

      <div className="flex items-center justify-between">
        <div>
          <p className="font-medium text-neutral-900 dark:text-white mb-1">
            Security Alerts
          </p>
          <p className="text-sm text-neutral-600 dark:text-neutral-400">
            Get notified about security threats and vulnerabilities
          </p>
        </div>
        <label className="relative inline-flex items-center cursor-pointer">
          <input
            type="checkbox"
            className="sr-only peer"
            checked={preferences.securityAlertsEnabled}
            onChange={() => handleToggle('securityAlertsEnabled')}
            disabled={isLoading}
          />
          <div className="w-11 h-6 bg-neutral-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-primary-300 dark:peer-focus:ring-primary-800 rounded-full peer dark:bg-neutral-700 peer-checked:after:translate-x-full rtl:peer-checked:after:-translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:start-[2px] after:bg-white after:border-neutral-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all dark:border-neutral-600 peer-checked:bg-primary-600 peer-disabled:opacity-50 peer-disabled:cursor-not-allowed"></div>
        </label>
      </div>

      <div className="flex items-center justify-between">
        <div>
          <p className="font-medium text-neutral-900 dark:text-white mb-1">
            Product Updates & Marketing
          </p>
          <p className="text-sm text-neutral-600 dark:text-neutral-400">
            Stay informed about new features and improvements
          </p>
        </div>
        <label className="relative inline-flex items-center cursor-pointer">
          <input
            type="checkbox"
            className="sr-only peer"
            checked={preferences.marketingOptIn}
            onChange={() => handleToggle('marketingOptIn')}
            disabled={isLoading}
          />
          <div className="w-11 h-6 bg-neutral-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-primary-300 dark:peer-focus:ring-primary-800 rounded-full peer dark:bg-neutral-700 peer-checked:after:translate-x-full rtl:peer-checked:after:-translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:start-[2px] after:bg-white after:border-neutral-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all dark:border-neutral-600 peer-checked:bg-primary-600 peer-disabled:opacity-50 peer-disabled:cursor-not-allowed"></div>
        </label>
      </div>

      <div className="flex items-center justify-between">
        <div>
          <p className="font-medium text-neutral-900 dark:text-white mb-1">
            Credit Alerts
          </p>
          <p className="text-sm text-neutral-600 dark:text-neutral-400">
            Receive notifications when your credits are running low
          </p>
        </div>
        <label className="relative inline-flex items-center cursor-pointer">
          <input
            type="checkbox"
            className="sr-only peer"
            checked={preferences.creditAlertsEnabled}
            onChange={() => handleToggle('creditAlertsEnabled')}
            disabled={isLoading}
          />
          <div className="w-11 h-6 bg-neutral-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-primary-300 dark:peer-focus:ring-primary-800 rounded-full peer dark:bg-neutral-700 peer-checked:after:translate-x-full rtl:peer-checked:after:-translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:start-[2px] after:bg-white after:border-neutral-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all dark:border-neutral-600 peer-checked:bg-primary-600 peer-disabled:opacity-50 peer-disabled:cursor-not-allowed"></div>
        </label>
      </div>
    </div>
  );
}
