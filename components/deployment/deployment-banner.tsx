/**
 * Deployment Mode Banner
 * Shows users whether they're using self-hosted or managed SaaS version
 */

'use client';

import { useEffect, useState } from 'react';

interface DeploymentInfo {
  mode: 'self-hosted' | 'managed-saas';
  displayName: string;
  description: string;
  requiresSubscription: boolean;
  features: {
    apiGeneration: boolean;
    honeypots: boolean;
    surveillance: boolean;
    insights: boolean;
    autoFix: boolean;
  };
}

export function DeploymentBanner() {
  const [info, setInfo] = useState<DeploymentInfo | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    fetch('/api/deployment/info')
      .then(res => res.json())
      .then(data => {
        setInfo(data);
        setIsLoading(false);
      })
      .catch(() => {
        setIsLoading(false);
      });
  }, []);

  if (isLoading || !info) {
    return null;
  }

  // Only show banner for self-hosted deployments
  if (info.mode !== 'self-hosted') {
    return null;
  }

  const hasApiKey = info.features.apiGeneration;

  return (
    <div
      className={`w-full border-b ${hasApiKey ? 'bg-green-50 border-green-200' : 'bg-yellow-50 border-yellow-200'}`}
    >
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-2">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div
              className={`flex-shrink-0 ${hasApiKey ? 'text-green-600' : 'text-yellow-600'}`}
            >
              {hasApiKey ? (
                <svg
                  className="h-5 w-5"
                  fill="currentColor"
                  viewBox="0 0 20 20"
                >
                  <path
                    fillRule="evenodd"
                    d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z"
                    clipRule="evenodd"
                  />
                </svg>
              ) : (
                <svg
                  className="h-5 w-5"
                  fill="currentColor"
                  viewBox="0 0 20 20"
                >
                  <path
                    fillRule="evenodd"
                    d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z"
                    clipRule="evenodd"
                  />
                </svg>
              )}
            </div>
            <div>
              <p
                className={`text-sm font-medium ${hasApiKey ? 'text-green-800' : 'text-yellow-800'}`}
              >
                {info.displayName}
              </p>
              <p
                className={`text-xs ${hasApiKey ? 'text-green-600' : 'text-yellow-600'}`}
              >
                {hasApiKey
                  ? 'All features unlocked with your API keys'
                  : 'Configure OPENAI_API_KEY to enable AI features'}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            {!hasApiKey && (
              <a
                href="/docs/setup"
                className="text-xs font-medium text-yellow-700 hover:text-yellow-800 underline"
              >
                Setup Guide
              </a>
            )}
            <a
              href="https://github.com/duncan982/devfortress"
              target="_blank"
              rel="noopener noreferrer"
              className={`text-xs font-medium ${hasApiKey ? 'text-green-700 hover:text-green-800' : 'text-yellow-700 hover:text-yellow-800'} flex items-center gap-1`}
            >
              <svg className="h-4 w-4" fill="currentColor" viewBox="0 0 20 20">
                <path
                  fillRule="evenodd"
                  d="M10 0C4.477 0 0 4.484 0 10.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0110 4.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.203 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.942.359.31.678.921.678 1.856 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0020 10.017C20 4.484 15.522 0 10 0z"
                  clipRule="evenodd"
                />
              </svg>
              Open Source
            </a>
          </div>
        </div>
      </div>
    </div>
  );
}
