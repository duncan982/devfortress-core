'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';

interface HoneypotInfo {
  id: string;
  name: string;
  status: string;
}

interface ProjectInfo {
  id: string;
  name: string;
}

interface DataSourceFilterProps {
  currentSource: string;
  basePath: string;
}

/**
 * Enhanced data source filter with per-honeypot and per-API selection
 * Allows users to filter insights by specific honeypots or APIs
 */
export function DataSourceFilter({
  currentSource,
  basePath,
}: DataSourceFilterProps) {
  const [honeypots, setHoneypots] = useState<HoneypotInfo[]>([]);
  const [projects, setProjects] = useState<ProjectInfo[]>([]);
  const [showAdvanced, setShowAdvanced] = useState(false);

  useEffect(() => {
    async function fetchSources() {
      try {
        const [hpRes, projRes] = await Promise.all([
          fetch('/api/honeypots').catch(() => null),
          fetch('/api/projects').catch(() => null),
        ]);

        if (hpRes?.ok) {
          const data = await hpRes.json();
          const hpList = Array.isArray(data) ? data : data.honeypots || [];
          setHoneypots(hpList);
        }

        if (projRes?.ok) {
          const data = await projRes.json();
          const projList = Array.isArray(data) ? data : data.projects || [];
          setProjects(projList);
        }
      } catch {
        // Ignore fetch errors
      }
    }
    fetchSources();
  }, []);

  const isSpecificSource = currentSource.startsWith('hp:') || currentSource.startsWith('api:');

  return (
    <div className="mb-6 rounded-lg border border-neutral-200 bg-white p-3 sm:p-4 dark:border-neutral-700 dark:bg-neutral-800">
      <div className="flex flex-col gap-3 sm:flex-row sm:flex-wrap sm:items-center">
        <span className="text-sm font-medium text-neutral-700 dark:text-neutral-300">
          Data Source:
        </span>

        {/* Quick filter buttons */}
        <div className="flex flex-wrap gap-2">
          <Link
            href={`${basePath}?source=all`}
            className={`rounded-lg px-4 py-2 text-sm font-medium transition-colors ${
              currentSource === 'all'
                ? 'bg-purple-600 text-white'
                : 'bg-neutral-100 text-neutral-700 hover:bg-neutral-200 dark:bg-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-600'
            }`}
          >
            🔄 All Sources
          </Link>
          <Link
            href={`${basePath}?source=honeypots`}
            className={`rounded-lg px-4 py-2 text-sm font-medium transition-colors ${
              currentSource === 'honeypots'
                ? 'bg-red-600 text-white'
                : 'bg-neutral-100 text-neutral-700 hover:bg-neutral-200 dark:bg-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-600'
            }`}
          >
            🍯 Honeypots Only
          </Link>
          <Link
            href={`${basePath}?source=apis`}
            className={`rounded-lg px-4 py-2 text-sm font-medium transition-colors ${
              currentSource === 'apis'
                ? 'bg-blue-600 text-white'
                : 'bg-neutral-100 text-neutral-700 hover:bg-neutral-200 dark:bg-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-600'
            }`}
          >
            🚀 Deployed APIs Only
          </Link>

          {/* Advanced filter toggle */}
          <button
            onClick={() => setShowAdvanced(!showAdvanced)}
            className={`rounded-lg px-4 py-2 text-sm font-medium transition-colors ${
              isSpecificSource
                ? 'bg-green-600 text-white'
                : 'bg-neutral-100 text-neutral-700 hover:bg-neutral-200 dark:bg-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-600'
            }`}
          >
            🎯 Specific Source {showAdvanced ? '▲' : '▼'}
          </button>
        </div>
      </div>

      {/* Advanced: Per-honeypot / Per-API selection */}
      {showAdvanced && (
        <div className="mt-4 grid gap-4 border-t border-neutral-200 pt-4 sm:grid-cols-2 dark:border-neutral-700">
          {/* Honeypots list */}
          <div>
            <h4 className="mb-2 text-xs font-semibold uppercase tracking-wider text-red-600 dark:text-red-400">
              🍯 Honeypots
            </h4>
            {honeypots.length === 0 ? (
              <p className="text-xs text-neutral-500 dark:text-neutral-400">
                No honeypots found.{' '}
                <Link href="/dashboard/honeypots/create" className="underline">
                  Create one
                </Link>
              </p>
            ) : (
              <div className="flex flex-wrap gap-2">
                {honeypots.map((hp) => (
                  <Link
                    key={hp.id}
                    href={`${basePath}?source=hp:${hp.id}`}
                    className={`rounded-lg px-3 py-1.5 text-xs font-medium transition-colors ${
                      currentSource === `hp:${hp.id}`
                        ? 'bg-red-600 text-white'
                        : 'border border-red-200 bg-red-50 text-red-700 hover:bg-red-100 dark:border-red-800 dark:bg-red-950/30 dark:text-red-300 dark:hover:bg-red-900/50'
                    }`}
                  >
                    {hp.name}
                    <span
                      className={`ml-1.5 inline-block h-1.5 w-1.5 rounded-full ${
                        hp.status === 'ACTIVE' || hp.status === 'DEPLOYED'
                          ? 'bg-green-500'
                          : 'bg-neutral-400'
                      }`}
                    />
                  </Link>
                ))}
              </div>
            )}
          </div>

          {/* APIs list */}
          <div>
            <h4 className="mb-2 text-xs font-semibold uppercase tracking-wider text-blue-600 dark:text-blue-400">
              🚀 API Projects
            </h4>
            {projects.length === 0 ? (
              <p className="text-xs text-neutral-500 dark:text-neutral-400">
                No API projects found.{' '}
                <Link href="/build/generate" className="underline">
                  Generate one
                </Link>
              </p>
            ) : (
              <div className="flex flex-wrap gap-2">
                {projects.map((proj) => (
                  <Link
                    key={proj.id}
                    href={`${basePath}?source=api:${proj.id}`}
                    className={`rounded-lg px-3 py-1.5 text-xs font-medium transition-colors ${
                      currentSource === `api:${proj.id}`
                        ? 'bg-blue-600 text-white'
                        : 'border border-blue-200 bg-blue-50 text-blue-700 hover:bg-blue-100 dark:border-blue-800 dark:bg-blue-950/30 dark:text-blue-300 dark:hover:bg-blue-900/50'
                    }`}
                  >
                    {proj.name}
                  </Link>
                ))}
              </div>
            )}
          </div>

          {/* Combined selection hint */}
          <div className="col-span-full">
            <p className="text-xs text-neutral-500 dark:text-neutral-400">
              💡 Tip: Select a specific honeypot or API to see insights from that source only.
              Use &ldquo;All Sources&rdquo; to see combined insights across all your honeypots and APIs.
            </p>
          </div>
        </div>
      )}
    </div>
  );
}
