/**
 * Honeypot Statistics Dashboard Component
 * Displays comprehensive statistics and metrics
 */

'use client';

import React, { useState, useEffect } from 'react';
import { Activity, Shield, Users, TrendingUp } from 'lucide-react';

interface HoneypotStats {
  totalRequests: number;
  uniqueIps: number;
  threatsDetected: number;
  blockedIps: number;
  topPaths: Array<{ path: string; count: number }>;
  threatsByType: Record<string, number>;
}

interface HoneypotStatsProps {
  honeypotId: string;
  days?: number;
}

export function HoneypotStats({ honeypotId, days = 7 }: HoneypotStatsProps) {
  const [stats, setStats] = useState<HoneypotStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [timeRange, setTimeRange] = useState(days);

  useEffect(() => {
    fetchStats();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [honeypotId, timeRange]);

  const fetchStats = async () => {
    try {
      setLoading(true);
      const response = await fetch(
        `/api/honeypots/${honeypotId}/stats?days=${timeRange}`
      );
      const data = await response.json();
      setStats(data.stats);
    } catch {
      // Error silently handled
      setStats(null);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center p-8">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-gray-900 dark:border-neutral-100"></div>
      </div>
    );
  }

  if (!stats) {
    return (
      <div className="text-center py-8 bg-gray-50 dark:bg-neutral-800 rounded-lg border border-gray-200 dark:border-neutral-700">
        <p className="text-gray-600 dark:text-neutral-400">
          No statistics available
        </p>
      </div>
    );
  }

  const statCards = [
    {
      label: 'Total Requests',
      value: stats.totalRequests.toLocaleString(),
      icon: Activity,
      color: 'blue',
    },
    {
      label: 'Unique IPs',
      value: stats.uniqueIps.toLocaleString(),
      icon: Users,
      color: 'green',
    },
    {
      label: 'Threats Detected',
      value: stats.threatsDetected.toLocaleString(),
      icon: Shield,
      color: 'orange',
    },
    {
      label: 'Blocked IPs',
      value: stats.blockedIps.toLocaleString(),
      icon: TrendingUp,
      color: 'red',
    },
  ];

  const getColorClasses = (color: string) => {
    switch (color) {
      case 'blue':
        return 'bg-blue-100 dark:bg-blue-900/50 text-blue-600 dark:text-blue-400';
      case 'green':
        return 'bg-green-100 dark:bg-green-900/50 text-green-600 dark:text-green-400';
      case 'orange':
        return 'bg-orange-100 dark:bg-orange-900/50 text-orange-600 dark:text-orange-400';
      case 'red':
        return 'bg-red-100 dark:bg-red-900/50 text-red-600 dark:text-red-400';
      default:
        return 'bg-gray-100 dark:bg-neutral-700 text-gray-600 dark:text-neutral-400';
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-xl font-semibold text-gray-900 dark:text-neutral-100">
          Statistics
        </h2>
        <select
          value={timeRange}
          onChange={e => setTimeRange(parseInt(e.target.value))}
          className="px-3 py-2 border border-gray-300 dark:border-neutral-600 dark:bg-neutral-700 dark:text-neutral-100 rounded-md text-sm"
        >
          <option value={1}>Last 24 hours</option>
          <option value={7}>Last 7 days</option>
          <option value={30}>Last 30 days</option>
          <option value={90}>Last 90 days</option>
        </select>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {statCards.map(card => {
          const Icon = card.icon;
          return (
            <div
              key={card.label}
              className="bg-white dark:bg-neutral-800 border border-gray-200 dark:border-neutral-700 rounded-lg p-4 shadow-sm"
            >
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm text-gray-600 dark:text-neutral-400">
                  {card.label}
                </span>
                <div className={`p-2 rounded ${getColorClasses(card.color)}`}>
                  <Icon className="h-4 w-4" />
                </div>
              </div>
              <p className="text-2xl font-bold text-gray-900 dark:text-neutral-100">
                {card.value}
              </p>
            </div>
          );
        })}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Top Paths */}
        <div className="bg-white dark:bg-neutral-800 border border-gray-200 dark:border-neutral-700 rounded-lg p-4 shadow-sm">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-neutral-100 mb-4">
            Most Accessed Paths
          </h3>
          {stats.topPaths.length === 0 ? (
            <p className="text-gray-500 dark:text-neutral-500 text-sm">
              No data available
            </p>
          ) : (
            <div className="space-y-3">
              {stats.topPaths.map((item, index) => (
                <div key={index} className="flex items-center justify-between">
                  <div className="flex-1">
                    <p className="text-sm font-mono text-gray-900 dark:text-neutral-100 truncate">
                      {item.path}
                    </p>
                    <div className="mt-1 bg-gray-200 dark:bg-neutral-600 rounded-full h-2">
                      <div
                        className="bg-blue-600 h-2 rounded-full"
                        style={{
                          width: `${(item.count / stats.topPaths[0].count) * 100}%`,
                        }}
                      ></div>
                    </div>
                  </div>
                  <span className="ml-4 text-sm font-semibold text-gray-600 dark:text-neutral-400">
                    {item.count}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Threats by Type */}
        <div className="bg-white dark:bg-neutral-800 border border-gray-200 dark:border-neutral-700 rounded-lg p-4 shadow-sm">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-neutral-100 mb-4">
            Threats by Type
          </h3>
          {Object.keys(stats.threatsByType).length === 0 ? (
            <p className="text-gray-500 dark:text-neutral-500 text-sm">
              No threats detected
            </p>
          ) : (
            <div className="space-y-3">
              {Object.entries(stats.threatsByType)
                .sort((a, b) => b[1] - a[1])
                .map(([type, count]) => (
                  <div key={type} className="flex items-center justify-between">
                    <div className="flex-1">
                      <p className="text-sm text-gray-900 dark:text-neutral-100 capitalize">
                        {type}
                      </p>
                      <div className="mt-1 bg-gray-200 dark:bg-neutral-600 rounded-full h-2">
                        <div
                          className="bg-red-600 h-2 rounded-full"
                          style={{
                            width: `${
                              (count /
                                Math.max(
                                  ...Object.values(stats.threatsByType)
                                )) *
                              100
                            }%`,
                          }}
                        ></div>
                      </div>
                    </div>
                    <span className="ml-4 text-sm font-semibold text-gray-600 dark:text-neutral-400">
                      {count}
                    </span>
                  </div>
                ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
