/**
 * Honeypot Threat Alerts Component
 * Displays real-time threat alerts with actionable recommendations
 */

'use client';

import React, { useState, useEffect } from 'react';
import {
  AlertTriangle,
  Shield,
  AlertCircle,
  CheckCircle,
  X,
} from 'lucide-react';

interface ThreatAlert {
  id: string;
  honeypotId: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  type: string;
  description: string;
  recommendation: string;
  ip: string;
  path: string;
  timestamp: string;
  autoBlocked: boolean;
}

interface ThreatAlertsProps {
  honeypotId: string;
}

export function ThreatAlerts({ honeypotId }: ThreatAlertsProps) {
  const [alerts, setAlerts] = useState<ThreatAlert[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState<'all' | 'critical' | 'high'>('all');

  useEffect(() => {
    fetchAlerts();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [honeypotId, filter]);

  const fetchAlerts = async () => {
    try {
      setLoading(true);
      const severityFilter = filter === 'all' ? '' : `&severity=${filter}`;
      const response = await fetch(
        `/api/honeypots/${honeypotId}/alerts?limit=20${severityFilter}`
      );
      const data = await response.json();
      setAlerts(data.alerts || []);
    } catch {
      // Error silently handled - component shows empty state
      setAlerts([]);
    } finally {
      setLoading(false);
    }
  };

  const resolveAlert = async (alertId: string) => {
    try {
      await fetch(`/api/honeypots/${honeypotId}/alerts`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          alertId,
          resolution: 'Reviewed and resolved by user',
        }),
      });
      fetchAlerts();
    } catch {
      // Error silently handled
    }
  };

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case 'critical':
        return <AlertTriangle className="h-5 w-5 text-error-600 dark:text-error-400" />;
      case 'high':
        return <AlertCircle className="h-5 w-5 text-orange-600 dark:text-orange-400" />;
      case 'medium':
        return <Shield className="h-5 w-5 text-warning-600 dark:text-warning-400" />;
      default:
        return <AlertCircle className="h-5 w-5 text-primary-600 dark:text-primary-400" />;
    }
  };

  const getSeverityBadgeClass = (severity: string) => {
    switch (severity) {
      case 'critical':
        return 'bg-error-100 text-error-800 border-error-300 dark:bg-error-900 dark:text-error-200 dark:border-error-700';
      case 'high':
        return 'bg-orange-100 text-orange-800 border-orange-300 dark:bg-orange-900 dark:text-orange-200 dark:border-orange-700';
      case 'medium':
        return 'bg-warning-100 text-warning-800 border-warning-300 dark:bg-warning-900 dark:text-warning-200 dark:border-warning-700';
      default:
        return 'bg-primary-100 text-primary-800 border-primary-300 dark:bg-primary-900 dark:text-primary-200 dark:border-primary-700';
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center p-8">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-neutral-900 dark:border-neutral-100"></div>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-xl font-semibold text-neutral-900 dark:text-neutral-100">Threat Alerts</h2>
        <div className="flex gap-2">
          <button
            onClick={() => setFilter('all')}
            className={`px-3 py-1 rounded-md text-sm ${
              filter === 'all'
                ? 'bg-neutral-900 text-white dark:bg-neutral-100 dark:text-neutral-900'
                : 'bg-neutral-100 text-neutral-700 hover:bg-neutral-200 dark:bg-neutral-800 dark:text-neutral-300 dark:hover:bg-neutral-700'
            }`}
          >
            All
          </button>
          <button
            onClick={() => setFilter('critical')}
            className={`px-3 py-1 rounded-md text-sm ${
              filter === 'critical'
                ? 'bg-error-600 text-white'
                : 'bg-neutral-100 text-neutral-700 hover:bg-neutral-200 dark:bg-neutral-800 dark:text-neutral-300 dark:hover:bg-neutral-700'
            }`}
          >
            Critical
          </button>
          <button
            onClick={() => setFilter('high')}
            className={`px-3 py-1 rounded-md text-sm ${
              filter === 'high'
                ? 'bg-orange-600 text-white'
                : 'bg-neutral-100 text-neutral-700 hover:bg-neutral-200 dark:bg-neutral-800 dark:text-neutral-300 dark:hover:bg-neutral-700'
            }`}
          >
            High
          </button>
        </div>
      </div>

      {alerts.length === 0 ? (
        <div className="text-center py-8 bg-neutral-50 rounded-lg border border-neutral-200 dark:bg-neutral-900 dark:border-neutral-700">
          <CheckCircle className="h-12 w-12 text-success-500 dark:text-success-400 mx-auto mb-3" />
          <p className="text-neutral-600 dark:text-neutral-400">No threats detected</p>
        </div>
      ) : (
        <div className="space-y-3">
          {alerts.map(alert => (
            <div
              key={alert.id}
              className="bg-white border border-neutral-200 rounded-lg p-4 shadow-sm hover:shadow-md transition-shadow dark:bg-neutral-900 dark:border-neutral-700"
            >
              <div className="flex items-start justify-between">
                <div className="flex items-start gap-3 flex-1">
                  <div className="mt-1">{getSeverityIcon(alert.severity)}</div>
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-2">
                      <span
                        className={`px-2 py-1 rounded text-xs font-medium border ${getSeverityBadgeClass(
                          alert.severity
                        )}`}
                      >
                        {alert.severity.toUpperCase()}
                      </span>
                      {alert.autoBlocked && (
                        <span className="px-2 py-1 rounded text-xs font-medium bg-error-100 text-error-800 border border-error-300 dark:bg-error-900 dark:text-error-200 dark:border-error-700">
                          AUTO-BLOCKED
                        </span>
                      )}
                    </div>
                    <h3 className="font-semibold text-neutral-900 dark:text-neutral-100 mb-1">
                      {alert.description}
                    </h3>
                    <div className="text-sm text-neutral-600 dark:text-neutral-400 space-y-1">
                      <p>
                        <span className="font-medium">IP:</span> {alert.ip}
                      </p>
                      <p>
                        <span className="font-medium">Path:</span> {alert.path}
                      </p>
                      <p>
                        <span className="font-medium">Type:</span> {alert.type}
                      </p>
                      <p className="text-xs text-neutral-500 dark:text-neutral-500">
                        {new Date(alert.timestamp).toLocaleString()}
                      </p>
                    </div>
                    <div className="mt-3 p-3 bg-primary-50 border border-primary-200 rounded dark:bg-primary-950 dark:border-primary-800">
                      <p className="text-sm text-primary-900 dark:text-primary-100">
                        <span className="font-medium">Recommendation:</span>{' '}
                        {alert.recommendation}
                      </p>
                    </div>
                  </div>
                </div>
                <button
                  onClick={() => resolveAlert(alert.id)}
                  className="ml-4 p-1 hover:bg-neutral-100 dark:hover:bg-neutral-800 rounded"
                  title="Resolve alert"
                >
                  <X className="h-5 w-5 text-neutral-500 dark:text-neutral-400" />
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
