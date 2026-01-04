'use client';

/**
 * System Monitoring Dashboard Component
 * Displays ML training metrics, anomaly detection, and system-wide performance
 */

import { useState, useEffect } from 'react';
import {
  Activity,
  AlertTriangle,
  Brain,
  Shield,
  TrendingUp,
  Users,
} from 'lucide-react';
import { logError } from '@core/lib/logger/client';

interface SystemMonitoringData {
  mlTraining: {
    totalTrainingRuns: number;
    successfulRuns: number;
    failedRuns: number;
    averageAccuracy: number;
    averageTrainingTime: number;
    lastTrainingDate?: string;
    modelsDeployed: number;
    datasetSize: number;
  };
  anomalyDetection: {
    totalAnomaliesDetected: number;
    highSeverityAnomalies: number;
    mediumSeverityAnomalies: number;
    lowSeverityAnomalies: number;
    detectionRate: number;
    falsePositiveRate: number;
    lastDetectionDate?: string;
  };
  system: {
    apiGeneration: {
      totalGenerations: number;
      last24Hours: number;
      averageGenerationTime: number;
      successRate: number;
    };
    security: {
      totalScans: number;
      vulnerabilitiesFound: number;
      honeypotsTrigger: number;
      threatsBlocked: number;
    };
    users: {
      totalUsers: number;
      activeUsers: number;
      newUsers: number;
      churnRate: number;
    };
    performance: {
      averageResponseTime: number;
      uptime: number;
      errorRate: number;
    };
  };
  alerts: string[];
}

export function SystemMonitoringDashboard() {
  const [data, setData] = useState<SystemMonitoringData | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 5 * 60 * 1000); // Refresh every 5 minutes
    return () => clearInterval(interval);
  }, []);

  const fetchData = async () => {
    try {
      const response = await fetch('/api/admin/system-monitoring');
      if (!response.ok) throw new Error('Failed to fetch monitoring data');
      const result = await response.json();
      setData(result);
    } catch (error) {
      logError('Error fetching system monitoring data', error);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="p-8 text-center">
        <div className="inline-block animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-primary-600"></div>
        <p className="mt-4 text-neutral-600 dark:text-neutral-400">
          Loading system monitoring data...
        </p>
      </div>
    );
  }

  if (!data) {
    return (
      <div className="p-8 text-center text-error-600 dark:text-error-400">
        Failed to load monitoring data. Please refresh the page.
      </div>
    );
  }

  return (
    <div className="space-y-6 p-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <h1 className="text-3xl font-bold text-neutral-900 dark:text-neutral-100">
          System Monitoring Dashboard
        </h1>
        <button
          onClick={fetchData}
          className="px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700"
        >
          Refresh
        </button>
      </div>

      {/* Alerts */}
      {data.alerts.length > 0 && (
        <div className="bg-error-50 dark:bg-error-950 border-l-4 border-error-500 p-4 rounded">
          <div className="flex items-center">
            <AlertTriangle className="w-5 h-5 text-error-500 mr-2" />
            <h3 className="text-lg font-semibold text-error-800 dark:text-error-200">
              Active Alerts
            </h3>
          </div>
          <ul className="mt-2 space-y-1">
            {data.alerts.map((alert, index) => (
              <li
                key={index}
                className="text-sm text-error-700 dark:text-error-300"
              >
                • {alert}
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* ML Training Metrics */}
      <div className="bg-white dark:bg-neutral-900 rounded-lg shadow border border-neutral-200 dark:border-neutral-700 p-6">
        <div className="flex items-center mb-4">
          <Brain className="w-6 h-6 text-primary-600 dark:text-primary-400 mr-2" />
          <h2 className="text-xl font-semibold text-neutral-900 dark:text-neutral-100">
            ML Training & Performance
          </h2>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <MetricCard
            label="Total Training Runs"
            value={data.mlTraining.totalTrainingRuns}
            icon={<Activity className="w-4 h-4" />}
          />
          <MetricCard
            label="Success Rate"
            value={`${((data.mlTraining.successfulRuns / data.mlTraining.totalTrainingRuns) * 100).toFixed(1)}%`}
            icon={<TrendingUp className="w-4 h-4" />}
            color="text-green-600"
          />
          <MetricCard
            label="Average Accuracy"
            value={`${data.mlTraining.averageAccuracy.toFixed(1)}%`}
            icon={<TrendingUp className="w-4 h-4" />}
            color={
              data.mlTraining.averageAccuracy >= 85
                ? 'text-success-600 dark:text-success-400'
                : 'text-warning-600 dark:text-warning-400'
            }
          />
          <MetricCard
            label="Models Deployed"
            value={data.mlTraining.modelsDeployed}
            icon={<Brain className="w-4 h-4" />}
          />
        </div>
        {data.mlTraining.lastTrainingDate && (
          <p className="mt-4 text-sm text-neutral-600 dark:text-neutral-400">
            Last training:{' '}
            {new Date(data.mlTraining.lastTrainingDate).toLocaleString()}
          </p>
        )}
      </div>

      {/* Anomaly Detection */}
      <div className="bg-white dark:bg-neutral-900 rounded-lg shadow border border-neutral-200 dark:border-neutral-700 p-6">
        <div className="flex items-center mb-4">
          <Shield className="w-6 h-6 text-error-600 dark:text-error-400 mr-2" />
          <h2 className="text-xl font-semibold text-neutral-900 dark:text-neutral-100">
            Anomaly Detection
          </h2>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <MetricCard
            label="Total Anomalies"
            value={data.anomalyDetection.totalAnomaliesDetected}
            icon={<AlertTriangle className="w-4 h-4" />}
          />
          <MetricCard
            label="High Severity"
            value={data.anomalyDetection.highSeverityAnomalies}
            icon={<AlertTriangle className="w-4 h-4" />}
            color="text-red-600"
          />
          <MetricCard
            label="Detection Rate"
            value={`${data.anomalyDetection.detectionRate.toFixed(1)}%`}
            icon={<TrendingUp className="w-4 h-4" />}
            color="text-green-600"
          />
          <MetricCard
            label="False Positive Rate"
            value={`${data.anomalyDetection.falsePositiveRate.toFixed(1)}%`}
            icon={<Activity className="w-4 h-4" />}
            color={
              data.anomalyDetection.falsePositiveRate < 5
                ? 'text-success-600 dark:text-success-400'
                : 'text-warning-600 dark:text-warning-400'
            }
          />
        </div>
      </div>

      {/* API Generation */}
      <div className="bg-white dark:bg-neutral-900 rounded-lg shadow border border-neutral-200 dark:border-neutral-700 p-6">
        <div className="flex items-center mb-4">
          <Activity className="w-6 h-6 text-primary-600 dark:text-primary-400 mr-2" />
          <h2 className="text-xl font-semibold text-neutral-900 dark:text-neutral-100">
            API Generation
          </h2>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <MetricCard
            label="Total Generations"
            value={data.system.apiGeneration.totalGenerations}
            icon={<Activity className="w-4 h-4" />}
          />
          <MetricCard
            label="Last 24 Hours"
            value={data.system.apiGeneration.last24Hours}
            icon={<TrendingUp className="w-4 h-4" />}
          />
          <MetricCard
            label="Success Rate"
            value={`${data.system.apiGeneration.successRate.toFixed(1)}%`}
            icon={<TrendingUp className="w-4 h-4" />}
            color="text-green-600"
          />
          <MetricCard
            label="Avg Generation Time"
            value={`${data.system.apiGeneration.averageGenerationTime.toFixed(1)}s`}
            icon={<Activity className="w-4 h-4" />}
          />
        </div>
      </div>

      {/* Security */}
      <div className="bg-white dark:bg-neutral-900 rounded-lg shadow border border-neutral-200 dark:border-neutral-700 p-6">
        <div className="flex items-center mb-4">
          <Shield className="w-6 h-6 text-success-600 dark:text-success-400 mr-2" />
          <h2 className="text-xl font-semibold text-neutral-900 dark:text-neutral-100">
            Security
          </h2>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <MetricCard
            label="Total Scans"
            value={data.system.security.totalScans}
            icon={<Shield className="w-4 h-4" />}
          />
          <MetricCard
            label="Vulnerabilities Found"
            value={data.system.security.vulnerabilitiesFound}
            icon={<AlertTriangle className="w-4 h-4" />}
            color="text-yellow-600"
          />
          <MetricCard
            label="Honeypot Triggers"
            value={data.system.security.honeypotsTrigger}
            icon={<Activity className="w-4 h-4" />}
          />
          <MetricCard
            label="Threats Blocked"
            value={data.system.security.threatsBlocked}
            icon={<Shield className="w-4 h-4" />}
            color="text-green-600"
          />
        </div>
      </div>

      {/* Users */}
      <div className="bg-white dark:bg-neutral-900 rounded-lg shadow border border-neutral-200 dark:border-neutral-700 p-6">
        <div className="flex items-center mb-4">
          <Users className="w-6 h-6 text-primary-600 dark:text-primary-400 mr-2" />
          <h2 className="text-xl font-semibold text-neutral-900 dark:text-neutral-100">
            Users
          </h2>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <MetricCard
            label="Total Users"
            value={data.system.users.totalUsers}
            icon={<Users className="w-4 h-4" />}
          />
          <MetricCard
            label="Active Users (30d)"
            value={data.system.users.activeUsers}
            icon={<Activity className="w-4 h-4" />}
            color="text-green-600"
          />
          <MetricCard
            label="New Users (7d)"
            value={data.system.users.newUsers}
            icon={<TrendingUp className="w-4 h-4" />}
            color="text-blue-600"
          />
          <MetricCard
            label="Churn Rate"
            value={`${data.system.users.churnRate.toFixed(1)}%`}
            icon={<Activity className="w-4 h-4" />}
            color={
              data.system.users.churnRate < 5
                ? 'text-success-600 dark:text-success-400'
                : 'text-error-600 dark:text-error-400'
            }
          />
        </div>
      </div>

      {/* Performance */}
      <div className="bg-white dark:bg-neutral-900 rounded-lg shadow border border-neutral-200 dark:border-neutral-700 p-6">
        <div className="flex items-center mb-4">
          <Activity className="w-6 h-6 text-primary-600 dark:text-primary-400 mr-2" />
          <h2 className="text-xl font-semibold text-neutral-900 dark:text-neutral-100">
            Performance
          </h2>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <MetricCard
            label="Avg Response Time"
            value={`${data.system.performance.averageResponseTime}ms`}
            icon={<Activity className="w-4 h-4" />}
            color={
              data.system.performance.averageResponseTime < 200
                ? 'text-success-600 dark:text-success-400'
                : 'text-warning-600 dark:text-warning-400'
            }
          />
          <MetricCard
            label="Uptime"
            value={`${data.system.performance.uptime.toFixed(2)}%`}
            icon={<TrendingUp className="w-4 h-4" />}
            color="text-green-600"
          />
          <MetricCard
            label="Error Rate"
            value={`${data.system.performance.errorRate.toFixed(2)}%`}
            icon={<AlertTriangle className="w-4 h-4" />}
            color={
              data.system.performance.errorRate < 1
                ? 'text-success-600 dark:text-success-400'
                : 'text-error-600 dark:text-error-400'
            }
          />
        </div>
      </div>
    </div>
  );
}

interface MetricCardProps {
  label: string;
  value: string | number;
  icon: React.ReactNode;
  color?: string;
}

function MetricCard({
  label,
  value,
  icon,
  color = 'text-neutral-600 dark:text-neutral-400',
}: MetricCardProps) {
  return (
    <div className="bg-neutral-50 dark:bg-neutral-800 rounded-lg p-4">
      <div className="flex items-center justify-between mb-2">
        <span className="text-sm text-neutral-600 dark:text-neutral-400">
          {label}
        </span>
        <span className={color}>{icon}</span>
      </div>
      <div className={`text-2xl font-bold ${color}`}>{value}</div>
    </div>
  );
}
