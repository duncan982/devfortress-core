/**
 * Honeypot Redeploy Component
 * Allows users to redeploy suspended honeypots
 */

'use client';

import React, { useState } from 'react';
import { RefreshCw, AlertTriangle } from 'lucide-react';

interface RedeployHoneypotProps {
  honeypotId: string;
  honeypotName: string;
  suspendedReason?: string;
  onRedeploy?: () => void;
}

export function RedeployHoneypot({
  honeypotId,
  honeypotName,
  suspendedReason,
  onRedeploy,
}: RedeployHoneypotProps) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);

  const handleRedeploy = async () => {
    try {
      setLoading(true);
      setError(null);

      const response = await fetch(`/api/honeypots/${honeypotId}/redeploy`, {
        method: 'POST',
      });

      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.error || 'Failed to redeploy honeypot');
      }

      setSuccess(true);
      if (onRedeploy) {
        onRedeploy();
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-6">
      <div className="flex items-start gap-4">
        <AlertTriangle className="h-6 w-6 text-yellow-600 flex-shrink-0 mt-1" />
        <div className="flex-1">
          <h3 className="text-lg font-semibold text-gray-900 mb-2">
            Honeypot Suspended
          </h3>
          <p className="text-sm text-gray-700 mb-3">
            <span className="font-medium">{honeypotName}</span> has been
            suspended due to security threat detection.
          </p>
          {suspendedReason && (
            <div className="mb-4 p-3 bg-white rounded border border-yellow-300">
              <p className="text-sm text-gray-700">
                <span className="font-medium">Reason:</span> {suspendedReason}
              </p>
            </div>
          )}

          {success ? (
            <div className="p-4 bg-green-50 border border-green-200 rounded">
              <p className="text-sm text-green-800">
                ✓ Redeployment initiated successfully. The honeypot will be
                active shortly.
              </p>
            </div>
          ) : (
            <>
              <p className="text-sm text-gray-600 mb-4">
                You can redeploy this honeypot after reviewing the threat alerts
                and taking appropriate action. The honeypot will be available
                for redeployment after a brief security review period.
              </p>

              {error && (
                <div className="mb-4 p-3 bg-red-50 border border-red-200 rounded">
                  <p className="text-sm text-red-800">{error}</p>
                </div>
              )}

              <button
                onClick={handleRedeploy}
                disabled={loading}
                className="flex items-center gap-2 px-4 py-2 bg-yellow-600 text-white rounded-md hover:bg-yellow-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                <RefreshCw
                  className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`}
                />
                {loading ? 'Redeploying...' : 'Redeploy Honeypot'}
              </button>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
