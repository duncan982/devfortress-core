/**
 * MFA Setup Component
 * Allows users to enable/disable two-factor authentication
 */

'use client';

import React, { useState } from 'react';
import { Shield, Copy, Check, X } from 'lucide-react';
import Image from 'next/image';

interface MFASetupProps {
  onComplete?: () => void;
}

export function MFASetup({ onComplete }: MFASetupProps) {
  const [step, setStep] = useState<'init' | 'qr' | 'verify' | 'complete'>(
    'init'
  );
  const [qrCodeUrl, setQrCodeUrl] = useState<string>('');
  const [secret, setSecret] = useState<string>('');
  const [backupCodes, setBackupCodes] = useState<string[]>([]);
  const [token, setToken] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copiedSecret, setCopiedSecret] = useState(false);
  const [copiedCodes, setCopiedCodes] = useState(false);

  const handleSetup = async () => {
    try {
      setLoading(true);
      setError(null);

      const response = await fetch('/api/auth/mfa/setup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'setup' }),
      });

      if (!response.ok) {
        throw new Error('Failed to generate MFA secret');
      }

      const data = await response.json();
      setQrCodeUrl(data.qrCodeUrl);
      setSecret(data.secret);
      setBackupCodes(data.backupCodes);
      setStep('qr');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred');
    } finally {
      setLoading(false);
    }
  };

  const handleVerify = async () => {
    try {
      setLoading(true);
      setError(null);

      const response = await fetch('/api/auth/mfa/setup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'enable', token }),
      });

      if (!response.ok) {
        throw new Error('Invalid verification code');
      }

      setStep('complete');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Invalid code');
    } finally {
      setLoading(false);
    }
  };

  const copyToClipboard = (text: string, type: 'secret' | 'codes') => {
    navigator.clipboard.writeText(text);
    if (type === 'secret') {
      setCopiedSecret(true);
      setTimeout(() => setCopiedSecret(false), 2000);
    } else {
      setCopiedCodes(true);
      setTimeout(() => setCopiedCodes(false), 2000);
    }
  };

  if (step === 'init') {
    return (
      <div className="bg-white dark:bg-neutral-800 border border-gray-200 dark:border-neutral-700 rounded-lg p-6 shadow-sm">
        <div className="flex items-start gap-4">
          <div className="p-3 bg-blue-100 dark:bg-blue-900/50 rounded-lg">
            <Shield className="h-6 w-6 text-blue-600 dark:text-blue-400" />
          </div>
          <div className="flex-1">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-neutral-100 mb-2">
              Two-Factor Authentication
            </h3>
            <p className="text-sm text-gray-600 dark:text-neutral-400 mb-4">
              Add an extra layer of security to your account by requiring a
              verification code in addition to your password.
            </p>
            <button
              onClick={handleSetup}
              disabled={loading}
              className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 disabled:opacity-50 transition-colors"
            >
              {loading ? 'Setting up...' : 'Enable 2FA'}
            </button>
          </div>
        </div>
      </div>
    );
  }

  if (step === 'qr') {
    return (
      <div className="bg-white dark:bg-neutral-800 border border-gray-200 dark:border-neutral-700 rounded-lg p-6 shadow-sm">
        <h3 className="text-lg font-semibold text-gray-900 dark:text-neutral-100 mb-4">
          Scan QR Code
        </h3>

        <div className="space-y-6">
          <div>
            <p className="text-sm text-gray-600 dark:text-neutral-400 mb-4">
              Scan this QR code with your authenticator app (Authy, Microsoft
              Authenticator, etc.):
            </p>
            <div className="flex justify-center mb-4">
              {qrCodeUrl && (
                <Image
                  src={qrCodeUrl}
                  alt="MFA QR Code"
                  width={200}
                  height={200}
                  className="border border-gray-300 dark:border-neutral-600 rounded"
                />
              )}
            </div>
          </div>

          <div>
            <p className="text-sm text-gray-600 dark:text-neutral-400 mb-2">
              Or enter this secret key manually:
            </p>
            <div className="flex items-center gap-2">
              <code className="flex-1 px-3 py-2 bg-gray-100 dark:bg-neutral-700 rounded font-mono text-sm dark:text-neutral-300">
                {secret}
              </code>
              <button
                onClick={() => copyToClipboard(secret, 'secret')}
                className="p-2 hover:bg-gray-100 dark:hover:bg-neutral-700 rounded"
                title="Copy secret"
              >
                {copiedSecret ? (
                  <Check className="h-5 w-5 text-green-600" />
                ) : (
                  <Copy className="h-5 w-5 text-gray-600 dark:text-neutral-400" />
                )}
              </button>
            </div>
          </div>

          <div>
            <p className="text-sm font-medium text-gray-900 dark:text-neutral-100 mb-2">
              Save these backup codes:
            </p>
            <div className="bg-gray-50 dark:bg-neutral-700 border border-gray-200 dark:border-neutral-600 rounded p-3 mb-2">
              <div className="grid grid-cols-2 gap-2 font-mono text-sm dark:text-neutral-300">
                {backupCodes.map((code, i) => (
                  <div key={i}>{code}</div>
                ))}
              </div>
            </div>
            <button
              onClick={() => copyToClipboard(backupCodes.join('\n'), 'codes')}
              className="text-sm text-blue-600 hover:text-blue-700 flex items-center gap-1"
            >
              {copiedCodes ? (
                <>
                  <Check className="h-4 w-4" /> Copied!
                </>
              ) : (
                <>
                  <Copy className="h-4 w-4" /> Copy all codes
                </>
              )}
            </button>
          </div>

          <button
            onClick={() => setStep('verify')}
            className="w-full px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors"
          >
            Continue
          </button>
        </div>
      </div>
    );
  }

  if (step === 'verify') {
    return (
      <div className="bg-white dark:bg-neutral-800 border border-gray-200 dark:border-neutral-700 rounded-lg p-6 shadow-sm">
        <h3 className="text-lg font-semibold text-gray-900 dark:text-neutral-100 mb-4">
          Verify Setup
        </h3>

        <p className="text-sm text-gray-600 dark:text-neutral-400 mb-4">
          Enter the 6-digit code from your authenticator app to complete setup:
        </p>

        <div className="space-y-4">
          <input
            type="text"
            value={token}
            onChange={e =>
              setToken(e.target.value.replace(/\D/g, '').slice(0, 6))
            }
            placeholder="000000"
            className="w-full px-4 py-2 border border-gray-300 dark:border-neutral-600 dark:bg-neutral-700 dark:text-neutral-100 rounded-md text-center text-2xl tracking-widest font-mono"
            maxLength={6}
          />

          {error && (
            <div className="p-3 bg-red-50 dark:bg-red-900/30 border border-red-200 dark:border-red-800 rounded flex items-center gap-2">
              <X className="h-4 w-4 text-red-600 dark:text-red-400" />
              <p className="text-sm text-red-800 dark:text-red-200">{error}</p>
            </div>
          )}

          <button
            onClick={handleVerify}
            disabled={loading || token.length !== 6}
            className="w-full px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 disabled:opacity-50 transition-colors"
          >
            {loading ? 'Verifying...' : 'Verify and Enable'}
          </button>
        </div>
      </div>
    );
  }

  if (step === 'complete') {
    return (
      <div className="bg-white dark:bg-neutral-800 border border-gray-200 dark:border-neutral-700 rounded-lg p-6 shadow-sm">
        <div className="text-center">
          <div className="inline-flex items-center justify-center w-16 h-16 bg-green-100 dark:bg-green-900/50 rounded-full mb-4">
            <Check className="h-8 w-8 text-green-600 dark:text-green-400" />
          </div>
          <h3 className="text-lg font-semibold text-gray-900 dark:text-neutral-100 mb-2">
            2FA Enabled Successfully!
          </h3>
          <p className="text-sm text-gray-600 dark:text-neutral-400 mb-6">
            Your account is now protected with two-factor authentication.
          </p>
          <button
            onClick={onComplete}
            className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors"
          >
            Done
          </button>
        </div>
      </div>
    );
  }

  return null;
}
