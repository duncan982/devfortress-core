/**
 * Privacy Actions Component
 * Data export and account deletion
 */
'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { logError } from '@core/lib/logger/client';

export function PrivacyActions() {
  const router = useRouter();
  const [isDownloading, setIsDownloading] = useState(false);
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [isDeleting, setIsDeleting] = useState(false);
  const [deleteConfirmText, setDeleteConfirmText] = useState('');

  const handleDownloadData = async () => {
    setIsDownloading(true);

    try {
      const response = await fetch('/api/user/data-export');

      if (!response.ok) {
        throw new Error('Failed to download data');
      }

      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `devfortress-data-${new Date().toISOString().split('T')[0]}.json`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (error) {
      logError('Failed to download user data', error);
      alert('Failed to download data. Please try again.');
    } finally {
      setIsDownloading(false);
    }
  };

  const handleDeleteAccount = async () => {
    if (deleteConfirmText !== 'DELETE') {
      alert('Please type DELETE to confirm');
      return;
    }

    setIsDeleting(true);

    try {
      const response = await fetch('/api/user/delete-account', {
        method: 'DELETE',
      });

      if (!response.ok) {
        throw new Error('Failed to delete account');
      }

      // Redirect to sign out page
      router.push('/auth/signout');
    } catch (error) {
      logError('Failed to delete account', error);
      alert('Failed to delete account. Please contact support.');
    } finally {
      setIsDeleting(false);
    }
  };

  return (
    <div className="space-y-4">
      <div>
        <button
          onClick={handleDownloadData}
          disabled={isDownloading}
          className="text-primary-600 dark:text-primary-400 hover:underline text-sm font-medium disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {isDownloading ? 'Downloading...' : 'Download Your Data'}
        </button>
        <p className="text-xs text-neutral-500 dark:text-neutral-400 mt-1">
          Export all your data in JSON format
        </p>
      </div>

      <div>
        <button
          onClick={() => setShowDeleteConfirm(!showDeleteConfirm)}
          className="text-error-600 dark:text-error-400 hover:underline text-sm font-medium"
        >
          Delete Account
        </button>
        <p className="text-xs text-neutral-500 dark:text-neutral-400 mt-1">
          Permanently delete your account and all associated data
        </p>

        {showDeleteConfirm && (
          <div className="mt-4 p-4 bg-error-50 dark:bg-error-900/20 border border-error-200 dark:border-error-800 rounded-md">
            <p className="text-sm text-error-700 dark:text-error-400 mb-3">
              <strong>Warning:</strong> This action cannot be undone. All your
              data, including API projects, honeypots, and team information,
              will be permanently deleted.
            </p>
            <div className="mb-3">
              <label
                htmlFor="delete-confirm"
                className="block text-sm font-medium text-error-700 dark:text-error-400 mb-2"
              >
                Type <strong>DELETE</strong> to confirm
              </label>
              <input
                id="delete-confirm"
                type="text"
                value={deleteConfirmText}
                onChange={e => setDeleteConfirmText(e.target.value)}
                className="w-full px-3 py-2 border border-error-300 dark:border-error-700 rounded-md bg-white dark:bg-neutral-900 text-neutral-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-error-500"
                placeholder="DELETE"
              />
            </div>
            <div className="flex gap-2">
              <button
                onClick={handleDeleteAccount}
                disabled={isDeleting || deleteConfirmText !== 'DELETE'}
                className="px-4 py-2 bg-error-600 hover:bg-error-700 disabled:bg-neutral-400 text-white rounded-md font-medium transition-colors disabled:cursor-not-allowed text-sm"
              >
                {isDeleting ? 'Deleting...' : 'Delete Account'}
              </button>
              <button
                onClick={() => {
                  setShowDeleteConfirm(false);
                  setDeleteConfirmText('');
                }}
                className="px-4 py-2 bg-neutral-200 dark:bg-neutral-700 hover:bg-neutral-300 dark:hover:bg-neutral-600 text-neutral-900 dark:text-white rounded-md font-medium transition-colors text-sm"
              >
                Cancel
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
