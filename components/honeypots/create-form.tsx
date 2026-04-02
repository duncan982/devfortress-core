/**
 * Honeypot creation form component
 */

'use client';

import { useState, useTransition } from 'react';
import { useRouter } from 'next/navigation';
import { SubscriptionPlan } from '@prisma/client';

interface ApiProject {
  id: string;
  name: string;
  framework: string | null;
  language: string | null;
}

interface HoneypotCreateFormProps {
  apiProjects: ApiProject[];
  tier: SubscriptionPlan;
  remainingSlots: number;
}

export default function HoneypotCreateForm({
  apiProjects,
  tier,
  remainingSlots,
}: HoneypotCreateFormProps) {
  const router = useRouter();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [, startTransition] = useTransition();

  const [formData, setFormData] = useState({
    name: '',
    slug: '',
    apiProjectId: '',
  });

  const validateSlug = (slug: string): boolean => {
    return /^[a-z0-9][a-z0-9-]*$/.test(slug);
  };

  const handleSlugChange = (value: string) => {
    setFormData({ ...formData, slug: value });
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);

    // Validate slug format
    if (!validateSlug(formData.slug)) {
      setError(
        'Slug must contain only lowercase letters, numbers, and hyphens, and cannot start with a hyphen'
      );
      setLoading(false);
      return;
    }

    try {
      // Create honeypot
      const createResponse = await fetch('/api/honeypots', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          name: formData.name,
          slug: formData.slug,
          apiProjectId: formData.apiProjectId || undefined,
          tier,
        }),
      });

      if (!createResponse.ok) {
        const errorData = await createResponse.json();
        throw new Error(errorData.error || 'Failed to create honeypot');
      }

      const honeypot = await createResponse.json();

      // Redirect to honeypot details
      router.push(`/dashboard/honeypots/${honeypot.id}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred');
      setLoading(false);
    }
  };

  const generateSlug = (name: string) => {
    return name
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-|-$/g, '');
  };

  return (
    <form
      onSubmit={handleSubmit}
      className="bg-white dark:bg-neutral-900 rounded-lg shadow-md p-6"
    >
      <div className="space-y-6">
        {/* Name */}
        <div>
          <label
            htmlFor="name"
            className="block text-sm font-medium text-neutral-700 dark:text-neutral-300 mb-2"
          >
            Honeypot Name *
          </label>
          <input
            type="text"
            id="name"
            required
            value={formData.name}
            onChange={e => {
              setFormData({
                ...formData,
                name: e.target.value,
                slug: generateSlug(e.target.value),
              });
            }}
            className="w-full px-4 py-2 border border-neutral-300 dark:border-neutral-700 bg-white dark:bg-neutral-950 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-transparent text-neutral-900 dark:text-neutral-100"
            placeholder="My Security Honeypot"
            disabled={loading}
          />
          <p className="mt-1 text-sm text-neutral-500 dark:text-neutral-400">
            A descriptive name for your honeypot configuration
          </p>
        </div>

        {/* Slug */}
        <div>
          <label
            htmlFor="slug"
            className="block text-sm font-medium text-neutral-700 dark:text-neutral-300 mb-2"
          >
            Slug *
          </label>
          <input
            type="text"
            id="slug"
            required
            value={formData.slug}
            onChange={e => handleSlugChange(e.target.value)}
            className={`w-full px-4 py-2 border rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-transparent bg-white dark:bg-neutral-950 text-neutral-900 dark:text-neutral-100 ${
              formData.slug && !validateSlug(formData.slug)
                ? 'border-error-300 dark:border-error-700 focus:ring-error-500'
                : 'border-neutral-300 dark:border-neutral-700'
            }`}
            placeholder="my-security-honeypot"
            disabled={loading}
          />
          {formData.slug && !validateSlug(formData.slug) && (
            <p className="mt-1 text-sm text-error-600 dark:text-error-400">
              Slug must contain only lowercase letters, numbers, and hyphens,
              and cannot start with a hyphen
            </p>
          )}
          <p className="mt-1 text-sm text-neutral-500 dark:text-neutral-400">
            URL-friendly identifier (lowercase letters, numbers, and hyphens
            only)
          </p>
        </div>

        {/* API Project Selection */}
        <div>
          <label
            htmlFor="apiProjectId"
            className="block text-sm font-medium text-neutral-700 dark:text-neutral-300 mb-2"
          >
            Base API Project (Optional)
          </label>
          <select
            id="apiProjectId"
            value={formData.apiProjectId}
            onChange={e =>
              startTransition(() => {
                setFormData({ ...formData, apiProjectId: e.target.value });
              })
            }
            className="w-full px-4 py-2 border border-neutral-300 dark:border-neutral-700 bg-white dark:bg-neutral-950 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-transparent text-neutral-900 dark:text-neutral-100"
            disabled={loading}
          >
            <option value="">Create standalone honeypot</option>
            {apiProjects.map(project => (
              <option key={project.id} value={project.id}>
                {project.name} ({project.framework} / {project.language})
              </option>
            ))}
          </select>
          <p className="mt-1 text-sm text-neutral-500 dark:text-neutral-400">
            Select an API project to base the honeypot on, or create a
            standalone decoy
          </p>
        </div>

        {/* Info Box */}
        <div className="bg-primary-50 dark:bg-primary-950/40 border border-primary-200 dark:border-primary-800 rounded-lg p-4">
          <h3 className="text-sm font-semibold text-primary-900 dark:text-primary-100 mb-2">
            📝 Honeypot Configuration
          </h3>
          <ul className="text-sm text-primary-800 dark:text-primary-200 space-y-1">
            <li>
              • Creates a honeypot configuration that can be deployed later
            </li>
            <li>
              • Choose an existing API project or create a standalone decoy
            </li>
            <li>• Configure rate limiting and threat detection settings</li>
            <li>
              • Remaining slots: {remainingSlots} of your {tier} plan
            </li>
          </ul>
        </div>

        {/* Error Message */}
        {error && (
          <div className="bg-error-50 dark:bg-error-950/40 border border-error-200 dark:border-error-800 rounded-lg p-4">
            <p className="text-error-800 dark:text-error-200">{error}</p>
          </div>
        )}

        {/* Submit Button */}
        <div className="flex justify-between items-center pt-4">
          <button
            type="button"
            onClick={() => router.back()}
            className="px-6 py-2 border border-neutral-300 dark:border-neutral-700 rounded-lg text-neutral-700 dark:text-neutral-300 hover:bg-neutral-50 dark:hover:bg-neutral-800"
            disabled={loading}
          >
            Cancel
          </button>
          <button
            type="submit"
            disabled={loading}
            className="px-6 py-2 bg-gradient-to-r from-primary-600 to-purple-600 text-white rounded-lg hover:shadow-lg transition-shadow font-semibold disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {loading ? 'Creating...' : '📝 Create Honeypot'}
          </button>
        </div>
      </div>
    </form>
  );
}
