/**
 * SDK Credentials Management Page
 * Create projects and manage SDK credentials for applications, APIs, and agents.
 *
 * MVP Focus: Collect Phase — SDK Surveillance
 * Connects to /api/sdk/credentials for real credential management.
 */

'use client';

import { useState, useCallback, useEffect, Fragment } from 'react';
import Link from 'next/link';
import { BreadcrumbNav } from '@core/components/navigation/BreadcrumbNav';
import { BREADCRUMB_PATHS } from '@core/components/navigation/breadcrumb-constants';

/* ------------------------------------------------------------------ */
/*  Types                                                              */
/* ------------------------------------------------------------------ */

type ProjectType = 'application' | 'api' | 'agent';

interface SdkCredential {
  projectId: string;
  projectName: string;
  projectType: ProjectType;
  apiKey: string;
  webhookSecret: string;
  createdAt: string;
  status: 'active' | 'revoked';
}

type AliasWorkload =
  | 'ci'
  | 'agent'
  | 'plugin'
  | 'browser'
  | 'server'
  | 'custom';
type AliasStatus = 'active' | 'rotated' | 'revoked';

interface CredentialAlias {
  id: string;
  projectId: string;
  projectName: string;
  workload: AliasWorkload;
  label: string;
  aliasToken: string;
  status: AliasStatus;
  createdAt: string;
  expiresAt: string | null;
  lastUsedAt: string | null;
  rotationCount: number;
  scope: string[];
  tags: Record<string, string>;
}

const TYPE_META: Record<
  ProjectType,
  { label: string; icon: string; desc: string }
> = {
  application: {
    label: 'Application',
    icon: '🖥️',
    desc: 'Web or mobile application with user sessions',
  },
  api: {
    label: 'API',
    icon: '🔗',
    desc: 'REST / GraphQL API endpoints',
  },
  agent: {
    label: 'Agent',
    icon: '🤖',
    desc: 'AI agent with tool-call capabilities',
  },
};

/* ------------------------------------------------------------------ */
/*  Code Examples                                                      */
/* ------------------------------------------------------------------ */

function getIntegrationExamples(
  projectId: string,
  apiKey: string,
  webhookSecret: string
) {
  return {
    nextjs: `// middleware.ts — Next.js App Router
import { DevFortress } from 'devfortress-sdk';

const df = new DevFortress({
  projectId: '${projectId}',
  apiKey: '${apiKey}',
  webhookSecret: '${webhookSecret}',
  mode: 'external', // or 'internal' / 'hybrid'
});

export async function middleware(request) {
  const ip = request.headers.get('x-forwarded-for') || 'unknown';

  if (await df.isBlocked(ip)) {
    return new Response('Forbidden', { status: 403 });
  }

  await df.observe({
    ip,
    method: request.method,
    path: request.nextUrl.pathname,
    headers: Object.fromEntries(request.headers),
  });

  return NextResponse.next();
}`,
    express: `// Express.js middleware
const { DevFortress } = require('devfortress-sdk');

const df = new DevFortress({
  projectId: '${projectId}',
  apiKey: '${apiKey}',
  webhookSecret: '${webhookSecret}',
  mode: 'external',
});

df.onThreatDetected('*', (event) => {
  console.log('Threat:', event.threat_type, 'from', event.ip);
});

app.use(async (req, res, next) => {
  const ip = req.ip || req.headers['x-forwarded-for'] || 'unknown';

  if (await df.isBlocked(ip)) {
    return res.status(403).json({ error: 'Blocked' });
  }

  await df.observe({
    ip,
    method: req.method,
    path: req.path,
    headers: req.headers,
  });

  next();
});`,
    python: `# FastAPI middleware
from devfortress import DevFortress

df = DevFortress(
    project_id="${projectId}",
    api_key="${apiKey}",
    webhook_secret="${webhookSecret}",
    mode="external",
)

@app.middleware("http")
async def devfortress_middleware(request, call_next):
    ip = request.client.host

    if await df.is_blocked(ip):
        return JSONResponse(status_code=403, content={"error": "Blocked"})

    await df.observe(
        ip=ip,
        method=request.method,
        path=request.url.path,
        headers=dict(request.headers),
    )

    return await call_next(request)`,
    curl: `# Test event ingestion (all 3 credentials required)
curl -X POST https://www.devfortress.net/api/events/ingest \\
  -H "Content-Type: application/json" \\
  -H "x-api-key: ${apiKey}" \\
  -d '{
    "events": [{
      "eventType": "page_view",
      "ip": "192.168.1.1",
      "severity": "LOW",
      "method": "GET",
      "path": "/dashboard",
      "clMode": "external",
      "authPhase": "post_auth",
      "actionTaken": "allowed",
      "responseLatencyMs": 42
    }]
  }'

# Your Project ID: ${projectId}
# Use it when initializing the SDK in your application.`,
  };
}

/* ------------------------------------------------------------------ */
/*  Component                                                          */
/* ------------------------------------------------------------------ */

export default function CredentialsPage() {
  /* Page tab: 'credentials' | 'aliases' */
  const [pageTab, setPageTab] = useState<'credentials' | 'aliases'>(
    'credentials'
  );

  const [credentials, setCredentials] = useState<SdkCredential[]>([]);
  const [loading, setLoading] = useState(true);
  const [creating, setCreating] = useState(false);
  const [showCreate, setShowCreate] = useState(false);
  const [newProjectName, setNewProjectName] = useState('');
  const [newProjectType, setNewProjectType] =
    useState<ProjectType>('application');
  const [visibleKeys, setVisibleKeys] = useState<Set<string>>(new Set());
  const [copiedField, setCopiedField] = useState<string | null>(null);
  const [activeExample, setActiveExample] = useState<string>('nextjs');
  const [selectedCredential, setSelectedCredential] = useState<string | null>(
    null
  );
  const [error, setError] = useState<string | null>(null);

  /* A19 Alias tab state */
  const [aliases, setAliases] = useState<CredentialAlias[]>([]);
  const [aliasLoading, setAliasLoading] = useState(false);
  const [aliasError, setAliasError] = useState<string | null>(null);
  const [showCreateAlias, setShowCreateAlias] = useState(false);
  const [newAliasProjectId, setNewAliasProjectId] = useState('');
  const [newAliasLabel, setNewAliasLabel] = useState('');
  const [newAliasWorkload, setNewAliasWorkload] =
    useState<AliasWorkload>('custom');
  const [creatingAlias, setCreatingAlias] = useState(false);
  /* View-once alias key state — key is shown exactly once after creation */
  const [viewOnceKey, setViewOnceKey] = useState<{
    aliasId: string;
    aliasKey: string;
    label: string;
  } | null>(null);
  const [viewOnceCopied, setViewOnceCopied] = useState(false);

  /* Revoke confirmation state */
  const [revokeModal, setRevokeModal] = useState<{
    projectId: string;
    aliasId: string;
    label: string;
  } | null>(null);
  const [isRevokingFamily, setIsRevokingFamily] = useState(false);

  /* Load existing credentials on mount */
  useEffect(() => {
    async function loadCredentials() {
      try {
        const res = await fetch('/api/sdk/credentials');
        if (res.ok) {
          const data = await res.json();
          setCredentials(data.credentials || []);
        }
      } catch {
        /* empty state is fine */
      } finally {
        setLoading(false);
      }
    }
    loadCredentials();
  }, []);

  /* Load aliases when alias tab becomes active */
  useEffect(() => {
    if (pageTab !== 'aliases') return;
    async function loadAliases() {
      setAliasLoading(true);
      setAliasError(null);
      try {
        const all: CredentialAlias[] = [];
        for (const cred of credentials) {
          const res = await fetch(`/api/projects/${cred.projectId}/aliases`);
          if (res.ok) {
            const data = await res.json();
            const list = (data.aliases || data || []) as CredentialAlias[];
            all.push(
              ...list.map(a => ({
                ...a,
                projectName: cred.projectName,
                projectId: cred.projectId,
              }))
            );
          }
        }
        setAliases(all);
      } catch {
        setAliasError('Failed to load aliases');
      } finally {
        setAliasLoading(false);
      }
    }
    loadAliases();
  }, [pageTab, credentials]);

  /* Create new alias */
  const handleCreateAlias = useCallback(async () => {
    if (!newAliasProjectId || !newAliasLabel.trim() || creatingAlias) return;
    setCreatingAlias(true);
    setAliasError(null);
    try {
      const res = await fetch(`/api/projects/${newAliasProjectId}/aliases`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          workload: newAliasWorkload,
          label: newAliasLabel.trim(),
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Failed to create alias');
      const cred = credentials.find(c => c.projectId === newAliasProjectId);
      // Build local alias record (aliasKey is NOT stored — show once only)
      const newAliasRecord: CredentialAlias = {
        id: data.aliasId,
        projectId: newAliasProjectId,
        projectName: cred?.projectName ?? '',
        workload: data.workload ?? newAliasWorkload,
        label: data.label ?? newAliasLabel.trim(),
        aliasToken: '[hidden after creation]',
        status: 'active',
        createdAt: data.createdAt ?? new Date().toISOString(),
        expiresAt: data.expiresAt ?? null,
        lastUsedAt: null,
        rotationCount: 0,
        scope: data.scope ?? [],
        tags: data.tags ?? {},
      };
      setAliases(prev => [newAliasRecord, ...prev]);
      setShowCreateAlias(false);
      setNewAliasLabel('');
      // Show the raw key exactly once
      setViewOnceKey({
        aliasId: data.aliasId,
        aliasKey: data.aliasKey,
        label: newAliasRecord.label,
      });
      setViewOnceCopied(false);
    } catch (err) {
      setAliasError(
        err instanceof Error ? err.message : 'Failed to create alias'
      );
    } finally {
      setCreatingAlias(false);
    }
  }, [
    newAliasProjectId,
    newAliasLabel,
    newAliasWorkload,
    creatingAlias,
    credentials,
  ]);

  /* Rotate alias */
  const handleRotateAlias = useCallback(
    async (projectId: string, aliasId: string) => {
      try {
        const res = await fetch(
          `/api/projects/${projectId}/aliases/${aliasId}/rotate`,
          {
            method: 'POST',
          }
        );
        if (res.ok) {
          const data = await res.json();
          setAliases(prev =>
            prev.map(a =>
              a.id === aliasId
                ? {
                    ...a,
                    aliasToken: data.alias?.aliasToken ?? a.aliasToken,
                    rotationCount: (a.rotationCount || 0) + 1,
                  }
                : a
            )
          );
        }
      } catch {
        /* silent */
      }
    },
    []
  );

  /* Revoke alias */
  const handleRevokeAlias = useCallback(
    async (projectId: string, aliasId: string, revokeFamily = false) => {
      try {
        const res = await fetch(
          `/api/projects/${projectId}/aliases/${aliasId}`,
          {
            method: 'DELETE',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ revokeFamily }),
          }
        );
        if (res.ok) {
          if (revokeFamily) {
            setAliases(prev =>
              prev.map(a =>
                a.projectId === projectId
                  ? { ...a, status: 'revoked' as const }
                  : a
              )
            );
          } else {
            setAliases(prev =>
              prev.map(a =>
                a.id === aliasId ? { ...a, status: 'revoked' as const } : a
              )
            );
          }
        }
      } catch {
        /* silent */
      } finally {
        setRevokeModal(null);
      }
    },
    []
  );

  /* Create new credential via API */
  const handleCreate = useCallback(async () => {
    if (!newProjectName.trim() || creating) return;
    setCreating(true);
    setError(null);

    try {
      const res = await fetch('/api/sdk/credentials', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: newProjectName.trim(),
          projectType: newProjectType,
        }),
      });

      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.error || 'Failed to create credentials');
      }

      const cred = data.credential as SdkCredential;
      setCredentials(prev => [cred, ...prev]);
      setSelectedCredential(cred.projectId);
      setNewProjectName('');
      setShowCreate(false);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : 'Failed to create credentials'
      );
    } finally {
      setCreating(false);
    }
  }, [newProjectName, newProjectType, creating]);

  const toggleKeyVisibility = useCallback((id: string) => {
    setVisibleKeys(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }, []);

  const copyToClipboard = useCallback(async (text: string, fieldId: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedField(fieldId);
      setTimeout(() => setCopiedField(null), 2000);
    } catch {
      /* clipboard not available */
    }
  }, []);

  const handleRevoke = useCallback(async (projectId: string) => {
    try {
      const res = await fetch('/api/sdk/credentials?projectId=' + projectId, {
        method: 'DELETE',
      });
      if (res.ok) {
        setCredentials(prev =>
          prev.map(c =>
            c.projectId === projectId ? { ...c, status: 'revoked' as const } : c
          )
        );
      }
    } catch {
      /* handle silently */
    }
  }, []);

  const maskKey = (key: string, visible: boolean) =>
    visible ? key : key.slice(0, 10) + '\u2022'.repeat(20) + key.slice(-4);

  const activeCred = credentials.find(c => c.projectId === selectedCredential);
  const examples = activeCred
    ? getIntegrationExamples(
        activeCred.projectId,
        activeCred.apiKey,
        activeCred.webhookSecret
      )
    : null;

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-neutral-50 dark:bg-neutral-950">
        <div className="text-neutral-500 dark:text-neutral-400">
          Loading credentials...
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-neutral-50 dark:bg-neutral-950">
      <div className="mx-auto max-w-6xl px-4 py-8 sm:px-6 lg:px-8">
        {/* Breadcrumb Navigation */}
        <div className="mb-4">
          <BreadcrumbNav
            items={[BREADCRUMB_PATHS.dashboard]}
            currentPage="SDK Credentials"
          />
        </div>

        {/* Header */}
        <div className="mb-6 flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold text-neutral-900 dark:text-white">
              SDK Credentials
            </h1>
            <p className="mt-1 text-neutral-500 dark:text-neutral-400">
              Create projects and generate API keys for the DevFortress SDK.
              Each project gets a <strong>Project ID</strong>,{' '}
              <strong>API Key</strong>, and <strong>Webhook Secret</strong>.
            </p>
          </div>
          {pageTab === 'credentials' && (
            <button
              onClick={() => setShowCreate(true)}
              className="inline-flex items-center rounded-lg bg-primary-600 px-5 py-2.5 text-sm font-medium text-white shadow-sm transition-colors hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2"
            >
              <svg
                className="mr-2 h-4 w-4"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M12 4v16m8-8H4"
                />
              </svg>
              New Project
            </button>
          )}
          {pageTab === 'aliases' && (
            <button
              onClick={() => setShowCreateAlias(true)}
              className="inline-flex items-center rounded-lg bg-primary-600 px-5 py-2.5 text-sm font-medium text-white shadow-sm transition-colors hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2"
            >
              <svg
                className="mr-2 h-4 w-4"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M12 4v16m8-8H4"
                />
              </svg>
              New Alias
            </button>
          )}
        </div>

        {/* Page Tabs */}
        <div className="mb-6 flex gap-1 rounded-xl border border-neutral-200 bg-white p-1 dark:border-neutral-800 dark:bg-neutral-900 w-fit">
          {[
            { id: 'credentials', label: '🔑 SDK Credentials' },
            { id: 'aliases', label: '🎭 Credential Aliases', badge: 'A19' },
          ].map(tab => (
            <button
              key={tab.id}
              onClick={() => setPageTab(tab.id as 'credentials' | 'aliases')}
              className={`flex items-center gap-2 rounded-lg px-4 py-2 text-sm font-medium transition-colors ${
                pageTab === tab.id
                  ? 'bg-primary-600 text-white shadow-sm'
                  : 'text-neutral-600 hover:text-neutral-900 dark:text-neutral-400 dark:hover:text-white'
              }`}
            >
              {tab.label}
              {tab.badge && (
                <span
                  className={`rounded px-1.5 py-0.5 text-xs font-bold ${
                    pageTab === tab.id
                      ? 'bg-primary-500 text-white'
                      : 'bg-amber-100 text-amber-700 dark:bg-amber-900 dark:text-amber-300'
                  }`}
                >
                  {tab.badge}
                </span>
              )}
            </button>
          ))}
        </div>

        {/* ── CREDENTIALS TAB ── */}
        {pageTab === 'credentials' && (
          <>
            {error && (
              <div className="mb-6 rounded-lg border border-red-200 bg-red-50 p-4 text-sm text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400">
                {error}
                <button
                  onClick={() => setError(null)}
                  className="ml-2 underline"
                >
                  Dismiss
                </button>
              </div>
            )}

            {showCreate && (
              <div className="mb-8 rounded-2xl border border-primary-200 bg-white p-6 shadow-sm dark:border-primary-800 dark:bg-neutral-900">
                <h2 className="mb-4 text-lg font-semibold text-neutral-900 dark:text-white">
                  Create New Project
                </h2>
                <div className="grid gap-4 sm:grid-cols-2">
                  <div>
                    <label
                      htmlFor="projectName"
                      className="mb-1 block text-sm font-medium text-neutral-700 dark:text-neutral-300"
                    >
                      Project Name
                    </label>
                    <input
                      id="projectName"
                      type="text"
                      value={newProjectName}
                      onChange={e => setNewProjectName(e.target.value)}
                      placeholder="e.g. ecommerce-production"
                      className="w-full rounded-lg border border-neutral-300 bg-white px-4 py-2.5 text-sm text-neutral-900 transition-colors focus:border-primary-500 focus:ring-2 focus:ring-primary-500/20 dark:border-neutral-700 dark:bg-neutral-800 dark:text-white"
                      onKeyDown={e => e.key === 'Enter' && handleCreate()}
                    />
                  </div>
                  <div>
                    <span className="mb-1 block text-sm font-medium text-neutral-700 dark:text-neutral-300">
                      Project Type
                    </span>
                    <div className="flex gap-2">
                      {(Object.keys(TYPE_META) as ProjectType[]).map(type => (
                        <button
                          key={type}
                          onClick={() => setNewProjectType(type)}
                          className={`flex-1 rounded-lg border px-3 py-2.5 text-sm font-medium transition-colors ${
                            newProjectType === type
                              ? 'border-primary-500 bg-primary-50 text-primary-700 dark:bg-primary-950 dark:text-primary-300'
                              : 'border-neutral-200 bg-white text-neutral-600 hover:bg-neutral-50 dark:border-neutral-700 dark:bg-neutral-800 dark:text-neutral-400'
                          }`}
                        >
                          <span className="block text-lg" aria-hidden="true">
                            {TYPE_META[type].icon}
                          </span>
                          <span className="mt-0.5 block">
                            {TYPE_META[type].label}
                          </span>
                        </button>
                      ))}
                    </div>
                  </div>
                </div>
                <p className="mt-2 text-xs text-neutral-500 dark:text-neutral-400">
                  {TYPE_META[newProjectType].desc}
                </p>
                <div className="mt-4 flex justify-end gap-3">
                  <button
                    onClick={() => {
                      setShowCreate(false);
                      setError(null);
                    }}
                    className="rounded-lg border border-neutral-300 px-4 py-2 text-sm font-medium text-neutral-700 hover:bg-neutral-50 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={handleCreate}
                    disabled={!newProjectName.trim() || creating}
                    className="rounded-lg bg-primary-600 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-primary-700 disabled:cursor-not-allowed disabled:opacity-50"
                  >
                    {creating ? 'Generating...' : 'Generate Credentials'}
                  </button>
                </div>
              </div>
            )}

            {credentials.length === 0 && !showCreate ? (
              <div className="rounded-2xl border-2 border-dashed border-neutral-300 bg-white p-12 text-center dark:border-neutral-700 dark:bg-neutral-900">
                <div className="mb-4 text-5xl" aria-hidden="true">
                  🔑
                </div>
                <h2 className="mb-2 text-xl font-semibold text-neutral-900 dark:text-white">
                  No SDK Credentials Yet
                </h2>
                <p className="mx-auto mb-6 max-w-md text-neutral-500 dark:text-neutral-400">
                  Create your first project to get a <strong>Project ID</strong>
                  , <strong>API Key</strong>, and{' '}
                  <strong>Webhook Secret</strong>. The SDK starts collecting
                  security events immediately after integration.
                </p>
                <button
                  onClick={() => setShowCreate(true)}
                  className="inline-flex items-center rounded-lg bg-primary-600 px-6 py-3 text-sm font-medium text-white transition-colors hover:bg-primary-700"
                >
                  Create Your First Project
                </button>
              </div>
            ) : (
              <div className="space-y-4">
                {credentials.map(cred => {
                  const isKeyVisible = visibleKeys.has(cred.projectId);
                  const isSelected = selectedCredential === cred.projectId;
                  const meta =
                    TYPE_META[cred.projectType as ProjectType] ||
                    TYPE_META.application;

                  return (
                    <Fragment key={cred.projectId}>
                      <div
                        className={`rounded-2xl border bg-white transition-all dark:bg-neutral-900 ${
                          cred.status === 'revoked'
                            ? 'border-red-200 opacity-60 dark:border-red-800'
                            : isSelected
                              ? 'border-primary-300 ring-2 ring-primary-500/20 dark:border-primary-700'
                              : 'border-neutral-200 dark:border-neutral-800'
                        }`}
                      >
                        <div
                          className="flex cursor-pointer items-center justify-between px-6 py-4"
                          onClick={() =>
                            setSelectedCredential(
                              isSelected ? null : cred.projectId
                            )
                          }
                          role="button"
                          tabIndex={0}
                          onKeyDown={e =>
                            e.key === 'Enter' &&
                            setSelectedCredential(
                              isSelected ? null : cred.projectId
                            )
                          }
                        >
                          <div className="flex items-center gap-3">
                            <span className="text-2xl" aria-hidden="true">
                              {meta.icon}
                            </span>
                            <div>
                              <h3 className="font-semibold text-neutral-900 dark:text-white">
                                {cred.projectName}
                              </h3>
                              <p className="text-xs text-neutral-500 dark:text-neutral-400">
                                {meta.label} &bull;{' '}
                                {new Date(cred.createdAt).toLocaleDateString()}
                              </p>
                            </div>
                          </div>
                          <div className="flex items-center gap-3">
                            <span
                              className={`rounded-full px-3 py-1 text-xs font-medium ${
                                cred.status === 'active'
                                  ? 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400'
                                  : 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400'
                              }`}
                            >
                              {cred.status === 'active'
                                ? '\u25CF Active'
                                : '\u2717 Revoked'}
                            </span>
                            <svg
                              className={`h-5 w-5 text-neutral-400 transition-transform ${isSelected ? 'rotate-180' : ''}`}
                              fill="none"
                              stroke="currentColor"
                              viewBox="0 0 24 24"
                            >
                              <path
                                strokeLinecap="round"
                                strokeLinejoin="round"
                                strokeWidth={2}
                                d="M19 9l-7 7-7-7"
                              />
                            </svg>
                          </div>
                        </div>

                        {isSelected && (
                          <div className="border-t border-neutral-100 px-6 py-5 dark:border-neutral-800">
                            {/* Project ID */}
                            <div className="mb-4">
                              <label className="mb-1 block text-xs font-medium text-neutral-500 dark:text-neutral-400">
                                Project ID
                                <span className="ml-2 rounded bg-blue-100 px-1.5 py-0.5 text-[10px] font-semibold text-blue-700 dark:bg-blue-900/30 dark:text-blue-400">
                                  REQUIRED FOR SDK
                                </span>
                              </label>
                              <div className="flex items-center gap-2">
                                <code className="flex-1 rounded-lg bg-neutral-100 px-3 py-2 font-mono text-sm text-neutral-800 dark:bg-neutral-800 dark:text-neutral-200">
                                  {cred.projectId}
                                </code>
                                <button
                                  onClick={() =>
                                    copyToClipboard(
                                      cred.projectId,
                                      `pid-${cred.projectId}`
                                    )
                                  }
                                  className="rounded-lg border border-neutral-200 p-2 text-neutral-500 hover:bg-neutral-50 dark:border-neutral-700 dark:hover:bg-neutral-800"
                                  title="Copy Project ID"
                                >
                                  {copiedField === `pid-${cred.projectId}`
                                    ? '\u2705'
                                    : '\uD83D\uDCCB'}
                                </button>
                              </div>
                            </div>

                            {/* API Key */}
                            <div className="mb-4">
                              <label className="mb-1 block text-xs font-medium text-neutral-500 dark:text-neutral-400">
                                API Key
                              </label>
                              <div className="flex items-center gap-2">
                                <code className="flex-1 rounded-lg bg-neutral-100 px-3 py-2 font-mono text-sm text-neutral-800 dark:bg-neutral-800 dark:text-neutral-200">
                                  {maskKey(cred.apiKey, isKeyVisible)}
                                </code>
                                <button
                                  onClick={() =>
                                    toggleKeyVisibility(cred.projectId)
                                  }
                                  className="rounded-lg border border-neutral-200 p-2 text-neutral-500 hover:bg-neutral-50 dark:border-neutral-700 dark:hover:bg-neutral-800"
                                  title={isKeyVisible ? 'Hide' : 'Show'}
                                >
                                  {isKeyVisible
                                    ? '\uD83D\uDE48'
                                    : '\uD83D\uDC41\uFE0F'}
                                </button>
                                <button
                                  onClick={() =>
                                    copyToClipboard(
                                      cred.apiKey,
                                      `key-${cred.projectId}`
                                    )
                                  }
                                  className="rounded-lg border border-neutral-200 p-2 text-neutral-500 hover:bg-neutral-50 dark:border-neutral-700 dark:hover:bg-neutral-800"
                                  title="Copy"
                                >
                                  {copiedField === `key-${cred.projectId}`
                                    ? '\u2705'
                                    : '\uD83D\uDCCB'}
                                </button>
                              </div>
                            </div>

                            {/* Webhook Secret */}
                            <div className="mb-4">
                              <label className="mb-1 block text-xs font-medium text-neutral-500 dark:text-neutral-400">
                                Webhook Secret
                              </label>
                              <div className="flex items-center gap-2">
                                <code className="flex-1 rounded-lg bg-neutral-100 px-3 py-2 font-mono text-sm text-neutral-800 dark:bg-neutral-800 dark:text-neutral-200">
                                  {maskKey(cred.webhookSecret, isKeyVisible)}
                                </code>
                                <button
                                  onClick={() =>
                                    copyToClipboard(
                                      cred.webhookSecret,
                                      `secret-${cred.projectId}`
                                    )
                                  }
                                  className="rounded-lg border border-neutral-200 p-2 text-neutral-500 hover:bg-neutral-50 dark:border-neutral-700 dark:hover:bg-neutral-800"
                                  title="Copy"
                                >
                                  {copiedField === `secret-${cred.projectId}`
                                    ? '\u2705'
                                    : '\uD83D\uDCCB'}
                                </button>
                              </div>
                            </div>

                            {/* Quick copy all .env */}
                            <div className="mb-4 rounded-lg border border-blue-200 bg-blue-50/50 p-3 dark:border-blue-800 dark:bg-blue-950/30">
                              <p className="mb-2 text-xs font-medium text-blue-700 dark:text-blue-400">
                                SDK Configuration (all three values needed)
                              </p>
                              <button
                                onClick={() =>
                                  copyToClipboard(
                                    `DEVFORTRESS_PROJECT_ID=${cred.projectId}\nDEVFORTRESS_API_KEY=${cred.apiKey}\nDEVFORTRESS_WEBHOOK_SECRET=${cred.webhookSecret}`,
                                    `env-${cred.projectId}`
                                  )
                                }
                                className="rounded-lg bg-blue-600 px-4 py-2 text-xs font-medium text-white transition-colors hover:bg-blue-700"
                              >
                                {copiedField === `env-${cred.projectId}`
                                  ? '\u2705 Copied .env variables!'
                                  : '\uD83D\uDCCB Copy as .env variables'}
                              </button>
                            </div>

                            {cred.status === 'active' && (
                              <div className="flex justify-end">
                                <button
                                  onClick={() => handleRevoke(cred.projectId)}
                                  className="rounded-lg border border-red-200 px-4 py-2 text-sm font-medium text-red-600 transition-colors hover:bg-red-50 dark:border-red-800 dark:text-red-400 dark:hover:bg-red-950"
                                >
                                  Revoke Credentials
                                </button>
                              </div>
                            )}
                          </div>
                        )}
                      </div>
                    </Fragment>
                  );
                })}
              </div>
            )}

            {activeCred && activeCred.status === 'active' && examples && (
              <div className="mt-8 overflow-hidden rounded-2xl border border-neutral-200 bg-white dark:border-neutral-800 dark:bg-neutral-900">
                <div className="border-b border-neutral-100 px-6 py-4 dark:border-neutral-800">
                  <h2 className="text-lg font-semibold text-neutral-900 dark:text-white">
                    Integration Guide &mdash; {activeCred.projectName}
                  </h2>
                  <p className="text-sm text-neutral-500 dark:text-neutral-400">
                    Copy one of these examples into your project. All three
                    credentials (Project ID, API Key, Webhook Secret) are
                    included.
                  </p>
                </div>
                <div className="flex border-b border-neutral-100 px-6 dark:border-neutral-800">
                  {[
                    { id: 'nextjs', label: 'Next.js' },
                    { id: 'express', label: 'Express' },
                    { id: 'python', label: 'Python' },
                    { id: 'curl', label: 'cURL' },
                  ].map(tab => (
                    <button
                      key={tab.id}
                      onClick={() => setActiveExample(tab.id)}
                      className={`border-b-2 px-4 py-3 text-sm font-medium transition-colors ${
                        activeExample === tab.id
                          ? 'border-primary-600 text-primary-600 dark:text-primary-400'
                          : 'border-transparent text-neutral-500 hover:text-neutral-700 dark:text-neutral-400'
                      }`}
                    >
                      {tab.label}
                    </button>
                  ))}
                </div>
                <div className="p-6">
                  <div className="relative overflow-x-auto rounded-lg bg-neutral-900 p-4">
                    <button
                      onClick={() =>
                        copyToClipboard(
                          examples[activeExample as keyof typeof examples],
                          `example-${activeExample}`
                        )
                      }
                      className="absolute right-3 top-3 rounded-md bg-neutral-700 px-3 py-1.5 text-xs font-medium text-neutral-200 transition-colors hover:bg-neutral-600"
                    >
                      {copiedField === `example-${activeExample}`
                        ? '\u2705 Copied'
                        : '\uD83D\uDCCB Copy'}
                    </button>
                    <pre className="overflow-x-auto whitespace-pre font-mono text-sm text-green-400">
                      {examples[activeExample as keyof typeof examples]}
                    </pre>
                  </div>
                </div>
              </div>
            )}

            <div className="mt-8 flex flex-wrap gap-4">
              <Link
                href="/docs/validation-guide"
                className="inline-flex items-center text-sm text-primary-600 hover:text-primary-700 dark:text-primary-400 dark:hover:text-primary-300"
              >
                🧪 Validate your integration →
              </Link>
              <Link
                href="/dashboard/collect/surveillance"
                className="inline-flex items-center text-sm text-primary-600 hover:text-primary-700 dark:text-primary-400 dark:hover:text-primary-300"
              >
                📊 View live events →
              </Link>
              <Link
                href="/dashboard/projects"
                className="inline-flex items-center text-sm text-primary-600 hover:text-primary-700 dark:text-primary-400 dark:hover:text-primary-300"
              >
                📁 Manage projects →
              </Link>
            </div>
          </>
        )}

        {/* ── ALIASES TAB (A19) ── */}
        {pageTab === 'aliases' && (
          <div>
            {/* A19 explanation banner */}
            <div className="mb-6 rounded-xl border border-amber-200 bg-amber-50 p-4 dark:border-amber-800 dark:bg-amber-950/30">
              <div className="flex items-start gap-3">
                <span className="text-2xl">🎭</span>
                <div>
                  <p className="font-semibold text-amber-900 dark:text-amber-200">
                  </p>
                  <p className="mt-1 text-sm text-amber-800 dark:text-amber-300">
                    Issue short-lived alias tokens per workload (CI, agent,
                    plugin, browser) so your real API key never leaves your
                    server. Each alias is independently rotatable and revocable
                    without rotating your primary key.
                  </p>
                </div>
              </div>
            </div>

            {aliasError && (
              <div className="mb-4 rounded-lg border border-red-200 bg-red-50 p-4 text-sm text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400">
                {aliasError}
                <button
                  onClick={() => setAliasError(null)}
                  className="ml-2 underline"
                >
                  Dismiss
                </button>
              </div>
            )}

            {/* Create Alias Form */}
            {showCreateAlias && (
              <div className="mb-6 rounded-2xl border border-primary-200 bg-white p-6 shadow-sm dark:border-primary-800 dark:bg-neutral-900">
                <h2 className="mb-4 text-lg font-semibold text-neutral-900 dark:text-white">
                  New Credential Alias
                </h2>
                <div className="grid gap-4 sm:grid-cols-3">
                  <div>
                    <label className="mb-1 block text-sm font-medium text-neutral-700 dark:text-neutral-300">
                      Project
                    </label>
                    <select
                      value={newAliasProjectId}
                      onChange={e => setNewAliasProjectId(e.target.value)}
                      className="w-full rounded-lg border border-neutral-300 bg-white px-3 py-2.5 text-sm text-neutral-900 dark:border-neutral-700 dark:bg-neutral-800 dark:text-white"
                    >
                      <option value="">Select project…</option>
                      {credentials
                        .filter(c => c.status === 'active')
                        .map(c => (
                          <option key={c.projectId} value={c.projectId}>
                            {c.projectName}
                          </option>
                        ))}
                    </select>
                  </div>
                  <div>
                    <label className="mb-1 block text-sm font-medium text-neutral-700 dark:text-neutral-300">
                      Label
                    </label>
                    <input
                      type="text"
                      value={newAliasLabel}
                      onChange={e => setNewAliasLabel(e.target.value)}
                      placeholder="e.g. github-actions-deploy"
                      className="w-full rounded-lg border border-neutral-300 bg-white px-3 py-2.5 text-sm text-neutral-900 dark:border-neutral-700 dark:bg-neutral-800 dark:text-white"
                    />
                  </div>
                  <div>
                    <label className="mb-1 block text-sm font-medium text-neutral-700 dark:text-neutral-300">
                      Workload Type
                    </label>
                    <select
                      value={newAliasWorkload}
                      onChange={e =>
                        setNewAliasWorkload(e.target.value as AliasWorkload)
                      }
                      className="w-full rounded-lg border border-neutral-300 bg-white px-3 py-2.5 text-sm text-neutral-900 dark:border-neutral-700 dark:bg-neutral-800 dark:text-white"
                    >
                      {(
                        [
                          'ci',
                          'agent',
                          'plugin',
                          'browser',
                          'server',
                          'custom',
                        ] as AliasWorkload[]
                      ).map(w => (
                        <option key={w} value={w}>
                          {w.toUpperCase()}
                        </option>
                      ))}
                    </select>
                  </div>
                </div>
                <div className="mt-4 flex justify-end gap-3">
                  <button
                    onClick={() => {
                      setShowCreateAlias(false);
                      setAliasError(null);
                    }}
                    className="rounded-lg border border-neutral-300 px-4 py-2 text-sm font-medium text-neutral-700 hover:bg-neutral-50 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={handleCreateAlias}
                    disabled={
                      !newAliasProjectId ||
                      !newAliasLabel.trim() ||
                      creatingAlias
                    }
                    className="rounded-lg bg-primary-600 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-primary-700 disabled:cursor-not-allowed disabled:opacity-50"
                  >
                    {creatingAlias ? 'Creating…' : 'Create Alias'}
                  </button>
                </div>
              </div>
            )}

            {aliasLoading ? (
              <div className="py-12 text-center text-neutral-500 dark:text-neutral-400">
                Loading aliases…
              </div>
            ) : aliases.length === 0 ? (
              <div className="rounded-2xl border-2 border-dashed border-neutral-300 bg-white p-12 text-center dark:border-neutral-700 dark:bg-neutral-900">
                <div className="mb-4 text-5xl" aria-hidden="true">
                  🎭
                </div>
                <h2 className="mb-2 text-xl font-semibold text-neutral-900 dark:text-white">
                  No Aliases Yet
                </h2>
                <p className="mx-auto mb-6 max-w-md text-neutral-500 dark:text-neutral-400">
                  Create your first alias token to issue short-lived,
                  workload-scoped credentials without exposing your primary API
                  key.
                </p>
                {credentials.length === 0 && (
                  <p className="text-sm text-amber-600 dark:text-amber-400">
                    ⚠️ Create an SDK project first before issuing aliases.
                  </p>
                )}
              </div>
            ) : (
              <div className="overflow-hidden rounded-2xl border border-neutral-200 bg-white dark:border-neutral-800 dark:bg-neutral-900">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-neutral-100 bg-neutral-50 dark:border-neutral-800 dark:bg-neutral-800/50">
                      <th className="px-4 py-3 text-left font-medium text-neutral-700 dark:text-neutral-300">
                        Label
                      </th>
                      <th className="px-4 py-3 text-left font-medium text-neutral-700 dark:text-neutral-300">
                        Project
                      </th>
                      <th className="px-4 py-3 text-left font-medium text-neutral-700 dark:text-neutral-300">
                        Workload
                      </th>
                      <th className="px-4 py-3 text-left font-medium text-neutral-700 dark:text-neutral-300">
                        Status
                      </th>
                      <th className="px-4 py-3 text-left font-medium text-neutral-700 dark:text-neutral-300">
                        Rotations
                      </th>
                      <th className="px-4 py-3 text-left font-medium text-neutral-700 dark:text-neutral-300">
                        Expires
                      </th>
                      <th className="px-4 py-3 text-right font-medium text-neutral-700 dark:text-neutral-300">
                        Actions
                      </th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-neutral-100 dark:divide-neutral-800">
                    {aliases.map(alias => (
                      <tr
                        key={alias.id}
                        className="hover:bg-neutral-50 dark:hover:bg-neutral-800/40"
                      >
                        <td className="px-4 py-3">
                          <div className="font-medium text-neutral-900 dark:text-white">
                            {alias.label}
                          </div>
                          <div className="font-mono text-xs text-neutral-500 dark:text-neutral-500">
                            {alias.aliasToken?.slice(0, 16)}…
                          </div>
                        </td>
                        <td className="px-4 py-3 text-neutral-600 dark:text-neutral-400">
                          {alias.projectName}
                        </td>
                        <td className="px-4 py-3">
                          <span className="rounded-full bg-neutral-100 px-2 py-0.5 text-xs font-medium uppercase text-neutral-600 dark:bg-neutral-800 dark:text-neutral-400">
                            {alias.workload}
                          </span>
                        </td>
                        <td className="px-4 py-3">
                          <span
                            className={`rounded-full px-2 py-0.5 text-xs font-semibold ${
                              alias.status === 'active'
                                ? 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400'
                                : alias.status === 'rotated'
                                  ? 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400'
                                  : 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400'
                            }`}
                          >
                            {alias.status}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-neutral-600 dark:text-neutral-400">
                          {alias.rotationCount ?? 0}×
                        </td>
                        <td className="px-4 py-3 text-neutral-600 dark:text-neutral-400">
                          {alias.expiresAt
                            ? new Date(alias.expiresAt).toLocaleDateString()
                            : '∞ Never'}
                        </td>
                        <td className="px-4 py-3 text-right">
                          <div className="flex items-center justify-end gap-2">
                            {alias.status === 'active' && (
                              <>
                                <button
                                  onClick={() =>
                                    handleRotateAlias(alias.projectId, alias.id)
                                  }
                                  className="rounded px-2 py-1 text-xs font-medium text-blue-600 hover:bg-blue-50 dark:text-blue-400 dark:hover:bg-blue-950"
                                  title="Rotate alias token"
                                >
                                  🔄 Rotate
                                </button>
                                <button
                                  onClick={() =>
                                    setRevokeModal({
                                      projectId: alias.projectId,
                                      aliasId: alias.id,
                                      label: alias.label,
                                    })
                                  }
                                  className="rounded px-2 py-1 text-xs font-medium text-red-600 hover:bg-red-50 dark:text-red-400 dark:hover:bg-red-950"
                                  title="Revoke alias"
                                >
                                  🚫 Revoke
                                </button>
                              </>
                            )}
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            <div className="mt-8 flex flex-wrap gap-4">
              <Link
                href="/dashboard/projects"
                className="inline-flex items-center text-sm text-primary-600 hover:text-primary-700 dark:text-primary-400 dark:hover:text-primary-300"
              >
                📁 Manage projects →
              </Link>
              <a
                href="https://devfortress.net/docs/credential-aliasing"
                className="inline-flex items-center text-sm text-primary-600 hover:text-primary-700 dark:text-primary-400 dark:hover:text-primary-300"
              >
                📖 A19 aliasing docs →
              </a>
            </div>
          </div>
        )}
      </div>

      {/* ── VIEW-ONCE ALIAS KEY MODAL ── */}
      {viewOnceKey && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="w-full max-w-lg rounded-2xl border border-amber-400 bg-neutral-900 p-6 shadow-2xl">
            <div className="mb-4 flex items-center gap-3">
              <span className="text-3xl">🔐</span>
              <div>
                <h2 className="text-lg font-bold text-white">
                  Alias Key — View Once
                </h2>
                <p className="text-sm text-amber-400 font-medium">
                  {viewOnceKey.label}
                </p>
              </div>
            </div>
            <div className="mb-4 rounded-lg border border-red-500/50 bg-red-950/30 p-3 text-sm text-red-300">
              ⚠️ <strong>This key will never be shown again.</strong> Copy it
              now and store it securely (e.g. your CI/CD secrets vault or
              password manager). DevFortress only stores a hash — not the raw
              key.
            </div>
            <div className="mb-4 flex items-center gap-2">
              <code className="flex-1 overflow-x-auto rounded-lg bg-neutral-800 px-3 py-2 font-mono text-sm text-green-400 select-all whitespace-nowrap">
                {viewOnceKey.aliasKey}
              </code>
              <button
                onClick={async () => {
                  await navigator.clipboard.writeText(viewOnceKey.aliasKey);
                  setViewOnceCopied(true);
                }}
                className={`rounded-lg px-3 py-2 text-sm font-medium transition-colors ${viewOnceCopied ? 'bg-green-600 text-white' : 'bg-amber-500 text-black hover:bg-amber-400'}`}
              >
                {viewOnceCopied ? '✅ Copied!' : '📋 Copy'}
              </button>
            </div>
            <p className="mb-4 text-xs text-neutral-500">
              Alias ID:{' '}
              <code className="text-neutral-400">{viewOnceKey.aliasId}</code>
            </p>
            <button
              onClick={() => {
                setViewOnceKey(null);
                setViewOnceCopied(false);
              }}
              disabled={!viewOnceCopied}
              className="w-full rounded-lg bg-neutral-700 py-2.5 text-sm font-medium text-white transition-colors hover:bg-neutral-600 disabled:cursor-not-allowed disabled:opacity-40"
            >
              {viewOnceCopied
                ? 'I have saved my key — Close'
                : 'Copy the key first to continue'}
            </button>
          </div>
        </div>
      )}

      {/* ── REVOKE CONFIRMATION MODAL ── */}
      {revokeModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="w-full max-w-md rounded-2xl border border-red-500/30 bg-white p-6 shadow-2xl dark:bg-neutral-900">
            <h2 className="mb-2 text-lg font-bold text-neutral-900 dark:text-white">
              Revoke Credential Alias?
            </h2>
            <p className="mb-4 text-sm text-neutral-500 dark:text-neutral-400">
              Are you sure you want to revoke{' '}
              <strong>{revokeModal.label}</strong>? This action is immediate and
              permanent.
            </p>

            <div className="mb-6 rounded-lg border border-neutral-100 bg-neutral-50 p-4 dark:border-neutral-800 dark:bg-neutral-950">
              <label className="flex cursor-pointer items-start gap-3">
                <input
                  type="checkbox"
                  checked={isRevokingFamily}
                  onChange={e => setIsRevokingFamily(e.target.checked)}
                  className="mt-1 h-4 w-4 rounded border-neutral-300 text-primary-600 focus:ring-primary-500"
                />
                <div>
                  <span className="text-sm font-semibold text-neutral-900 dark:text-white">
                    Revoke all aliases in this family
                  </span>
                  <p className="text-xs text-neutral-500 dark:text-neutral-400">
                    Emergency revocation for all{' '}
                    {
                      aliases.filter(a => a.projectId === revokeModal.projectId)
                        .length
                    }{' '}
                    aliases tied to this project&apos;s real API key.
                  </p>
                </div>
              </label>
            </div>

            <div className="flex gap-3">
              <button
                onClick={() => {
                  setRevokeModal(null);
                  setIsRevokingFamily(false);
                }}
                className="flex-1 rounded-lg border border-neutral-300 py-2 text-sm font-medium text-neutral-700 hover:bg-neutral-50 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
              >
                Cancel
              </button>
              <button
                onClick={() =>
                  handleRevokeAlias(
                    revokeModal.projectId,
                    revokeModal.aliasId,
                    isRevokingFamily
                  )
                }
                className="flex-1 rounded-lg bg-red-600 py-2 text-sm font-medium text-white transition-colors hover:bg-red-700"
              >
                Confirm Revocation
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
