/**
 * SDK Credentials Management Page (open-core)
 * Create projects and manage SDK credentials for applications, APIs, and agents.
 *
 * MVP Focus: Collect Phase — SDK Surveillance
 * Connects to /api/sdk/credentials for real credential management.
 */

'use client';

import { useState, useCallback, useEffect, Fragment } from 'react';
import Link from 'next/link';

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
curl -X POST https://your-platform/api/events/ingest \\
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
    visible ? key : key.slice(0, 10) + '•'.repeat(20) + key.slice(-4);

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
        {/* Breadcrumb */}
        <nav className="mb-4 flex items-center gap-2 text-sm text-neutral-500">
          <Link
            href="/dashboard"
            className="hover:text-neutral-700 dark:hover:text-neutral-300"
          >
            Dashboard
          </Link>
          <span>/</span>
          <span className="text-neutral-900 dark:text-white">
            SDK Credentials
          </span>
        </nav>

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
        </div>

        {error && (
          <div className="mb-6 rounded-lg border border-red-200 bg-red-50 p-4 text-sm text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400">
            {error}
            <button onClick={() => setError(null)} className="ml-2 underline">
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
              Create your first project to get a <strong>Project ID</strong>,{' '}
              <strong>API Key</strong>, and <strong>Webhook Secret</strong>. The
              SDK starts collecting security events immediately after
              integration.
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
                          {cred.status === 'active' ? '● Active' : '✗ Revoked'}
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
                                ? '✅'
                                : '📋'}
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
                              {isKeyVisible ? '🙈' : '👁️'}
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
                                ? '✅'
                                : '📋'}
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
                                ? '✅'
                                : '📋'}
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
                              ? '✅ Copied .env variables!'
                              : '📋 Copy as .env variables'}
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
                credentials (Project ID, API Key, Webhook Secret) are included.
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
                    ? '✅ Copied'
                    : '📋 Copy'}
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
      </div>
    </div>
  );
}
