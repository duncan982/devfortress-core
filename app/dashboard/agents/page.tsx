import Link from 'next/link';

export default function AgentsPage() {
  return (
    <div className="flex flex-1 flex-col items-center justify-center p-8 text-center">
      <div className="max-w-md">
        <div className="mb-4 text-5xl">🤖</div>
        <h1 className="mb-2 text-2xl font-bold text-neutral-900 dark:text-white">
          Agent Analytics
        </h1>
        <p className="mb-2 text-neutral-600 dark:text-neutral-400">
          Per-agent event filtering, behavioral baselines, and anomaly detection
          are available on the DevFortress hosted platform.
        </p>
        <p className="mb-6 text-sm text-neutral-500 dark:text-neutral-500">
          Self-hosted open-core includes agent event collection via the SDK —
          upgrade for advanced per-agent analytics and threat scoring.
        </p>
        <Link
          href="https://devfortress.net/pricing?ref=open-core-agents"
          target="_blank"
          rel="noopener noreferrer"
          className="inline-flex items-center gap-2 rounded-lg bg-primary-600 px-6 py-2.5 text-sm font-semibold text-white transition-colors hover:bg-primary-700"
        >
          View Plans →
        </Link>
      </div>
    </div>
  );
}
