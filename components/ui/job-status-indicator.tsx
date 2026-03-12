/**
 * Job Status Indicator — Header navigation badge
 * Shows pending/processing job count with a link to the consulting dashboard.
 * Polls /api/consulting/jobs when there are active jobs.
 */

'use client';

import { useState, useEffect, useCallback, useRef } from 'react';
import Link from 'next/link';

interface JobStatusSummary {
  pending: number;
  processing: number;
}

const POLL_INTERVAL_ACTIVE = 10_000; // 10 seconds when jobs are active
const POLL_INTERVAL_IDLE = 60_000; // 60 seconds when idle

export function JobStatusIndicator() {
  const [summary, setSummary] = useState<JobStatusSummary>({
    pending: 0,
    processing: 0,
  });
  const [isVisible, setIsVisible] = useState(false);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const mountedRef = useRef(false);

  const fetchJobStatus = useCallback(async () => {
    try {
      const [pendingRes, processingRes] = await Promise.all([
        fetch('/api/consulting/jobs?status=PENDING&limit=1'),
        fetch('/api/consulting/jobs?status=PROCESSING&limit=1'),
      ]);

      if (!pendingRes.ok || !processingRes.ok) return;

      const pendingData = await pendingRes.json();
      const processingData = await processingRes.json();

      const pending = pendingData.total ?? pendingData.jobs?.length ?? 0;
      const processing =
        processingData.total ?? processingData.jobs?.length ?? 0;

      setSummary({ pending, processing });
      setIsVisible(pending > 0 || processing > 0);
    } catch {
      // Silently fail — job status is not critical
    }
  }, []);

  // Initial fetch on mount
  useEffect(() => {
    if (!mountedRef.current) {
      mountedRef.current = true;
      // Defer initial fetch to avoid synchronous setState in effect
      const id = setTimeout(() => fetchJobStatus(), 0);
      return () => clearTimeout(id);
    }
  }, [fetchJobStatus]);

  // Polling loop
  useEffect(() => {
    const interval =
      summary.pending > 0 || summary.processing > 0
        ? POLL_INTERVAL_ACTIVE
        : POLL_INTERVAL_IDLE;

    timerRef.current = setTimeout(() => {
      fetchJobStatus();
    }, interval);

    return () => {
      if (timerRef.current) clearTimeout(timerRef.current);
    };
  }, [fetchJobStatus, summary.pending, summary.processing]);

  if (!isVisible) return null;

  const total = summary.pending + summary.processing;
  const isProcessing = summary.processing > 0;

  return (
    <Link
      href="/build/jobs"
      className="relative inline-flex items-center gap-1.5 rounded-lg border border-amber-200 bg-amber-50 px-2.5 py-1.5 text-xs font-medium text-amber-800 transition-colors hover:bg-amber-100 dark:border-amber-800 dark:bg-amber-950/50 dark:text-amber-300 dark:hover:bg-amber-900/50"
      title={`${summary.pending} pending, ${summary.processing} processing`}
    >
      {isProcessing ? (
        <span className="relative flex h-2.5 w-2.5">
          <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-amber-400 opacity-75" />
          <span className="relative inline-flex h-2.5 w-2.5 rounded-full bg-amber-500" />
        </span>
      ) : (
        <span className="inline-flex h-2.5 w-2.5 rounded-full bg-amber-400" />
      )}
      <span>
        {total} {total === 1 ? 'Job' : 'Jobs'}
      </span>
    </Link>
  );
}
