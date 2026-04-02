/**
 * Consulting Job Queue Service
 *
 * PostgreSQL-backed job queue for long-running consulting and batch operations.
 * Uses SELECT ... FOR UPDATE SKIP LOCKED for reliable concurrent job processing
 * without requiring Redis/Bull/external queue infrastructure.
 *
 * Supports: AUDIT, URL_SCAN, BATCH_BUILD, BATCH_ANALYZE, HONEYPOT_DEPLOY
 */

import { prisma } from '@core/lib/prisma';
import { logInfo, logError, logWarn } from '@core/lib/logger';
import { createNotification } from '@core/lib/notifications-server';
import { Prisma } from '@prisma/client';
import type {
  ConsultingJobType,
  ConsultingJobStatus,
  ConsultingJob,
} from '@prisma/client';

// ============================================================
// Types
// ============================================================

export interface EnqueueJobInput {
  type: ConsultingJobType;
  input: Record<string, unknown>;
  userId: string;
  clientId?: string;
  priority?: number;
}

export interface JobStatusResponse {
  id: string;
  type: ConsultingJobType;
  status: ConsultingJobStatus;
  progress: number;
  output: unknown;
  error: string | null;
  createdAt: Date;
  startedAt: Date | null;
  completedAt: Date | null;
}

export interface ProcessableJob {
  id: string;
  type: ConsultingJobType;
  input: unknown;
  userId: string;
  clientId: string | null;
}

export interface JobNotifyOptions {
  userId: string;
  jobType: ConsultingJobType;
}

const JOB_TYPE_LABELS: Record<ConsultingJobType, string> = {
  AUDIT: 'Security Audit',
  URL_SCAN: 'URL Scan',
  BATCH_BUILD: 'Batch API Build',
  BATCH_ANALYZE: 'Batch Code Analysis',
  HONEYPOT_DEPLOY: 'Honeypot Deployment',
};

// ============================================================
// On-demand job processing trigger
// ============================================================

/**
 * Fire-and-forget trigger of the process-jobs endpoint.
 * On Vercel Hobby plan, cron jobs run only once daily, so we trigger
 * the job processor immediately after enqueuing to ensure prompt execution.
 * Falls back silently if the trigger fails (daily cron acts as safety net).
 *
 * Fires an immediate trigger + follow-up triggers at 10s and 30s
 * to ensure the queue drains even under cold start conditions.
 */
async function triggerJobProcessing(): Promise<void> {
  try {
    // Prefer deployment-scoped VERCEL_URL first to avoid preview jobs being
    // triggered against production APP_URL.
    const baseUrl = process.env.VERCEL_URL || process.env.NEXT_PUBLIC_APP_URL;
    if (!baseUrl) {
      logWarn('No base URL configured — skipping on-demand job trigger');
      return;
    }

    const url = baseUrl.startsWith('http')
      ? `${baseUrl}/api/cron/process-jobs`
      : `https://${baseUrl}/api/cron/process-jobs`;

    const cronSecret = process.env.CRON_SECRET?.trim().replace(/\\n$/, '');

    // Use a shorter timeout (15s) to avoid blocking the calling function
    const doTrigger = () =>
      fetch(url, {
        method: 'GET',
        headers: {
          ...(cronSecret ? { Authorization: `Bearer ${cronSecret}` } : {}),
        },
        signal: AbortSignal.timeout(15000),
      });

    // Single immediate trigger — setTimeout calls do NOT survive in serverless.
    // The cron worker itself handles auto-draining via self-trigger at the end.
    doTrigger().catch(err => {
      logWarn('On-demand job trigger failed — daily cron will pick up', {
        error: err instanceof Error ? err.message : String(err),
      });
    });
  } catch {
    // Non-critical — daily cron will pick up any missed jobs
  }
}

// ============================================================
// Enqueue
// ============================================================

/**
 * Add a new job to the queue.
 * Returns the created job record.
 */
export async function enqueueJob(
  params: EnqueueJobInput
): Promise<ConsultingJob> {
  const job = await prisma.consultingJob.create({
    data: {
      type: params.type,
      status: 'PENDING',
      input: params.input as Prisma.InputJsonValue,
      userId: params.userId,
      clientId: params.clientId ?? null,
      priority: params.priority ?? 0,
      progress: 0,
    },
  });

  logInfo('Job enqueued', {
    jobId: job.id,
    type: params.type,
    userId: params.userId,
  });

  // Trigger immediate processing (fire-and-forget)
  // On Hobby plan, cron runs daily; this ensures near-instant job execution
  triggerJobProcessing();

  return job;
}

// ============================================================
// Dequeue — claim the next available job
// ============================================================

/**
 * Atomically claim the next PENDING job using FOR UPDATE SKIP LOCKED.
 * Wrapped in $transaction for PgBouncer compatibility (Supabase pooler).
 * Returns null if no jobs are available.
 */
export async function dequeueNextJob(): Promise<ProcessableJob | null> {
  // Use $transaction to ensure FOR UPDATE SKIP LOCKED works through PgBouncer
  const jobs = await prisma.$transaction(async tx => {
    return tx.$queryRaw<ProcessableJob[]>`
      UPDATE "ConsultingJob"
      SET status = 'PROCESSING'::"ConsultingJobStatus",
          "startedAt" = NOW(),
          "updatedAt" = NOW()
      WHERE id = (
        SELECT id FROM "ConsultingJob"
        WHERE status = 'PENDING'::"ConsultingJobStatus"
        ORDER BY priority DESC, "createdAt" ASC
        LIMIT 1
        FOR UPDATE SKIP LOCKED
      )
      RETURNING id, type, input, "userId", "clientId"
    `;
  });

  if (jobs.length === 0) {
    return null;
  }

  const job = jobs[0];
  logInfo('Job dequeued for processing', { jobId: job.id, type: job.type });
  return job;
}

// ============================================================
// Progress & Status Updates
// ============================================================

/**
 * Update job progress (0-100).
 */
export async function updateJobProgress(
  jobId: string,
  progress: number
): Promise<void> {
  await prisma.consultingJob.update({
    where: { id: jobId },
    data: {
      progress: Math.min(100, Math.max(0, progress)),
    },
  });
}

export async function completeJob(
  jobId: string,
  output: Record<string, unknown>,
  notify?: JobNotifyOptions
): Promise<void> {
  await prisma.consultingJob.update({
    where: { id: jobId },
    data: {
      status: 'COMPLETED',
      progress: 100,
      output: output as Prisma.InputJsonValue,
      completedAt: new Date(),
    },
  });

  logInfo('Job completed', { jobId });

  if (notify) {
    const label = JOB_TYPE_LABELS[notify.jobType] ?? notify.jobType;
    try {
      await createNotification(
        notify.userId,
        'SYSTEM',
        `${label} Complete`,
        `Your ${label.toLowerCase()} job has finished successfully.`,
        { jobId, jobType: notify.jobType, status: 'COMPLETED' }
      );
    } catch (err) {
      logError('Failed to send job completion notification', {
        jobId,
        userId: notify.userId,
        error: err,
      });
    }
  }
}

export async function failJob(
  jobId: string,
  error: string,
  notify?: JobNotifyOptions
): Promise<void> {
  await prisma.consultingJob.update({
    where: { id: jobId },
    data: {
      status: 'FAILED',
      error,
      completedAt: new Date(),
    },
  });

  logError('Job failed', { jobId, error });

  if (notify) {
    const label = JOB_TYPE_LABELS[notify.jobType] ?? notify.jobType;
    try {
      await createNotification(
        notify.userId,
        'SYSTEM',
        `${label} Failed`,
        `Your ${label.toLowerCase()} job encountered an error: ${error}`,
        { jobId, jobType: notify.jobType, status: 'FAILED', error }
      );
    } catch (err) {
      logError('Failed to send job failure notification', {
        jobId,
        userId: notify.userId,
        error: err,
      });
    }
  }
}

/**
 * Cancel a pending or processing job.
 * PENDING jobs are cancelled immediately.
 * PROCESSING jobs are marked as CANCELLED (the handler should check for this).
 */
export async function cancelJob(jobId: string): Promise<boolean> {
  const result = await prisma.consultingJob.updateMany({
    where: {
      id: jobId,
      status: { in: ['PENDING', 'PROCESSING'] },
    },
    data: {
      status: 'CANCELLED',
      completedAt: new Date(),
      error: 'Cancelled by user',
    },
  });

  if (result.count > 0) {
    logInfo('Job cancelled', { jobId });
    return true;
  }

  logWarn('Cannot cancel job — not in PENDING or PROCESSING state', { jobId });
  return false;
}

// ============================================================
// Queries
// ============================================================

/**
 * Get the status of a specific job.
 */
export async function getJobStatus(
  jobId: string
): Promise<JobStatusResponse | null> {
  const job = await prisma.consultingJob.findUnique({
    where: { id: jobId },
    select: {
      id: true,
      type: true,
      status: true,
      progress: true,
      output: true,
      error: true,
      createdAt: true,
      startedAt: true,
      completedAt: true,
    },
  });

  return job;
}

/**
 * List jobs for a user, optionally filtered by status and/or type.
 */
export async function getJobsByUser(
  userId: string,
  filters?: {
    status?: ConsultingJobStatus;
    type?: ConsultingJobType;
    limit?: number;
    offset?: number;
  }
): Promise<{ jobs: ConsultingJob[]; total: number }> {
  const where = {
    userId,
    ...(filters?.status && { status: filters.status }),
    ...(filters?.type && { type: filters.type }),
  };

  const [jobs, total] = await Promise.all([
    prisma.consultingJob.findMany({
      where,
      orderBy: { createdAt: 'desc' },
      take: filters?.limit ?? 20,
      skip: filters?.offset ?? 0,
      include: {
        client: {
          select: { id: true, name: true, company: true },
        },
        auditReport: {
          select: { id: true, status: true, overallScore: true, pdfUrl: true },
        },
      },
    }),
    prisma.consultingJob.count({ where }),
  ]);

  return { jobs, total };
}

/**
 * Count pending jobs (useful for dashboard display).
 */
export async function countPendingJobs(): Promise<number> {
  return prisma.consultingJob.count({
    where: { status: 'PENDING' },
  });
}

/**
 * Clean up stale PROCESSING jobs that have been running longer than the timeout.
 * Marks them as FAILED so they can be retried or investigated.
 */
export async function cleanupStaleJobs(
  timeoutMinutes: number = 30
): Promise<number> {
  const cutoff = new Date(Date.now() - timeoutMinutes * 60 * 1000);

  const result = await prisma.consultingJob.updateMany({
    where: {
      status: 'PROCESSING',
      startedAt: {
        lt: cutoff,
      },
    },
    data: {
      status: 'FAILED',
      error: `Job timed out after ${timeoutMinutes} minutes`,
      completedAt: new Date(),
    },
  });

  if (result.count > 0) {
    logWarn('Cleaned up stale jobs', { count: result.count, timeoutMinutes });
  }

  return result.count;
}
