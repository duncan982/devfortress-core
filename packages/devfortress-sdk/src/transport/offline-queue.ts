/**
 * S38 — Offline Queue with Exponential Backoff
 *
 * Queues events when network is unavailable and retries with exponential backoff.
 * Drops events after 5 failed attempts to prevent unbounded memory growth.
 * Suitable for 2G/3G connections with intermittent connectivity.
 *
 * Author: Duncan Ndungu Ndegwa
 */

type SendFn = (events: object[]) => Promise<boolean>;

interface QueueEntry {
  payload: object;
  attempts: number;
  nextRetryAt: number;
}

export class OfflineQueue {
  private queue: QueueEntry[] = [];
  private processing = false;
  private readonly maxAttempts = 5;
  private readonly baseDelayMs = 1000;

  enqueue(payload: object): void {
    this.queue.push({ payload, attempts: 0, nextRetryAt: Date.now() });
    this.scheduleFlush();
  }

  private scheduleFlush(): void {
    if (this.processing) return;
    setTimeout(() => {
      void this.flush();
    }, 100);
  }

  async flush(sendFn?: SendFn): Promise<void> {
    if (!sendFn || this.processing || this.queue.length === 0) return;
    this.processing = true;
    const now = Date.now();
    const ready = this.queue.filter(e => e.nextRetryAt <= now);

    for (const entry of ready) {
      const success = await sendFn([entry.payload]);
      if (success) {
        this.queue = this.queue.filter(e => e !== entry);
      } else {
        entry.attempts++;
        if (entry.attempts >= this.maxAttempts) {
          this.queue = this.queue.filter(e => e !== entry);
          console.warn('[OfflineQueue] Max retries exceeded, dropping event');
        } else {
          // Exponential backoff: 1s, 2s, 4s, 8s, 16s (capped at 60s)
          const delay = Math.min(
            this.baseDelayMs * Math.pow(2, entry.attempts),
            60000
          );
          entry.nextRetryAt = Date.now() + delay;
        }
      }
    }
    this.processing = false;
  }

  get size(): number {
    return this.queue.length;
  }

  clear(): void {
    this.queue = [];
  }
}
