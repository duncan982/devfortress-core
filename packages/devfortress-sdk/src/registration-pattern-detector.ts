/**
 * DevFortress SDK — A8: Registration Pattern Detector
 *
 * Detects mass registration campaigns, bot armies, and credential
 * stuffing setup by analyzing registration metadata patterns.
 *
 * Signals: timing patterns, email domain clustering, IP velocity,
 * user-agent consistency, honeypot correlation.
 *
 * Patent Pending.
 * @packageDocumentation
 */

export interface RegistrationDetectorConfig {
  /** Max registrations per IP per window. Default: 3 */
  maxPerIP?: number;
  /** Max registrations per email domain per window. Default: 10 */
  maxPerDomain?: number;
  /** Sliding window in ms. Default: 3_600_000 (1 hour) */
  windowMs?: number;
  /** Max tracked entries. Default: 100_000 */
  maxEntries?: number;
  /** Disposable email domain list. */
  disposableDomains?: Set<string>;
  debug?: boolean;
}

export interface RegistrationEvent {
  ip: string;
  email: string;
  userAgent?: string;
  timestamp?: number;
  /** Whether a honeypot field was filled */
  honeypotTriggered?: boolean;
  /** Time from page load to form submit (ms) */
  formFillDurationMs?: number;
}

export interface RegistrationResult {
  allowed: boolean;
  riskScore: number;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  action: 'allow' | 'captcha' | 'delay' | 'block';
  signals: string[];
  reason: string;
}

// Common disposable email domains
const DEFAULT_DISPOSABLE_DOMAINS = new Set([
  'mailinator.com',
  'guerrillamail.com',
  'tempmail.com',
  'throwaway.email',
  'yopmail.com',
  '10minutemail.com',
  'trashmail.com',
  'dispostable.com',
  'sharklasers.com',
  'guerrillamailblock.com',
  'grr.la',
  'temp-mail.org',
  'fakeinbox.com',
  'getnada.com',
  'maildrop.cc',
  'inboxbear.com',
]);

interface IPRecord {
  registrations: number[];
  emails: Set<string>;
  userAgents: Set<string>;
}

interface DomainRecord {
  registrations: number[];
  ips: Set<string>;
}

export class RegistrationPatternDetector {
  private readonly config: Required<RegistrationDetectorConfig>;
  private readonly ipRecords = new Map<string, IPRecord>();
  private readonly domainRecords = new Map<string, DomainRecord>();
  private cleanupTimer: ReturnType<typeof setInterval> | null = null;

  constructor(config: RegistrationDetectorConfig = {}) {
    this.config = {
      maxPerIP: config.maxPerIP ?? 3,
      maxPerDomain: config.maxPerDomain ?? 10,
      windowMs: config.windowMs ?? 3_600_000,
      maxEntries: config.maxEntries ?? 100_000,
      disposableDomains: config.disposableDomains ?? DEFAULT_DISPOSABLE_DOMAINS,
      debug: config.debug ?? false,
    };

    this.cleanupTimer = setInterval(
      () => this.cleanup(),
      this.config.windowMs / 2
    );
    if (this.cleanupTimer.unref) this.cleanupTimer.unref();
  }

  evaluate(event: RegistrationEvent): RegistrationResult {
    const now = event.timestamp ?? Date.now();
    const { ip, email, userAgent, honeypotTriggered, formFillDurationMs } =
      event;
    const signals: string[] = [];
    let riskScore = 0;

    // Extract email domain
    const emailDomain = email.split('@')[1]?.toLowerCase() ?? '';

    // ── IP velocity check ──
    let ipRec = this.ipRecords.get(ip);
    if (!ipRec) {
      ipRec = { registrations: [], emails: new Set(), userAgents: new Set() };
      this.ipRecords.set(ip, ipRec);
    }
    ipRec.registrations = ipRec.registrations.filter(
      t => now - t <= this.config.windowMs
    );
    ipRec.registrations.push(now);
    ipRec.emails.add(email);
    if (userAgent) ipRec.userAgents.add(userAgent);

    if (ipRec.registrations.length > this.config.maxPerIP) {
      riskScore += 30;
      signals.push(
        `IP velocity: ${ipRec.registrations.length} registrations from ${ip}`
      );
    }

    // ── Domain velocity check ──
    let domainRec = this.domainRecords.get(emailDomain);
    if (!domainRec) {
      domainRec = { registrations: [], ips: new Set() };
      this.domainRecords.set(emailDomain, domainRec);
    }
    domainRec.registrations = domainRec.registrations.filter(
      t => now - t <= this.config.windowMs
    );
    domainRec.registrations.push(now);
    domainRec.ips.add(ip);

    if (domainRec.registrations.length > this.config.maxPerDomain) {
      riskScore += 20;
      signals.push(
        `Domain velocity: ${domainRec.registrations.length} registrations for @${emailDomain}`
      );
    }

    // ── Disposable email check ──
    if (this.config.disposableDomains.has(emailDomain)) {
      riskScore += 25;
      signals.push(`Disposable email domain: @${emailDomain}`);
    }

    // ── Honeypot trigger ──
    if (honeypotTriggered) {
      riskScore += 40;
      signals.push('Honeypot field filled (bot indicator)');
    }

    // ── Form fill speed (bot detection) ──
    if (formFillDurationMs !== undefined) {
      if (formFillDurationMs < 2000) {
        riskScore += 30;
        signals.push(`Suspiciously fast form fill: ${formFillDurationMs}ms`);
      } else if (formFillDurationMs < 5000) {
        riskScore += 10;
        signals.push(`Fast form fill: ${formFillDurationMs}ms`);
      }
    }

    // ── Same UA for all registrations from IP ──
    if (ipRec.registrations.length > 2 && ipRec.userAgents.size === 1) {
      riskScore += 10;
      signals.push('Identical user-agent across multiple registrations');
    }

    // ── Email pattern: sequential or generated ──
    if (
      /^[a-z]+\d{3,}@/.test(email) ||
      /^(test|user|admin|bot)\d+@/.test(email)
    ) {
      riskScore += 15;
      signals.push('Email matches generated/sequential pattern');
    }

    // Cap and determine result
    riskScore = Math.min(100, riskScore);

    let severity: RegistrationResult['severity'];
    let action: RegistrationResult['action'];
    let allowed = true;

    if (riskScore >= 70) {
      severity = 'CRITICAL';
      action = 'block';
      allowed = false;
    } else if (riskScore >= 50) {
      severity = 'HIGH';
      action = 'captcha';
      allowed = true;
    } else if (riskScore >= 25) {
      severity = 'MEDIUM';
      action = 'delay';
      allowed = true;
    } else {
      severity = 'LOW';
      action = 'allow';
      allowed = true;
    }

    // Enforce max entries with LRU eviction
    if (this.ipRecords.size > this.config.maxEntries) {
      const first = this.ipRecords.keys().next().value;
      if (first !== undefined) this.ipRecords.delete(first);
    }

    const reason =
      signals.length > 0
        ? `Registration risk (score=${riskScore}): ${signals.join('; ')}`
        : `Registration allowed (score=${riskScore})`;

    return { allowed, riskScore, severity, action, signals, reason };
  }

  getStats(): { trackedIPs: number; trackedDomains: number } {
    return {
      trackedIPs: this.ipRecords.size,
      trackedDomains: this.domainRecords.size,
    };
  }

  private cleanup(): void {
    const now = Date.now();
    for (const [key, rec] of this.ipRecords) {
      rec.registrations = rec.registrations.filter(
        t => now - t <= this.config.windowMs
      );
      if (rec.registrations.length === 0) this.ipRecords.delete(key);
    }
    for (const [key, rec] of this.domainRecords) {
      rec.registrations = rec.registrations.filter(
        t => now - t <= this.config.windowMs
      );
      if (rec.registrations.length === 0) this.domainRecords.delete(key);
    }
  }

  destroy(): void {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = null;
    }
  }
}
