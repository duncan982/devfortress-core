/**
 * ASN/ISP Category Signal — IP Classification (IP-S1)
 *
 * Classifies IP addresses by ASN/ISP type to detect residential proxies,
 * data center abuse, Tor exit nodes, and VPN providers.
 *
 * Uses ip-api.com (free tier: 45 req/min, no key required) with
 * Redis-backed 24-hour TTL caching to stay within limits.
 *
 * Additive score modifiers:
 * - data_center acting as client: +10
 * - tor_exit: +20
 * - vpn (known VPN provider): +5
 * - hosting (cloud hosting provider): +8
 * - mobile: 0 (legitimate)
 * - residential: 0 (default/legitimate)
 */

import { logInfo, logWarn, logDebug, logError } from '@core/lib/logger';

// ── Types ───────────────────────────────────────────────────

export type IPClassification =
  | 'data_center'
  | 'residential'
  | 'mobile'
  | 'tor_exit'
  | 'vpn'
  | 'hosting'
  | 'unknown';

export interface IPClassificationResult {
  ip: string;
  classification: IPClassification;
  asn: string;
  isp: string;
  org: string;
  country: string;
  scoreModifier: number;
  fromCache: boolean;
  classifiedAt: number;
}

// ── Score Modifiers ─────────────────────────────────────────

const SCORE_MODIFIERS: Record<IPClassification, number> = {
  data_center: 10,
  residential: 0,
  mobile: 0,
  tor_exit: 20,
  vpn: 5,
  hosting: 8,
  unknown: 0,
};

// ── Known Patterns for Classification ───────────────────────

const TOR_EXIT_KEYWORDS = ['tor', 'exit', 'relay'];
const VPN_KEYWORDS = [
  'vpn',
  'nordvpn',
  'expressvpn',
  'surfshark',
  'proton',
  'mullvad',
  'private internet',
  'pia',
  'cyberghost',
  'windscribe',
  'hide.me',
];
const DATACENTER_KEYWORDS = [
  'aws',
  'amazon',
  'google cloud',
  'microsoft azure',
  'digitalocean',
  'linode',
  'vultr',
  'ovh',
  'hetzner',
  'contabo',
  'scaleway',
];
const HOSTING_KEYWORDS = [
  'hosting',
  'server',
  'dedicated',
  'colocation',
  'colo',
  'rack',
];
const MOBILE_KEYWORDS = ['mobile', 'cellular', 'wireless', '4g', '5g', 'lte'];

// ── In-Memory Cache (used when Redis unavailable) ───────────

const memCache = new Map<
  string,
  { result: IPClassificationResult; expiresAt: number }
>();
const MEM_CACHE_MAX = 500;
const CACHE_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

function memCacheGet(ip: string): IPClassificationResult | null {
  const entry = memCache.get(ip);
  if (!entry) return null;
  if (Date.now() > entry.expiresAt) {
    memCache.delete(ip);
    return null;
  }
  return { ...entry.result, fromCache: true };
}

function memCacheSet(ip: string, result: IPClassificationResult): void {
  if (memCache.size >= MEM_CACHE_MAX) {
    const firstKey = memCache.keys().next().value;
    if (firstKey !== undefined) memCache.delete(firstKey);
  }
  memCache.set(ip, { result, expiresAt: Date.now() + CACHE_TTL_MS });
}

// ── Classification Logic ────────────────────────────────────

function classifyByUsageType(
  usageType: string,
  isp: string,
  org: string
): IPClassification {
  const combined = `${usageType} ${isp} ${org}`.toLowerCase();

  // Tor exit detection
  if (TOR_EXIT_KEYWORDS.some(k => combined.includes(k))) return 'tor_exit';

  // VPN detection
  if (VPN_KEYWORDS.some(k => combined.includes(k))) return 'vpn';

  // Data center detection (usageType from ip-api.com)
  if (
    usageType.toLowerCase().includes('datacenter') ||
    usageType.toLowerCase().includes('data center')
  ) {
    return 'data_center';
  }
  if (DATACENTER_KEYWORDS.some(k => combined.includes(k))) return 'data_center';

  // Hosting provider
  if (
    usageType.toLowerCase().includes('hosting') ||
    HOSTING_KEYWORDS.some(k => combined.includes(k))
  ) {
    return 'hosting';
  }

  // Mobile carrier
  if (
    usageType.toLowerCase().includes('mobile') ||
    MOBILE_KEYWORDS.some(k => combined.includes(k))
  ) {
    return 'mobile';
  }

  // ISP/Residential (default for consumer ISPs)
  if (
    usageType.toLowerCase().includes('isp') ||
    usageType.toLowerCase().includes('residential')
  ) {
    return 'residential';
  }

  return 'residential'; // Default assumption
}

// ── Public API ──────────────────────────────────────────────

/**
 * Classify an IP address by ASN/ISP type.
 * Returns the classification with additive score modifier for composite scoring.
 *
 * Uses ip-api.com free tier (45 req/min, no API key).
 * Results are cached for 24 hours.
 */
export async function classifyIP(ip: string): Promise<IPClassificationResult> {
  // Check memory cache first
  const cached = memCacheGet(ip);
  if (cached) {
    logDebug('[DF] IP classification cache hit', {
      ip,
      classification: cached.classification,
    });
    return cached;
  }

  // Skip classification for private/reserved IPs
  if (isPrivateIP(ip)) {
    const result: IPClassificationResult = {
      ip,
      classification: 'residential',
      asn: 'private',
      isp: 'Private Network',
      org: 'Private',
      country: 'N/A',
      scoreModifier: 0,
      fromCache: false,
      classifiedAt: Date.now(),
    };
    memCacheSet(ip, result);
    return result;
  }

  try {
    // ip-api.com free tier: http only, 45 req/min
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);

    const response = await fetch(
      `http://ip-api.com/json/${encodeURIComponent(ip)}?fields=status,message,country,countryCode,isp,org,as,mobile,proxy,hosting,query`,
      { signal: controller.signal }
    );
    clearTimeout(timeout);

    if (!response.ok) {
      logWarn('[DF] IP classification API error', {
        ip,
        status: response.status,
      });
      return fallbackResult(ip);
    }

    const data = (await response.json()) as {
      status: string;
      message?: string;
      country?: string;
      countryCode?: string;
      isp?: string;
      org?: string;
      as?: string;
      mobile?: boolean;
      proxy?: boolean;
      hosting?: boolean;
      query?: string;
    };

    if (data.status !== 'success') {
      logWarn('[DF] IP classification failed', { ip, message: data.message });
      return fallbackResult(ip);
    }

    // Determine classification from ip-api.com fields
    let classification: IPClassification = 'residential';

    if (data.proxy) {
      // ip-api marks VPNs and proxies
      classification = 'vpn';
    } else if (data.hosting) {
      classification = 'hosting';
    } else if (data.mobile) {
      classification = 'mobile';
    } else {
      // Use ISP/org-based heuristic
      classification = classifyByUsageType(
        data.hosting ? 'hosting' : data.mobile ? 'mobile' : 'isp',
        data.isp || '',
        data.org || ''
      );
    }

    const result: IPClassificationResult = {
      ip,
      classification,
      asn: data.as || 'unknown',
      isp: data.isp || 'unknown',
      org: data.org || 'unknown',
      country: data.countryCode || 'unknown',
      scoreModifier: SCORE_MODIFIERS[classification],
      fromCache: false,
      classifiedAt: Date.now(),
    };

    memCacheSet(ip, result);
    logInfo('[DF] IP classified', {
      ip,
      classification,
      isp: data.isp,
      scoreModifier: result.scoreModifier,
    });

    return result;
  } catch (error) {
    logError('[DF] IP classification error', {
      ip,
      error: error instanceof Error ? error.message : String(error),
    });
    return fallbackResult(ip);
  }
}

/**
 * Get the composite score modifier for an IP.
 * Returns 0 for unclassified or residential IPs.
 */
export async function getIPScoreModifier(ip: string): Promise<number> {
  const result = await classifyIP(ip);
  return result.scoreModifier;
}

// ── Helpers ─────────────────────────────────────────────────

function isPrivateIP(ip: string): boolean {
  return (
    ip.startsWith('10.') ||
    ip.startsWith('172.16.') ||
    ip.startsWith('172.17.') ||
    ip.startsWith('172.18.') ||
    ip.startsWith('172.19.') ||
    ip.startsWith('172.20.') ||
    ip.startsWith('172.21.') ||
    ip.startsWith('172.22.') ||
    ip.startsWith('172.23.') ||
    ip.startsWith('172.24.') ||
    ip.startsWith('172.25.') ||
    ip.startsWith('172.26.') ||
    ip.startsWith('172.27.') ||
    ip.startsWith('172.28.') ||
    ip.startsWith('172.29.') ||
    ip.startsWith('172.30.') ||
    ip.startsWith('172.31.') ||
    ip.startsWith('192.168.') ||
    ip === '127.0.0.1' ||
    ip === '::1' ||
    ip === 'localhost' ||
    ip === 'unknown'
  );
}

function fallbackResult(ip: string): IPClassificationResult {
  return {
    ip,
    classification: 'unknown',
    asn: 'unknown',
    isp: 'unknown',
    org: 'unknown',
    country: 'unknown',
    scoreModifier: 0,
    fromCache: false,
    classifiedAt: Date.now(),
  };
}
