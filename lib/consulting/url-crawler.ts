/**
 * URL Crawler Service
 *
 * Discovers API endpoints and resources from a given URL.
 * Used for URL-based security scanning in consulting and DIY features.
 *
 * Strategies:
 * 1. Sitemap.xml parsing
 * 2. robots.txt analysis
 * 3. Common API path probing (/api/*, /v1/*, /.well-known/)
 * 4. OpenAPI/Swagger discovery (/docs, /swagger.json, /openapi.json)
 */

import { logInfo, logError, logWarn } from '@core/lib/logger';

// ============================================================
// Types
// ============================================================

export interface DiscoveredEndpoint {
  url: string;
  method: string;
  source: 'sitemap' | 'robots' | 'probe' | 'openapi' | 'html';
  statusCode?: number;
  contentType?: string;
}

export interface CrawlResult {
  baseUrl: string;
  endpoints: DiscoveredEndpoint[];
  openApiSpec?: Record<string, unknown>;
  sitemapUrls: string[];
  robotsDisallowed: string[];
  crawlDuration: number;
  errors: string[];
}

// Common API paths to probe
const COMMON_API_PATHS = [
  '/api',
  '/api/v1',
  '/api/v2',
  '/v1',
  '/v2',
  '/graphql',
  '/rest',
  '/api/health',
  '/api/status',
  '/health',
  '/healthz',
  '/status',
  '/.well-known/security.txt',
  '/.well-known/openid-configuration',
];

// OpenAPI/Swagger discovery paths
const OPENAPI_PATHS = [
  '/openapi.json',
  '/openapi.yaml',
  '/swagger.json',
  '/swagger.yaml',
  '/api-docs',
  '/api/docs',
  '/docs/api',
  '/api/swagger.json',
  '/api/openapi.json',
  '/v1/swagger.json',
  '/v2/swagger.json',
];

// ============================================================
// Core Crawler
// ============================================================

/**
 * Crawl a URL to discover its API surface and resources.
 * Runs all discovery strategies in parallel.
 */
export async function crawlUrl(targetUrl: string): Promise<CrawlResult> {
  const startTime = Date.now();
  const errors: string[] = [];

  // Normalize URL
  let baseUrl: string;
  try {
    const parsed = new URL(targetUrl);
    baseUrl = `${parsed.protocol}//${parsed.host}`;
  } catch {
    throw new Error(`Invalid URL: ${targetUrl}`);
  }

  logInfo('Starting URL crawl', { baseUrl });

  // Run all discovery strategies in parallel
  const [sitemapResult, robotsResult, probeResult, openapiResult] =
    await Promise.allSettled([
      discoverFromSitemap(baseUrl),
      discoverFromRobots(baseUrl),
      probeCommonPaths(baseUrl),
      discoverOpenApi(baseUrl),
    ]);

  const endpoints: DiscoveredEndpoint[] = [];
  const sitemapUrls: string[] = [];
  const robotsDisallowed: string[] = [];
  let openApiSpec: Record<string, unknown> | undefined;

  // Collect sitemap results
  if (sitemapResult.status === 'fulfilled') {
    sitemapUrls.push(...sitemapResult.value.urls);
    endpoints.push(...sitemapResult.value.endpoints);
  } else {
    errors.push(`Sitemap: ${sitemapResult.reason}`);
  }

  // Collect robots results
  if (robotsResult.status === 'fulfilled') {
    robotsDisallowed.push(...robotsResult.value.disallowed);
    endpoints.push(...robotsResult.value.endpoints);
  } else {
    errors.push(`Robots: ${robotsResult.reason}`);
  }

  // Collect probe results
  if (probeResult.status === 'fulfilled') {
    endpoints.push(...probeResult.value);
  } else {
    errors.push(`Probe: ${probeResult.reason}`);
  }

  // Collect OpenAPI results
  if (openapiResult.status === 'fulfilled' && openapiResult.value) {
    openApiSpec = openapiResult.value.spec;
    endpoints.push(...openapiResult.value.endpoints);
  } else if (openapiResult.status === 'rejected') {
    errors.push(`OpenAPI: ${openapiResult.reason}`);
  }

  // Deduplicate endpoints by URL + method
  const seen = new Set<string>();
  const dedupedEndpoints = endpoints.filter(ep => {
    const key = `${ep.method}:${ep.url}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  const duration = Date.now() - startTime;

  logInfo('URL crawl completed', {
    baseUrl,
    endpointCount: dedupedEndpoints.length,
    duration,
  });

  return {
    baseUrl,
    endpoints: dedupedEndpoints,
    openApiSpec,
    sitemapUrls,
    robotsDisallowed,
    crawlDuration: duration,
    errors,
  };
}

// ============================================================
// Discovery Strategies
// ============================================================

/**
 * Fetch and parse sitemap.xml for URLs.
 */
async function discoverFromSitemap(
  baseUrl: string
): Promise<{ urls: string[]; endpoints: DiscoveredEndpoint[] }> {
  const urls: string[] = [];
  const endpoints: DiscoveredEndpoint[] = [];

  try {
    const response = await fetchWithTimeout(`${baseUrl}/sitemap.xml`, 5000);
    if (!response.ok) return { urls, endpoints };

    const text = await response.text();

    // Simple XML parsing — extract <loc> tags
    const locRegex = /<loc>\s*(.*?)\s*<\/loc>/gi;
    let match: RegExpExecArray | null;
    while ((match = locRegex.exec(text)) !== null) {
      const url = match[1].trim();
      urls.push(url);

      // Flag API-looking URLs
      if (
        url.includes('/api/') ||
        url.includes('/v1/') ||
        url.includes('/v2/')
      ) {
        endpoints.push({
          url,
          method: 'GET',
          source: 'sitemap',
        });
      }
    }
  } catch (error) {
    logWarn('Sitemap discovery failed', {
      baseUrl,
      error: error instanceof Error ? error.message : String(error),
    });
  }

  return { urls, endpoints };
}

/**
 * Fetch and parse robots.txt for disallowed paths and API hints.
 */
async function discoverFromRobots(
  baseUrl: string
): Promise<{ disallowed: string[]; endpoints: DiscoveredEndpoint[] }> {
  const disallowed: string[] = [];
  const endpoints: DiscoveredEndpoint[] = [];

  try {
    const response = await fetchWithTimeout(`${baseUrl}/robots.txt`, 5000);
    if (!response.ok) return { disallowed, endpoints };

    const text = await response.text();
    const lines = text.split('\n');

    for (const line of lines) {
      const trimmed = line.trim();
      if (trimmed.startsWith('Disallow:')) {
        const path = trimmed.replace('Disallow:', '').trim();
        if (path) {
          disallowed.push(path);

          // Disallowed API paths are interesting — they exist
          if (
            path.includes('/api') ||
            path.includes('/admin') ||
            path.includes('/internal')
          ) {
            endpoints.push({
              url: `${baseUrl}${path}`,
              method: 'GET',
              source: 'robots',
            });
          }
        }
      }
    }
  } catch (error) {
    logWarn('Robots.txt discovery failed', {
      baseUrl,
      error: error instanceof Error ? error.message : String(error),
    });
  }

  return { disallowed, endpoints };
}

/**
 * Probe common API paths to see which ones respond.
 */
async function probeCommonPaths(
  baseUrl: string
): Promise<DiscoveredEndpoint[]> {
  const endpoints: DiscoveredEndpoint[] = [];

  const probes = COMMON_API_PATHS.map(async path => {
    try {
      const url = `${baseUrl}${path}`;
      const response = await fetchWithTimeout(url, 5000);

      // Any non-404 response means the path exists
      if (response.status !== 404) {
        const contentType = response.headers.get('content-type') || 'unknown';
        endpoints.push({
          url,
          method: 'GET',
          source: 'probe',
          statusCode: response.status,
          contentType,
        });
      }
    } catch {
      // Timeout or network error — skip
    }
  });

  await Promise.allSettled(probes);
  return endpoints;
}

/**
 * Look for OpenAPI/Swagger specs.
 */
async function discoverOpenApi(baseUrl: string): Promise<{
  spec: Record<string, unknown>;
  endpoints: DiscoveredEndpoint[];
} | null> {
  for (const path of OPENAPI_PATHS) {
    try {
      const url = `${baseUrl}${path}`;
      const response = await fetchWithTimeout(url, 5000);

      if (response.ok) {
        const contentType = response.headers.get('content-type') || '';
        if (
          contentType.includes('json') ||
          contentType.includes('yaml') ||
          path.endsWith('.json')
        ) {
          const text = await response.text();
          try {
            const spec = JSON.parse(text);

            // Extract endpoints from OpenAPI spec
            const endpoints: DiscoveredEndpoint[] = [];
            if (spec.paths) {
              for (const [apiPath, methods] of Object.entries(spec.paths)) {
                const methodObj = methods as Record<string, unknown>;
                for (const method of [
                  'get',
                  'post',
                  'put',
                  'patch',
                  'delete',
                ]) {
                  if (methodObj[method]) {
                    endpoints.push({
                      url: `${baseUrl}${apiPath}`,
                      method: method.toUpperCase(),
                      source: 'openapi',
                    });
                  }
                }
              }
            }

            logInfo('OpenAPI spec discovered', {
              baseUrl,
              path,
              endpointCount: endpoints.length,
            });

            return { spec, endpoints };
          } catch {
            // Not valid JSON — try next path
          }
        }
      }
    } catch {
      // Timeout or network error — try next path
    }
  }

  return null;
}

// ============================================================
// Helpers
// ============================================================

/**
 * Fetch with a timeout to avoid hanging on slow responses.
 */
async function fetchWithTimeout(
  url: string,
  timeoutMs: number
): Promise<Response> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(url, {
      signal: controller.signal,
      headers: {
        'User-Agent': 'DevFortress-SecurityScanner/1.0',
        Accept: 'application/json, text/html, text/xml, */*',
      },
      redirect: 'follow',
    });
    return response;
  } finally {
    clearTimeout(timeout);
  }
}
