/**
 * URL Crawler Service
 *
 * Discovers API endpoints and resources from a given URL.
 * Used for URL-based security scanning in consulting and DIY features.
 *
 * Strategies:
 * 1. Sitemap.xml parsing (including sitemap index)
 * 2. robots.txt analysis
 * 3. Common API path probing (/api/*, /v1/*, /.well-known/)
 * 4. OpenAPI/Swagger discovery (/docs, /swagger.json, /openapi.json)
 * 5. HTML link extraction (crawls homepage and linked pages for hrefs)
 * 6. Next.js / framework-specific route discovery
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
  '/api/v3',
  '/v1',
  '/v2',
  '/v3',
  '/graphql',
  '/rest',
  '/api/health',
  '/api/status',
  '/health',
  '/healthz',
  '/status',
  '/ready',
  '/ping',
  '/.well-known/security.txt',
  '/.well-known/openid-configuration',
  '/api/auth',
  '/api/auth/login',
  '/api/auth/register',
  '/api/auth/session',
  '/api/users',
  '/api/products',
  '/api/orders',
  '/api/search',
  '/api/config',
  '/api/settings',
  '/api/webhook',
  '/api/webhooks',
  '/api/notifications',
  '/api/upload',
  '/api/download',
  '/api/export',
  '/api/import',
  '/api/admin',
  '/api/analytics',
  '/api/metrics',
  '/api/events',
  '/api/logs',
  '/api/payments',
  '/api/checkout',
  '/api/cart',
  '/api/categories',
  '/api/comments',
  '/api/reviews',
  '/api/feedback',
  '/api/contact',
  '/api/support',
  '/api/tickets',
  '/api/projects',
  '/api/teams',
  '/api/billing',
  '/api/subscription',
  '/api/integrations',
  '/api/media',
  '/api/files',
  '/api/inventory',
  '/api/shipping',
  '/feed',
  '/rss',
  '/atom.xml',
  '/feed.xml',
  '/sitemap',
  '/manifest.json',
  '/robots.txt',
  '/_next/data',
  '/api/trpc',
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
  const [sitemapResult, robotsResult, probeResult, openapiResult, htmlResult] =
    await Promise.allSettled([
      discoverFromSitemap(baseUrl),
      discoverFromRobots(baseUrl),
      probeCommonPaths(baseUrl),
      discoverOpenApi(baseUrl),
      discoverFromHtml(baseUrl),
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

  // Collect HTML link discovery results
  if (htmlResult.status === 'fulfilled') {
    endpoints.push(...htmlResult.value);
  } else if (htmlResult.status === 'rejected') {
    errors.push(`HTML: ${htmlResult.reason}`);
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
  const visitedSitemaps = new Set<string>();

  async function parseSitemap(sitemapUrl: string): Promise<void> {
    if (visitedSitemaps.has(sitemapUrl)) {
      return;
    }
    visitedSitemaps.add(sitemapUrl);

    const response = await fetchWithTimeout(sitemapUrl, 7000);
    if (!response.ok) return;

    const text = await response.text();
    const locRegex = /<loc>\s*(.*?)\s*<\/loc>/gi;
    let match: RegExpExecArray | null;

    while ((match = locRegex.exec(text)) !== null) {
      const foundUrl = match[1].trim();
      if (!foundUrl) continue;

      // Handle sitemap indexes recursively
      if (foundUrl.endsWith('.xml') && foundUrl.includes('sitemap')) {
        if (visitedSitemaps.size < 15) {
          await parseSitemap(foundUrl);
        }
        continue;
      }

      urls.push(foundUrl);
      endpoints.push({
        url: foundUrl,
        method: 'GET',
        source: 'sitemap',
      });
    }
  }

  try {
    await parseSitemap(`${baseUrl}/sitemap.xml`);
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
// HTML Link Discovery
// ============================================================

/**
 * Crawl the homepage and internal pages to discover links via HTML parsing.
 * Extracts href/action attributes from anchors, forms, and script/data attributes.
 * Follows internal links one level deep for broader discovery.
 */
async function discoverFromHtml(
  baseUrl: string
): Promise<DiscoveredEndpoint[]> {
  const endpoints: DiscoveredEndpoint[] = [];
  const visited = new Set<string>();
  const pagesToCrawl = [baseUrl, `${baseUrl}/`];

  // Crawl up to 60 internal pages for broader endpoint discovery
  const maxPages = 60;

  for (let i = 0; i < pagesToCrawl.length && visited.size < maxPages; i++) {
    const pageUrl = pagesToCrawl[i];
    if (visited.has(pageUrl)) continue;
    visited.add(pageUrl);

    try {
      const response = await fetchWithTimeout(pageUrl, 8000);
      if (!response.ok) continue;

      const contentType = response.headers.get('content-type') || '';
      if (!contentType.includes('html')) continue;

      const html = await response.text();

      // Extract and inspect JS bundles for route/API strings
      const scriptSrcRegex = /<script[^>]+src=["']([^"']+)["'][^>]*>/gi;
      let scriptMatch: RegExpExecArray | null;
      const scriptUrls: string[] = [];
      while ((scriptMatch = scriptSrcRegex.exec(html)) !== null) {
        const scriptSrc = scriptMatch[1].trim();
        const resolvedScript = resolveUrl(baseUrl, scriptSrc);
        if (resolvedScript) {
          scriptUrls.push(resolvedScript);
        }
      }

      const scriptCandidates = scriptUrls.slice(0, 15);
      for (const scriptUrl of scriptCandidates) {
        try {
          const scriptRes = await fetchWithTimeout(scriptUrl, 7000);
          if (!scriptRes.ok) continue;
          const scriptBody = await scriptRes.text();

          const apiPathRegex = /["'`](\/api\/[a-zA-Z0-9_\-./:{}]+)["'`]/g;
          let apiMatch: RegExpExecArray | null;
          while ((apiMatch = apiPathRegex.exec(scriptBody)) !== null) {
            const apiPath = apiMatch[1].trim();
            const resolvedApi = resolveUrl(baseUrl, apiPath);
            if (!resolvedApi) continue;

            endpoints.push({
              url: resolvedApi,
              method: 'GET',
              source: 'html',
            });
          }
        } catch {
          // Ignore script fetch failures
        }
      }

      // Extract all href values from anchor tags
      const hrefRegex = /href=["']([^"'#]+?)["']/gi;
      let match: RegExpExecArray | null;
      while ((match = hrefRegex.exec(html)) !== null) {
        const href = match[1].trim();
        const resolved = resolveUrl(baseUrl, href);
        if (!resolved) continue;

        // Only process same-origin links
        try {
          const parsedUrl = new URL(resolved);
          if (parsedUrl.origin !== new URL(baseUrl).origin) continue;

          const path = parsedUrl.pathname;

          // Add as endpoint
          endpoints.push({
            url: resolved,
            method: 'GET',
            source: 'html',
          });

          // Queue internal pages for deeper crawl (limit depth)
          if (
            visited.size < maxPages &&
            !visited.has(resolved) &&
            !pagesToCrawl.includes(resolved) &&
            !path.match(
              /\.(js|css|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|pdf|zip)$/i
            )
          ) {
            pagesToCrawl.push(resolved);
          }
        } catch {
          // Invalid URL — skip
        }
      }

      // Extract form actions
      const formRegex = /action=["']([^"']+?)["']/gi;
      while ((match = formRegex.exec(html)) !== null) {
        const action = match[1].trim();
        const resolved = resolveUrl(baseUrl, action);
        if (resolved) {
          endpoints.push({
            url: resolved,
            method: 'POST',
            source: 'html',
          });
        }
      }

      // Extract data-href, data-url, data-src attributes (common in SPAs)
      const dataUrlRegex =
        /data-(?:href|url|src|endpoint|api)=["']([^"']+?)["']/gi;
      while ((match = dataUrlRegex.exec(html)) !== null) {
        const dataUrl = match[1].trim();
        const resolved = resolveUrl(baseUrl, dataUrl);
        if (resolved) {
          endpoints.push({
            url: resolved,
            method: 'GET',
            source: 'html',
          });
        }
      }

      // Extract URLs from inline script fetch/axios calls
      const fetchRegex =
        /(?:fetch|axios\.(?:get|post|put|delete|patch))\s*\(\s*["'`]([^"'`]+?)["'`]/gi;
      while ((match = fetchRegex.exec(html)) !== null) {
        const fetchUrl = match[1].trim();
        const resolved = resolveUrl(baseUrl, fetchUrl);
        if (resolved) {
          // Try to detect method from the call
          const methodMatch = match[0].match(
            /axios\.(get|post|put|delete|patch)/i
          );
          endpoints.push({
            url: resolved,
            method: methodMatch ? methodMatch[1].toUpperCase() : 'GET',
            source: 'html',
          });
        }
      }

      // Extract Next.js build manifest paths if available
      const buildIdRegex = /_next\/data\/([^/]+)\//g;
      while ((match = buildIdRegex.exec(html)) !== null) {
        // Next.js app — try to extract routes from __NEXT_DATA__
        const nextDataRegex = /__NEXT_DATA__\s*=\s*({[^<]+})/;
        const nextMatch = nextDataRegex.exec(html);
        if (nextMatch) {
          try {
            const nextData = JSON.parse(nextMatch[1]);
            // Extract dynamic routes from build manifest
            if (nextData.buildId) {
              logInfo('Next.js app detected', {
                baseUrl,
                buildId: nextData.buildId,
              });
            }
          } catch {
            // Not valid JSON
          }
        }
      }
    } catch (error) {
      logWarn('HTML crawl failed for page', {
        pageUrl,
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }

  return endpoints;
}

/**
 * Resolve a potentially relative URL against a base URL.
 */
function resolveUrl(baseUrl: string, href: string): string | null {
  try {
    // Skip javascript:, mailto:, tel:, and data: URLs
    if (/^(javascript|mailto|tel|data):/i.test(href)) return null;
    // Skip fragments and empty
    if (!href || href === '#' || href.startsWith('#')) return null;

    return new URL(href, baseUrl).href;
  } catch {
    return null;
  }
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
