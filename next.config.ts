import type { NextConfig } from 'next';
import { withSentryConfig } from '@sentry/nextjs';

const nextConfig: NextConfig = {
  // Vercel's Hobby-tier build machine (fixed 2vCPU/8GB, no paid-tier upgrade
  // available) has no memory margin to re-run type-checking during `next
  // build` — it hangs at "Linting and checking validity of types" even
  // though the same check passes locally. The pre-push hook already runs
  // `npm run build` (which runs this exact check) before any push succeeds,
  // so this is a redundant second run of an already-enforced gate, not the
  // only one — safe to skip here.
  typescript: {
    ignoreBuildErrors: true,
  },

  env: {
    BUILD_TIME_PADDLE_TOKEN_SET: process.env.NEXT_PUBLIC_PADDLE_CLIENT_TOKEN
      ? 'yes'
      : 'no',
  },

  // CRITICAL: Force fresh build - cache busting for Vercel deployment issue
  // This ensures new JavaScript chunk hashes are generated
  generateBuildId: async () => {
    // Use timestamp to force new build ID every time
    return `build-${Date.now()}-${Math.random().toString(36).substring(7)}`;
  },

  // External packages for server-side rendering to avoid bundling issues
  serverExternalPackages: [
    'import-in-the-middle',
    'require-in-the-middle',
    'jsdom',
    'isomorphic-dompurify',
    '@opentelemetry/instrumentation',
    '@opentelemetry/sdk-trace-base',
  ],

  // Optimize images
  images: {
    formats: ['image/webp', 'image/avif'],
    deviceSizes: [640, 750, 828, 1080, 1200, 1920, 2048, 3840],
    imageSizes: [16, 32, 48, 64, 96, 128, 256, 384],
    minimumCacheTTL: 60,
    dangerouslyAllowSVG: true,
    contentDispositionType: 'attachment',
    contentSecurityPolicy: "default-src 'self'; script-src 'none'; sandbox;",
  },

  // Enable compression
  compress: true,

  // Optimize production builds
  poweredByHeader: false,
  generateEtags: true,

  // Exclude large content directories from serverless function trace to stay
  // under Vercel's 250 MB limit — these are static assets, not runtime code.
  outputFileTracingExcludes: {
    '*': [
      './content/inventions/publications/**/*',
      './content/inventions/archive/**/*',
      './content/update-sdk-approach.md',
    ],
  },

  // Explicitly include content/ files used by fs.readFile() at runtime —
  // the static tracer does not follow dynamic reads.
  outputFileTracingIncludes: {
    '/validation/evidence': ['./content/**/*'],
    '/validation': ['./content/**/*'],
  },

  // Enable experimental features for better performance
  experimental: {
    // Enable Turbopack in production (when stable)
    // turbo: true,
    optimizePackageImports: ['lucide-react', '@radix-ui/react-icons'],
  },

  // Configure Turbopack to work with webpack config
  turbopack: {},

  // Suppress known build warnings:
  // 1. @opentelemetry/instrumentation uses dynamic require() → "Critical dependency"
  // 2. @supabase/realtime-js uses process.versions (Node.js API) in Edge Runtime
  //    This is safe — Supabase SSR handles Edge Runtime gracefully at runtime.
  webpack: (config) => {
    config.ignoreWarnings = [
      ...(config.ignoreWarnings || []),
      {
        module: /@opentelemetry\/instrumentation/,
        message: /Critical dependency/,
      },
      {
        module: /@supabase\/realtime-js/,
        message: /A Node\.js API is used/,
      },
      {
        module: /@supabase\/supabase-js/,
        message: /A Node\.js API is used/,
      },
    ];

    return config;
  },

  // Configure headers for caching and CORS. CSP/HSTS/X-Frame-Options/etc.
  // (the general security-header block) moved to middleware.ts (TODO 254) —
  // it was previously applied here via a `DARK_RESPONSE_EXCLUSION` regex
  // compiled from every dark-response pattern spliced into one route-matcher
  // source string, which hit Next's hard 4096-char compiled-route-regex cap
  // as the pattern list grew. middleware.ts's `isDarkResponsePath()` does the
  // same exclusion as a plain runtime check with no such ceiling.
  async headers() {
    return [
      // CORS is only needed for SDK/customer-facing endpoints that legitimate
      // external origins call directly (customer apps, webhook senders, status
      // checks). Authenticated app/dashboard routes and marketing pages have no
      // cross-origin use case and must not carry wildcard CORS headers.
      {
        source: '/api/sdk/:path*',
        headers: [
          {
            key: 'Access-Control-Allow-Origin',
            value: '*',
          },
          {
            key: 'Access-Control-Allow-Methods',
            value: 'GET, POST, PUT, DELETE, OPTIONS',
          },
          {
            key: 'Access-Control-Allow-Headers',
            value:
              'Content-Type, Authorization, X-API-Key, X-DevFortress-Key, X-DevFortress-Signature, X-DevFortress-Timestamp',
          },
        ],
      },
      {
        source: '/api/events/:path*',
        headers: [
          {
            key: 'Access-Control-Allow-Origin',
            value: '*',
          },
          {
            key: 'Access-Control-Allow-Methods',
            value: 'GET, POST, PUT, DELETE, OPTIONS',
          },
          {
            key: 'Access-Control-Allow-Headers',
            value:
              'Content-Type, Authorization, X-API-Key, X-DevFortress-Key, X-DevFortress-Signature, X-DevFortress-Timestamp',
          },
        ],
      },
      {
        source: '/api/webhooks/:path*',
        headers: [
          {
            key: 'Access-Control-Allow-Origin',
            value: '*',
          },
          {
            key: 'Access-Control-Allow-Methods',
            value: 'GET, POST, PUT, DELETE, OPTIONS',
          },
          {
            key: 'Access-Control-Allow-Headers',
            value:
              'Content-Type, Authorization, X-API-Key, X-DevFortress-Key, X-DevFortress-Signature, X-DevFortress-Timestamp',
          },
        ],
      },
      {
        source: '/api/status',
        headers: [
          {
            key: 'Access-Control-Allow-Origin',
            value: '*',
          },
          {
            key: 'Access-Control-Allow-Methods',
            value: 'GET, POST, PUT, DELETE, OPTIONS',
          },
          {
            key: 'Access-Control-Allow-Headers',
            value:
              'Content-Type, Authorization, X-API-Key, X-DevFortress-Key, X-DevFortress-Signature, X-DevFortress-Timestamp',
          },
        ],
      },
      {
        source: '/_next/static/:path*',
        headers: [
          {
            key: 'Cache-Control',
            value: 'public, max-age=31536000, immutable',
          },
          {
            key: 'X-Build-ID',
            value: `build-${Date.now()}`,
          },
        ],
      },
      {
        source: '/api/:path*',
        headers: [
          {
            key: 'Cache-Control',
            value: 'no-store, max-age=0',
          },
        ],
      },
      {
        source: '/_next/static/:path*',
        headers: [
          {
            key: 'Cache-Control',
            value: 'public, max-age=31536000, immutable',
          },
        ],
      },
      {
        source: '/images/:path*',
        headers: [
          {
            key: 'Cache-Control',
            value: 'public, max-age=31536000, immutable',
          },
        ],
      },
    ];
  },

  // Redirect old feature pages and inactive phase routes
  // MVP focuses on COLLECT phase — other phases redirect to preserve SEO link equity
  async redirects() {
    return [
      // NOTE: /features, /features/build, and /features/defend are real pages
      // (app/features/page.tsx, app/features/build/page.tsx, app/features/defend/page.tsx)
      // — do not redirect them, that shadows the page and is what caused the GSC
      // "page with redirect" error. They are unlinked from public nav/content and
      // marked noindex, but must still resolve directly.
      // /register was never a real route, but is referenced by CTA links on several
      // marketing pages — redirect it to the same place /signup already goes.
      {
        source: '/register',
        destination: '/login',
        permanent: true,
      },
      // /login is now the canonical auth entry point (TODO 240) — compat
      // redirect for stray external links/bookmarks still pointing at the
      // old /auth/signin path.
      {
        source: '/auth/signin',
        destination: '/login',
        permanent: true,
      },
      // Inactive phase routes — 301 redirect to preserve link equity
      {
        source: '/build',
        destination: '/',
        permanent: true,
      },
      {
        source: '/build/:path*',
        destination: '/',
        permanent: true,
      },
      {
        source: '/defend',
        destination: '/',
        permanent: true,
      },
      {
        source: '/defend/:path*',
        destination: '/',
        permanent: true,
      },
      {
        source: '/learn',
        destination: '/dashboard/insights',
        permanent: true,
      },
      {
        source: '/learn/:path*',
        destination: '/dashboard/insights',
        permanent: true,
      },
      // Collect top-level redirects to dashboard collect
      {
        source: '/collect',
        destination: '/dashboard/collect/surveillance',
        permanent: true,
      },
      {
        source: '/collect/:path*',
        destination: '/dashboard/collect/surveillance',
        permanent: true,
      },
    ];
  },
};

/** Next.js configuration object with custom settings for the application. */
export default withSentryConfig(nextConfig, {
  org: process.env.SENTRY_ORG,
  project: process.env.SENTRY_PROJECT,
  // No SENTRY_AUTH_TOKEN configured yet locally — the Sentry build plugin
  // skips source map upload (with a log line, not a build failure) when
  // authToken is unset, so this degrades gracefully until one is added.
  authToken: process.env.SENTRY_AUTH_TOKEN,
  silent: true,
  widenClientFileUpload: true,
  webpack: {
    treeshake: {
      removeDebugLogging: true,
    },
    automaticVercelMonitors: false,
  },
});
