import type { NextConfig } from 'next';

const nextConfig: NextConfig = {
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
  webpack: (config, { isServer }) => {
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

    if (isServer) {
      // Suppress "Module not found" for optional SDK peer deps not bundled in open-core
      config.externals = [
        ...(Array.isArray(config.externals) ? config.externals : []),
        'fastify',
        'hono',
        'express',
        (
          { request }: { request?: string },
          callback: (err?: Error | null, result?: string) => void
        ) => {
          if (request && /\.node$/.test(request)) {
            return callback(null, `commonjs ${request}`);
          }
          callback();
        },
      ];
    }

    return config;
  },

  // Configure headers for caching and security
  async headers() {
    // Allow Vercel Live preview toolbar in Vercel preview deployments
    const isVercelPreview =
      process.env.VERCEL === '1' && process.env.VERCEL_ENV !== 'production';
    const frameOptions = isVercelPreview ? 'SAMEORIGIN' : 'DENY';
    const cspFrameAncestors = isVercelPreview
      ? "frame-ancestors 'self' https://vercel.live"
      : "frame-ancestors 'self'";

    const scriptSrc = [
      "'self'",
      "'unsafe-eval'",
      "'unsafe-inline'",
      'https://vercel.live',
      'https://js.hcaptcha.com',
      'https://hcaptcha.com',
      'https://challenges.cloudflare.com',
      'https://*.cloudflare.com',
      'https://static.cloudflareinsights.com',
      'https://www.googletagmanager.com',
      'https://www.google-analytics.com',
      'https://cdn.paddle.com',
      'https://sandbox-cdn.paddle.com',
    ].join(' ');

    const connectSrc = [
      "'self'",
      'https://vercel.live',
      'https://*.supabase.co',
      'wss://*.supabase.co',
      'https://github.githubassets.com',
      'https://github.com',
      'https://api.github.com',
      'https://hcaptcha.com',
      'https://*.hcaptcha.com',
      'https://sentry.hcaptcha.com',
      'https://challenges.cloudflare.com',
      'https://*.cloudflare.com',
      'https://cloudflareinsights.com',
      'https://www.googletagmanager.com',
      'https://www.google-analytics.com',
      'https://sandbox-api.paddle.com',
      'https://sandbox-buy.paddle.com',
      'https://*.paddle.com',
      'https://pay.paddle.com',
      'https://checkout.paddle.com',
    ].join(' ');

    return [
      {
        source: '/:path*',
        headers: [
          {
            key: 'X-DNS-Prefetch-Control',
            value: 'on',
          },
          {
            key: 'Strict-Transport-Security',
            value: 'max-age=63072000; includeSubDomains; preload',
          },
          {
            key: 'X-Content-Type-Options',
            value: 'nosniff',
          },
          {
            key: 'X-Frame-Options',
            value: frameOptions,
          },
          {
            key: 'X-XSS-Protection',
            value: '1; mode=block',
          },
          {
            key: 'Referrer-Policy',
            value: 'origin-when-cross-origin',
          },
          {
            key: 'Permissions-Policy',
            value:
              'camera=(), microphone=(), geolocation=(), interest-cohort=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()',
          },
          {
            key: 'Content-Security-Policy',
            value: `${cspFrameAncestors}; script-src ${scriptSrc}; script-src-elem ${scriptSrc}; connect-src ${connectSrc}; style-src 'self' 'unsafe-inline' https://hcaptcha.com https://challenges.cloudflare.com https://sandbox-cdn.paddle.com https://cdn.paddle.com; frame-src 'self' https://vercel.live https://hcaptcha.com https://challenges.cloudflare.com https://newassets.hcaptcha.com https://*.paddle.com https://sandbox-buy.paddle.com`,
          },
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
      {
        source: '/features',
        destination: '/',
        permanent: true,
      },
      {
        source: '/features/build',
        destination: '/',
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
export default nextConfig;
