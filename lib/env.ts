import { z } from 'zod';

// Use console for env diagnostics since logger depends on env
/* eslint-disable no-console */

const isNonProduction = typeof window === 'undefined' && process.env.NODE_ENV !== 'production';

export const normalizeBooleanString = (value: string) => {
  const normalized = value.trim().toLowerCase();
  if (['true', '1', 'yes', 'y', 'on'].includes(normalized)) {
    return true;
  }

  if (['false', '0', 'no', 'n', 'off', ''].includes(normalized)) {
    return false;
  }

  // Invalid/placeholder values (like --value from build systems) default to false
  return false;
};

const booleanSchema = z
  .union([z.boolean(), z.string()])
  .transform(value =>
    typeof value === 'boolean' ? value : normalizeBooleanString(value)
  );

// Filter out invalid placeholder values from environment (like --value from build systems)
const filteredEnv = typeof window === 'undefined' ? Object.fromEntries(
  Object.entries(process.env).filter(([key, value]) => {
    // Don't filter sensitive API keys and secrets - preserve them even if they look like placeholders
    if (
      key.includes('API_KEY') ||
      key.includes('SECRET') ||
      key.includes('TOKEN') ||
      key.includes('KEY')
    ) {
      return true;
    }

    // Filter out placeholder values that start with -- (common in build systems)
    if (typeof value !== 'string') return true;
    const trimmed = value.trim();

    // Handle quoted placeholder values (e.g., "--value\n" from Vercel)
    const unquoted = trimmed.replace(/^["']|["']$/g, '').trim();

    // Filter out various forms of placeholder values
    return !(
      trimmed.startsWith('--') ||
      trimmed === '--value' ||
      unquoted.startsWith('--') ||
      unquoted === '--value' ||
      unquoted === '' ||
      unquoted.toLowerCase() === 'null' ||
      unquoted.toLowerCase() === 'undefined' ||
      // Additional Vercel-specific placeholders
      unquoted === 'placeholder' ||
      trimmed.includes('placeholder')
    );
  })
) : {};

// OpenAI validation and fallback constants
const VALID_OPENAI_MODELS = [
  'gpt-4o',
  'gpt-4o-mini',
  'gpt-4-turbo',
  'gpt-4-turbo-preview',
  'gpt-4',
  'gpt-4-32k',
  'gpt-3.5-turbo',
  'gpt-3.5-turbo-16k',
] as const;

const OPENAI_MODEL_FALLBACK = 'gpt-4o-mini';
const OPENAI_MAX_TOKENS_FALLBACK = 2000;

const isValidOpenAIModel = (model: string): boolean => {
  return VALID_OPENAI_MODELS.includes(
    model as (typeof VALID_OPENAI_MODELS)[number]
  );
};

const isValidMaxTokens = (tokens: string | number): boolean => {
  const num = typeof tokens === 'string' ? parseInt(tokens, 10) : tokens;
  return !isNaN(num) && num >= 256 && num <= 4096;
};

const rawEnv = {
  // Start with filtered environment to preserve API keys and filter placeholders
  ...filteredEnv,
  NEXT_PUBLIC_SUPABASE_URL:
    typeof window === 'undefined' ? process.env.NEXT_PUBLIC_SUPABASE_URL?.trim().replace(/[\r\n]+$/, '') : undefined,
  NEXT_PUBLIC_SUPABASE_ANON_KEY:
    typeof window === 'undefined' ? process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY?.trim().replace(/[\r\n]+$/, '') : undefined,
  PORTAL_ENABLED:
    typeof window === 'undefined' ? (process.env.PORTAL_ENABLED ??
    process.env.NEXT_PUBLIC_PORTAL_ENABLED ??
    'false') : 'false',
  DEV_LOGIN_ENABLED:
    process.env.DEV_LOGIN_ENABLED ?? (isNonProduction ? 'true' : 'false'),
  // Only set defaults for dev login in actual development environment
  ...(isNonProduction && {
    DEV_LOGIN_EMAIL:
      process.env.DEV_LOGIN_EMAIL ?? 'developer@vortexsecure.local',
    DEV_LOGIN_NAME: process.env.DEV_LOGIN_NAME ?? 'VortexSecure Developer',
    DEV_LOGIN_PASSWORD: process.env.DEV_LOGIN_PASSWORD,
    LOG_INGESTION_TOKEN:
      process.env.LOG_INGESTION_TOKEN ??
      'development-log-token-change-me-immediately-2025',
  }),
  DEV_LOGIN_PASSWORD: process.env.DEV_LOGIN_PASSWORD,
  NEXT_PUBLIC_PORTAL_ENABLED: process.env.NEXT_PUBLIC_PORTAL_ENABLED ?? 'false',
  NEXT_PUBLIC_DEV_LOGIN_ENABLED:
    process.env.NEXT_PUBLIC_DEV_LOGIN_ENABLED ??
    (isNonProduction ? 'true' : 'false'),
  // Explicitly handle LOG_INGESTION_TOKEN - only include if valid, otherwise exclude
  ...(process.env.LOG_INGESTION_TOKEN &&
  process.env.LOG_INGESTION_TOKEN.length >= 32
    ? { LOG_INGESTION_TOKEN: process.env.LOG_INGESTION_TOKEN }
    : { LOG_INGESTION_TOKEN: undefined }),
};

const optionalString = z
  .string()
  .transform(val => {
    const trimmed = val.trim();
    return trimmed === '' ? undefined : trimmed;
  })
  .optional();

export const envSchema = z.object({
  NODE_ENV: z
    .enum(['development', 'test', 'production'])
    .default('development'),
  PORTAL_ENABLED: booleanSchema.optional().default(false),
  GITHUB_CLIENT_ID: optionalString,
  GITHUB_CLIENT_SECRET: optionalString,
  GITHUB_APP_ID: optionalString,
  GITHUB_APP_WEBHOOK_SECRET: optionalString,
  GITHUB_PRIVATE_KEY: optionalString,
  OPENAI_API_KEY: optionalString,
  OPENAI_MODEL: z
    .string()
    .transform(val => {
      const trimmed = val.trim();
      if (isValidOpenAIModel(trimmed)) {
        return trimmed;
      } else {
        console.warn(
          `[ENV FALLBACK] Invalid OPENAI_MODEL "${trimmed}". Using fallback "${OPENAI_MODEL_FALLBACK}".`
        );
        return OPENAI_MODEL_FALLBACK;
      }
    })
    .default(OPENAI_MODEL_FALLBACK),
  OPENAI_MAX_TOKENS: z
    .union([z.string(), z.number()])
    .transform(val => {
      if (isValidMaxTokens(val)) {
        return typeof val === 'string' ? parseInt(val, 10) : val;
      } else {
        console.warn(
          `[ENV FALLBACK] Invalid OPENAI_MAX_TOKENS "${val}". Using fallback "${OPENAI_MAX_TOKENS_FALLBACK}".`
        );
        return OPENAI_MAX_TOKENS_FALLBACK;
      }
    })
    .default(OPENAI_MAX_TOKENS_FALLBACK),
  SESSION_MAX_AGE_DAYS: z.coerce.number().min(1).max(30).default(7),
  IDLE_TIMEOUT_MINUTES: z.coerce.number().min(5).max(120).default(15),
  DEV_LOGIN_ENABLED: booleanSchema.optional().default(false),
  DEV_LOGIN_EMAIL: z.string().email().optional(),
  DEV_LOGIN_NAME: z.string().min(1).optional(),
  DEV_LOGIN_PASSWORD: z.string().optional(),
  NEXT_PUBLIC_PORTAL_ENABLED: booleanSchema.optional().default(false),
  NEXT_PUBLIC_DEV_LOGIN_ENABLED: booleanSchema.optional().default(false),
  LOG_INGESTION_TOKEN: optionalString.refine(
    value => value === undefined || value.length >= 32,
    'LOG_INGESTION_TOKEN must be at least 32 characters'
  ),
  // Supabase URLs - use real values if set, otherwise use placeholders for build
  NEXT_PUBLIC_SUPABASE_URL: z
    .string()
    .url()
    .refine(url => {
      // Warn if using placeholder in production
      if (
        url.includes('placeholder') &&
        process.env.NODE_ENV === 'production'
      ) {
        console.warn(
          '⚠️ WARNING: Using placeholder Supabase URL in production!'
        );
        console.warn('Set NEXT_PUBLIC_SUPABASE_URL environment variable');
      }
      return true;
    }, 'Invalid Supabase URL')
    .default('https://placeholder.supabase.co'),
  NEXT_PUBLIC_SUPABASE_ANON_KEY: z
    .string()
    .refine(key => {
      // Warn if using placeholder in production
      if (
        key.includes('placeholder') &&
        process.env.NODE_ENV === 'production'
      ) {
        console.warn(
          '⚠️ WARNING: Using placeholder Supabase anon key in production!'
        );
        console.warn('Set NEXT_PUBLIC_SUPABASE_ANON_KEY environment variable');
      }
      return true;
    }, 'Invalid Supabase anon key')
    .default('placeholder-anon-key'),
  SUPABASE_SERVICE_ROLE_KEY: optionalString,
  TURNSTILE_SECRET_KEY: optionalString,
  NEXT_PUBLIC_TURNSTILE_SITE_KEY: optionalString,
  NEXT_PUBLIC_APP_URL: z.string().url().default('http://localhost:3000'),
  NEXTAUTH_SECRET: z.string().min(32).optional(),
  NEXTAUTH_URL: z.string().url().optional(),
  TAX_NEXUS_STATES: z.string().default('CA,NY,TX,FL,WA'),
});

export type Env = z.infer<typeof envSchema>;

let parsedEnv: Env | null = null;

export const getEnv = (): Env => {
  if (parsedEnv) {
    return parsedEnv;
  }

  // Diagnostic logging for Supabase env vars
  // Only log in development environment and avoid sensitive data
  if (process.env.NODE_ENV === 'development') {
    // Removed logging of env details for security
  }

  try {
    parsedEnv = envSchema.parse(rawEnv);

    if (
      typeof window === 'undefined' &&
      process.env.NODE_ENV === 'development'
    ) {
      // Removed logging for security
    }

    // Check for VERCEL_TOKEN (required for honeypot deployment)
    // Only check on server-side to avoid client-side process.env access
    if (typeof window === 'undefined' && !process.env.VERCEL_TOKEN) {
      console.warn(
        '[ENV WARN] VERCEL_TOKEN not set - honeypot deployment will fail'
      );
      console.warn(
        '[ENV WARN] Set VERCEL_TOKEN in Vercel dashboard with Deployments (Full) and Projects (Full) scopes'
      );
    } else if (typeof window === 'undefined') {
      // VERCEL_TOKEN is configured (not logged for security)
    }

    return parsedEnv;
  } catch (error) {
    console.error('[ENV ERROR] Failed to parse environment variables:', error);
    throw error;
  }
};

// Create a lazy proxy for env that only validates when accessed
export const env = new Proxy({} as Env, {
  get(target, prop) {
    const parsedEnv = getEnv();
    return parsedEnv[prop as keyof Env];
  },
});

// Safe exports that don't trigger validation at module load time
export const isProduction = typeof window === 'undefined' && process.env.NODE_ENV === 'production';
export const isDevelopment = typeof window === 'undefined' && process.env.NODE_ENV === 'development';

// These access env lazily through the proxy
export const getIsPortalEnabled = (): boolean => {
  return env.PORTAL_ENABLED || env.NEXT_PUBLIC_PORTAL_ENABLED;
};

export const getTaxNexusStates = (): string[] => {
  return env.TAX_NEXUS_STATES.split(',')
    .map(code => code.trim().toUpperCase())
    .filter(Boolean);
};
