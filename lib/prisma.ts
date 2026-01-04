import { PrismaClient } from '@prisma/client';

// Conditionally import logger only on server-side
const isBrowser = typeof window === 'undefined';
const { logDebug, logWarn, logError } = isBrowser
  ?  
    require('./logger')
  : { logDebug: () => {}, logWarn: () => {}, logError: () => {} };

declare global {
  let prisma: PrismaClient | undefined;
  let prismaConnected: boolean | undefined;
}

/**
 * Initialize Prisma client with enhanced resilience
 * Features:
 * - Connection pooling with configurable limits
 * - Automatic connection retry
 * - Query timeout configuration
 * - Connection lifecycle monitoring
 */
function initializePrisma(): PrismaClient {
  // Build DATABASE_URL with connection pooling parameters if not already present
  let databaseUrl = process.env.DATABASE_URL;
  if (databaseUrl && !databaseUrl.includes('connection_limit=')) {
    const url = new URL(databaseUrl);
    // Set connection pool parameters for better performance
    url.searchParams.set('connection_limit', '10'); // Max 10 connections
    url.searchParams.set('pool_timeout', '20'); // 20 second pool timeout
    url.searchParams.set('connect_timeout', '10'); // 10 second connection timeout
    databaseUrl = url.toString();
  }

  const client = new PrismaClient({
    log: process.env.NODE_ENV === 'development' ? ['warn', 'error'] : ['error'],
    datasources: {
      db: {
        url: databaseUrl,
      },
    },
  });

  // Test database connection with retry logic
  if (
    process.env.NODE_ENV === 'development' &&
    process.env.JEST_WORKER_ID === undefined
  ) {
    client
      .$connect()
      .then(() => {
         
        if (!(global as any).prismaConnected) {
          logDebug('Database connection established successfully');
           
          (global as any).prismaConnected = true;
        }
      })
      .catch(error => {
         
        if ((global as any).prismaConnected !== false) {
          logWarn('Database unavailable, using fallback data', {
            error: error.message,
            hint: 'Start PostgreSQL: docker-compose up -d OR sudo systemctl start postgresql',
          });
           
          (global as any).prismaConnected = false;
        }
      });
  }

  return client;
}

 
export const prisma: PrismaClient = (global as any).prisma ?? initializePrisma();

 
if (!(global as any).prisma) {
   
  (global as any).prisma = prisma;
}

/**
 * Check if database is available
 * Returns true if connected, false otherwise
 */
export async function isDatabaseAvailable(): Promise<boolean> {
  try {
    await prisma.$queryRaw`SELECT 1`;
    return true;
  } catch {
    return false;
  }
}

/**
 * Retry configuration for database operations
 */
const RETRY_CONFIG = {
  maxRetries: 3,
  baseDelay: 1000, // 1 second
  maxDelay: 10000, // 10 seconds
  retryableErrors: [
    'P1001', // Can't reach database server
    'P1002', // Database server timeout
    'P1008', // Operations timed out
    'P1017', // Server has closed the connection
    'P2024', // Timed out fetching connection
  ],
};

/**
 * Retry a database operation with exponential backoff
 */
async function retryOperation<T>(
  operation: () => Promise<T>,
  retries = RETRY_CONFIG.maxRetries
): Promise<T> {
  try {
    return await operation();
  } catch (error) {
    // Check if error is retryable
    const isRetryable =
      error &&
      typeof error === 'object' &&
      'code' in error &&
      typeof error.code === 'string' &&
      RETRY_CONFIG.retryableErrors.includes(error.code);

    if (!isRetryable || retries <= 0) {
      throw error;
    }

    // Calculate delay with exponential backoff
    const attempt = RETRY_CONFIG.maxRetries - retries + 1;
    const delay = Math.min(
      RETRY_CONFIG.baseDelay * Math.pow(2, attempt - 1),
      RETRY_CONFIG.maxDelay
    );

    logWarn('Database operation failed, retrying...', {
      error: error instanceof Error ? error.message : 'Unknown error',
      attempt,
      nextRetryIn: `${delay}ms`,
    });

    // Wait before retry
    await new Promise(resolve => setTimeout(resolve, delay));

    // Retry the operation
    return retryOperation(operation, retries - 1);
  }
}

/**
 * Safely execute a Prisma query with retry and fallback
 * Returns fallback value if all retries fail or database is unavailable
 */
export async function safePrismaQuery<T>(
  queryFn: () => Promise<T>,
  fallbackValue: T
): Promise<T> {
  try {
    return await retryOperation(queryFn);
  } catch (error) {
    if (
      error &&
      typeof error === 'object' &&
      'name' in error &&
      (error.name === 'PrismaClientInitializationError' ||
        error.name === 'PrismaClientKnownRequestError')
    ) {
      logWarn('Database unavailable after retries, using fallback data', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      return fallbackValue;
    }
    // Re-throw other errors
    throw error;
  }
}

/**
 * Get database status for health checks with connection pool metrics
 */
export async function getDatabaseStatus(): Promise<{
  connected: boolean;
  version?: string;
  error?: string;
  poolStatus?: {
    activeConnections?: number;
    idleConnections?: number;
    maxConnections?: number;
  };
  responseTime?: number;
}> {
  const startTime = Date.now();

  try {
    const result = await prisma.$queryRaw<
      Array<{ version: string }>
    >`SELECT version()`;

    const responseTime = Date.now() - startTime;

    // Get connection pool metrics
    const poolMetrics = await prisma.$queryRaw<
      Array<{ count: bigint }>
    >`SELECT COUNT(*) as count FROM pg_stat_activity WHERE datname = current_database()`;

    return {
      connected: true,
      version: result[0]?.version || 'Unknown',
      responseTime,
      poolStatus: {
        activeConnections: Number(poolMetrics[0]?.count || 0),
        maxConnections: 10, // Default pool size
      },
    };
  } catch (error) {
    logError('Database health check failed', { error });
    return {
      connected: false,
      error: error instanceof Error ? error.message : 'Unknown error',
      responseTime: Date.now() - startTime,
    };
  }
}

/**
 * Gracefully close database connection
 * Call this during application shutdown
 */
export async function closeDatabaseConnection(): Promise<void> {
  try {
    await prisma.$disconnect();
    logDebug('Database connection closed successfully');
  } catch (error) {
    logError('Error closing database connection', { error });
  }
}

/**
 * Execute a database query with timeout
 */
export async function queryWithTimeout<T>(
  queryFn: () => Promise<T>,
  timeoutMs = 10000
): Promise<T> {
  return Promise.race([
    queryFn(),
    new Promise<never>((_, reject) =>
      setTimeout(
        () => reject(new Error(`Query timeout after ${timeoutMs}ms`)),
        timeoutMs
      )
    ),
  ]);
}
