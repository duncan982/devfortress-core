import type { LogFunction, LoggerLike } from './logger/types';

const isBrowser = typeof window !== 'undefined';

const createBrowserLogger = (): LoggerLike => {
  const noop: LogFunction = () => undefined;

  return {
    error: noop,
    warn: noop,
    info: noop,
    debug: noop,
    http: noop,
  };
};

const createServerLogger = async (): Promise<LoggerLike> => {
  try {
    // Dynamic imports to avoid bundling Node.js modules in browser
    const winston = await import('winston');
    const path = await import('path');
    const fs = await import('fs');

    // Detect serverless environment (Vercel, AWS Lambda, etc.)
    const isServerless =
      process.env.VERCEL === '1' ||
      process.env.AWS_LAMBDA_FUNCTION_NAME !== undefined ||
      process.env.LAMBDA_TASK_ROOT !== undefined;

    const levels = {
      error: 0,
      warn: 1,
      info: 2,
      http: 3,
      debug: 4,
    } as const;

    const colors = {
      error: 'red',
      warn: 'yellow',
      info: 'green',
      http: 'magenta',
      debug: 'blue',
    } as const;

    winston.addColors(colors);

    const format = winston.format.combine(
      winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss:ms' }),
      winston.format.colorize({ all: true }),
      winston.format.printf(
        info => `${info.timestamp} - ${info.level}: ${info.message}`
      )
    );

    const transportList: any[] = [
      new winston.transports.Console({
        format: winston.format.combine(
          winston.format.colorize(),
          winston.format.simple()
        ),
        handleExceptions: true,
        handleRejections: true,
      }),
    ];

    // Only add file transports in non-serverless environments
    if (!isServerless) {
      const { default: DailyRotateFile } =
        await import('winston-daily-rotate-file');

      const logsDir = path.join(process.cwd(), 'logs');

      try {
        if (!fs.existsSync(logsDir)) {
          fs.mkdirSync(logsDir, { recursive: true });
        }

        transportList.push(
          new DailyRotateFile({
            filename: path.join(logsDir, 'error-%DATE%.log'),
            datePattern: 'YYYY-MM-DD',
            level: 'error',
            maxSize: '20m',
            maxFiles: '7d',
            format: winston.format.combine(
              winston.format.timestamp(),
              winston.format.json()
            ),
            handleExceptions: true,
            handleRejections: true,
          }),
          new DailyRotateFile({
            filename: path.join(logsDir, 'app-%DATE%.log'),
            datePattern: 'YYYY-MM-DD',
            maxSize: '20m',
            maxFiles: '7d',
            format: winston.format.combine(
              winston.format.timestamp(),
              winston.format.json()
            ),
          })
        );
      } catch (error) {
        // Silently fall back to console-only logging if file system is unavailable
        // Note: Using console.warn here is intentional as logger is not yet initialized
        // eslint-disable-next-line no-console
        console.warn('File logging disabled - filesystem unavailable:', error);
      }
    }

    const baseLogger = winston.createLogger({
      level: process.env.LOG_LEVEL || 'info',
      levels,
      format,
      transports: transportList,
      exitOnError: false,
    });

    return {
      error: (message: string, data?: unknown) =>
        baseLogger.error(message, data),
      warn: (message: string, data?: unknown) => baseLogger.warn(message, data),
      info: (message: string, data?: unknown) => baseLogger.info(message, data),
      debug: (message: string, data?: unknown) =>
        baseLogger.debug(message, data),
      http: (message: string, data?: unknown) => baseLogger.http(message, data),
    };
  } catch (error) {
    // Fallback to console logging if Winston fails to load
    // eslint-disable-next-line no-console
    console.warn('Winston logging failed, falling back to console:', error);
    return createBrowserLogger();
  }
};

let logger: LoggerLike | null = null;

const getLogger = async (): Promise<LoggerLike> => {
  if (logger) return logger;

  if (isBrowser) {
    logger = createBrowserLogger();
  } else {
    logger = await createServerLogger();
  }

  return logger;
};

/** Default logger instance for application-wide logging. */
export default logger;

/**
 * Logs an error message with optional error details.
 * Enhanced with security audit fields: timestamp, source IP, session token.
 * @param message - The error message to log.
 * @param error - Optional error object or details.
 * @param context - Optional context including IP, sessionToken, userId for security auditing.
 */
export const logError = async (
  message: string,
  error?: unknown,
  context?: { ip?: string; sessionToken?: string; userId?: string }
) => {
  const loggerInstance = await getLogger();
  loggerInstance.error(message, {
    timestamp: new Date().toISOString(),
    error: error instanceof Error ? error.message : error,
    stack: error instanceof Error ? error.stack : undefined,
    sourceIp: context?.ip,
    sessionToken: context?.sessionToken,
    userId: context?.userId,
  });
};

/**
 * Logs a warning message with optional data.
 * Enhanced with security audit fields: timestamp, source IP, session token.
 * @param message - The warning message to log.
 * @param data - Optional additional data to log.
 * @param context - Optional context including IP, sessionToken, userId for security auditing.
 */
export const logWarn = async (
  message: string,
  data?: unknown,
  context?: { ip?: string; sessionToken?: string; userId?: string }
) => {
  const loggerInstance = await getLogger();
  loggerInstance.warn(message, {
    timestamp: new Date().toISOString(),
    data,
    sourceIp: context?.ip,
    sessionToken: context?.sessionToken,
    userId: context?.userId,
  });
};

/**
 * Logs an info message with optional data.
 * Enhanced with security audit fields: timestamp, source IP, session token.
 * @param message - The info message to log.
 * @param data - Optional additional data to log.
 * @param context - Optional context including IP, sessionToken, userId for security auditing.
 */
export const logInfo = async (
  message: string,
  data?: unknown,
  context?: { ip?: string; sessionToken?: string; userId?: string }
) => {
  const loggerInstance = await getLogger();
  loggerInstance.info(message, {
    timestamp: new Date().toISOString(),
    data,
    sourceIp: context?.ip,
    sessionToken: context?.sessionToken,
    userId: context?.userId,
  });
};

/**
 * Logs a debug message with optional data.
 * Enhanced with security audit fields: timestamp, source IP, session token.
 * @param message - The debug message to log.
 * @param data - Optional additional data to log.
 * @param context - Optional context including IP, sessionToken, userId for security auditing.
 */
export const logDebug = async (
  message: string,
  data?: unknown,
  context?: { ip?: string; sessionToken?: string; userId?: string }
) => {
  const loggerInstance = await getLogger();
  loggerInstance.debug(message, {
    timestamp: new Date().toISOString(),
    data,
    sourceIp: context?.ip,
    sessionToken: context?.sessionToken,
    userId: context?.userId,
  });
};

/**
 * Logs an HTTP-related message with optional data.
 * @param message - The HTTP message to log.
 * @param data - Optional additional data to log.
 */
export const logHttp = async (message: string, data?: unknown) => {
  const loggerInstance = await getLogger();
  loggerInstance.http(message, data);
};
