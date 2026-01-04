export type LogLevel = 'error' | 'warn' | 'info' | 'debug' | 'http';

export type LogFunction = (message: string, data?: unknown) => void;

export type LoggerLike = Record<LogLevel, LogFunction>;
