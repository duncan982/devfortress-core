// Mock winston and other Node.js modules for testing
jest.mock('winston', () => ({
  format: {
    combine: jest.fn(() => 'combined-format'),
    timestamp: jest.fn(() => 'timestamp-format'),
    colorize: jest.fn(() => 'colorize-format'),
    printf: jest.fn(() => 'printf-format'),
    json: jest.fn(() => 'json-format'),
  },
  transports: {
    Console: jest.fn(),
    File: jest.fn(),
  },
  createLogger: jest.fn(() => ({
    error: jest.fn(),
    warn: jest.fn(),
    info: jest.fn(),
    debug: jest.fn(),
    http: jest.fn(),
  })),
  addColors: jest.fn(),
}));

jest.mock('path', () => ({
  join: jest.fn((...args) => args.join('/')),
}));

jest.mock('fs', () => ({
  existsSync: jest.fn(() => true),
  mkdirSync: jest.fn(),
}));

describe('Logger', () => {
  describe('Browser Logger', () => {
    it('should create a browser logger with noop functions', async () => {
      // Mock browser environment
      (globalThis as unknown as { window: unknown }).window = {};

      const { logError, logWarn, logInfo, logDebug } = await import('../../lib/logger');

      // Call the functions - they should not throw
      expect(() => logError('test')).not.toThrow();
      expect(() => logWarn('test')).not.toThrow();
      expect(() => logInfo('test')).not.toThrow();
      expect(() => logDebug('test')).not.toThrow();

      delete (globalThis as unknown as { window?: unknown }).window;
    });
  });

  describe('Server Logger', () => {
    it('should create a server logger with Winston', async () => {
      const { logError, logWarn, logInfo, logDebug } = await import('../../lib/logger');

      // Call the functions - they should not throw
      expect(() => logError('test')).not.toThrow();
      expect(() => logWarn('test')).not.toThrow();
      expect(() => logInfo('test')).not.toThrow();
      expect(() => logDebug('test')).not.toThrow();
    });
  });
});