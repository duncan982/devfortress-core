/** @type {import('jest').Config} */
module.exports = {
  testEnvironment: 'node',
  transform: {
    // Scoped override: files under packages/core cross the SDK's package boundary and
    // are reached by swc-core's own .swcrc auto-discovery (root .swcrc has an `env`
    // block), which then collides with the jsc.target @swc/jest infers below for files
    // that stay inside this package. swcrc:false stops that discovery for just this path.
    'packages/core/.+\\.(ts|tsx)$': [
      '@swc/jest',
      {
        jsc: {
          parser: {
            syntax: 'typescript',
            tsx: false,
          },
        },
        module: {
          type: 'commonjs',
        },
        swcrc: false,
      },
    ],
    '^.+\\.(ts|tsx)$': [
      '@swc/jest',
      {
        jsc: {
          parser: {
            syntax: 'typescript',
            tsx: false,
          },
        },
        module: {
          type: 'commonjs',
        },
      },
    ],
  },
  testMatch: ['<rootDir>/__tests__/**/*.test.ts'],
  transformIgnorePatterns: ['node_modules/'],
};
