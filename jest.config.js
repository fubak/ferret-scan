/** @type {import('jest').Config} */
const config = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/test', '<rootDir>/src'],
  testMatch: ['**/*.test.ts'],
  moduleFileExtensions: ['ts', 'js', 'json'],
  moduleNameMapper: {
    '^(\\.{1,2}/.*)\\.js$': '$1',
  },
  transform: {
    '^.+\\.ts$': ['ts-jest', {
      tsconfig: {
        module: 'CommonJS',
        moduleResolution: 'node',
        esModuleInterop: true,
      },
    }],
    // chalk v5+ is ESM-only; Babel transform allows Jest to import it in CJS mode
    '^.+\\.m?js$': ['babel-jest', { presets: [['@babel/preset-env', { targets: { node: 'current' } }]] }],
  },
  // Allow transformation of ESM-only node_modules (chalk, ansi-styles, etc.)
  transformIgnorePatterns: [
    '/node_modules/(?!(chalk|#ansi-styles|ansi-styles|supports-color)/)',
  ],
  collectCoverageFrom: [
    'src/**/*.ts',
    '!src/**/*.d.ts',
    '!src/**/*.test.ts',
  ],
  coverageDirectory: 'coverage',
  coverageReporters: ['text', 'lcov', 'html'],
  // Thresholds lock in Phase 2/3 coverage gains. Set at ~5% below current values
  // so routine refactors don't trip the CI gate, but silent regressions will fail.
  coverageThreshold: {
    global: {
      branches:   20,
      functions:  29,
      lines:      30,
      statements: 30,
    },
    './src/remediation/Fixer.ts': {
      lines:     73,
      functions: 75,
    },
    './src/remediation/Quarantine.ts': {
      lines:     75,
      functions: 95,
    },
    './src/utils/safeRegex.ts': {
      lines: 92,
    },
    './src/utils/glob.ts': {
      lines: 83,
    },
    './src/utils/contentCache.ts': {
      lines: 95,
    },
    './src/features/policyEnforcement.ts': {
      lines: 67,
    },
    './src/analyzers/AstAnalyzer.ts': {
      lines: 72,
    },
    './src/reporters/ConsoleReporter.ts': {
      lines: 82,
    },
    './src/reporters/HtmlReporter.ts': {
      lines: 75,
    },
    './src/reporters/SarifReporter.ts': {
      lines: 85,
    },
    './src/reporters/CsvReporter.ts': {
      lines: 95,
    },
    './src/scanner/WatchMode.ts': {
      lines: 46,
    },
  },
  verbose: true,
  testTimeout: 10000,
};

export default config;
