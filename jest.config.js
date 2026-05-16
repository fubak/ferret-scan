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
  // Target: 60%+ global coverage with real integrated tests (achieved ~55% in current push).
  // Long-term stretch: 80%+ on core logic.
  coverageThreshold: {
    global: {
      branches:   40,
      functions:  52,
      lines:      58,
      statements: 58,
    },
    './src/scanner/Scanner.ts': {
      lines: 80,
      functions: 83,
      branches: 58,
    },
    './src/scanner/PatternMatcher.ts': {
      lines: 91,
      functions: 79,
    },
    './src/scanner/FileDiscovery.ts': {
      lines: 70,
      functions: 72,
      branches: 56,
    },
    './src/scanner/reporting.ts': {
      lines: 95,
      functions: 90,
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
