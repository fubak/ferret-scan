import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals';
import type { ScannerConfig } from '../../src/types.js';

// ── Module mocks ───────────────────────────────────────────────────────────
// Must be declared before any imports that transitively load these modules.

type MockWatcher = {
  on: jest.MockedFunction<(event: string, handler: (...args: unknown[]) => unknown) => MockWatcher>;
  close: jest.MockedFunction<() => Promise<void>>;
  getWatched: jest.MockedFunction<() => Record<string, string[]>>;
  _handlers: Map<string, ((...args: unknown[]) => unknown)[]>;
};

function createMockWatcher(): MockWatcher {
  const handlers = new Map<string, ((...args: unknown[]) => unknown)[]>();
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const onFn: any = jest.fn().mockImplementation((event: unknown, handler: unknown) => {
    const key = String(event);
    const existing = handlers.get(key) ?? [];
    handlers.set(key, [...existing, handler as (...args: unknown[]) => unknown]);
    return watcher;
  });
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const closeFn: any = jest.fn().mockResolvedValue(undefined as never);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const getWatchedFn: any = jest.fn().mockReturnValue({ '/tmp': ['file.sh'] });
  const watcher: MockWatcher = {
    _handlers: handlers,
    on: onFn as MockWatcher['on'],
    close: closeFn as MockWatcher['close'],
    getWatched: getWatchedFn as MockWatcher['getWatched'],
  };
  return watcher;
}

let mockWatcher: MockWatcher;

jest.mock('chokidar', () => {
  return {
    __esModule: true,
    default: {
      watch: jest.fn().mockImplementation(() => mockWatcher),
    },
  };
});

const mockScanResult = {
  success: true,
  startTime: new Date(),
  endTime: new Date(),
  duration: 10,
  scannedPaths: ['/tmp'],
  totalFiles: 1,
  analyzedFiles: 1,
  skippedFiles: 0,
  findings: [],
  findingsBySeverity: { CRITICAL: [], HIGH: [], MEDIUM: [], LOW: [], INFO: [] },
  findingsByCategory: {
    exfiltration: [], credentials: [], injection: [], backdoors: [],
    'supply-chain': [], permissions: [], persistence: [], obfuscation: [],
    'ai-specific': [], 'advanced-hiding': [], behavioral: [],
  },
  overallRiskScore: 0,
  summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 },
  errors: [],
};

jest.mock('../../src/scanner/Scanner.js', () => ({
  scan: jest.fn().mockImplementation(() => Promise.resolve(mockScanResult)),
}));

// Import after mocks are declared
import chokidar from 'chokidar';
import { startWatchMode, createChangeNotifier } from '../../src/scanner/WatchMode.js';

// ── Helpers ────────────────────────────────────────────────────────────────

function makeConfig(overrides: Partial<ScannerConfig> = {}): ScannerConfig {
  return {
    paths: ['/tmp/test-watch'],
    severities: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'],
    categories: ['exfiltration', 'credentials', 'injection', 'backdoors', 'supply-chain',
      'permissions', 'persistence', 'obfuscation', 'ai-specific', 'advanced-hiding', 'behavioral'],
    ignore: [],
    failOn: 'CRITICAL',
    watch: true,
    threatIntel: false,
    semanticAnalysis: false,
    correlationAnalysis: false,
    autoRemediation: false,
    contextLines: 3,
    maxFileSize: 10_000_000,
    format: 'console',
    verbose: false,
    ci: false,
    ...overrides,
  };
}

// ── Tests ──────────────────────────────────────────────────────────────────

describe('WatchMode', () => {
  let consoleSpy: ReturnType<typeof jest.spyOn>;

  beforeEach(() => {
    mockWatcher = createMockWatcher();
    // Suppress console.log/console.error output during tests
    consoleSpy = jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    jest.restoreAllMocks();
    jest.useRealTimers();
  });

  describe('startWatchMode', () => {
    it('calls chokidar.watch with the configured paths', async () => {
      const config = makeConfig({ paths: ['/project/src', '/project/config'] });
      await startWatchMode(config);

      expect(chokidar.watch).toHaveBeenCalledWith(
        ['/project/src', '/project/config'],
        expect.objectContaining({ persistent: true, ignoreInitial: true }),
      );
    });

    it('registers handlers for add, change, unlink, error, and ready events', async () => {
      const config = makeConfig();
      await startWatchMode(config);

      expect(mockWatcher.on).toHaveBeenCalledWith('add', expect.any(Function));
      expect(mockWatcher.on).toHaveBeenCalledWith('change', expect.any(Function));
      expect(mockWatcher.on).toHaveBeenCalledWith('unlink', expect.any(Function));
      expect(mockWatcher.on).toHaveBeenCalledWith('error', expect.any(Function));
      expect(mockWatcher.on).toHaveBeenCalledWith('ready', expect.any(Function));
    });

    it('returns a cleanup function that closes the watcher', async () => {
      const config = makeConfig();
      const cleanup = await startWatchMode(config);

      cleanup();

      expect(mockWatcher.close).toHaveBeenCalled();
    });

    it('runs an initial scan on startup', async () => {
      const { scan } = await import('../../src/scanner/Scanner.js');
      jest.clearAllMocks();
      mockWatcher = createMockWatcher();

      const config = makeConfig();
      await startWatchMode(config);

      expect(scan).toHaveBeenCalledWith(config);
    });

    it('logs an error when a watch error occurs', async () => {
      const errorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
      const config = makeConfig();
      await startWatchMode(config);

      const errorHandlers = mockWatcher._handlers.get('error') ?? [];
      expect(errorHandlers.length).toBeGreaterThan(0);
      errorHandlers[0]?.(new Error('disk error'));

      expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining('Watch error'), expect.anything());
    });
  });

  describe('createChangeNotifier', () => {
    it('calls chokidar.watch with the specified paths', () => {
      const paths = ['/a', '/b'];
      const callback = jest.fn();
      createChangeNotifier(paths, callback);

      expect(chokidar.watch).toHaveBeenCalledWith(
        paths,
        expect.objectContaining({ persistent: true, ignoreInitial: true }),
      );
    });

    it('returns a cleanup function', () => {
      const cleanup = createChangeNotifier(['/tmp'], jest.fn());
      expect(typeof cleanup).toBe('function');
      // Calling cleanup should close the watcher without throwing
      expect(() => cleanup()).not.toThrow();
      expect(mockWatcher.close).toHaveBeenCalled();
    });

    it('batches change events and invokes callback after debounce delay', () => {
      jest.useFakeTimers();
      const callback = jest.fn<(files: string[]) => void>();
      createChangeNotifier(['/tmp'], callback, { debounceMs: 200 });

      // Trigger three 'all' events in quick succession
      const allHandlers = mockWatcher._handlers.get('all') ?? [];
      expect(allHandlers.length).toBeGreaterThan(0);
      allHandlers[0]?.('change', '/tmp/a.sh');
      allHandlers[0]?.('add', '/tmp/b.sh');
      allHandlers[0]?.('change', '/tmp/c.sh');

      // Not yet called (debounce pending)
      expect(callback).not.toHaveBeenCalled();

      // Advance past the debounce window
      jest.advanceTimersByTime(201);

      // Called once with all batched files
      expect(callback).toHaveBeenCalledTimes(1);
      expect(callback).toHaveBeenCalledWith(['/tmp/a.sh', '/tmp/b.sh', '/tmp/c.sh']);
    });

    it('ignores events that are not add/change/unlink', () => {
      jest.useFakeTimers();
      const callback = jest.fn();
      createChangeNotifier(['/tmp'], callback, { debounceMs: 50 });

      const allHandlers = mockWatcher._handlers.get('all') ?? [];
      allHandlers[0]?.('raw', '/tmp/something');
      jest.advanceTimersByTime(100);

      expect(callback).not.toHaveBeenCalled();
    });
  });

  describe('console output', () => {
    it('logs scanning info during startWatchMode', async () => {
      consoleSpy.mockRestore();
      const logSpy = jest.spyOn(console, 'log').mockImplementation(() => {});
      const config = makeConfig();
      await startWatchMode(config);

      expect(logSpy).toHaveBeenCalled();
    });
  });
});
