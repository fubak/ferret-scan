/**
 * WatchMode Tests
 * Tests for the debounce function and createChangeNotifier exported from WatchMode.ts
 */

// Mock Scanner to avoid ora (ESM-only) import issues
jest.mock('../scanner/Scanner.js', () => ({
  scan: jest.fn().mockResolvedValue({ findings: [] }),
}));

// Mock ConsoleReporter
jest.mock('../reporters/ConsoleReporter.js', () => ({
  generateConsoleReport: jest.fn().mockReturnValue('mock report'),
}));

import { createChangeNotifier } from '../scanner/WatchMode.js';

import { EventEmitter } from 'events';

class MockWatcher extends EventEmitter {
  close() { return Promise.resolve(); }
  getWatched() { return {}; }
}

let _mockWatcherInstance: MockWatcher | null = null;
const mockWatch = jest.fn((..._args: unknown[]) => {
  _mockWatcherInstance = new MockWatcher();
  return _mockWatcherInstance;
});

// Mock chokidar so we don't need real file watching
jest.mock('chokidar', () => ({
  __esModule: true,
  default: {
    watch: (...args: unknown[]) => mockWatch(...args),
  },
}));

function getWatcherInstance(): MockWatcher {
  return _mockWatcherInstance!;
}

describe('createChangeNotifier', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    jest.useFakeTimers();
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  it('returns a cleanup function', () => {
    const cleanup = createChangeNotifier(['/tmp'], jest.fn(), { debounceMs: 100 });
    expect(typeof cleanup).toBe('function');
    cleanup();
  });

  it('calls chokidar.watch with the given paths', () => {
    createChangeNotifier(['/project', '/home'], jest.fn(), { debounceMs: 100 });
    expect(mockWatch).toHaveBeenCalledWith(
      ['/project', '/home'],
      expect.any(Object)
    );
  });

  it('does not invoke callback before debounce period', () => {
    const callback = jest.fn();
    createChangeNotifier(['/tmp'], callback, { debounceMs: 500 });

    const watcher = getWatcherInstance();
    watcher.emit('all', 'change', '/tmp/file.md');
    // No time advance yet
    expect(callback).not.toHaveBeenCalled();
    const cleanup = createChangeNotifier(['/tmp'], callback, { debounceMs: 500 });
    cleanup();
  });

  it('invokes callback after debounce period with changed files', () => {
    const callback = jest.fn();
    createChangeNotifier(['/tmp'], callback, { debounceMs: 500 });

    const watcher = getWatcherInstance();
    watcher.emit('all', 'add', '/tmp/file1.md');
    watcher.emit('all', 'change', '/tmp/file2.md');

    jest.advanceTimersByTime(600);
    expect(callback).toHaveBeenCalledTimes(1);
    expect(callback).toHaveBeenCalledWith(
      expect.arrayContaining(['/tmp/file1.md', '/tmp/file2.md'])
    );
  });

  it('ignores non-add/change/unlink events', () => {
    const callback = jest.fn();
    createChangeNotifier(['/tmp'], callback, { debounceMs: 100 });

    const watcher = getWatcherInstance();
    watcher.emit('all', 'ready', '/tmp');
    watcher.emit('all', 'error', '/tmp');

    jest.advanceTimersByTime(200);
    expect(callback).not.toHaveBeenCalled();
  });

  it('debounces rapid file changes', () => {
    const callback = jest.fn();
    createChangeNotifier(['/tmp'], callback, { debounceMs: 300 });

    const watcher = getWatcherInstance();

    // Fire multiple change events rapidly
    for (let i = 0; i < 5; i++) {
      watcher.emit('all', 'change', `/tmp/file${i}.md`);
      jest.advanceTimersByTime(50);
    }

    // Not called yet
    expect(callback).not.toHaveBeenCalled();

    // Advance past debounce
    jest.advanceTimersByTime(400);
    // Should have been called once with all files
    expect(callback).toHaveBeenCalledTimes(1);
  });

  it('cleanup calls watcher.close()', () => {
    const cleanup = createChangeNotifier(['/tmp'], jest.fn(), { debounceMs: 100 });
    const watcher = getWatcherInstance();
    const closeSpy = jest.spyOn(watcher, 'close');
    cleanup();
    expect(closeSpy).toHaveBeenCalled();
  });
});
