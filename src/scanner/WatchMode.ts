/**
 * WatchMode - Real-time file watching and scanning
 * Monitors files for changes and automatically rescans
 */

import chokidar from 'chokidar';
import type { ScannerConfig } from '../types.js';
import { scan } from './Scanner.js';
import { generateConsoleReport } from '../reporters/ConsoleReporter.js';
import logger from '../utils/logger.js';

interface WatchOptions {
  debounceMs: number;
  batchChanges: boolean;
  ignored: string[];
}

interface WatchEvent {
  type: 'add' | 'change' | 'unlink';
  path: string;
  timestamp: Date;
}

const DEFAULT_WATCH_OPTIONS: WatchOptions = {
  debounceMs: 1000, // Wait 1 second after last change
  batchChanges: true, // Batch multiple changes together
  ignored: [
    '**/node_modules/**',
    '**/.git/**',
    '**/dist/**',
    '**/build/**',
    '**/*.log',
    '**/tmp/**',
    '**/.DS_Store',
  ],
};

/**
 * Debounce function calls
 */
function debounce<T extends any[]>(
  func: (...args: T) => void,
  wait: number
): (...args: T) => void {
  let timeout: NodeJS.Timeout;
  return (...args: T) => {
    clearTimeout(timeout);
    timeout = setTimeout(() => func(...args), wait);
  };
}

/**
 * Start watching files and scanning on changes
 */
export async function startWatchMode(
  config: ScannerConfig,
  options: Partial<WatchOptions> = {}
): Promise<() => void> {
  const watchOptions = { ...DEFAULT_WATCH_OPTIONS, ...options };
  const events: WatchEvent[] = [];
  let isScanning = false;

  logger.info(`🔍 Starting watch mode for: ${config.paths.join(', ')}`);
  logger.info(`⏱️  Debounce: ${watchOptions.debounceMs}ms`);

  // Initial scan
  console.log('🚀 Running initial scan...\n');
  const initialResult = await scan(config);
  const initialReport = generateConsoleReport(initialResult, {
    verbose: config.verbose,
    ci: config.ci,
  });
  console.log(initialReport);
  console.log('\n👀 Watching for changes...\n');

  // Debounced scan function
  const debouncedScan = debounce(async () => {
    if (isScanning) {
      logger.debug('Scan already in progress, skipping');
      return;
    }

    isScanning = true;
    const changedFiles = events.splice(0); // Clear events

    try {
      logger.info(`📝 File changes detected: ${changedFiles.length} event(s)`);

      if (config.verbose) {
        for (const event of changedFiles.slice(0, 5)) { // Show max 5 files
          const icon = event.type === 'add' ? '➕' : event.type === 'change' ? '📝' : '➖';
          logger.info(`   ${icon} ${event.path}`);
        }
        if (changedFiles.length > 5) {
          logger.info(`   ... and ${changedFiles.length - 5} more`);
        }
      }

      console.log('🔄 Rescanning...\n');
      const result = await scan(config);

      // Clear previous output and show new results
      if (!config.verbose && !config.ci) {
        process.stdout.write('\x1Bc'); // Clear screen
      }

      const report = generateConsoleReport(result, {
        verbose: config.verbose,
        ci: config.ci,
      });
      console.log(report);

      const timestamp = new Date().toLocaleTimeString();
      console.log(`\n✅ Scan completed at ${timestamp}`);
      console.log('👀 Watching for changes...\n');

    } catch (error) {
      console.error('❌ Scan failed:', error instanceof Error ? error.message : String(error));
    } finally {
      isScanning = false;
    }
  }, watchOptions.debounceMs);

  // Set up file watcher
  const watcher = chokidar.watch(config.paths, {
    ignored: [
      ...watchOptions.ignored,
      ...config.ignore.map(pattern => `**/${pattern}`),
    ],
    persistent: true,
    ignoreInitial: true, // Don't trigger on initial scan
    followSymlinks: false,
    depth: 10, // Reasonable recursion depth
    awaitWriteFinish: {
      stabilityThreshold: 100,
      pollInterval: 50,
    },
  });

  // Watch event handlers
  watcher.on('add', (path) => {
    events.push({ type: 'add', path, timestamp: new Date() });
    if (config.verbose) {
      logger.debug(`File added: ${path}`);
    }
    debouncedScan();
  });

  watcher.on('change', (path) => {
    events.push({ type: 'change', path, timestamp: new Date() });
    if (config.verbose) {
      logger.debug(`File changed: ${path}`);
    }
    debouncedScan();
  });

  watcher.on('unlink', (path) => {
    events.push({ type: 'unlink', path, timestamp: new Date() });
    if (config.verbose) {
      logger.debug(`File removed: ${path}`);
    }
    debouncedScan();
  });

  watcher.on('error', (error) => {
    console.error('❌ Watch error:', error);
  });

  watcher.on('ready', () => {
    const watched = watcher.getWatched();
    const watchedCount = Object.keys(watched).length;
    logger.info(`👁️  Watching ${watchedCount || 'multiple'} directories`);
  });

  // Handle graceful shutdown
  const cleanup = () => {
    logger.info('🛑 Stopping watch mode...');
    watcher.close();
  };

  process.on('SIGINT', cleanup);
  process.on('SIGTERM', cleanup);

  // Return cleanup function
  return cleanup;
}

/**
 * Watch mode with enhanced console output
 */
export async function startEnhancedWatchMode(
  config: ScannerConfig,
  options: Partial<WatchOptions> = {}
): Promise<() => void> {
  // Enhanced version with better UX
  const watchOptions = { ...DEFAULT_WATCH_OPTIONS, ...options };

  console.log('🚀 Ferret Watch Mode Starting...\n');
  console.log(`📂 Watching: ${config.paths.join(', ')}`);
  console.log(`⚙️  Debounce: ${watchOptions.debounceMs}ms`);
  console.log(`🔍 Severities: ${config.severities.join(', ')}`);
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

  return startWatchMode(config, options);
}

/**
 * Create a simple file change notifier
 */
export function createChangeNotifier(
  paths: string[],
  callback: (changedFiles: string[]) => void,
  options: Partial<WatchOptions> = {}
): () => void {
  const watchOptions = { ...DEFAULT_WATCH_OPTIONS, ...options };
  const changedFiles: string[] = [];

  const debouncedCallback = debounce(() => {
    const files = [...changedFiles];
    changedFiles.length = 0; // Clear array
    callback(files);
  }, watchOptions.debounceMs);

  const watcher = chokidar.watch(paths, {
    ignored: watchOptions.ignored,
    persistent: true,
    ignoreInitial: true,
  });

  watcher.on('all', (event, path) => {
    if (['add', 'change', 'unlink'].includes(event)) {
      changedFiles.push(path);
      debouncedCallback();
    }
  });

  return () => watcher.close();
}

export default { startWatchMode, startEnhancedWatchMode, createChangeNotifier };