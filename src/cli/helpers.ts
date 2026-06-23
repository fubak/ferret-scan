import type { CliOptions } from '../types.js';
import { loadConfig } from '../utils/config.js';
import { logger } from '../utils/logger.js';

export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/** Build CliOptions without explicitly setting undefined optional properties. */
export function buildCliOptions(
  options: { [K in keyof CliOptions]?: CliOptions[K] | undefined },
): CliOptions {
  return Object.fromEntries(
    Object.entries(options).filter(([, value]) => value !== undefined)
  ) as CliOptions;
}

export function loadConfigForPath(path: string | undefined, options: CliOptions = {}): ReturnType<typeof loadConfig> {
  return loadConfig(buildCliOptions({ ...options, ...(path !== undefined ? { path } : {}) }));
}

export function configureCliLogger(options: { verbose?: boolean | undefined; ci?: boolean | undefined }): void {
  const config: { verbose?: boolean; ci?: boolean; level: 'debug' | 'info' } = {
    level: options.verbose ? 'debug' : 'info',
  };
  if (options.verbose !== undefined) {
    config.verbose = options.verbose;
  }
  if (options.ci !== undefined) {
    config.ci = options.ci;
  }
  logger.configure(config);
}
