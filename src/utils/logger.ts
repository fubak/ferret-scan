/**
 * Logger utility for Ferret-Scan
 * Provides consistent logging with levels and formatting
 */

import type { Severity } from '../types.js';

export type LogLevel = 'debug' | 'info' | 'warn' | 'error' | 'silent';

interface LoggerConfig {
  level: LogLevel;
  verbose: boolean;
  ci: boolean;
}

const LOG_LEVELS: Record<LogLevel, number> = {
  debug: 0,
  info: 1,
  warn: 2,
  error: 3,
  silent: 4,
};

class Logger {
  private config: LoggerConfig = {
    level: 'info',
    verbose: false,
    ci: false,
  };

  configure(config: Partial<LoggerConfig>): void {
    this.config = { ...this.config, ...config };
  }

  private shouldLog(level: LogLevel): boolean {
    return LOG_LEVELS[level] >= LOG_LEVELS[this.config.level];
  }

  private formatMessage(level: LogLevel, message: string): string {
    if (this.config.ci) {
      return `[${level.toUpperCase()}] ${message}`;
    }
    const timestamp = new Date().toISOString();
    return `[${timestamp}] [${level.toUpperCase()}] ${message}`;
  }

  debug(message: string, ...args: unknown[]): void {
    if (this.shouldLog('debug') && this.config.verbose) {
      console.error(this.formatMessage('debug', message), ...args);
    }
  }

  info(message: string, ...args: unknown[]): void {
    if (this.shouldLog('info')) {
      console.error(this.formatMessage('info', message), ...args);
    }
  }

  warn(message: string, ...args: unknown[]): void {
    if (this.shouldLog('warn')) {
      console.error(this.formatMessage('warn', message), ...args);
    }
  }

  error(message: string, ...args: unknown[]): void {
    if (this.shouldLog('error')) {
      console.error(this.formatMessage('error', message), ...args);
    }
  }

  /** Log without any formatting - for direct output */
  raw(message: string): void {
    if (this.config.level !== 'silent') {
      console.error(message);
    }
  }

  /** Log finding with severity-appropriate formatting */
  finding(severity: Severity, message: string): void {
    if (this.shouldLog('info')) {
      console.error(`[${severity}] ${message}`);
    }
  }

  /** Get current log level */
  getLevel(): LogLevel {
    return this.config.level;
  }

  /** Check if verbose mode is enabled */
  isVerbose(): boolean {
    return this.config.verbose;
  }
}

// Singleton logger instance
export const logger = new Logger();

export default logger;
