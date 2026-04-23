/**
 * Unit tests for logger.ts
 */

import { describe, it, expect, beforeEach, jest } from '@jest/globals';
import { logger } from '../../src/utils/logger.js';

describe('Logger', () => {
  let consoleSpy: ReturnType<typeof jest.spyOn>;

  beforeEach(() => {
    consoleSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
    logger.configure({ level: 'debug', verbose: true, ci: false });
  });

  afterEach(() => {
    consoleSpy.mockRestore();
    logger.configure({ level: 'info', verbose: false, ci: false });
  });

  describe('configure()', () => {
    it('merges partial config without losing existing values', () => {
      logger.configure({ level: 'warn' });
      logger.configure({ verbose: true });

      // verbose should be true, level should be warn
      expect(logger.isVerbose()).toBe(true);
      expect(logger.getLevel()).toBe('warn');
    });
  });

  describe('getLevel() and isVerbose()', () => {
    it('returns configured log level', () => {
      logger.configure({ level: 'error' });
      expect(logger.getLevel()).toBe('error');
    });

    it('returns verbose flag', () => {
      logger.configure({ verbose: false });
      expect(logger.isVerbose()).toBe(false);

      logger.configure({ verbose: true });
      expect(logger.isVerbose()).toBe(true);
    });
  });

  describe('debug()', () => {
    it('outputs when level is debug and verbose is true', () => {
      logger.configure({ level: 'debug', verbose: true });
      logger.debug('debug message');
      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining('DEBUG'),
        // no extra args
      );
    });

    it('does not output when verbose is false', () => {
      logger.configure({ level: 'debug', verbose: false });
      logger.debug('debug message');
      expect(consoleSpy).not.toHaveBeenCalled();
    });

    it('does not output when level is above debug', () => {
      logger.configure({ level: 'info', verbose: true });
      logger.debug('debug message');
      expect(consoleSpy).not.toHaveBeenCalled();
    });
  });

  describe('info()', () => {
    it('outputs when level is info or lower', () => {
      logger.configure({ level: 'info' });
      logger.info('info message');
      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining('INFO'),
      );
    });

    it('does not output when level is warn or higher', () => {
      logger.configure({ level: 'warn' });
      logger.info('info message');
      expect(consoleSpy).not.toHaveBeenCalled();
    });

    it('does not output when level is silent', () => {
      logger.configure({ level: 'silent' });
      logger.info('info message');
      expect(consoleSpy).not.toHaveBeenCalled();
    });
  });

  describe('warn()', () => {
    it('outputs at warn level', () => {
      logger.configure({ level: 'warn' });
      logger.warn('warn message');
      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining('WARN'),
      );
    });

    it('does not output when level is error or higher', () => {
      logger.configure({ level: 'error' });
      logger.warn('warn message');
      expect(consoleSpy).not.toHaveBeenCalled();
    });
  });

  describe('error()', () => {
    it('outputs at error level', () => {
      logger.configure({ level: 'error' });
      logger.error('error message');
      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining('ERROR'),
      );
    });

    it('does not output when level is silent', () => {
      logger.configure({ level: 'silent' });
      logger.error('error message');
      expect(consoleSpy).not.toHaveBeenCalled();
    });

    it('passes additional args to console.error', () => {
      logger.configure({ level: 'error' });
      const extra = { detail: 'some object' };
      logger.error('error with extra', extra);
      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining('ERROR'),
        extra,
      );
    });
  });

  describe('raw()', () => {
    it('outputs raw message without formatting', () => {
      logger.configure({ level: 'info' });
      logger.raw('raw output');
      expect(consoleSpy).toHaveBeenCalledWith('raw output');
    });

    it('does not output when level is silent', () => {
      logger.configure({ level: 'silent' });
      logger.raw('raw output');
      expect(consoleSpy).not.toHaveBeenCalled();
    });
  });

  describe('finding()', () => {
    it('outputs finding with severity prefix', () => {
      logger.configure({ level: 'info' });
      logger.finding('CRITICAL', 'found issue');
      expect(consoleSpy).toHaveBeenCalledWith('[CRITICAL] found issue');
    });

    it('does not output when level is silent', () => {
      logger.configure({ level: 'silent' });
      logger.finding('HIGH', 'found issue');
      expect(consoleSpy).not.toHaveBeenCalled();
    });
  });

  describe('CI mode formatting', () => {
    it('uses CI format without timestamp', () => {
      logger.configure({ level: 'info', ci: true });
      logger.info('ci message');
      const call = consoleSpy.mock.calls[0]?.[0] as string;
      expect(call).toMatch(/^\[INFO\] ci message$/);
      // No timestamp in CI mode
      expect(call).not.toMatch(/\d{4}-\d{2}-\d{2}T/);
    });

    it('uses full format with timestamp in non-CI mode', () => {
      logger.configure({ level: 'info', ci: false });
      logger.info('non-ci message');
      const call = consoleSpy.mock.calls[0]?.[0] as string;
      expect(call).toMatch(/\d{4}-\d{2}-\d{2}T/); // ISO timestamp present
    });
  });
});
