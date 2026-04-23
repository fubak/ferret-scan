/**
 * Path Security Tests
 * Tests for path traversal protection utilities
 */

import {
  isPathWithinBase,
  validatePathWithinBase,
  sanitizeFilename,
  safeResolvePath
} from '../../src/utils/pathSecurity.js';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';

describe('Path Security Utilities', () => {
  const basePath = tmpdir();

  describe('isPathWithinBase', () => {
    it('should allow paths within base directory', () => {
      const safePath = resolve(basePath, 'subdir', 'file.txt');
      expect(isPathWithinBase(safePath, basePath)).toBe(true);
    });

    it('should reject paths that escape with ../', () => {
      const dangerousPath = resolve(basePath, '..', 'etc', 'passwd');
      expect(isPathWithinBase(dangerousPath, basePath)).toBe(false);
    });

    it('should reject absolute paths outside base', () => {
      const outsidePath = '/etc/passwd';
      expect(isPathWithinBase(outsidePath, basePath)).toBe(false);
    });

    it('should handle current directory references', () => {
      const currentDirPath = resolve(basePath, '.', 'file.txt');
      expect(isPathWithinBase(currentDirPath, basePath)).toBe(true);
    });

    it('should handle complex traversal attempts', () => {
      const complexPath = resolve(basePath, 'a', '..', '..', 'etc', 'passwd');
      expect(isPathWithinBase(complexPath, basePath)).toBe(false);
    });
  });

  describe('validatePathWithinBase', () => {
    it('should not throw for valid paths', () => {
      const safePath = resolve(basePath, 'safe.txt');
      expect(() => {
        validatePathWithinBase(safePath, basePath, 'test');
      }).not.toThrow();
    });

    it('should throw for path traversal attempts', () => {
      const dangerousPath = resolve(basePath, '..', 'etc', 'passwd');
      expect(() => {
        validatePathWithinBase(dangerousPath, basePath, 'test');
      }).toThrow(/Path traversal detected in test/);
    });

    it('should include operation name in error message', () => {
      const dangerousPath = resolve(basePath, '..', 'evil');
      expect(() => {
        validatePathWithinBase(dangerousPath, basePath, 'backup operation');
      }).toThrow(/backup operation.*escapes base directory/);
    });
  });

  describe('sanitizeFilename', () => {
    it('should remove path separators', () => {
      expect(sanitizeFilename('path/to/file.txt')).toBe('file.txt');
      expect(sanitizeFilename('path\\to\\file.txt')).toBe('path_to_file.txt');
    });

    it('should remove parent directory references', () => {
      expect(sanitizeFilename('../file.txt')).toBe('file.txt'); // basename() removes path
      expect(sanitizeFilename('file..txt')).toBe('file_txt');
    });

    it('should remove dangerous characters', () => {
      expect(sanitizeFilename('file<>:|?*.txt')).toBe('file______.txt'); // 6 chars replaced with _
    });

    it('should remove leading dots', () => {
      expect(sanitizeFilename('...hidden.txt')).toBe('_.hidden.txt'); // only leading dots
      expect(sanitizeFilename('.hidden')).toBe('_hidden');
    });

    it('should handle complex malicious inputs', () => {
      const malicious = '../../etc/passwd|rm -rf /';
      const sanitized = sanitizeFilename(malicious);
      expect(sanitized).not.toContain('..');
      expect(sanitized).not.toContain('/');
      expect(sanitized).not.toContain('|');
    });

    it('should preserve reasonable filename structure', () => {
      expect(sanitizeFilename('my-file_v1.2.txt')).toBe('my-file_v1.2.txt');
      expect(sanitizeFilename('backup.2024-01-01.sql')).toBe('backup.2024-01-01.sql');
    });
  });

  describe('safeResolvePath', () => {
    it('should resolve safe paths normally', () => {
      const result = safeResolvePath(basePath, 'subdir', 'file.txt');
      const expected = resolve(basePath, 'subdir', 'file.txt');
      expect(result).toBe(expected);
    });

    it('should sanitize and allow path segments that become safe', () => {
      const result = safeResolvePath(basePath, '..', 'etc', 'passwd');
      // After sanitization: '..' becomes '_', so this is safe
      expect(result).not.toBeNull();
      expect(result).toContain('_');
    });

    it('should sanitize path segments', () => {
      const result = safeResolvePath(basePath, 'sub..dir', 'file<>.txt');
      expect(result).toContain('sub_dir');
      expect(result).toContain('file__.txt');
    });

    it('should sanitize multiple malicious segments', () => {
      const result = safeResolvePath(basePath, '../evil', '../../etc', 'passwd');
      // After sanitization these become safe directory names
      expect(result).not.toBeNull();
    });

    it('should handle empty and null segments gracefully', () => {
      const result = safeResolvePath(basePath, '', 'file.txt');
      expect(result).toBe(resolve(basePath, 'file.txt'));
    });
  });

  describe('Real-world attack scenarios', () => {
    it('should handle null byte characters', () => {
      const malicious = 'file.txt\0.exe';
      const sanitized = sanitizeFilename(malicious);
      // Null bytes might be converted to spaces or removed
      expect(sanitized).not.toBe(malicious);
    });

    it('should prevent Unicode normalization attacks', () => {
      // These are different Unicode representations of similar-looking paths
      const normalized1 = sanitizeFilename('file../passwd');
      const normalized2 = sanitizeFilename('file．．/passwd');
      expect(normalized1).not.toContain('..');
      expect(normalized2).not.toContain('..');
    });

    it('should handle very long filenames', () => {
      const longName = 'a'.repeat(1000) + '.txt';
      const sanitized = sanitizeFilename(longName);
      // Function doesn't truncate, just sanitizes
      expect(sanitized.length).toBeGreaterThan(1000);
      expect(sanitized).toContain('a');
    });

    it('should prevent symlink-style attacks in path construction', () => {
      const symlinkPath = resolve(basePath, 'symlink_to_root', '..', '..', 'etc', 'passwd');
      expect(isPathWithinBase(symlinkPath, basePath)).toBe(false);
    });

    it('should handle Windows drive letter injection', () => {
      const windowsPath = 'C:\\Windows\\System32\\config\\SAM';
      const sanitized = sanitizeFilename(windowsPath);
      expect(sanitized).not.toContain('C:');
      expect(sanitized).not.toContain('\\');
    });
  });

  describe('Edge cases', () => {
    it('should handle empty inputs safely', () => {
      expect(() => sanitizeFilename('')).not.toThrow();
      expect(sanitizeFilename('')).toBe('');
    });

    it('should handle whitespace-only inputs', () => {
      expect(sanitizeFilename('   \t\n   ')).toBe('   \t\n   '); // Preserve whitespace
    });

    it('should handle base path being a file vs directory', () => {
      const filePath = resolve(basePath, 'somefile.txt');
      const testPath = resolve(filePath, 'subpath'); // This would be invalid anyway
      // The function treats the filePath as base, so subpath would be within it
      expect(isPathWithinBase(testPath, filePath)).toBe(true);
    });

    it('should handle relative base paths', () => {
      const relativePath = './relative/base';
      const testPath = resolve(relativePath, 'safe.txt');
      const result = isPathWithinBase(testPath, relativePath);
      expect(typeof result).toBe('boolean'); // Should not crash
    });
  });
});