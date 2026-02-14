/* eslint-disable no-useless-escape */
/**
 * Path Security Utilities
 * Provides path traversal protection for file operations
 */

import { resolve, relative, isAbsolute, basename } from 'node:path';

/**
 * Validates that a resolved path is within the expected base directory
 * Prevents path traversal attacks (e.g., ../../etc/passwd)
 */
export function isPathWithinBase(targetPath: string, baseDir: string): boolean {
  // Resolve both paths to absolute canonical forms
  const resolvedBase = resolve(baseDir);
  const resolvedTarget = resolve(targetPath);

  // Check if target starts with base
  const relativePath = relative(resolvedBase, resolvedTarget);

  // If relative path starts with '..' or is absolute, it's outside base
  return !relativePath.startsWith('..') && !isAbsolute(relativePath);
}

/**
 * Validates path and throws if it escapes the base directory
 */
export function validatePathWithinBase(
  targetPath: string,
  baseDir: string,
  operationName: string
): void {
  if (!isPathWithinBase(targetPath, baseDir)) {
    throw new Error(
      `Path traversal detected in ${operationName}: ` +
      `'${targetPath}' escapes base directory '${baseDir}'`
    );
  }
}

/**
 * Sanitizes a filename by removing path separators and dangerous characters
 */
export function sanitizeFilename(filename: string): string {
  // Get just the base filename first
  const base = basename(filename);

  return base
    .replace(/[\/\\]/g, '_')      // Replace path separators
    .replace(/\.\./g, '_')        // Replace parent directory references
    .replace(/[<>:"|?*]/g, '_')   // Remove invalid filename characters
    .replace(/^\.+/, '_');        // Remove leading dots
}

/**
 * Safely resolves a path within a base directory
 * Returns null if the path would escape the base
 */
export function safeResolvePath(
  baseDir: string,
  ...pathSegments: string[]
): string | null {
  const sanitizedSegments = pathSegments.map(segment =>
    segment.split(/[\/\\]/).map(sanitizeFilename).join('/')
  );

  const resolvedPath = resolve(baseDir, ...sanitizedSegments);

  if (!isPathWithinBase(resolvedPath, baseDir)) {
    return null;
  }

  return resolvedPath;
}

export default {
  isPathWithinBase,
  validatePathWithinBase,
  sanitizeFilename,
  safeResolvePath,
};
