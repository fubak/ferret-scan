/**
 * Git Hooks Integration - Pre-commit and pre-push hooks for security scanning
 * Provides automatic security scanning on git operations
 */

import { execSync } from 'node:child_process';
import { writeFileSync, existsSync, mkdirSync, readFileSync, chmodSync } from 'node:fs';
import { resolve } from 'node:path';
import logger from '../utils/logger.js';

const PRE_COMMIT_HOOK = `#!/bin/sh
# Ferret Security Scanner - Pre-commit Hook
# Automatically scans staged files for security issues

# Get list of staged files
STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM)

if [ -z "$STAGED_FILES" ]; then
  exit 0
fi

# Run ferret scan on staged files only
echo "🦫 Running Ferret security scan on staged files..."

# Create temp file with staged files
TEMP_FILE=$(mktemp)
echo "$STAGED_FILES" > "$TEMP_FILE"

# Run scan with staged files
npx ferret scan --staged --fail-on \${FERRET_FAIL_ON:-HIGH} --ci

SCAN_EXIT_CODE=$?

rm -f "$TEMP_FILE"

if [ $SCAN_EXIT_CODE -ne 0 ]; then
  echo ""
  echo "❌ Security issues found! Commit blocked."
  echo "   Run 'ferret scan' for details or use --no-verify to bypass."
  exit 1
fi

echo "✅ Security scan passed!"
exit 0
`;

const PRE_PUSH_HOOK = `#!/bin/sh
# Ferret Security Scanner - Pre-push Hook
# Scans all changes before pushing

echo "🦫 Running Ferret security scan before push..."

npx ferret scan --fail-on \${FERRET_FAIL_ON:-CRITICAL} --ci

SCAN_EXIT_CODE=$?

if [ $SCAN_EXIT_CODE -ne 0 ]; then
  echo ""
  echo "❌ Critical security issues found! Push blocked."
  echo "   Run 'ferret scan' for details or use --no-verify to bypass."
  exit 1
fi

echo "✅ Security scan passed!"
exit 0
`;

export interface HookInstallOptions {
  preCommit: boolean;
  prePush: boolean;
  force: boolean;
  failOn: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
}

const DEFAULT_OPTIONS: HookInstallOptions = {
  preCommit: true,
  prePush: false,
  force: false,
  failOn: 'HIGH',
};

/**
 * Find git hooks directory
 */
function findGitHooksDir(): string | null {
  try {
    const gitDir = execSync('git rev-parse --git-dir', { encoding: 'utf-8' }).trim();
    return resolve(gitDir, 'hooks');
  } catch {
    return null;
  }
}

/**
 * Check if we're in a git repository
 */
export function isGitRepository(): boolean {
  try {
    execSync('git rev-parse --git-dir', { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

/**
 * Get staged files from git
 */
export function getStagedFiles(): string[] {
  try {
    const output = execSync('git diff --cached --name-only --diff-filter=ACM', {
      encoding: 'utf-8',
    });
    return output.trim().split('\n').filter(Boolean);
  } catch {
    return [];
  }
}

/**
 * Get changed files between commits
 */
export function getChangedFiles(from: string, to = 'HEAD'): string[] {
  try {
    const output = execSync(`git diff --name-only ${from}..${to}`, {
      encoding: 'utf-8',
    });
    return output.trim().split('\n').filter(Boolean);
  } catch {
    return [];
  }
}

/**
 * Install git hooks
 */
export function installHooks(options: Partial<HookInstallOptions> = {}): {
  success: boolean;
  installed: string[];
  errors: string[];
} {
  const config = { ...DEFAULT_OPTIONS, ...options };
  const installed: string[] = [];
  const errors: string[] = [];

  const hooksDir = findGitHooksDir();
  if (!hooksDir) {
    return {
      success: false,
      installed: [],
      errors: ['Not a git repository'],
    };
  }

  // Ensure hooks directory exists
  mkdirSync(hooksDir, { recursive: true });

  // Install pre-commit hook
  if (config.preCommit) {
    const hookPath = resolve(hooksDir, 'pre-commit');

    if (existsSync(hookPath) && !config.force) {
      const existing = readFileSync(hookPath, 'utf-8');
      if (!existing.includes('Ferret Security Scanner')) {
        errors.push('pre-commit hook already exists (use --force to overwrite)');
      } else {
        logger.info('pre-commit hook already installed');
        installed.push('pre-commit');
      }
    } else {
      try {
        const hook = PRE_COMMIT_HOOK.replace('${FERRET_FAIL_ON:-HIGH}', `\${FERRET_FAIL_ON:-${config.failOn}}`);
        writeFileSync(hookPath, hook, 'utf-8');
        chmodSync(hookPath, 0o755);
        installed.push('pre-commit');
        logger.info('Installed pre-commit hook');
      } catch (error) {
        errors.push(`Failed to install pre-commit hook: ${error}`);
      }
    }
  }

  // Install pre-push hook
  if (config.prePush) {
    const hookPath = resolve(hooksDir, 'pre-push');

    if (existsSync(hookPath) && !config.force) {
      const existing = readFileSync(hookPath, 'utf-8');
      if (!existing.includes('Ferret Security Scanner')) {
        errors.push('pre-push hook already exists (use --force to overwrite)');
      } else {
        logger.info('pre-push hook already installed');
        installed.push('pre-push');
      }
    } else {
      try {
        writeFileSync(hookPath, PRE_PUSH_HOOK, 'utf-8');
        chmodSync(hookPath, 0o755);
        installed.push('pre-push');
        logger.info('Installed pre-push hook');
      } catch (error) {
        errors.push(`Failed to install pre-push hook: ${error}`);
      }
    }
  }

  return {
    success: errors.length === 0,
    installed,
    errors,
  };
}

/**
 * Uninstall git hooks
 */
export function uninstallHooks(): {
  success: boolean;
  removed: string[];
  errors: string[];
} {
  const removed: string[] = [];
  const errors: string[] = [];

  const hooksDir = findGitHooksDir();
  if (!hooksDir) {
    return {
      success: false,
      removed: [],
      errors: ['Not a git repository'],
    };
  }

  const hooks = ['pre-commit', 'pre-push'];

  for (const hook of hooks) {
    const hookPath = resolve(hooksDir, hook);

    if (existsSync(hookPath)) {
      try {
        const content = readFileSync(hookPath, 'utf-8');
        if (content.includes('Ferret Security Scanner')) {
          const { unlinkSync } = require('node:fs');
          unlinkSync(hookPath);
          removed.push(hook);
          logger.info(`Removed ${hook} hook`);
        }
      } catch (error) {
        errors.push(`Failed to remove ${hook} hook: ${error}`);
      }
    }
  }

  return {
    success: errors.length === 0,
    removed,
    errors,
  };
}

/**
 * Check hook status
 */
export function getHookStatus(): {
  preCommit: 'installed' | 'not-installed' | 'other';
  prePush: 'installed' | 'not-installed' | 'other';
} {
  const hooksDir = findGitHooksDir();

  const checkHook = (name: string): 'installed' | 'not-installed' | 'other' => {
    if (!hooksDir) return 'not-installed';

    const hookPath = resolve(hooksDir, name);
    if (!existsSync(hookPath)) return 'not-installed';

    const content = readFileSync(hookPath, 'utf-8');
    return content.includes('Ferret Security Scanner') ? 'installed' : 'other';
  };

  return {
    preCommit: checkHook('pre-commit'),
    prePush: checkHook('pre-push'),
  };
}

export default {
  isGitRepository,
  getStagedFiles,
  getChangedFiles,
  installHooks,
  uninstallHooks,
  getHookStatus,
};
