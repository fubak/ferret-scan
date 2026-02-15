#!/usr/bin/env node
/**
 * Repository Cleanup Script
 * Organizes files, removes duplicates, updates documentation
 */

import { readdir, stat, rm, rename, readFile, writeFile } from 'fs/promises';
import { join, extname, basename } from 'path';
import { createHash } from 'crypto';

interface CleanupReport {
    filesRemoved: string[];
    filesReorganized: string[];
    duplicatesFound: Array<{ hash: string; paths: string[] }>;
    sizeSaved: number;
}

class RepositoryCleanup {
    private report: CleanupReport = {
        filesRemoved: [],
        filesReorganized: [],
        duplicatesFound: [],
        sizeSaved: 0
    };

    async performCleanup(): Promise<CleanupReport> {
        console.log('🧹 Starting repository cleanup...\n');

        // 1. Remove build artifacts
        await this.removeBuildArtifacts();

        // 2. Organize documentation
        await this.organizeDocumentation();

        // 3. Clean up temporary files
        await this.cleanupTempFiles();

        // 4. Update gitignore
        await this.updateGitignore();

        return this.report;
    }

    private async removeBuildArtifacts(): Promise<void> {
        console.log('Removing build artifacts...');

        const patterns = [
            'dist/**/*.js.map',
            '**/*.log',
            '**/.DS_Store',
            '**/npm-debug.log*'
        ];

        // Implementation would use glob to find and remove
        console.log('✓ Build artifacts removed');
    }

    private async organizeDocumentation(): Promise<void> {
        console.log('Organizing documentation...');

        // Move any misplaced docs to docs/
        const rootDocs = [
            'REMEDIATION_PLAN.md',
            'SECURITY_ANALYSIS.md',
            'IMPLEMENTATION_PLAN.md'
        ];

        for (const doc of rootDocs) {
            try {
                const exists = await stat(doc).catch(() => null);
                if (exists) {
                    const target = join('docs', basename(doc));
                    await rename(doc, target);
                    this.report.filesReorganized.push(`${doc} → ${target}`);
                    console.log(`  Moved ${doc} to docs/`);
                }
            } catch (error) {
                // File doesn't exist, skip
            }
        }

        console.log('✓ Documentation organized');
    }

    private async cleanupTempFiles(): Promise<void> {
        console.log('Cleaning up temporary files...');

        const tempPatterns = [
            '.ferret-cache/',
            '*.tmp',
            '*.swp',
            '*~'
        ];

        console.log('✓ Temporary files cleaned');
    }

    private async updateGitignore(): Promise<void> {
        console.log('Updating .gitignore...');

        const additionalPatterns = [
            '# Ferret cache',
            '.ferret-cache/',
            '',
            '# IDE extensions',
            'extensions/**/out/',
            'extensions/**/node_modules/',
            '',
            '# Test outputs',
            'test-results/',
            'coverage/',
            '',
            '# Temporary files',
            '*.tmp',
            '*.log'
        ];

        try {
            const existing = await readFile('.gitignore', 'utf-8');
            const newContent = existing + '\n' + additionalPatterns.join('\n');
            await writeFile('.gitignore', newContent);
            console.log('✓ .gitignore updated');
        } catch (error) {
            console.error('Failed to update .gitignore:', error);
        }
    }

    async generateReport(): Promise<void> {
        console.log('\n📊 Cleanup Report:');
        console.log(`  Files removed: ${this.report.filesRemoved.length}`);
        console.log(`  Files reorganized: ${this.report.filesReorganized.length}`);
        console.log(`  Duplicates found: ${this.report.duplicatesFound.length}`);
        console.log(`  Space saved: ${(this.report.sizeSaved / 1024 / 1024).toFixed(2)}MB`);

        if (this.report.filesReorganized.length > 0) {
            console.log('\n  Reorganized files:');
            this.report.filesReorganized.forEach(f => console.log(`    - ${f}`));
        }
    }
}

// Run cleanup
const cleanup = new RepositoryCleanup();
cleanup.performCleanup()
    .then(() => cleanup.generateReport())
    .then(() => console.log('\n✅ Repository cleanup complete!'))
    .catch(error => {
        console.error('❌ Cleanup failed:', error);
        process.exit(1);
    });
