/**
 * Marketplace Scanner
 * Scans AI agent marketplaces and repositories for security issues
 */

import { tmpdir } from 'os';
import { join } from 'path';
import { mkdtemp, rm } from 'fs/promises';
import type { Finding } from '../types.js';
import { scan } from '../scanner/Scanner.js';
import logger from '../utils/logger.js';

export interface MarketplacePlugin {
    id: string;
    name: string;
    author: string;
    version: string;
    source: 'claude-marketplace' | 'cursor-extensions' | 'community';
    capabilities: string[];
    permissions: string[];
    downloadUrl?: string;
    sourceCode?: string;
    metadata: PluginMetadata;
}

export interface PluginMetadata {
    description: string;
    downloads: number;
    rating: number;
    lastUpdated: Date;
    homepage?: string;
    repository?: string;
}

export interface PluginScanResult {
    plugin: MarketplacePlugin;
    findings: Finding[];
    riskScore: number;
    analysisSkipped?: string;
    recommendation: 'safe' | 'review' | 'dangerous' | 'malicious';
}

export interface MarketplaceScanConfig {
    source: string;
    includePopular?: boolean;
    minimumDownloads?: number;
    maximumPlugins?: number;
}

export class MarketplaceScanner {
    constructor() {
        // Scanner is now a function, not a class
    }

    async scanMarketplace(config: MarketplaceScanConfig): Promise<PluginScanResult[]> {
        logger.info(`Starting marketplace scan: ${config.source}`);

        const plugins = await this.fetchPluginList(config);
        logger.info(`Found ${plugins.length} plugins to analyze`);

        const results: PluginScanResult[] = [];

        for (const plugin of plugins) {
            try {
                const result = await this.analyzePlugin(plugin);
                results.push(result);
                logger.info(`Analyzed ${plugin.name}: ${result.findings.length} findings, risk ${result.riskScore}`);
            } catch (error) {
                logger.warn(`Failed to analyze plugin ${plugin.name}:`, error);
                results.push({
                    plugin,
                    findings: [],
                    riskScore: 0,
                    analysisSkipped: `Analysis error: ${error}`,
                    recommendation: 'review'
                });
            }
        }

        return results;
    }

    async analyzePlugin(plugin: MarketplacePlugin): Promise<PluginScanResult> {
        // Check for dangerous permission combinations first
        const permissionFindings = this.checkPermissions(plugin);

        // Analyze source code if available
        let codeFindings: Finding[] = [];
        if (plugin.sourceCode || plugin.downloadUrl) {
            codeFindings = await this.analyzePluginSourceCode(plugin);
        }

        const allFindings = [...permissionFindings, ...codeFindings];
        const riskScore = this.calculatePluginRisk(plugin, allFindings);
        const recommendation = this.getRecommendation(riskScore, allFindings);

        return {
            plugin,
            findings: allFindings,
            riskScore,
            recommendation
        };
    }

    private checkPermissions(plugin: MarketplacePlugin): Finding[] {
        const findings: Finding[] = [];

        // Dangerous capability combinations
        const dangerousCombos = [
            {
                caps: ['shell:execute', 'network:outbound'],
                severity: 'CRITICAL' as const,
                description: 'Can execute shell commands and communicate with external servers'
            },
            {
                caps: ['file:write', 'network:outbound', 'startup:autorun'],
                severity: 'CRITICAL' as const,
                description: 'Can write files, access network, and run on startup - potential persistence mechanism'
            },
            {
                caps: ['clipboard:read', 'network:outbound'],
                severity: 'HIGH' as const,
                description: 'Can read clipboard and send data externally - potential credential theft'
            },
            {
                caps: ['file:read', 'network:outbound'],
                severity: 'MEDIUM' as const,
                description: 'Can read files and communicate externally - potential data exfiltration'
            }
        ];

        for (const combo of dangerousCombos) {
            if (combo.caps.every(cap => plugin.capabilities.includes(cap))) {
                findings.push({
                    ruleId: 'MARKETPLACE-001',
                    ruleName: 'Dangerous Capability Combination',
                    severity: combo.severity,
                    category: 'permissions',
                    file: `marketplace:${plugin.id}`,
                    relativePath: plugin.name,
                    line: 0,
                    match: combo.caps.join(' + '),
                    context: [],
                    remediation: `Review plugin behavior: ${combo.description}`,
                    metadata: {
                        plugin: plugin.name,
                        capabilities: combo.caps
                    },
                    timestamp: new Date(),
                    riskScore: combo.severity === 'CRITICAL' ? 100 : combo.severity === 'HIGH' ? 75 : 50
                });
            }
        }

        // Excessive permissions
        if (plugin.capabilities.length > 8) {
            findings.push({
                ruleId: 'MARKETPLACE-002',
                ruleName: 'Excessive Permissions Requested',
                severity: 'MEDIUM',
                category: 'permissions',
                file: `marketplace:${plugin.id}`,
                relativePath: plugin.name,
                line: 0,
                match: `${plugin.capabilities.length} capabilities`,
                context: [],
                remediation: 'Review if all permissions are necessary for plugin functionality',
                metadata: {
                    plugin: plugin.name,
                    capabilityCount: plugin.capabilities.length,
                    capabilities: plugin.capabilities
                },
                timestamp: new Date(),
                riskScore: 50
            });
        }

        return findings;
    }

    private async analyzePluginSourceCode(plugin: MarketplacePlugin): Promise<Finding[]> {
        if (!plugin.sourceCode && !plugin.downloadUrl) {
            return [];
        }

        // Create temporary directory for analysis
        const tempDir = await mkdtemp(join(tmpdir(), 'ferret-plugin-'));

        try {
            // Download or extract source code
            const sourcePath = await this.extractPluginSource(plugin, tempDir);

            // Run ferret scan on the source
            const scanResult = await scan({
                paths: [sourcePath],
                configOnly: false,
                marketplaceMode: 'all',
                docDampening: false,
                redact: false,
                severities: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
                categories: [
                    'exfiltration',
                    'credentials',
                    'injection',
                    'backdoors',
                    'supply-chain',
                    'permissions',
                    'persistence',
                    'obfuscation',
                    'ai-specific'
                ],
                ignore: [],
                customRules: [],
                failOn: 'HIGH',
                watch: false,
                threatIntel: false,
                semanticAnalysis: true,
                correlationAnalysis: true,
                entropyAnalysis: true,
                mcpValidation: true,
                dependencyAnalysis: true,
                dependencyAudit: false,
                capabilityMapping: true,
                ignoreComments: true,
                mitreAtlas: true,
                mitreAtlasCatalog: {
                    enabled: false,
                    autoUpdate: false,
                    sourceUrl: '',
                    cachePath: '',
                    cacheTtlHours: 0,
                    timeoutMs: 0,
                    forceRefresh: false
                },
                llmAnalysis: false,
                llm: {} as any,
                autoRemediation: false,
                contextLines: 3,
                maxFileSize: 10 * 1024 * 1024,
                format: 'json',
                verbose: false,
                ci: false
            });

            return scanResult.findings;
        } finally {
            // Cleanup
            await rm(tempDir, { recursive: true, force: true });
        }
    }

    private async extractPluginSource(_plugin: MarketplacePlugin, tempDir: string): Promise<string> {
        // Implementation would download and extract plugin source
        // For now, return temp dir
        return tempDir;
    }

    private calculatePluginRisk(plugin: MarketplacePlugin, findings: Finding[]): number {
        let risk = 0;

        // Base risk on findings
        for (const finding of findings) {
            switch (finding.severity) {
                case 'CRITICAL':
                    risk += 40;
                    break;
                case 'HIGH':
                    risk += 25;
                    break;
                case 'MEDIUM':
                    risk += 15;
                    break;
                case 'LOW':
                    risk += 5;
                    break;
            }
        }

        // Adjust for plugin popularity (lower risk for popular, well-reviewed plugins)
        if (plugin.metadata.downloads > 10000 && plugin.metadata.rating > 4.5) {
            risk = risk * 0.7;
        }

        // Adjust for verification status
        if (plugin.source === 'claude-marketplace') {
            risk = risk * 0.8; // Marketplace has some vetting
        }

        return Math.min(100, Math.round(risk));
    }

    private getRecommendation(
        riskScore: number,
        findings: Finding[]
    ): 'safe' | 'review' | 'dangerous' | 'malicious' {
        const hasCritical = findings.some(f => f.severity === 'CRITICAL');

        if (hasCritical || riskScore >= 80) {
            return 'malicious';
        } else if (riskScore >= 60) {
            return 'dangerous';
        } else if (riskScore >= 30) {
            return 'review';
        } else {
            return 'safe';
        }
    }

    private async fetchPluginList(_config: MarketplaceScanConfig): Promise<MarketplacePlugin[]> {
        // Mock implementation - in production would fetch from actual marketplace APIs
        return [];
    }
}
