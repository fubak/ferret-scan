/**
 * AI-Powered Rule Generation
 * Generates security rules from threat intelligence using LLM
 */

import type { Rule, ThreatCategory, Severity } from '../types.js';
import { createLlmProvider, type LlmProvider } from '../features/llmAnalysis.js';
import logger from '../utils/logger.js';

export interface ThreatReport {
    id: string;
    title: string;
    category: ThreatCategory;
    description: string;
    attackVectors: string[];
    iocs: string[];
    mitreAtlasTechniques?: string[];
}

export interface GeneratedRule extends Rule {
    generatedFrom: string;
    confidence: number;
    validated: boolean;
}

export class AIRuleGenerator {
    private llmProvider: LlmProvider;

    constructor(_apiKey: string, model = 'gpt-4o-mini') {
        const provider = createLlmProvider({
            provider: 'openai-compatible',
            baseUrl: 'https://api.openai.com/v1/chat/completions',
            model,
            apiKeyEnv: 'OPENAI_API_KEY',
            timeoutMs: 30000,
            jsonMode: true,
            maxInputChars: 10000,
            maxOutputTokens: 1000,
            temperature: 0,
            systemPromptAddendum: '',
            includeMitreAtlasTechniques: false,
            maxMitreAtlasTechniques: 0,
            cacheDir: '.ferret-cache/llm',
            cacheTtlHours: 168,
            maxRetries: 2,
            retryBackoffMs: 500,
            retryMaxBackoffMs: 5000,
            minRequestIntervalMs: 250,
            onlyIfFindings: false,
            maxFindingsPerFile: 10,
            maxFiles: 25,
            minConfidence: 0.6
        });

        if (!provider) {
            throw new Error('Failed to create LLM provider');
        }

        this.llmProvider = provider;
    }

    async generateFromThreatIntel(reports: ThreatReport[]): Promise<GeneratedRule[]> {
        const rules: GeneratedRule[] = [];

        for (const report of reports) {
            try {
                const generated = await this.generateRule(report);
                rules.push(...generated);
            } catch (error) {
                logger.warn(`Failed to generate rule from ${report.id}:`, error);
            }
        }

        return rules;
    }

    private async generateRule(report: ThreatReport): Promise<GeneratedRule[]> {
        const prompt = {
            system: `You are a cybersecurity expert generating ferret-scan security rules.
Generate rules that can detect AI agent security threats through static analysis.
Return valid JSON with an array of rules matching this schema:
{
  "rules": [{
    "id": "CATEGORY-###",
    "name": "Descriptive Name",
    "category": "${report.category}",
    "severity": "CRITICAL|HIGH|MEDIUM|LOW",
    "description": "What this detects",
    "patterns": ["regex1", "regex2"],
    "fileTypes": ["md", "json", "yaml", "sh"],
    "components": ["skill", "agent", "hook"],
    "remediation": "How to fix",
    "confidence": 0.0-1.0
  }]
}`,
            user: `Generate security rules for this threat:
Title: ${report.title}
Category: ${report.category}
Description: ${report.description}
Attack Vectors: ${report.attackVectors.join(', ')}
Indicators: ${report.iocs.join(', ')}

Generate 1-3 specific detection rules.`
        };

        const response = await this.llmProvider.analyze(prompt);
        const parsed = JSON.parse(response);

        const rules: GeneratedRule[] = parsed.rules.map((r: any) => ({
            id: r.id,
            name: r.name,
            category: r.category as ThreatCategory,
            severity: r.severity as Severity,
            description: r.description,
            patterns: r.patterns.map((p: string) => new RegExp(p, 'gi')),
            fileTypes: r.fileTypes,
            components: r.components,
            remediation: r.remediation,
            references: [],
            enabled: false, // Disabled by default until validated
            generatedFrom: report.id,
            confidence: r.confidence || 0.7,
            validated: false
        }));

        return rules;
    }
}
