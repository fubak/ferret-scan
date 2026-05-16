/**
 * RuleGenerator Tests
 * Tests for AIRuleGenerator in src/ai-rules/RuleGenerator.ts
 */

import { AIRuleGenerator } from '../ai-rules/RuleGenerator.js';
import type { ThreatReport } from '../ai-rules/RuleGenerator.js';

// Mock the LLM provider creation
jest.mock('../features/llmAnalysis.js', () => ({
  createLlmProvider: jest.fn().mockReturnValue({
    name: 'mock-provider',
    analyze: jest.fn(),
  }),
}));

import { createLlmProvider } from '../features/llmAnalysis.js';

function makeThreatReport(overrides: Partial<ThreatReport> = {}): ThreatReport {
  return {
    id: 'THREAT-001',
    title: 'Prompt Injection Attack',
    category: 'injection',
    description: 'Attacker crafts prompts to override instructions',
    attackVectors: ['user input', 'system prompt manipulation'],
    iocs: ['IGNORE PREVIOUS', 'jailbreak', 'DAN mode'],
    ...overrides,
  };
}

describe('AIRuleGenerator', () => {
  let generator: AIRuleGenerator;
  let mockAnalyze: jest.Mock;

  beforeEach(() => {
    jest.clearAllMocks();
    // Get the mocked analyze function
    const mockProvider = {
      name: 'mock-provider',
      analyze: jest.fn(),
    };
    mockAnalyze = mockProvider.analyze;
    (createLlmProvider as jest.Mock).mockReturnValue(mockProvider);

    generator = new AIRuleGenerator('test-api-key', 'gpt-4o-mini');
  });

  // -------------------------------------------------------------------------
  // Constructor
  // -------------------------------------------------------------------------

  describe('constructor', () => {
    it('creates an instance successfully when provider is returned', () => {
      expect(generator).toBeInstanceOf(AIRuleGenerator);
    });

    it('throws when createLlmProvider returns null', () => {
      (createLlmProvider as jest.Mock).mockReturnValueOnce(null);
      expect(() => new AIRuleGenerator('key')).toThrow('Failed to create LLM provider');
    });

    it('uses default model when not specified', () => {
      expect(() => new AIRuleGenerator('key')).not.toThrow();
    });

    it('accepts custom model parameter', () => {
      expect(() => new AIRuleGenerator('key', 'gpt-3.5-turbo')).not.toThrow();
    });
  });

  // -------------------------------------------------------------------------
  // generateFromThreatIntel
  // -------------------------------------------------------------------------

  describe('generateFromThreatIntel', () => {
    it('returns empty array for empty reports', async () => {
      const rules = await generator.generateFromThreatIntel([]);
      expect(rules).toEqual([]);
    });

    it('generates rules from a threat report', async () => {
      const ruleResponse = JSON.stringify({
        rules: [
          {
            id: 'INJ-001',
            name: 'Prompt Injection Detection',
            category: 'injection',
            severity: 'HIGH',
            description: 'Detects prompt injection patterns',
            patterns: ['IGNORE PREVIOUS', 'jailbreak'],
            fileTypes: ['md', 'json'],
            components: ['agent', 'skill'],
            remediation: 'Validate all user input',
            confidence: 0.85,
          },
        ],
      });

      mockAnalyze.mockResolvedValue(ruleResponse);

      const rules = await generator.generateFromThreatIntel([makeThreatReport()]);
      expect(rules).toHaveLength(1);
      expect(rules[0]?.id).toBe('INJ-001');
      expect(rules[0]?.name).toBe('Prompt Injection Detection');
      expect(rules[0]?.generatedFrom).toBe('THREAT-001');
      expect(rules[0]?.validated).toBe(false);
      expect(rules[0]?.enabled).toBe(false);
      expect(rules[0]?.confidence).toBe(0.85);
    });

    it('converts patterns strings to RegExp objects', async () => {
      const ruleResponse = JSON.stringify({
        rules: [
          {
            id: 'INJ-002',
            name: 'Test Rule',
            category: 'injection',
            severity: 'MEDIUM',
            description: 'Test',
            patterns: ['test.*pattern', '\\bmalicious\\b'],
            fileTypes: ['md'],
            components: ['agent'],
            remediation: 'Fix it',
            confidence: 0.7,
          },
        ],
      });

      mockAnalyze.mockResolvedValue(ruleResponse);

      const rules = await generator.generateFromThreatIntel([makeThreatReport()]);
      expect(rules[0]?.patterns[0]).toBeInstanceOf(RegExp);
      expect(rules[0]?.patterns[1]).toBeInstanceOf(RegExp);
    });

    it('uses default confidence of 0.7 when not provided', async () => {
      const ruleResponse = JSON.stringify({
        rules: [
          {
            id: 'INJ-003',
            name: 'No Confidence Rule',
            category: 'injection',
            severity: 'LOW',
            description: 'Test',
            patterns: ['test'],
            fileTypes: ['md'],
            components: [],
            remediation: 'Fix',
            // confidence omitted
          },
        ],
      });

      mockAnalyze.mockResolvedValue(ruleResponse);

      const rules = await generator.generateFromThreatIntel([makeThreatReport()]);
      expect(rules[0]?.confidence).toBe(0.7);
    });

    it('processes multiple threat reports', async () => {
      const ruleResponse1 = JSON.stringify({
        rules: [{ id: 'R-001', name: 'Rule 1', category: 'injection', severity: 'HIGH',
          description: 'D', patterns: ['p1'], fileTypes: ['md'], components: [], remediation: 'fix', confidence: 0.8 }],
      });
      const ruleResponse2 = JSON.stringify({
        rules: [{ id: 'R-002', name: 'Rule 2', category: 'credentials', severity: 'CRITICAL',
          description: 'D', patterns: ['p2'], fileTypes: ['json'], components: [], remediation: 'fix', confidence: 0.9 }],
      });

      mockAnalyze
        .mockResolvedValueOnce(ruleResponse1)
        .mockResolvedValueOnce(ruleResponse2);

      const reports = [
        makeThreatReport({ id: 'T-001' }),
        makeThreatReport({ id: 'T-002', category: 'credentials' }),
      ];

      const rules = await generator.generateFromThreatIntel(reports);
      expect(rules).toHaveLength(2);
      expect(rules[0]?.generatedFrom).toBe('T-001');
      expect(rules[1]?.generatedFrom).toBe('T-002');
    });

    it('skips reports that fail to generate and continues with others', async () => {
      const successResponse = JSON.stringify({
        rules: [
          {
            id: 'R-001', name: 'Good Rule', category: 'injection', severity: 'HIGH',
            description: 'D', patterns: ['p1'], fileTypes: ['md'], components: [], remediation: 'fix', confidence: 0.8,
          },
        ],
      });

      mockAnalyze
        .mockRejectedValueOnce(new Error('LLM error'))
        .mockResolvedValueOnce(successResponse);

      const reports = [
        makeThreatReport({ id: 'FAIL-001' }),
        makeThreatReport({ id: 'SUCCESS-001' }),
      ];

      const rules = await generator.generateFromThreatIntel(reports);
      // Only the second report should produce rules
      expect(rules).toHaveLength(1);
      expect(rules[0]?.generatedFrom).toBe('SUCCESS-001');
    });

    it('generates rules with references as empty array', async () => {
      const ruleResponse = JSON.stringify({
        rules: [
          {
            id: 'R-001', name: 'Rule', category: 'injection', severity: 'HIGH',
            description: 'D', patterns: ['p'], fileTypes: ['md'], components: [], remediation: 'fix', confidence: 0.8,
          },
        ],
      });

      mockAnalyze.mockResolvedValue(ruleResponse);

      const rules = await generator.generateFromThreatIntel([makeThreatReport()]);
      expect(rules[0]?.references).toEqual([]);
    });

    it('handles multiple rules returned from a single report', async () => {
      const ruleResponse = JSON.stringify({
        rules: [
          { id: 'R-001', name: 'Rule 1', category: 'injection', severity: 'HIGH',
            description: 'D', patterns: ['p1'], fileTypes: ['md'], components: [], remediation: 'fix', confidence: 0.8 },
          { id: 'R-002', name: 'Rule 2', category: 'injection', severity: 'MEDIUM',
            description: 'D', patterns: ['p2'], fileTypes: ['json'], components: [], remediation: 'fix', confidence: 0.75 },
          { id: 'R-003', name: 'Rule 3', category: 'injection', severity: 'LOW',
            description: 'D', patterns: ['p3'], fileTypes: ['yaml'], components: [], remediation: 'fix', confidence: 0.6 },
        ],
      });

      mockAnalyze.mockResolvedValue(ruleResponse);

      const rules = await generator.generateFromThreatIntel([makeThreatReport()]);
      expect(rules).toHaveLength(3);
    });
  });
});
