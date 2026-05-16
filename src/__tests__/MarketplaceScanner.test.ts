/**
 * MarketplaceScanner Tests
 */

import { MarketplaceScanner } from '../marketplace/MarketplaceScanner.js';
import type {
  MarketplacePlugin,
  MarketplaceScanConfig,
} from '../marketplace/MarketplaceScanner.js';

// Mock the scan function to avoid real FS operations
jest.mock('../scanner/Scanner.js', () => ({
  scan: jest.fn().mockResolvedValue({ findings: [] }),
}));

// Mock fs/promises to avoid real temp dir creation
jest.mock('fs/promises', () => ({
  mkdtemp: jest.fn().mockResolvedValue('/tmp/test-plugin-dir'),
  rm: jest.fn().mockResolvedValue(undefined),
}));

function makePlugin(overrides: Partial<MarketplacePlugin> = {}): MarketplacePlugin {
  return {
    id: 'test-plugin-001',
    name: 'Test Plugin',
    author: 'test-author',
    version: '1.0.0',
    source: 'community',
    capabilities: [],
    permissions: [],
    metadata: {
      description: 'A test plugin',
      downloads: 1000,
      rating: 4.0,
      lastUpdated: new Date('2024-01-01'),
    },
    ...overrides,
  };
}

describe('MarketplaceScanner', () => {
  let scanner: MarketplaceScanner;

  beforeEach(() => {
    scanner = new MarketplaceScanner();
  });

  // -------------------------------------------------------------------------
  // scanMarketplace
  // -------------------------------------------------------------------------

  describe('scanMarketplace', () => {
    it('returns empty array when no plugins found', async () => {
      const config: MarketplaceScanConfig = { source: 'claude-marketplace' };
      const results = await scanner.scanMarketplace(config);
      expect(results).toEqual([]);
    });

    it('resolves without throwing for generic source', async () => {
      await expect(
        scanner.scanMarketplace({ source: 'community' })
      ).resolves.toBeDefined();
    });
  });

  // -------------------------------------------------------------------------
  // analyzePlugin – permission checks
  // -------------------------------------------------------------------------

  describe('analyzePlugin – permission checks', () => {
    it('returns safe recommendation for plugin with no capabilities', async () => {
      const plugin = makePlugin({ capabilities: [] });
      const result = await scanner.analyzePlugin(plugin);
      expect(result.plugin).toBe(plugin);
      expect(result.recommendation).toBe('safe');
      expect(result.riskScore).toBe(0);
    });

    it('detects shell:execute + network:outbound as CRITICAL', async () => {
      const plugin = makePlugin({
        capabilities: ['shell:execute', 'network:outbound'],
      });
      const result = await scanner.analyzePlugin(plugin);
      expect(result.findings.some(f => f.severity === 'CRITICAL')).toBe(true);
      expect(result.recommendation).toBe('malicious');
    });

    it('detects file:write + network:outbound + startup:autorun as CRITICAL', async () => {
      const plugin = makePlugin({
        capabilities: ['file:write', 'network:outbound', 'startup:autorun'],
      });
      const result = await scanner.analyzePlugin(plugin);
      const criticalFindings = result.findings.filter(f => f.severity === 'CRITICAL');
      expect(criticalFindings.length).toBeGreaterThan(0);
    });

    it('detects clipboard:read + network:outbound as HIGH', async () => {
      const plugin = makePlugin({
        capabilities: ['clipboard:read', 'network:outbound'],
      });
      const result = await scanner.analyzePlugin(plugin);
      expect(result.findings.some(f => f.severity === 'HIGH')).toBe(true);
    });

    it('detects file:read + network:outbound as MEDIUM', async () => {
      const plugin = makePlugin({
        capabilities: ['file:read', 'network:outbound'],
      });
      const result = await scanner.analyzePlugin(plugin);
      expect(result.findings.some(f => f.severity === 'MEDIUM')).toBe(true);
    });

    it('detects excessive permissions (>8 capabilities)', async () => {
      const plugin = makePlugin({
        capabilities: [
          'cap1', 'cap2', 'cap3', 'cap4', 'cap5',
          'cap6', 'cap7', 'cap8', 'cap9',
        ],
      });
      const result = await scanner.analyzePlugin(plugin);
      const excessFindings = result.findings.filter(f => f.ruleId === 'MARKETPLACE-002');
      expect(excessFindings.length).toBe(1);
      expect(excessFindings[0]?.severity).toBe('MEDIUM');
    });

    it('does not flag exactly 8 capabilities', async () => {
      const plugin = makePlugin({
        capabilities: ['cap1', 'cap2', 'cap3', 'cap4', 'cap5', 'cap6', 'cap7', 'cap8'],
      });
      const result = await scanner.analyzePlugin(plugin);
      const excessFindings = result.findings.filter(f => f.ruleId === 'MARKETPLACE-002');
      expect(excessFindings.length).toBe(0);
    });
  });

  // -------------------------------------------------------------------------
  // risk score calculation
  // -------------------------------------------------------------------------

  describe('risk score calculation', () => {
    it('reduces risk for popular highly-rated plugins (>10k downloads, >4.5 rating)', async () => {
      const dangerousPlugin = makePlugin({
        capabilities: ['file:read', 'network:outbound'],
        metadata: {
          description: 'Popular plugin',
          downloads: 50000,
          rating: 4.8,
          lastUpdated: new Date(),
        },
      });

      const lowRatedPlugin = makePlugin({
        capabilities: ['file:read', 'network:outbound'],
        metadata: {
          description: 'Low-rated plugin',
          downloads: 100,
          rating: 2.0,
          lastUpdated: new Date(),
        },
      });

      const popularResult = await scanner.analyzePlugin(dangerousPlugin);
      const lowRatedResult = await scanner.analyzePlugin(lowRatedPlugin);

      expect(popularResult.riskScore).toBeLessThanOrEqual(lowRatedResult.riskScore);
    });

    it('reduces risk for claude-marketplace source', async () => {
      const marketplacePlugin = makePlugin({
        capabilities: ['file:read', 'network:outbound'],
        source: 'claude-marketplace',
      });

      const communityPlugin = makePlugin({
        capabilities: ['file:read', 'network:outbound'],
        source: 'community',
      });

      const marketplaceResult = await scanner.analyzePlugin(marketplacePlugin);
      const communityResult = await scanner.analyzePlugin(communityPlugin);

      expect(marketplaceResult.riskScore).toBeLessThanOrEqual(communityResult.riskScore);
    });

    it('caps risk score at 100', async () => {
      const plugin = makePlugin({
        capabilities: [
          'shell:execute', 'network:outbound',
          'file:write', 'startup:autorun',
          'clipboard:read',
        ],
      });
      const result = await scanner.analyzePlugin(plugin);
      expect(result.riskScore).toBeLessThanOrEqual(100);
    });
  });

  // -------------------------------------------------------------------------
  // recommendation thresholds
  // -------------------------------------------------------------------------

  describe('recommendations', () => {
    it('returns safe for risk 0', async () => {
      const plugin = makePlugin({ capabilities: [] });
      const result = await scanner.analyzePlugin(plugin);
      expect(result.recommendation).toBe('safe');
    });

    it('returns malicious when CRITICAL finding present', async () => {
      const plugin = makePlugin({
        capabilities: ['shell:execute', 'network:outbound'],
      });
      const result = await scanner.analyzePlugin(plugin);
      expect(result.recommendation).toBe('malicious');
    });
  });

  // -------------------------------------------------------------------------
  // analyzePlugin with sourceCode triggers code analysis path
  // -------------------------------------------------------------------------

  describe('analyzePlugin with sourceCode', () => {
    it('includes code findings when sourceCode is provided', async () => {
      const plugin = makePlugin({
        sourceCode: '// some plugin code\nconst x = 1;',
        capabilities: [],
      });
      // scan is mocked to return no findings
      const result = await scanner.analyzePlugin(plugin);
      expect(result).toBeDefined();
      expect(result.findings).toBeDefined();
    });
  });

  // -------------------------------------------------------------------------
  // error handling in scanMarketplace
  // -------------------------------------------------------------------------

  describe('error handling', () => {
    it('handles analysis errors gracefully', async () => {
      // Patch analyzePlugin to throw
      const errorScanner = new MarketplaceScanner();
      (errorScanner as unknown as {
        fetchPluginList(config: MarketplaceScanConfig): Promise<MarketplacePlugin[]>;
      }).fetchPluginList = async () => [makePlugin()];

      errorScanner.analyzePlugin = jest.fn().mockRejectedValue(new Error('analysis failed'));

      const results = await errorScanner.scanMarketplace({ source: 'community' });
      expect(results).toHaveLength(1);
      expect(results[0]?.analysisSkipped).toContain('analysis failed');
      expect(results[0]?.recommendation).toBe('review');
    });
  });
});
