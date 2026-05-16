/**
 * IAnalyzer — interface for pluggable file analyzers
 */

import type { DiscoveredFile, Finding, Rule, ScannerConfig } from '../types.js';

export interface AnalyzerContext {
  file: DiscoveredFile;
  content: string;
  config: ScannerConfig;
  /** Merged rule set (base + custom) for this scan */
  rules: Rule[];
  /** Findings accumulated so far (allows later analyzers to gate on earlier results) */
  existingFindings: Finding[];
}

export interface IAnalyzer {
  readonly name: string;
  shouldRun(ctx: AnalyzerContext): boolean;
  analyze(ctx: AnalyzerContext): Promise<Finding[]>;
}
