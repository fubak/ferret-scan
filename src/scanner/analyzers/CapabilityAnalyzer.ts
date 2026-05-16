import type { Finding } from '../../types.js';
import type { IAnalyzer, AnalyzerContext } from '../IAnalyzer.js';
import { analyzeCapabilitiesContent, capabilityProfileToFindings } from '../../features/capabilityMapping.js';

export class CapabilityAnalyzer implements IAnalyzer {
  readonly name = 'CapabilityAnalyzer';

  shouldRun(ctx: AnalyzerContext): boolean {
    return ctx.config.capabilityMapping && ctx.file.type === 'json';
  }

  async analyze(ctx: AnalyzerContext): Promise<Finding[]> {
    const profile = analyzeCapabilitiesContent(ctx.file.path, ctx.content);
    if (!profile) {
      return [];
    }
    const capFindings = capabilityProfileToFindings(profile);
    for (const f of capFindings) {
      f.relativePath = ctx.file.relativePath;
    }
    return capFindings;
  }
}
