import { basename } from 'node:path';
import type { Finding } from '../../types.js';
import type { IAnalyzer, AnalyzerContext } from '../IAnalyzer.js';
import { analyzeDependencies, dependencyAssessmentsToFindings } from '../../features/dependencyRisk.js';

export class DependencyAnalyzer implements IAnalyzer {
  readonly name = 'DependencyAnalyzer';

  shouldRun(ctx: AnalyzerContext): boolean {
    return (
      ctx.config.dependencyAnalysis &&
      basename(ctx.file.path).toLowerCase() === 'package.json'
    );
  }

  async analyze(ctx: AnalyzerContext): Promise<Finding[]> {
    const depResult = analyzeDependencies(ctx.file.path, ctx.config.dependencyAudit);
    const depFindings = dependencyAssessmentsToFindings(depResult);
    for (const f of depFindings) {
      f.relativePath = ctx.file.relativePath;
    }
    return depFindings;
  }
}
