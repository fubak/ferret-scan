import type { Finding } from '../../types.js';
import type { IAnalyzer, AnalyzerContext } from '../IAnalyzer.js';
import { analyzeEntropy, entropyFindingsToFindings } from '../../features/entropyAnalysis.js';

export class EntropyAnalyzer implements IAnalyzer {
  readonly name = 'EntropyAnalyzer';

  shouldRun(ctx: AnalyzerContext): boolean {
    return ctx.config.entropyAnalysis;
  }

  async analyze(ctx: AnalyzerContext): Promise<Finding[]> {
    const entropyFindings = analyzeEntropy(ctx.content, ctx.file);
    return entropyFindingsToFindings(entropyFindings, ctx.file, ctx.content);
  }
}
