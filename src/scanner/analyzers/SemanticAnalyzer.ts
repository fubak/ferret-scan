import type { Finding } from '../../types.js';
import type { IAnalyzer, AnalyzerContext } from '../IAnalyzer.js';
import {
  analyzeFile as analyzeFileSemantics,
  shouldAnalyze as shouldAnalyzeSemantics,
  getMemoryUsage,
} from '../../analyzers/AstAnalyzer.js';
import logger from '../../utils/logger.js';

export class SemanticAnalyzer implements IAnalyzer {
  readonly name = 'SemanticAnalyzer';

  shouldRun(ctx: AnalyzerContext): boolean {
    return ctx.config.semanticAnalysis && shouldAnalyzeSemantics(ctx.file, ctx.config);
  }

  async analyze(ctx: AnalyzerContext): Promise<Finding[]> {
    const memBefore = getMemoryUsage();
    if (memBefore.used > 1000) {
      logger.warn(
        `High memory usage (${memBefore.used}MB) - skipping semantic analysis for ${ctx.file.relativePath}`
      );
      return [];
    }

    logger.debug(`Running semantic analysis on ${ctx.file.relativePath}`);
    const semanticFindings = await analyzeFileSemantics(ctx.file, ctx.content, ctx.rules);

    const memAfter = getMemoryUsage();
    logger.debug(`Semantic analysis memory: ${memAfter.used - memBefore.used}MB delta`);

    return semanticFindings;
  }
}
