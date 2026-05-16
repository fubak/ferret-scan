import type { Finding } from '../../types.js';
import type { IAnalyzer, AnalyzerContext } from '../IAnalyzer.js';
import { loadThreatDatabase } from '../../intelligence/ThreatFeed.js';
import { matchIndicators, shouldMatchIndicators } from '../../intelligence/IndicatorMatcher.js';
import logger from '../../utils/logger.js';

export class ThreatIntelAnalyzer implements IAnalyzer {
  readonly name = 'ThreatIntelAnalyzer';

  shouldRun(ctx: AnalyzerContext): boolean {
    return ctx.config.threatIntel && shouldMatchIndicators(ctx.file, ctx.config);
  }

  async analyze(ctx: AnalyzerContext): Promise<Finding[]> {
    const threatDB = loadThreatDatabase();
    logger.debug(`Running threat intelligence matching on ${ctx.file.relativePath}`);
    const threatFindings = matchIndicators(threatDB, ctx.file, ctx.content, {
      minConfidence: 50,
      enablePatternMatching: true,
      maxMatchesPerFile: 50,
    });
    logger.debug(`Found ${threatFindings.length} threat intelligence matches`);
    return threatFindings;
  }
}
