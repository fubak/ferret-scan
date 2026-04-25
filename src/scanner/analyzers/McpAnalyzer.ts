import type { Finding } from '../../types.js';
import type { IAnalyzer, AnalyzerContext } from '../IAnalyzer.js';
import { validateMcpConfigContent, mcpAssessmentsToFindings } from '../../features/mcpValidator.js';

export class McpAnalyzer implements IAnalyzer {
  readonly name = 'McpAnalyzer';

  shouldRun(ctx: AnalyzerContext): boolean {
    return ctx.config.mcpValidation && ctx.file.component === 'mcp' && ctx.file.type === 'json';
  }

  async analyze(ctx: AnalyzerContext): Promise<Finding[]> {
    const mcpResult = validateMcpConfigContent(ctx.content);
    if (!mcpResult.valid || mcpResult.assessments.length === 0) {
      return [];
    }
    const mcpFindings = mcpAssessmentsToFindings(mcpResult.assessments, ctx.file.path);
    for (const f of mcpFindings) {
      f.relativePath = ctx.file.relativePath;
    }
    return mcpFindings;
  }
}
