import type { Finding } from '../../types.js';
import type { IAnalyzer, AnalyzerContext } from '../IAnalyzer.js';
import { analyzeWithLlm, type LlmProvider } from '../../features/llmAnalysis.js';
import logger from '../../utils/logger.js';

export interface LlmRuntime {
  analyzed: number;
  disabled: boolean;
  disabledReason?: string;
}

export class LlmAnalyzer implements IAnalyzer {
  readonly name = 'LlmAnalyzer';

  constructor(
    private readonly llmProvider: LlmProvider | null,
    private readonly llmRuntime: LlmRuntime
  ) {}

  shouldRun(ctx: AnalyzerContext): boolean {
    return (
      ctx.config.llmAnalysis &&
      this.llmProvider !== null &&
      !this.llmRuntime.disabled &&
      this.llmRuntime.analyzed < ctx.config.llm.maxFiles
    );
  }

  async analyze(ctx: AnalyzerContext): Promise<Finding[]> {
    // shouldRun already guards llmProvider non-null, but TypeScript needs the cast
    const provider = this.llmProvider!;
    const llmResult = await analyzeWithLlm(
      provider,
      ctx.config.llm,
      ctx.file,
      ctx.content,
      ctx.existingFindings
    );

    if (llmResult.ran) {
      this.llmRuntime.analyzed += 1;
    }

    if (llmResult.error) {
      if (!this.llmRuntime.disabled && /\bHTTP 429\b/i.test(llmResult.error)) {
        this.llmRuntime.disabled = true;
        this.llmRuntime.disabledReason = 'rate limited (HTTP 429)';
        logger.warn('LLM disabled for remainder of scan due to rate limiting (HTTP 429)');
      }
      // Re-throw so the caller's catch block records it as a file error
      throw new Error(`LLM analysis: ${llmResult.error}`);
    }

    return llmResult.findings;
  }
}
