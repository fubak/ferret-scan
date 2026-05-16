/**
 * LLM Analysis Types & Schemas
 */

import { z } from 'zod';
import type { LlmScanConfig } from '../../types.js';

export interface LlmProvider {
  name: string;
  analyze(prompt: { system: string; user: string }): Promise<string>;
}

export const LlmFindingSchema = z.object({
  title: z.string().min(1).max(200),
  severity: z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']),
  category: z.string().min(1).max(50),
  line: z.number().int().min(1).max(1_000_000).optional(),
  match: z.string().min(1).max(2000),
  remediation: z.string().min(1).max(5000),
  confidence: z.number().min(0).max(1),
});

export const LlmResponseSchema = z.object({
  findings: z.array(LlmFindingSchema),
});

export interface LineRange {
  start: number;
  end: number;
}

export type { LlmScanConfig };
