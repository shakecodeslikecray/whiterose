/**
 * Validation utilities for safe JSON parsing with Zod schemas
 */

import { z, ZodSchema, ZodError } from 'zod';
import {
  Bug,
  CodebaseUnderstanding,
  CacheState,
  WhiteroseConfig,
  AdversarialResult,
  BugSeverity,
  BugCategory,
  ConfidenceLevel,
} from '../types.js';

/**
 * Safe JSON parse with Zod validation
 * Returns undefined if parsing or validation fails
 */
export function safeParseJson<T>(
  json: string,
  schema: ZodSchema<T>
): { success: true; data: T } | { success: false; error: string } {
  try {
    const parsed = JSON.parse(json);
    const result = schema.safeParse(parsed);
    if (result.success) {
      return { success: true, data: result.data };
    }
    return { success: false, error: formatZodError(result.error) };
  } catch (error: any) {
    return { success: false, error: error.message || 'Invalid JSON' };
  }
}

/**
 * Format Zod error for logging
 */
export function formatZodError(error: ZodError): string {
  return error.errors
    .map((e) => `${e.path.join('.')}: ${e.message}`)
    .join(', ');
}

/**
 * Partial Bug schema for LLM output (may not have all fields)
 * LLM output often lacks id, createdAt, etc.
 * Made very lenient to handle varied LLM responses.
 */
export const PartialBugFromLLM = z.object({
  file: z.string(),
  line: z.number(),
  endLine: z.number().optional(),
  title: z.string(),
  description: z.string().optional().default(''),
  severity: BugSeverity.optional().default('medium'),
  category: BugCategory.optional().default('logic-error'),
  codePath: z.array(z.object({
    step: z.number().optional(),
    file: z.string().optional(),
    line: z.number().optional(),
    code: z.string().optional().default(''),
    explanation: z.string().optional().default(''),
  })).optional().default([]),
  evidence: z.array(z.string()).optional().default([]),
  suggestedFix: z.string().optional(),
  confidence: z.object({
    overall: ConfidenceLevel.optional().default('medium'),
    codePathValidity: z.number().min(0).max(1).optional().default(0.5),
    reachability: z.number().min(0).max(1).optional().default(0.5),
    intentViolation: z.boolean().optional().default(false),
    staticToolSignal: z.boolean().optional().default(false),
    adversarialSurvived: z.boolean().optional().default(false),
  }).optional().default({}),
});
export type PartialBugFromLLM = z.infer<typeof PartialBugFromLLM>;

/**
 * Partial Understanding schema for LLM output
 */
export const PartialUnderstandingFromLLM = z.object({
  summary: z.object({
    type: z.string().optional().default('unknown'),
    framework: z.string().optional(),
    language: z.string().optional().default('unknown'),
    description: z.string().optional().default(''),
  }).optional().default({}),
  features: z.array(z.object({
    name: z.string(),
    description: z.string(),
    priority: z.enum(['critical', 'high', 'medium', 'low', 'ignore']).optional().default('medium'),
    constraints: z.array(z.string()).optional().default([]),
    relatedFiles: z.array(z.string()).optional().default([]),
  })).optional().default([]),
  contracts: z.array(z.object({
    function: z.string(),
    file: z.string(),
    inputs: z.array(z.object({
      name: z.string(),
      type: z.string(),
      constraints: z.string().optional(),
    })).optional().default([]),
    outputs: z.object({
      type: z.string(),
      constraints: z.string().optional(),
    }).optional().default({ type: 'unknown' }),
    invariants: z.array(z.string()).optional().default([]),
    sideEffects: z.array(z.string()).optional().default([]),
    throws: z.array(z.string()).optional(),
  })).optional().default([]),
  dependencies: z.record(z.string(), z.string()).optional().default({}),
});
export type PartialUnderstandingFromLLM = z.infer<typeof PartialUnderstandingFromLLM>;

/**
 * Adversarial validation result schema
 */
export const AdversarialResultSchema = z.object({
  survived: z.boolean(),
  counterArguments: z.array(z.string()).optional().default([]),
  confidence: ConfidenceLevel.optional(),
});

/**
 * SARIF schema (simplified for whiterose needs)
 */
export const SarifResultSchema = z.object({
  $schema: z.string().optional(),
  version: z.string(),
  runs: z.array(z.object({
    tool: z.object({
      driver: z.object({
        name: z.string(),
        version: z.string().optional(),
        informationUri: z.string().optional(),
        rules: z.array(z.any()).optional(),
      }),
    }),
    results: z.array(z.object({
      ruleId: z.string().optional(),
      level: z.enum(['none', 'note', 'warning', 'error']).optional(),
      message: z.object({
        text: z.string(),
      }),
      locations: z.array(z.object({
        physicalLocation: z.object({
          artifactLocation: z.object({
            uri: z.string(),
          }),
          region: z.object({
            startLine: z.number(),
            endLine: z.number().optional(),
          }).optional(),
        }),
      })).optional(),
    })).optional().default([]),
  })),
});
export type SarifResult = z.infer<typeof SarifResultSchema>;

/**
 * GitHub issue schema (from gh CLI output)
 */
export const GitHubIssueSchema = z.object({
  number: z.number(),
  title: z.string(),
  body: z.string().nullable(),
  state: z.string(),
  labels: z.array(z.object({
    name: z.string(),
  })).optional().default([]),
  url: z.string().optional(),
});
export type GitHubIssue = z.infer<typeof GitHubIssueSchema>;

/**
 * ESLint output schema
 */
export const ESLintOutputSchema = z.array(z.object({
  filePath: z.string(),
  messages: z.array(z.object({
    ruleId: z.string().nullable(),
    severity: z.number(),
    message: z.string(),
    line: z.number(),
    column: z.number(),
  })),
  errorCount: z.number(),
  warningCount: z.number(),
}));
export type ESLintOutput = z.infer<typeof ESLintOutputSchema>;

/**
 * Package.json schema (minimal)
 */
export const PackageJsonSchema = z.object({
  name: z.string().optional(),
  version: z.string().optional(),
  description: z.string().optional(),
  scripts: z.record(z.string(), z.string()).optional(),
  dependencies: z.record(z.string(), z.string()).optional(),
  devDependencies: z.record(z.string(), z.string()).optional(),
  workspaces: z.union([
    z.array(z.string()),
    z.object({ packages: z.array(z.string()) }),
  ]).optional(),
});
export type PackageJson = z.infer<typeof PackageJsonSchema>;

// Re-export schemas from types for convenience
export { Bug, CodebaseUnderstanding, CacheState, WhiteroseConfig };
