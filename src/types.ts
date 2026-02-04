import { z } from 'zod';

// ─────────────────────────────────────────────────────────────
// Bug & Finding Types
// ─────────────────────────────────────────────────────────────

export const BugSeverity = z.enum(['critical', 'high', 'medium', 'low']);
export type BugSeverity = z.infer<typeof BugSeverity>;

export const FindingKind = z.enum(['bug', 'smell']);
export type FindingKind = z.infer<typeof FindingKind>;

// 12 categories grouped into 4 families:
// SECURITY: injection, auth-bypass, secrets-exposure
// RELIABILITY: null-reference, boundary-error, resource-leak, async-issue
// CORRECTNESS: logic-error, data-validation, type-coercion
// DESIGN: concurrency, intent-violation
export const BugCategory = z.enum([
  // Security (external threats)
  'injection',           // SQL injection, XSS, command injection, path traversal
  'auth-bypass',         // Authentication/authorization flaws, privilege escalation
  'secrets-exposure',    // Hardcoded credentials, leaked tokens, exposed API keys
  // Reliability (runtime failures)
  'null-reference',      // Null/undefined dereference, optional chaining needed
  'boundary-error',      // Off-by-one, array bounds, integer overflow, loop issues
  'resource-leak',       // Unclosed connections, file handles, memory leaks, timers
  'async-issue',         // Missing await, unhandled promises, race conditions
  // Correctness (wrong behavior)
  'logic-error',         // Wrong operators, incorrect conditions, bad math, wrong comparisons
  'data-validation',     // Missing input validation, format checking, sanitization
  'type-coercion',       // Implicit coercion bugs, wrong type handling, NaN propagation
  // Design (intent violations)
  'concurrency',         // Thread safety, deadlocks, shared state mutation
  'intent-violation',    // Code does opposite of what comments/names suggest
]);
export type BugCategory = z.infer<typeof BugCategory>;

export const ConfidenceLevel = z.enum(['high', 'medium', 'low']);
export type ConfidenceLevel = z.infer<typeof ConfidenceLevel>;

export const ConfidenceScore = z.object({
  overall: ConfidenceLevel,
  codePathValidity: z.number().min(0).max(1),
  reachability: z.number().min(0).max(1),
  intentViolation: z.boolean(),
  staticToolSignal: z.boolean(),
  adversarialSurvived: z.boolean(),
});
export type ConfidenceScore = z.infer<typeof ConfidenceScore>;

export const CodePathStep = z.object({
  step: z.number(),
  file: z.string(),
  line: z.number(),
  code: z.string(),
  explanation: z.string(),
});
export type CodePathStep = z.infer<typeof CodePathStep>;

export const BugStatus = z.enum(['open', 'fixed', 'false-positive', 'wont-fix']);
export type BugStatus = z.infer<typeof BugStatus>;

export const Bug = z.object({
  id: z.string(),
  title: z.string(),
  description: z.string(),
  file: z.string(),
  line: z.number(),
  endLine: z.number().optional(),
  kind: FindingKind.default('bug'),
  severity: BugSeverity,
  category: BugCategory,
  confidence: ConfidenceScore,
  codePath: z.array(CodePathStep),
  evidence: z.array(z.string()),
  suggestedFix: z.string().optional(),
  relatedContract: z.string().optional(),
  staticAnalysisSignals: z.array(z.string()).optional(),
  createdAt: z.string().datetime(),
  // Fix tracking
  status: BugStatus.default('open'),
  fixedAt: z.string().datetime().optional(),
  fixCommit: z.string().optional(),
  // Scanner metadata
  passName: z.string().optional(), // Which pass found this bug
});
export type Bug = z.infer<typeof Bug>;

// ─────────────────────────────────────────────────────────────
// Config Types
// ─────────────────────────────────────────────────────────────

export const ProviderType = z.enum([
  'claude-code',
  'aider',
  'codex',
  'opencode',
  'ollama',
  'gemini',
]);
export type ProviderType = z.infer<typeof ProviderType>;

export const PriorityLevel = z.enum(['critical', 'high', 'medium', 'low', 'ignore']);
export type PriorityLevel = z.infer<typeof PriorityLevel>;

export const PackageConfig = z.object({
  path: z.string(),
  priority: PriorityLevel,
  include: z.array(z.string()).optional(),
  exclude: z.array(z.string()).optional(),
});
export type PackageConfig = z.infer<typeof PackageConfig>;

export const MonorepoConfig = z.object({
  detection: z.enum(['auto', 'explicit']),
  packages: z.array(PackageConfig).optional(),
  crossPackageAnalysis: z.boolean().default(true),
});
export type MonorepoConfig = z.infer<typeof MonorepoConfig>;

export const WhiteroseConfig = z.object({
  version: z.string().default('1'),
  provider: ProviderType.default('claude-code'),
  providerFallback: z.array(ProviderType).optional(),

  // Scan settings
  include: z.array(z.string()).default(['**/*.ts', '**/*.tsx', '**/*.js', '**/*.jsx']),
  exclude: z.array(z.string()).default(['node_modules', 'dist', 'build', '.next', 'coverage']),

  // Priority areas
  priorities: z
    .record(z.string(), PriorityLevel)
    .default({}),

  // Bug categories to scan for (all 12 categories by default)
  categories: z.array(BugCategory).default([
    // Security
    'injection',
    'auth-bypass',
    'secrets-exposure',
    // Reliability
    'null-reference',
    'boundary-error',
    'resource-leak',
    'async-issue',
    // Correctness
    'logic-error',
    'data-validation',
    'type-coercion',
    // Design
    'concurrency',
    'intent-violation',
  ]),

  // Confidence threshold for reporting
  minConfidence: ConfidenceLevel.default('low'),

  // Monorepo settings
  monorepo: MonorepoConfig.optional(),

  // Static analysis integration
  staticAnalysis: z.object({
    typescript: z.boolean().default(true),
    eslint: z.boolean().default(true),
  }).default({}),

  // Output settings
  output: z.object({
    sarif: z.boolean().default(true),
    markdown: z.boolean().default(true),
    sarifPath: z.string().default('.whiterose/reports'),
    markdownPath: z.string().default('BUGS.md'),
  }).default({}),
});
export type WhiteroseConfig = z.infer<typeof WhiteroseConfig>;

// ─────────────────────────────────────────────────────────────
// Intent & Contract Types
// ─────────────────────────────────────────────────────────────

export const BehavioralContract = z.object({
  function: z.string(),
  file: z.string(),
  inputs: z.array(
    z.object({
      name: z.string(),
      type: z.string(),
      constraints: z.string().optional(),
    })
  ),
  outputs: z.object({
    type: z.string(),
    constraints: z.string().optional(),
  }),
  invariants: z.array(z.string()),
  sideEffects: z.array(z.string()),
  throws: z.array(z.string()).optional(),
});
export type BehavioralContract = z.infer<typeof BehavioralContract>;

export const FeatureIntent = z.object({
  name: z.string(),
  description: z.string(),
  priority: PriorityLevel,
  constraints: z.array(z.string()),
  relatedFiles: z.array(z.string()),
});
export type FeatureIntent = z.infer<typeof FeatureIntent>;

export const CodebaseUnderstanding = z.object({
  version: z.string(),
  generatedAt: z.string().datetime(),
  summary: z.object({
    framework: z.string().optional(),
    language: z.string(),
    type: z.string(), // e-commerce, saas, api, etc.
    description: z.string(),
  }),
  features: z.array(FeatureIntent),
  contracts: z.array(BehavioralContract),
  dependencies: z.record(z.string(), z.string()),
  structure: z.object({
    totalFiles: z.number(),
    totalLines: z.number(),
    packages: z.array(z.string()).optional(),
  }),
});
export type CodebaseUnderstanding = z.infer<typeof CodebaseUnderstanding>;

// ─────────────────────────────────────────────────────────────
// Cache Types
// ─────────────────────────────────────────────────────────────

export const FileHash = z.object({
  path: z.string(),
  hash: z.string(),
  lastModified: z.string().datetime(),
});
export type FileHash = z.infer<typeof FileHash>;

export const CacheState = z.object({
  version: z.string(),
  lastFullScan: z.string().datetime().optional(),
  lastIncrementalScan: z.string().datetime().optional(),
  fileHashes: z.array(FileHash),
});
export type CacheState = z.infer<typeof CacheState>;

// ─────────────────────────────────────────────────────────────
// Provider Types
// ─────────────────────────────────────────────────────────────

// NOTE: AnalysisContext removed - use ScanContext from CoreScanner instead

export interface StaticAnalysisResult {
  tool: 'typescript' | 'eslint';
  file: string;
  line: number;
  message: string;
  severity: 'error' | 'warning' | 'info';
  code?: string;
}

// NOTE: LLMProvider interface removed - use PromptExecutor + CoreScanner instead
// See src/core/scanner.ts for the new LSP-compliant architecture

export interface AdversarialResult {
  survived: boolean;
  counterArguments: string[];
  adjustedConfidence?: ConfidenceScore;
}

// ─────────────────────────────────────────────────────────────
// Scan Result Types
// ─────────────────────────────────────────────────────────────

export const ScanResult = z.object({
  id: z.string(),
  timestamp: z.string().datetime(),
  scanType: z.enum(['full', 'incremental']),
  filesScanned: z.number(),
  filesChanged: z.number().optional(),
  duration: z.number(), // ms
  bugs: z.array(Bug),
  summary: z.object({
    critical: z.number(),
    high: z.number(),
    medium: z.number(),
    low: z.number(),
    total: z.number(),
    bugs: z.number(),
    smells: z.number(),
  }),
});
export type ScanResult = z.infer<typeof ScanResult>;
