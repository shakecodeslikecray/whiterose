/**
 * Core Scanner - LSP-Compliant Architecture
 *
 * Scanning logic lives HERE, not in providers.
 * Providers are just "dumb prompt executors".
 *
 * This ensures all providers get the same 19-pass scanning,
 * batching, deduplication, and merging logic.
 */

import { Bug, CodebaseUnderstanding, WhiteroseConfig, BugCategory, BugSeverity, ConfidenceLevel, CodePathStep, FeatureIntent, BehavioralContract } from '../types.js';
import { getFullAnalysisPipeline } from '../providers/prompts/flow-analysis-prompts.js';
import { buildPassPrompt } from '../providers/prompts/multipass-prompts.js';
import { buildFlowAnalysisPrompt } from '../providers/prompts/flow-analysis-prompts.js';
import { buildUnderstandingPrompt } from '../providers/prompts/understanding.js';
import { getPassConfig } from './multipass-scanner.js';
import { getFlowPassConfig } from './flow-analyzer.js';
import { generateBugId } from './utils.js';

// ─────────────────────────────────────────────────────────────
// Simple Provider Interface (LSP-compliant)
// ─────────────────────────────────────────────────────────────

export interface PromptOptions {
  cwd: string;
  timeout?: number;
}

export interface PromptResult {
  output: string;
  error?: string;
}

/**
 * Minimal interface that ALL providers must implement.
 * No scanning logic - just execute prompts and return results.
 */
export interface PromptExecutor {
  name: string;
  isAvailable(): Promise<boolean>;
  runPrompt(prompt: string, options: PromptOptions): Promise<PromptResult>;
}

// ─────────────────────────────────────────────────────────────
// Scanner Configuration
// ─────────────────────────────────────────────────────────────

export interface ScannerConfig {
  batchSize: number;
  batchDelayMs: number;
  passTimeoutMs: number;
}

export const DEFAULT_SCANNER_CONFIG: ScannerConfig = {
  batchSize: 5,
  batchDelayMs: 2000,
  passTimeoutMs: 300000, // 5 minutes per pass
};

export interface StaticFinding {
  tool: string;
  file: string;
  line: number;
  message: string;
  severity: string;
}

export interface ScanContext {
  files: string[];
  understanding: CodebaseUnderstanding;
  staticResults: StaticFinding[];
  config?: WhiteroseConfig;
}

export interface ScanProgress {
  onPhaseStart?: (phase: string, passCount: number) => void;
  onPassStart?: (passName: string) => void;
  onPassComplete?: (passName: string, bugCount: number) => void;
  onPassError?: (passName: string, error: string) => void;
  onBugFound?: (bug: Bug) => void;
  onProgress?: (message: string) => void;
}

// ─────────────────────────────────────────────────────────────
// Core Scanner
// ─────────────────────────────────────────────────────────────

export class CoreScanner {
  private executor: PromptExecutor;
  private config: ScannerConfig;
  private progress: ScanProgress;

  constructor(
    executor: PromptExecutor,
    config: Partial<ScannerConfig> = {},
    progress: ScanProgress = {}
  ) {
    this.executor = executor;
    this.config = { ...DEFAULT_SCANNER_CONFIG, ...config };
    this.progress = progress;
  }

  /**
   * Run a thorough 19-pass scan with findings flowing through pipeline:
   *
   * Static Analysis → Unit Passes → Integration Passes → E2E Passes
   *                        ↓              ↓                  ↓
   *                   unitFindings → integrationFindings → e2eFindings
   *                        └──────────────┴─────────────────┘
   *                                       ↓
   *                              Combined + Deduped
   */
  async scan(context: ScanContext): Promise<Bug[]> {
    const cwd = process.cwd();
    const startTime = Date.now();

    // Get all passes from the pipeline
    const pipeline = getFullAnalysisPipeline();
    const unitPasses = pipeline[0].passes;
    const integrationPasses = pipeline[1].passes;
    const e2ePasses = pipeline[2].passes;
    const totalPasses = unitPasses.length + integrationPasses.length + e2ePasses.length;

    this.report(`\n════ CORE SCANNER (PIPELINE MODE) ════`);
    this.report(`  Provider: ${this.executor.name}`);
    this.report(`  Passes: ${totalPasses} (${unitPasses.length} unit → ${integrationPasses.length} integration → ${e2ePasses.length} E2E)`);
    this.report(`  Findings flow: Unit → Integration → E2E`);

    let globalBugIndex = 0;

    // ═══════════════════════════════════════════════════════════
    // PHASE 1: Unit Passes (pattern matching, single-file bugs)
    // Input: staticResults only
    // ═══════════════════════════════════════════════════════════
    this.report(`\n════ PHASE 1: UNIT ANALYSIS ════`);
    this.report(`  Looking for: injection, null refs, auth bypass, etc.`);

    const unitJobs = this.buildUnitPassJobs(context, unitPasses);
    const unitFindings = await this.runPassBatch(unitJobs, cwd, context.files, globalBugIndex);
    globalBugIndex += unitFindings.length;

    this.report(`  Phase 1 complete: ${unitFindings.length} findings`);

    // ═══════════════════════════════════════════════════════════
    // PHASE 2: Integration Passes (cross-file data flow)
    // Input: staticResults + unitFindings
    // ═══════════════════════════════════════════════════════════
    this.report(`\n════ PHASE 2: INTEGRATION ANALYSIS ════`);
    this.report(`  Building on ${unitFindings.length} unit findings`);
    this.report(`  Looking for: auth flows, data flows, trust boundaries`);

    const integrationJobs = this.buildIntegrationPassJobs(context, integrationPasses, unitFindings);
    const integrationFindings = await this.runPassBatch(integrationJobs, cwd, context.files, globalBugIndex);
    globalBugIndex += integrationFindings.length;

    this.report(`  Phase 2 complete: ${integrationFindings.length} findings`);

    // ═══════════════════════════════════════════════════════════
    // PHASE 3: E2E Passes (attack chains, full scenarios)
    // Input: staticResults + unitFindings + integrationFindings
    // ═══════════════════════════════════════════════════════════
    this.report(`\n════ PHASE 3: E2E ANALYSIS ════`);
    this.report(`  Building on ${unitFindings.length} unit + ${integrationFindings.length} integration findings`);
    this.report(`  Looking for: attack chains, privilege escalation, session bugs`);

    const allPreviousFindings = [...unitFindings, ...integrationFindings];
    const e2eJobs = this.buildE2EPassJobs(context, e2ePasses, allPreviousFindings);
    const e2eFindings = await this.runPassBatch(e2eJobs, cwd, context.files, globalBugIndex);

    this.report(`  Phase 3 complete: ${e2eFindings.length} findings`);

    // ═══════════════════════════════════════════════════════════
    // POST-PROCESSING: Combine and deduplicate
    // ═══════════════════════════════════════════════════════════
    this.report(`\n════ POST-PROCESSING ════`);

    const allBugs = [...unitFindings, ...integrationFindings, ...e2eFindings];
    this.report(`  Total raw findings: ${allBugs.length}`);

    const { unique: dedupedBugs, duplicatesRemoved } = this.deduplicateBugs(allBugs);
    this.report(`  Removed ${duplicatesRemoved} duplicates`);

    const mergedBugs = this.mergeSimilarBugs(dedupedBugs);
    const similarMerged = dedupedBugs.length - mergedBugs.length;
    if (similarMerged > 0) {
      this.report(`  Merged ${similarMerged} similar findings`);
    }

    // Summary
    const duration = Date.now() - startTime;
    const minutes = Math.floor(duration / 60000);
    const seconds = Math.round((duration % 60000) / 1000);

    this.report(`\n════ SCAN COMPLETE ════`);
    this.report(`  Duration: ${minutes}m ${seconds}s`);
    this.report(`  Unit: ${unitFindings.length} → Integration: ${integrationFindings.length} → E2E: ${e2eFindings.length}`);
    this.report(`  Final bugs: ${mergedBugs.length}`);

    return mergedBugs;
  }

  /**
   * Run a batch of passes in parallel (within a phase)
   */
  private async runPassBatch(
    passes: Array<{ name: string; prompt: string }>,
    cwd: string,
    files: string[],
    startIndex: number
  ): Promise<Bug[]> {
    const allBugs: Bug[] = [];
    let bugIndex = startIndex;

    for (let i = 0; i < passes.length; i += this.config.batchSize) {
      const batch = passes.slice(i, i + this.config.batchSize);
      const batchNum = Math.floor(i / this.config.batchSize) + 1;
      const totalBatches = Math.ceil(passes.length / this.config.batchSize);

      this.report(`\n  [Batch ${batchNum}/${totalBatches}] ${batch.map(p => p.name).join(', ')}`);

      const batchPromises = batch.map(async (pass) => {
        this.progress.onPassStart?.(pass.name);

        try {
          const result = await this.executor.runPrompt(pass.prompt, {
            cwd,
            timeout: this.config.passTimeoutMs,
          });

          const bugs = this.parseResponse(result.output, files, bugIndex, pass.name);
          bugIndex += bugs.length;

          this.progress.onPassComplete?.(pass.name, bugs.length);
          this.report(`    ✓ ${pass.name}: ${bugs.length} bugs`);

          return bugs;
        } catch (error: any) {
          this.progress.onPassError?.(pass.name, error.message);
          this.report(`    ✗ ${pass.name}: ${error.message}`);
          return [];
        }
      });

      const batchResults = await Promise.allSettled(batchPromises);

      for (const result of batchResults) {
        if (result.status === 'fulfilled') {
          allBugs.push(...result.value);
        }
      }

      // Delay between batches (except last)
      if (i + this.config.batchSize < passes.length) {
        await this.delay(this.config.batchDelayMs);
      }
    }

    return allBugs;
  }

  /**
   * Run a quick single-pass scan
   */
  async quickScan(context: ScanContext): Promise<Bug[]> {
    const cwd = process.cwd();

    this.report(`\n════ QUICK SCAN ════`);
    this.report(`  Provider: ${this.executor.name}`);

    const prompt = this.buildQuickScanPrompt(context);

    try {
      const result = await this.executor.runPrompt(prompt, {
        cwd,
        timeout: this.config.passTimeoutMs,
      });

      const bugs = this.parseResponse(result.output, context.files, 0, 'quick-scan');
      this.report(`  Found ${bugs.length} bugs`);

      return bugs;
    } catch (error: any) {
      this.report(`  Error: ${error.message}`);
      return [];
    }
  }

  /**
   * Generate codebase understanding (for init/refresh commands)
   * Uses the LLM to analyze project structure and extract features
   */
  async generateUnderstanding(files: string[], existingDocsSummary?: string): Promise<CodebaseUnderstanding> {
    const cwd = process.cwd();

    this.report(`\n════ GENERATING UNDERSTANDING ════`);
    this.report(`  Provider: ${this.executor.name}`);
    this.report(`  Files: ${files.length}`);

    const prompt = buildUnderstandingPrompt({ existingDocsSummary });

    try {
      const result = await this.executor.runPrompt(prompt, {
        cwd,
        timeout: this.config.passTimeoutMs * 2, // Allow more time for understanding
      });

      const understanding = this.parseUnderstandingResponse(result.output, files);
      this.report(`  Understanding complete`);

      return understanding;
    } catch (error: any) {
      this.report(`  Error: ${error.message}`);
      throw error;
    }
  }

  /**
   * Parse understanding response from LLM
   */
  private parseUnderstandingResponse(output: string, files: string[]): CodebaseUnderstanding {
    // Try to extract JSON from <json></json> tags
    const jsonMatch = output.match(/<json>([\s\S]*?)<\/json>/);
    let parsed: any;

    if (jsonMatch) {
      try {
        parsed = JSON.parse(jsonMatch[1]);
      } catch {
        // Try markdown code block
        const codeBlockMatch = output.match(/```(?:json)?\s*([\s\S]*?)```/);
        if (codeBlockMatch) {
          parsed = JSON.parse(codeBlockMatch[1]);
        }
      }
    } else {
      // Try to find any JSON object
      const jsonObjectMatch = output.match(/\{[\s\S]*\}/);
      if (jsonObjectMatch) {
        try {
          parsed = JSON.parse(jsonObjectMatch[0]);
        } catch {
          // Continue with defaults
        }
      }
    }

    // Build understanding with defaults
    const now = new Date().toISOString();

    // Count lines (rough estimate from file count)
    const estimatedLines = files.length * 150;

    // Parse features
    const features: FeatureIntent[] = (parsed?.features || []).map((f: any) => ({
      name: String(f.name || 'Unknown'),
      description: String(f.description || ''),
      priority: this.parseFeaturePriority(f.priority),
      constraints: Array.isArray(f.constraints) ? f.constraints.map(String) : [],
      relatedFiles: Array.isArray(f.relatedFiles) ? f.relatedFiles.map(String) : [],
    }));

    // Parse contracts
    const contracts: BehavioralContract[] = (parsed?.contracts || []).map((c: any) => ({
      function: String(c.function || ''),
      file: String(c.file || ''),
      inputs: Array.isArray(c.inputs) ? c.inputs : [],
      outputs: c.outputs || { type: 'unknown' },
      invariants: Array.isArray(c.invariants) ? c.invariants.map(String) : [],
      sideEffects: Array.isArray(c.sideEffects) ? c.sideEffects.map(String) : [],
      throws: Array.isArray(c.throws) ? c.throws.map(String) : undefined,
    }));

    return {
      version: '1',
      generatedAt: now,
      summary: {
        framework: parsed?.summary?.framework || undefined,
        language: parsed?.summary?.language || 'typescript',
        type: parsed?.summary?.type || 'unknown',
        description: parsed?.summary?.description || 'Project analyzed by whiterose',
      },
      features,
      contracts,
      dependencies: parsed?.dependencies || {},
      structure: {
        totalFiles: files.length,
        totalLines: parsed?.structure?.totalLines || estimatedLines,
        packages: parsed?.structure?.packages,
      },
    };
  }

  private parseFeaturePriority(value: any): 'critical' | 'high' | 'medium' | 'low' | 'ignore' {
    const v = String(value).toLowerCase();
    if (v === 'critical') return 'critical';
    if (v === 'high') return 'high';
    if (v === 'medium') return 'medium';
    if (v === 'ignore') return 'ignore';
    return 'low';
  }

  // ─────────────────────────────────────────────────────────────
  // Pass Building (with dependency injection)
  // ─────────────────────────────────────────────────────────────

  /**
   * Build unit pass jobs - these only see static analysis results
   */
  private buildUnitPassJobs(
    context: ScanContext,
    unitPasses: string[]
  ): Array<{ name: string; prompt: string }> {
    const jobs: Array<{ name: string; prompt: string }> = [];
    const { understanding, staticResults } = context;

    for (const passName of unitPasses) {
      const passConfig = getPassConfig(passName);
      if (!passConfig) continue;

      jobs.push({
        name: passName,
        prompt: buildPassPrompt({
          pass: passConfig,
          projectType: understanding.summary.type,
          framework: understanding.summary.framework || '',
          language: understanding.summary.language,
          totalFiles: understanding.structure.totalFiles,
          staticFindings: staticResults,
        }),
      });
    }

    return jobs;
  }

  /**
   * Build integration pass jobs - these see static + unit findings
   */
  private buildIntegrationPassJobs(
    context: ScanContext,
    integrationPasses: string[],
    unitFindings: Bug[]
  ): Array<{ name: string; prompt: string }> {
    const jobs: Array<{ name: string; prompt: string }> = [];
    const { understanding, staticResults } = context;

    // Convert unit findings to the format expected by prompts
    const previousFindings = unitFindings.map(f => ({
      title: f.title,
      file: f.file,
      line: f.line,
      category: f.category,
      severity: f.severity,
    }));

    for (const passName of integrationPasses) {
      const flowConfig = getFlowPassConfig(passName);
      if (!flowConfig) continue;

      jobs.push({
        name: passName,
        prompt: buildFlowAnalysisPrompt({
          pass: flowConfig,
          projectType: understanding.summary.type,
          framework: understanding.summary.framework || '',
          language: understanding.summary.language,
          totalFiles: understanding.structure.totalFiles,
          staticFindings: staticResults,
          previousFindings, // ← Unit findings passed to integration
        }),
      });
    }

    return jobs;
  }

  /**
   * Build E2E pass jobs - these see static + unit + integration findings
   */
  private buildE2EPassJobs(
    context: ScanContext,
    e2ePasses: string[],
    allPreviousFindings: Bug[]
  ): Array<{ name: string; prompt: string }> {
    const jobs: Array<{ name: string; prompt: string }> = [];
    const { understanding, staticResults } = context;

    // Convert findings to the format expected by prompts
    const previousFindings = allPreviousFindings.map(f => ({
      title: f.title,
      file: f.file,
      line: f.line,
      category: f.category,
      severity: f.severity,
    }));

    for (const passName of e2ePasses) {
      const flowConfig = getFlowPassConfig(passName);
      if (!flowConfig) continue;

      jobs.push({
        name: passName,
        prompt: buildFlowAnalysisPrompt({
          pass: flowConfig,
          projectType: understanding.summary.type,
          framework: understanding.summary.framework || '',
          language: understanding.summary.language,
          totalFiles: understanding.structure.totalFiles,
          staticFindings: staticResults,
          previousFindings, // ← All previous findings passed to E2E
        }),
      });
    }

    return jobs;
  }

  private buildQuickScanPrompt(context: ScanContext): string {
    const { understanding, staticResults } = context;

    const staticSignals = staticResults.length > 0
      ? `\nStatic analysis signals:\n${staticResults.slice(0, 30).map(r => `- ${r.file}:${r.line}: ${r.message}`).join('\n')}`
      : '';

    return `You are a security auditor. Analyze this ${understanding.summary.type} codebase for bugs.

Project: ${understanding.summary.description || 'Unknown'}
Framework: ${understanding.summary.framework || 'None'}
Language: ${understanding.summary.language}
${staticSignals}

Find bugs in these categories:
1. Injection (SQL, command, XSS)
2. Auth bypass
3. Null/undefined dereference
4. Logic errors
5. Async/race conditions
6. Resource leaks
7. Data validation issues
8. Secrets exposure

Output ONLY a JSON array:
[{"file": "path", "line": 42, "title": "Bug title", "description": "Details", "severity": "critical|high|medium|low", "category": "injection|auth-bypass|null-reference|logic-error|async-issue|resource-leak|data-validation|secrets-exposure", "evidence": ["evidence"], "suggestedFix": "fix"}]

If no bugs, return: []`;
  }

  // ─────────────────────────────────────────────────────────────
  // Response Parsing
  // ─────────────────────────────────────────────────────────────

  private parseResponse(output: string, files: string[], startIndex: number, passName: string): Bug[] {
    const bugs: Bug[] = [];

    // Find all JSON blocks in the output
    const jsonMatches = output.matchAll(/<json>([\s\S]*?)<\/json>/g);

    for (const match of jsonMatches) {
      try {
        const parsed = JSON.parse(match[1]);

        if (parsed.type === 'bug' && parsed.data) {
          const bug = this.parseBugData(parsed.data, startIndex + bugs.length, files, passName);
          if (bug) {
            bugs.push(bug);
            this.progress.onBugFound?.(bug);
          }
        }
      } catch {
        // Continue on parse error
      }
    }

    // Also try parsing as a plain JSON array (for quick scan)
    if (bugs.length === 0) {
      const arrayMatch = output.match(/\[[\s\S]*\]/);
      if (arrayMatch) {
        try {
          const parsed = JSON.parse(arrayMatch[0]);
          if (Array.isArray(parsed)) {
            for (const item of parsed) {
              const bug = this.parseBugData(item, startIndex + bugs.length, files, passName);
              if (bug) {
                bugs.push(bug);
                this.progress.onBugFound?.(bug);
              }
            }
          }
        } catch {
          // Continue
        }
      }
    }

    return bugs;
  }

  private parseBugData(data: any, index: number, files: string[], passName: string): Bug | null {
    if (!data.file || !data.line || !data.title) {
      return null;
    }

    // Resolve file path
    let filePath = data.file;
    if (!filePath.startsWith('/')) {
      const match = files.find(f => f.endsWith(filePath) || f.includes(filePath));
      if (match) filePath = match;
    }

    // Parse code path
    const codePath: CodePathStep[] = (data.codePath || data.dataFlow || []).map(
      (step: any, idx: number) => ({
        step: step.step || idx + 1,
        file: step.file || filePath,
        line: step.line || data.line,
        code: step.code || '',
        explanation: step.explanation || '',
      })
    );

    return {
      id: generateBugId(index),
      title: String(data.title).slice(0, 150),
      description: String(data.description || ''),
      file: filePath,
      line: Number(data.line) || 0,
      endLine: data.endLine ? Number(data.endLine) : undefined,
      kind: data.kind || 'bug',
      severity: this.parseSeverity(data.severity),
      category: this.parseCategory(data.category),
      confidence: {
        overall: this.parseConfidence(data.confidence),
        codePathValidity: 0.8,
        reachability: 0.8,
        intentViolation: false,
        staticToolSignal: false,
        adversarialSurvived: false,
      },
      codePath,
      evidence: Array.isArray(data.evidence) ? data.evidence.map(String) : [],
      suggestedFix: data.suggestedFix ? String(data.suggestedFix) : undefined,
      createdAt: new Date().toISOString(),
      status: 'open',
      passName,
    };
  }

  // ─────────────────────────────────────────────────────────────
  // Deduplication
  // ─────────────────────────────────────────────────────────────

  private deduplicateBugs(bugs: Bug[]): { unique: Bug[]; duplicatesRemoved: number } {
    const seen = new Map<string, Bug>();

    for (const bug of bugs) {
      const key = `${bug.file}:${bug.line}:${bug.category}`;
      const existing = seen.get(key);

      if (!existing) {
        seen.set(key, bug);
      } else {
        // Keep higher confidence, merge evidence
        const existingConf = this.confidenceToNum(existing.confidence.overall);
        const newConf = this.confidenceToNum(bug.confidence.overall);

        if (newConf > existingConf) {
          bug.evidence = [...new Set([...bug.evidence, ...existing.evidence])];
          seen.set(key, bug);
        } else {
          existing.evidence = [...new Set([...existing.evidence, ...bug.evidence])];
        }
      }
    }

    return {
      unique: Array.from(seen.values()),
      duplicatesRemoved: bugs.length - seen.size,
    };
  }

  private mergeSimilarBugs(bugs: Bug[]): Bug[] {
    // Group by file and nearby lines (within 5 lines)
    const groups = new Map<string, Bug[]>();

    for (const bug of bugs) {
      const fileKey = bug.file;
      if (!groups.has(fileKey)) {
        groups.set(fileKey, []);
      }
      groups.get(fileKey)!.push(bug);
    }

    const result: Bug[] = [];

    for (const fileBugs of groups.values()) {
      // Sort by line
      fileBugs.sort((a, b) => a.line - b.line);

      let i = 0;
      while (i < fileBugs.length) {
        const current = fileBugs[i];
        const merged: Bug[] = [current];

        // Look for bugs within 5 lines with same category
        let j = i + 1;
        while (j < fileBugs.length) {
          const next = fileBugs[j];
          if (next.line - current.line <= 5 && next.category === current.category) {
            merged.push(next);
            j++;
          } else {
            break;
          }
        }

        if (merged.length === 1) {
          result.push(current);
        } else {
          // Merge into one bug
          const highestSeverity = merged.reduce((max, b) =>
            this.severityToNum(b.severity) > this.severityToNum(max.severity) ? b : max
          );

          highestSeverity.evidence = [...new Set(merged.flatMap(b => b.evidence))];
          highestSeverity.description = merged.map(b => b.description).join('\n\n');
          result.push(highestSeverity);
        }

        i = j;
      }
    }

    return result;
  }

  // ─────────────────────────────────────────────────────────────
  // Helpers
  // ─────────────────────────────────────────────────────────────

  private report(message: string): void {
    this.progress.onProgress?.(message);
  }

  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  private parseSeverity(value: any): BugSeverity {
    const v = String(value).toLowerCase();
    if (v === 'critical') return 'critical';
    if (v === 'high') return 'high';
    if (v === 'medium') return 'medium';
    return 'low';
  }

  private parseCategory(value: any): BugCategory {
    const v = String(value).toLowerCase().replace(/[^a-z-]/g, '');
    const valid: BugCategory[] = [
      'injection', 'auth-bypass', 'secrets-exposure', 'null-reference',
      'boundary-error', 'resource-leak', 'async-issue', 'logic-error',
      'data-validation', 'type-coercion', 'concurrency', 'intent-violation',
    ];
    return valid.includes(v as BugCategory) ? (v as BugCategory) : 'logic-error';
  }

  private parseConfidence(value: any): ConfidenceLevel {
    if (typeof value === 'object' && value?.overall) {
      value = value.overall;
    }
    const v = String(value).toLowerCase();
    if (v === 'high') return 'high';
    if (v === 'low') return 'low';
    return 'medium';
  }

  private confidenceToNum(c: ConfidenceLevel): number {
    return c === 'high' ? 3 : c === 'medium' ? 2 : 1;
  }

  private severityToNum(s: BugSeverity): number {
    return s === 'critical' ? 4 : s === 'high' ? 3 : s === 'medium' ? 2 : 1;
  }
}
