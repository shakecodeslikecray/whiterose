import { execa } from 'execa';
import { spawn, type ChildProcess } from 'child_process';
import { readFileSync, existsSync } from 'fs';
import { resolve, isAbsolute } from 'path';
import {
  LLMProvider,
  ProviderType,
  AnalysisContext,
  Bug,
  AdversarialResult,
  CodebaseUnderstanding,
  StaticAnalysisResult,
} from '../../types.js';
import { isProviderAvailable, getProviderCommand } from '../detect.js';
import { generateBugId } from '../../core/utils.js';
import {
  safeParseJson,
  PartialBugFromLLM,
  PartialUnderstandingFromLLM,
  AdversarialResultSchema,
} from '../../core/validation.js';
import {
  buildUnderstandingPrompt,
  buildAdversarialPrompt,
  buildOptimizedQuickScanPrompt,
  buildPassPrompt,
  buildFlowAnalysisPrompt,
  getFullAnalysisPipeline,
} from '../prompts/index.js';
import {
  getPassConfig,
  deduplicateBugs,
  mergeSimilarBugs,
} from '../../core/multipass-scanner.js';
import {
  getFlowPassConfig,
} from '../../core/flow-analyzer.js';
import {
  prepareOptimizedScan,
  TIER_CONFIGS,
  cacheResults,
  checkCache,
  type ScanTier,
} from '../../core/optimized-scanner.js';
import { loadCache, saveCache } from '../../core/analysis-cache.js';

// Callback for streaming progress updates
type ProgressCallback = (message: string) => void;
type BugFoundCallback = (bug: Bug) => void;

// Protocol markers for parsing agent output
const MARKERS = {
  SCANNING: '###SCANNING:',
  BUG: '###BUG:',
  UNDERSTANDING: '###UNDERSTANDING:',
  COMPLETE: '###COMPLETE',
  ERROR: '###ERROR:',
};

export class ClaudeCodeProvider implements LLMProvider {
  name: ProviderType = 'claude-code';

  private progressCallback?: ProgressCallback;
  private bugFoundCallback?: BugFoundCallback;
  private currentProcess?: ChildProcess;
  private unsafeMode = false;

  async detect(): Promise<boolean> {
    return isProviderAvailable('claude-code');
  }

  async isAvailable(): Promise<boolean> {
    return isProviderAvailable('claude-code');
  }

  /**
   * Enable unsafe mode (--dangerously-skip-permissions).
   * WARNING: This bypasses Claude's permission prompts and should only be used
   * when you trust the codebase being analyzed.
   */
  setUnsafeMode(enabled: boolean): void {
    this.unsafeMode = enabled;
  }

  isUnsafeMode(): boolean {
    return this.unsafeMode;
  }

  setProgressCallback(callback: ProgressCallback): void {
    this.progressCallback = callback;
  }

  setBugFoundCallback(callback: BugFoundCallback): void {
    this.bugFoundCallback = callback;
  }

  private reportProgress(message: string): void {
    if (this.progressCallback) {
      this.progressCallback(message);
    }
  }

  private reportBug(bug: Bug): void {
    if (this.bugFoundCallback) {
      this.bugFoundCallback(bug);
    }
  }

  // Cancel any running analysis
  cancel(): void {
    if (this.currentProcess) {
      this.currentProcess.kill();
      this.currentProcess = undefined;
    }
  }

  async analyze(context: AnalysisContext, options?: { quick?: boolean }): Promise<Bug[]> {
    const { files, understanding, staticAnalysisResults } = context;

    if (files.length === 0) {
      return [];
    }

    // Quick scan: parallel single-file analysis (for pre-commit hooks)
    if (options?.quick) {
      return this.quickScan(files, understanding, staticAnalysisResults || []);
    }

    // Thorough scan: agentic exploration (for full audits)
    return this.thoroughScan(files, understanding, staticAnalysisResults || []);
  }

  // ─────────────────────────────────────────────────────────────
  // Quick Scan - Optimized AST-based analysis with caching
  // ─────────────────────────────────────────────────────────────
  private async quickScan(
    files: string[],
    understanding: CodebaseUnderstanding,
    staticResults: Array<{ tool: string; file: string; line: number; message: string; severity: string }>
  ): Promise<Bug[]> {
    const cwd = process.cwd();
    const tier: ScanTier = 'instant';
    const config = TIER_CONFIGS[tier];

    this.reportProgress(`Quick scan: preparing optimized analysis...`);

    // Convert to StaticAnalysisResult format (cast tool and severity to expected literals)
    const typedStaticResults: StaticAnalysisResult[] = staticResults.map(r => ({
      tool: r.tool as 'typescript' | 'eslint',
      file: r.file,
      line: r.line,
      message: r.message,
      severity: r.severity as 'error' | 'warning' | 'info',
    }));

    // Prepare optimized scan with AST extraction
    const scanResult = await prepareOptimizedScan(
      cwd,
      tier,
      understanding,
      typedStaticResults,
      files
    );

    // Report cache stats
    if (scanResult.cacheStats.hits > 0) {
      this.reportProgress(
        `Cache: ${scanResult.cacheStats.hits} hits, ${scanResult.cacheStats.misses} to analyze`
      );
    }

    // If everything is cached, we're done
    if (scanResult.cacheStats.misses === 0 && scanResult.targets.length === 0) {
      this.reportProgress(`Quick scan: all functions cached, no analysis needed`);
      return [];
    }

    this.reportProgress(
      `Quick scan: ${scanResult.targets.length} files, ${scanResult.cacheStats.misses} functions to analyze`
    );

    // Group static findings by file
    const staticByFile = new Map<string, Array<{ line: number; tool: string; message: string }>>();
    for (const result of staticResults) {
      const filePath = normalizeFilePath(result.file, cwd);
      const existing = staticByFile.get(filePath) || [];
      existing.push({ line: result.line, tool: result.tool, message: result.message });
      staticByFile.set(filePath, existing);
    }

    // Load cache for checking and storing
    const cache = loadCache(cwd);
    const bugs: Bug[] = [];
    let bugIndex = 0;
    let completed = 0;

    // Process files in parallel batches
    const BATCH_SIZE = config.parallelFiles;
    const targets = scanResult.targets;

    for (let i = 0; i < targets.length; i += BATCH_SIZE) {
      const batch = targets.slice(i, i + BATCH_SIZE);

      const batchResults = await Promise.all(
        batch.map(async (target) => {
          const context = scanResult.contexts.get(target.filePath);
          if (!context || context.changedUnits.length === 0) {
            completed++;
            return [];
          }

          // Check cache for each unit
          const { cachedBugs, uncachedUnits } = checkCache(
            cache,
            context.changedUnits,
            target.filePath
          );

          // If all units are cached, return cached bugs
          if (uncachedUnits.length === 0) {
            completed++;
            this.reportProgress(`Quick scan: ${completed}/${targets.length} (cached)`);
            return cachedBugs;
          }

          try {
            // Build optimized prompt with extracted functions
            const staticFindings = staticByFile.get(target.filePath) || [];
            const fileBugs = await this.analyzeOptimizedFile(
              target.filePath,
              context,
              understanding,
              staticFindings
            );

            // Cache the results
            cacheResults(cache, target.filePath, uncachedUnits, fileBugs);

            completed++;
            this.reportProgress(`Quick scan: ${completed}/${targets.length} files`);

            return [...cachedBugs, ...fileBugs];
          } catch (error) {
            completed++;
            this.reportProgress(`Quick scan: ${completed}/${targets.length} (error)`);
            return cachedBugs; // Return at least cached bugs on error
          }
        })
      );

      // Collect bugs from batch
      for (const fileBugs of batchResults) {
        for (const bugData of fileBugs) {
          // If already a Bug object (from cache), use it directly
          if (bugData.id && bugData.title && bugData.file) {
            bugs.push(bugData as Bug);
            this.reportBug(bugData as Bug);
          } else {
            // Parse from LLM response
            const bug = this.parseBugData(JSON.stringify(bugData), bugIndex++, files);
            if (bug) {
              bugs.push(bug);
              this.reportBug(bug);
            }
          }
        }
      }
    }

    // Save cache
    saveCache(cwd, cache);

    // PASS 2: Generate fixes for bugs without suggestedFix
    const bugsWithoutFix = bugs.filter(b => !b.suggestedFix || b.suggestedFix.trim() === '');
    if (bugsWithoutFix.length > 0) {
      this.reportProgress(`Generating fixes for ${bugsWithoutFix.length} bugs...`);

      for (const bug of bugsWithoutFix) {
        try {
          const fix = await this.generateFixForBug(bug, cwd);
          if (fix) {
            bug.suggestedFix = fix;
          }
        } catch {
          // Continue even if fix generation fails
        }
      }
    }

    this.reportProgress(`Quick scan complete. Found ${bugs.length} bugs.`);
    return bugs;
  }

  // Analyze a file using optimized AST-extracted context
  private async analyzeOptimizedFile(
    filePath: string,
    context: { changedUnits: Array<{ name: string; type: string; code: string; signature?: string; startLine: number; endLine: number; hash: string; calls: string[]; references: string[] }>; calleeSignatures: string[]; referencedTypes: Array<{ name: string; kind: string; code: string }>; relevantImports: Array<{ source: string; specifiers: string[] }>; estimatedTokens: number },
    understanding: CodebaseUnderstanding,
    staticFindings: Array<{ line: number; tool: string; message: string }>
  ): Promise<any[]> {
    // Skip if no functions to analyze
    if (context.changedUnits.length === 0) {
      return [];
    }

    // Convert OptimizedContext to prompt format
    const changedFunctions = context.changedUnits.map(u => ({
      name: u.name,
      type: u.type,
      code: u.code,
      signature: u.signature,
      startLine: u.startLine,
      endLine: u.endLine,
    }));

    // Build supporting context from callee signatures
    const supportingContext = context.calleeSignatures.map((sig, i) => ({
      name: `callee_${i}`,
      type: 'signature',
      code: sig,
      startLine: 0,
      endLine: 0,
    }));

    const typeDefinitions = context.referencedTypes.map(t => t.code);
    const imports = context.relevantImports.map(i =>
      `import { ${i.specifiers.join(', ')} } from '${i.source}'`
    );

    const prompt = buildOptimizedQuickScanPrompt({
      filePath,
      projectType: understanding.summary.type,
      framework: understanding.summary.framework || '',
      language: understanding.summary.language,
      changedFunctions,
      supportingContext,
      typeDefinitions,
      imports,
      staticFindings: staticFindings.length > 0 ? staticFindings : undefined,
      estimatedTokens: context.estimatedTokens,
    });

    try {
      const result = await this.runSimpleClaude(prompt, process.cwd());
      return this.parseQuickAnalysisResult(result, filePath);
    } catch {
      return [];
    }
  }

  // ─────────────────────────────────────────────────────────────
  // Thorough Scan - TRUE 10x Bug Hunter (PARALLEL VERSION)
  // ─────────────────────────────────────────────────────────────
  // OLD APPROACH: 19 passes × 5 min = 95 minutes (sequential)
  // NEW APPROACH: 19 passes in parallel = ~5 minutes (19x faster!)
  //
  // All passes run simultaneously:
  // - 10 unit passes (pattern-based)
  // - 5 integration passes (flow tracing)
  // - 5 E2E passes (attack chains)
  //
  // Results merged and deduplicated at the end.
  // ─────────────────────────────────────────────────────────────
  private async thoroughScan(
    files: string[],
    understanding: CodebaseUnderstanding,
    staticResults: Array<{ tool: string; file: string; line: number; message: string; severity: string }>
  ): Promise<Bug[]> {
    const cwd = process.cwd();
    const startTime = Date.now();

    // Get all passes from the pipeline
    const pipeline = getFullAnalysisPipeline();
    const unitPasses = pipeline[0].passes;
    const integrationPasses = pipeline[1].passes;
    const e2ePasses = pipeline[2].passes;
    const totalPasses = unitPasses.length + integrationPasses.length + e2ePasses.length;

    this.reportProgress(`\n════ 10x BUG HUNTER (PARALLEL) ════`);
    this.reportProgress(`  Running ${totalPasses} passes in parallel`);
    this.reportProgress(`  - ${unitPasses.length} unit passes`);
    this.reportProgress(`  - ${integrationPasses.length} integration passes`);
    this.reportProgress(`  - ${e2ePasses.length} E2E passes`);
    this.reportProgress(`  Expected: ~5 minutes total\n`);

    // Track progress across all parallel passes
    const passStatus = new Map<string, 'running' | 'done' | 'error'>();
    let globalBugIndex = 0;

    // Helper to run a single pass
    const runPass = async (
      passName: string,
      prompt: string
    ): Promise<Bug[]> => {
      passStatus.set(passName, 'running');
      const bugs: Bug[] = [];

      try {
        await this.runAgenticClaude(prompt, cwd, {
          onScanning: (file) => {
            this.reportProgress(`  [${passName}] ${file.split('/').pop()}`);
          },
          onBugFound: (bugData) => {
            const bug = this.parseBugData(bugData, globalBugIndex++, files);
            if (bug) {
              bugs.push(bug);
              this.reportBug(bug);
            }
          },
          onComplete: () => {},
          onError: (error) => {
            this.reportProgress(`  [${passName}] Error: ${error}`);
          },
        });
        passStatus.set(passName, 'done');
        this.reportProgress(`  ✓ ${passName}: ${bugs.length} bugs`);
      } catch (error: any) {
        passStatus.set(passName, 'error');
        this.reportProgress(`  ✗ ${passName}: ${error.message}`);
      }

      return bugs;
    };

    // Build all pass configs
    interface PassJob {
      name: string;
      prompt: string;
    }
    const allPasses: PassJob[] = [];

    // Unit passes
    for (const passName of unitPasses) {
      const passConfig = getPassConfig(passName);
      if (!passConfig) continue;

      allPasses.push({
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

    // Integration passes
    for (const passName of integrationPasses) {
      const flowConfig = getFlowPassConfig(passName);
      if (!flowConfig) continue;

      allPasses.push({
        name: passName,
        prompt: buildFlowAnalysisPrompt({
          pass: flowConfig,
          projectType: understanding.summary.type,
          framework: understanding.summary.framework || '',
          language: understanding.summary.language,
          totalFiles: understanding.structure.totalFiles,
          staticFindings: staticResults,
        }),
      });
    }

    // E2E passes
    for (const passName of e2ePasses) {
      const flowConfig = getFlowPassConfig(passName);
      if (!flowConfig) continue;

      allPasses.push({
        name: passName,
        prompt: buildFlowAnalysisPrompt({
          pass: flowConfig,
          projectType: understanding.summary.type,
          framework: understanding.summary.framework || '',
          language: understanding.summary.language,
          totalFiles: understanding.structure.totalFiles,
          staticFindings: staticResults,
        }),
      });
    }

    // Run passes in batches to avoid rate limits
    // Batch 5 at a time with small delays between batches
    const BATCH_SIZE = 5;
    const BATCH_DELAY_MS = 2000; // 2 second delay between batches
    const allResults: PromiseSettledResult<Bug[]>[] = [];

    this.reportProgress(`\nRunning ${allPasses.length} passes in batches of ${BATCH_SIZE}...`);

    for (let i = 0; i < allPasses.length; i += BATCH_SIZE) {
      const batch = allPasses.slice(i, i + BATCH_SIZE);
      const batchNum = Math.floor(i / BATCH_SIZE) + 1;
      const totalBatches = Math.ceil(allPasses.length / BATCH_SIZE);

      this.reportProgress(`\n[Batch ${batchNum}/${totalBatches}] Running: ${batch.map(p => p.name).join(', ')}`);

      const batchPromises = batch.map(pass => runPass(pass.name, pass.prompt));
      const batchResults = await Promise.allSettled(batchPromises);
      allResults.push(...batchResults);

      // Delay before next batch (except for last batch)
      if (i + BATCH_SIZE < allPasses.length) {
        this.reportProgress(`  Waiting ${BATCH_DELAY_MS / 1000}s before next batch...`);
        await new Promise(resolve => setTimeout(resolve, BATCH_DELAY_MS));
      }
    }

    // Collect all bugs
    const allBugs: Bug[] = [];
    let successCount = 0;
    let errorCount = 0;

    for (const result of allResults) {
      if (result.status === 'fulfilled') {
        allBugs.push(...result.value);
        successCount++;
      } else {
        errorCount++;
      }
    }

    this.reportProgress(`\n════ PASSES COMPLETE ════`);
    this.reportProgress(`  Successful: ${successCount}/${totalPasses}`);
    this.reportProgress(`  Errors: ${errorCount}`);
    this.reportProgress(`  Raw bugs found: ${allBugs.length}`);

    // ═══════════════════════════════════════════════════════════
    // POST-PROCESSING: Deduplicate and generate fixes
    // ═══════════════════════════════════════════════════════════
    this.reportProgress(`\n════ POST-PROCESSING ════`);

    // Exact deduplication
    const { unique: dedupedBugs, duplicatesRemoved } = deduplicateBugs(allBugs);
    this.reportProgress(`  Removed ${duplicatesRemoved} exact duplicates`);

    // Merge similar bugs
    const mergedBugs = mergeSimilarBugs(dedupedBugs);
    const similarMerged = dedupedBugs.length - mergedBugs.length;
    if (similarMerged > 0) {
      this.reportProgress(`  Merged ${similarMerged} similar findings`);
    }

    // Generate fixes for bugs without suggestedFix (in parallel too!)
    const bugsWithoutFix = mergedBugs.filter(b => !b.suggestedFix || b.suggestedFix.trim() === '');
    if (bugsWithoutFix.length > 0) {
      this.reportProgress(`  Generating fixes for ${bugsWithoutFix.length} bugs...`);

      // Generate fixes in parallel batches
      const FIX_BATCH_SIZE = 5;
      for (let i = 0; i < bugsWithoutFix.length; i += FIX_BATCH_SIZE) {
        const batch = bugsWithoutFix.slice(i, i + FIX_BATCH_SIZE);
        await Promise.all(
          batch.map(async (bug) => {
            try {
              const fix = await this.generateFixForBug(bug, cwd);
              if (fix) bug.suggestedFix = fix;
            } catch {
              // Continue on error
            }
          })
        );
      }
    }

    // ═══════════════════════════════════════════════════════════
    // FINAL SUMMARY
    // ═══════════════════════════════════════════════════════════
    const totalDuration = Date.now() - startTime;
    const minutes = Math.floor(totalDuration / 60000);
    const seconds = Math.round((totalDuration % 60000) / 1000);

    this.reportProgress(`\n════ ANALYSIS COMPLETE ════`);
    this.reportProgress(`  Duration: ${minutes}m ${seconds}s`);
    this.reportProgress(`  Passes run: ${totalPasses} (parallel)`);
    this.reportProgress(`  Raw bugs: ${allBugs.length}`);
    this.reportProgress(`  After dedup: ${mergedBugs.length}`);

    return mergedBugs;
  }


  // Generate a fix for a bug that doesn't have one
  private async generateFixForBug(bug: Bug, cwd: string): Promise<string | undefined> {
    // Read the file containing the bug
    let fileContent = '';
    try {
      if (existsSync(bug.file)) {
        fileContent = readFileSync(bug.file, 'utf-8');
        const lines = fileContent.split('\n');
        const start = Math.max(0, bug.line - 15);
        const end = Math.min(lines.length, (bug.endLine || bug.line) + 15);
        fileContent = lines.slice(start, end).join('\n');
      }
    } catch {
      // Continue without file content
    }

    const prompt = `You are a senior developer fixing a specific bug. Generate ONLY the fix code.

BUG DETAILS:
- Title: ${bug.title}
- Description: ${bug.description}
- File: ${bug.file}
- Line: ${bug.line}${bug.endLine ? ` to ${bug.endLine}` : ''}
- Category: ${bug.category}
- Severity: ${bug.severity}

CODE CONTEXT (lines ${Math.max(0, bug.line - 15)}-${(bug.endLine || bug.line) + 15}):
\`\`\`
${fileContent}
\`\`\`

${bug.codePath.length > 0 ? `CODE PATH:
${bug.codePath.map(s => `- ${s.file}:${s.line}: ${s.explanation}`).join('\n')}` : ''}

${bug.evidence.length > 0 ? `EVIDENCE:
${bug.evidence.map(e => `- ${e}`).join('\n')}` : ''}

TASK: Write the EXACT code fix. Output ONLY the fixed code that should replace the buggy code.
- Do NOT include explanations or markdown
- Do NOT include the entire file, only the fix
- The fix should be minimal and focused
- Output raw code that can be directly applied

FIX:`;

    try {
      const result = await this.runSimpleClaude(prompt, cwd);
      // Clean up the response - remove markdown code blocks if present
      let fix = result.trim();
      if (fix.startsWith('```')) {
        fix = fix.replace(/^```\w*\n?/, '').replace(/\n?```$/, '');
      }
      // Only return if it looks like actual code (not just explanation)
      if (fix.length > 0 && fix.length < 5000 && !fix.toLowerCase().startsWith('the fix')) {
        return fix;
      }
    } catch {
      // Silently fail
    }
    return undefined;
  }

  async adversarialValidate(bug: Bug, _context: AnalysisContext): Promise<AdversarialResult> {
    // Read the file containing the bug for context
    let fileContent = '';
    try {
      if (existsSync(bug.file)) {
        fileContent = readFileSync(bug.file, 'utf-8');
        const lines = fileContent.split('\n');
        const start = Math.max(0, bug.line - 20);
        const end = Math.min(lines.length, (bug.endLine || bug.line) + 20);
        fileContent = lines.slice(start, end).join('\n');
      }
    } catch {
      // File read failed, continue without content
    }

    const prompt = buildAdversarialPrompt({
      file: bug.file,
      line: bug.line,
      title: bug.title,
      description: bug.description,
      category: bug.category,
      severity: bug.severity,
      fileContent,
    });
    const result = await this.runSimpleClaude(prompt, process.cwd());

    return this.parseAdversarialResponse(result, bug);
  }

  async generateUnderstanding(files: string[], existingDocsSummary?: string): Promise<CodebaseUnderstanding> {
    const cwd = process.cwd();

    this.reportProgress(`Starting codebase analysis (${files.length} files)...`);

    const prompt = buildUnderstandingPrompt({ existingDocsSummary });
    let understandingJson = '';

    try {
      await this.runAgenticClaude(prompt, cwd, {
        onScanning: (file) => {
          this.reportProgress(`Examining: ${file}`);
        },
        onUnderstanding: (json) => {
          understandingJson = json;
        },
        onComplete: () => {
          this.reportProgress('Understanding complete.');
        },
        onError: (error) => {
          this.reportProgress(`Error: ${error}`);
        },
      });

      return this.parseUnderstandingResponse(understandingJson, files);
    } catch (error: any) {
      if (error.message?.includes('ENOENT')) {
        throw new Error('Claude CLI not found. Install it with: npm install -g @anthropic-ai/claude-code');
      }
      throw error;
    }
  }


  // ─────────────────────────────────────────────────────────────
  // JSON Extraction Helpers
  // ─────────────────────────────────────────────────────────────

  /**
   * Extract JSON from <json></json> tags (primary method)
   * Falls back to finding balanced JSON if tags not present
   */
  private extractJsonFromTags(response: string): string | null {
    // Primary: Try <json></json> tags
    const tagMatch = response.match(/<json>([\s\S]*?)<\/json>/);
    if (tagMatch) {
      return tagMatch[1].trim();
    }

    // Fallback: Try markdown code blocks
    const codeBlockMatch = response.match(/```(?:json)?\s*([\s\S]*?)```/);
    if (codeBlockMatch) {
      return codeBlockMatch[1].trim();
    }

    // Last resort: Find balanced JSON
    return this.findBalancedJson(response);
  }

  /**
   * Parse quick scan result - handles new <json></json> format
   */
  private parseQuickAnalysisResult(result: string, filePath: string): any[] {
    try {
      const jsonStr = this.extractJsonFromTags(result);
      if (!jsonStr) {
        return [];
      }

      const parsed = JSON.parse(jsonStr);

      // New format: { bugs: [], needsReview: [] }
      if (parsed.bugs && Array.isArray(parsed.bugs)) {
        const allBugs = [
          ...parsed.bugs.map((bug: any) => ({ ...bug, file: filePath })),
          // Also include needsReview items as low-confidence bugs
          ...(parsed.needsReview || []).map((item: any) => ({
            ...item,
            file: filePath,
            confidence: 'low',
            severity: item.severity || 'low',
          })),
        ];
        return allBugs;
      }

      // Legacy format: array of bugs directly
      if (Array.isArray(parsed)) {
        return parsed.map(bug => ({ ...bug, file: filePath }));
      }

      return [];
    } catch {
      return [];
    }
  }

  // ─────────────────────────────────────────────────────────────
  // Claude CLI Execution (Agentic Mode)
  // ─────────────────────────────────────────────────────────────

  private async runAgenticClaude(
    prompt: string,
    cwd: string,
    callbacks: {
      onScanning?: (file: string) => void;
      onBugFound?: (bugJson: string) => void;
      onUnderstanding?: (json: string) => void;
      onComplete?: () => void;
      onError?: (error: string) => void;
    }
  ): Promise<void> {
    // Reset buffers at start of each run
    this.streamBuffer = '';
    this.fullResponseBuffer = '';

    const claudeCommand = getProviderCommand('claude-code');

    // Build command arguments with proper streaming output format
    const args = [
      '-p', prompt,
      '--output-format', 'stream-json',
      '--verbose',
    ];

    // Always auto-approve for read-only operations (init/scan)
    // Write operations (fix) will use interactive mode separately
    args.push('--dangerously-skip-permissions');

    // Log start without dumping the prompt
    this.reportProgress(`Starting Claude analysis...`);

    // Use native spawn for proper streaming (execa v9 has buffering issues)
    this.currentProcess = spawn(claudeCommand, args, {
      cwd,
      env: {
        ...process.env,
        NO_COLOR: '1',
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    // Track if we've received ANY output
    let receivedOutput = false;
    let outputBytes = 0;

    // Heartbeat to show activity
    let lastActivity = Date.now();
    const heartbeat = setInterval(() => {
      const elapsed = Math.floor((Date.now() - lastActivity) / 1000);
      if (elapsed > 10) {
        const status = receivedOutput ? `${outputBytes} bytes received` : 'waiting for Claude...';
        this.reportProgress(`Analyzing... (${elapsed}s idle, ${status})`);
      }
    }, 5000);

    // Buffer for accumulating output
    let buffer = '';

    // Process streaming output
    this.currentProcess.stdout?.on('data', (chunk: Buffer) => {
      lastActivity = Date.now();
      receivedOutput = true;
      outputBytes += chunk.length;
      const text = chunk.toString();
      buffer += text;

      // Process complete lines
      const lines = buffer.split('\n');
      buffer = lines.pop() || ''; // Keep incomplete line in buffer

      for (const line of lines) {
        this.processAgentOutput(line, callbacks);
      }
    });

    this.currentProcess.stderr?.on('data', (chunk: Buffer) => {
      lastActivity = Date.now();
      receivedOutput = true;
      outputBytes += chunk.length;
      const text = chunk.toString().trim();
      if (text) {
        // Report stderr activity - show more for debugging
        this.reportProgress(`Claude stderr: ${text.slice(0, 100)}`);
      }
    });

    // Wait for process to complete
    try {
      await new Promise<void>((resolve, reject) => {
        // Timeout after 15 minutes for thorough agentic scans
        const timeout = setTimeout(() => {
          this.currentProcess?.kill();
          reject(new Error('Claude analysis timed out after 15 minutes'));
        }, 900000);

        this.currentProcess?.on('exit', (code) => {
          clearTimeout(timeout);
          if (code !== 0 && code !== null) {
            // Non-zero exit, but don't reject - we may have partial results
            this.reportProgress(`Claude exited with code ${code}`);
          }
          resolve();
        });

        this.currentProcess?.on('error', (err) => {
          clearTimeout(timeout);
          reject(err);
        });
      });
    } finally {
      // Clean up heartbeat - always runs, even on error/rejection
      clearInterval(heartbeat);
    }

    // Process any remaining buffer
    if (buffer.trim()) {
      this.processAgentOutput(buffer, callbacks);
    }

    // Extract all data from accumulated full response at the end
    if (this.fullResponseBuffer) {
      // Extract <json></json> blocks (primary method for new prompts)
      this.extractJsonBlocks(callbacks);

      // Fallback: try to extract from unstructured JSON (legacy)
      if (callbacks.onUnderstanding) {
        this.tryExtractUnderstandingJson(this.fullResponseBuffer, callbacks);
      }
    }

    this.currentProcess = undefined;
  }

  private processAgentOutput(
    line: string,
    callbacks: {
      onScanning?: (file: string) => void;
      onBugFound?: (bugJson: string) => void;
      onUnderstanding?: (json: string) => void;
      onComplete?: () => void;
      onError?: (error: string) => void;
    }
  ): void {
    const trimmed = line.trim();
    if (!trimmed) return;

    // Try to parse as JSON (stream-json format)
    try {
      const event = JSON.parse(trimmed);

      // Handle different event types from Claude's stream-json format
      if (event.type === 'system') {
        // Initialization event
        this.reportProgress('Claude initialized...');
      } else if (event.type === 'stream_event') {
        // Streaming events contain nested event data
        const innerEvent = event.event;
        if (innerEvent?.type === 'content_block_delta') {
          // Text chunk from Claude
          const text = innerEvent.delta?.text;
          if (text) {
            this.processTextContent(text, callbacks);
          }
        } else if (innerEvent?.type === 'content_block_start') {
          // New content block starting
          if (innerEvent.content_block?.type === 'tool_use') {
            const toolName = innerEvent.content_block.name || 'tool';
            this.reportProgress(`Using ${toolName}...`);
          }
        }
      } else if (event.type === 'assistant') {
        // Complete assistant message - extract text and tool use
        const content = event.message?.content || [];
        for (const item of content) {
          if (item.type === 'text' && item.text) {
            this.processTextContent(item.text, callbacks);
          } else if (item.type === 'tool_use') {
            const toolName = item.name || 'tool';
            const input = item.input || {};
            if (toolName === 'Read' && input.file_path) {
              callbacks.onScanning?.(input.file_path);
              this.reportProgress(`Reading: ${input.file_path.split('/').pop()}`);
            } else if (toolName === 'Glob' || toolName === 'Grep') {
              this.reportProgress(`Searching: ${input.pattern || '...'}`);
            } else {
              this.reportProgress(`Using ${toolName}...`);
            }
          }
        }
      } else if (event.type === 'user') {
        // Tool result - show activity
        if (event.tool_use_result) {
          const numFiles = event.tool_use_result.numFiles;
          if (numFiles) {
            this.reportProgress(`Found ${numFiles} files...`);
          }
        }
      } else if (event.type === 'result') {
        // Final result - check for our markers and understanding
        if (event.result) {
          this.processTextContent(event.result, callbacks);
          // Also try to extract JSON from the result if no marker found
          this.tryExtractUnderstandingJson(event.result, callbacks);
        }
        callbacks.onComplete?.();
      } else if (event.type === 'error') {
        callbacks.onError?.(event.error || event.message || 'Unknown error');
      }

      return;
    } catch {
      // Not JSON - fall through to marker-based parsing
    }

    // Legacy marker-based parsing
    if (trimmed.startsWith(MARKERS.SCANNING)) {
      const file = trimmed.slice(MARKERS.SCANNING.length).trim();
      callbacks.onScanning?.(file);
    } else if (trimmed.startsWith(MARKERS.BUG)) {
      const json = trimmed.slice(MARKERS.BUG.length).trim();
      callbacks.onBugFound?.(json);
    } else if (trimmed.startsWith(MARKERS.UNDERSTANDING)) {
      const json = trimmed.slice(MARKERS.UNDERSTANDING.length).trim();
      callbacks.onUnderstanding?.(json);
    } else if (trimmed.startsWith(MARKERS.COMPLETE)) {
      callbacks.onComplete?.();
    } else if (trimmed.startsWith(MARKERS.ERROR)) {
      const error = trimmed.slice(MARKERS.ERROR.length).trim();
      callbacks.onError?.(error);
    }
  }

  // Accumulated text for marker detection in streaming responses
  private streamBuffer = '';
  // Full response text for final extraction
  private fullResponseBuffer = '';

  private processTextContent(
    text: string,
    callbacks: {
      onScanning?: (file: string) => void;
      onBugFound?: (bugJson: string) => void;
      onUnderstanding?: (json: string) => void;
      onComplete?: () => void;
      onError?: (error: string) => void;
    }
  ): void {
    this.streamBuffer += text;
    this.fullResponseBuffer += text; // Accumulate for final extraction

    // Note: We extract <json> blocks at the END of streaming (in runAgenticClaude)
    // to avoid issues with incomplete blocks during streaming

    // Check for legacy markers (line-based)
    const lines = this.streamBuffer.split('\n');
    this.streamBuffer = lines.pop() || ''; // Keep incomplete line

    for (const line of lines) {
      const trimmed = line.trim();
      if (trimmed.startsWith(MARKERS.SCANNING)) {
        callbacks.onScanning?.(trimmed.slice(MARKERS.SCANNING.length).trim());
      } else if (trimmed.startsWith(MARKERS.BUG)) {
        callbacks.onBugFound?.(trimmed.slice(MARKERS.BUG.length).trim());
      } else if (trimmed.startsWith(MARKERS.UNDERSTANDING)) {
        callbacks.onUnderstanding?.(trimmed.slice(MARKERS.UNDERSTANDING.length).trim());
      } else if (trimmed.startsWith(MARKERS.COMPLETE)) {
        callbacks.onComplete?.();
      } else if (trimmed.startsWith(MARKERS.ERROR)) {
        callbacks.onError?.(trimmed.slice(MARKERS.ERROR.length).trim());
      }
    }
  }

  /**
   * Extract complete <json></json> blocks from the full response buffer
   * Called once at the end of streaming for reliability
   */
  private extractJsonBlocks(callbacks: {
    onBugFound?: (bugJson: string) => void;
    onUnderstanding?: (json: string) => void;
    onComplete?: () => void;
  }): void {
    // Look for complete <json>...</json> blocks
    const jsonBlockRegex = /<json>([\s\S]*?)<\/json>/g;
    let match;
    let bugsFound = 0;
    let needsReviewFound = 0;

    while ((match = jsonBlockRegex.exec(this.fullResponseBuffer)) !== null) {
      const jsonStr = match[1].trim();

      try {
        const parsed = JSON.parse(jsonStr);

        // Determine type from content
        if (parsed.type === 'bug' && parsed.data) {
          callbacks.onBugFound?.(JSON.stringify(parsed.data));
          bugsFound++;
          this.reportProgress(`Found: ${parsed.data.title}`);
        } else if (parsed.type === 'needsReview' && parsed.data) {
          // Treat needs-review as low-confidence bug
          callbacks.onBugFound?.(JSON.stringify({ ...parsed.data, confidence: 'low' }));
          needsReviewFound++;
          this.reportProgress(`Review: ${parsed.data.title}`);
        } else if (parsed.type === 'complete' && parsed.summary) {
          this.reportProgress(`Claude: ${parsed.summary.bugsFound} bugs, ${parsed.summary.needsReview} to review`);
          callbacks.onComplete?.();
        } else if (parsed.summary && (parsed.summary.type || parsed.summary.language)) {
          // Understanding object
          callbacks.onUnderstanding?.(jsonStr);
        } else if (parsed.bugs && Array.isArray(parsed.bugs)) {
          // Quick scan format - array of bugs
          for (const bug of parsed.bugs) {
            callbacks.onBugFound?.(JSON.stringify(bug));
            bugsFound++;
          }
          this.reportProgress(`Found ${parsed.bugs.length} bugs`);
        }
      } catch {
        // Invalid JSON, skip
      }
    }

    if (bugsFound > 0 || needsReviewFound > 0) {
      this.reportProgress(`Extracted: ${bugsFound} bugs, ${needsReviewFound} to review`);
    }
  }

  // Try to extract understanding JSON from text without markers
  private tryExtractUnderstandingJson(
    text: string,
    callbacks: {
      onUnderstanding?: (json: string) => void;
    }
  ): void {
    // First try code blocks (most reliable)
    const codeBlockMatch = text.match(/```(?:json)?\s*([\s\S]*?)```/);
    if (codeBlockMatch) {
      const jsonStr = codeBlockMatch[1].trim();
      try {
        const parsed = JSON.parse(jsonStr);
        if (parsed.summary && (parsed.summary.type || parsed.summary.language)) {
          callbacks.onUnderstanding?.(jsonStr);
          return;
        }
      } catch {
        // Not valid JSON in code block
      }
    }

    // Try to find balanced JSON objects containing "summary"
    // Track string state to avoid counting braces inside strings
    const candidates: string[] = [];
    let depth = 0;
    let start = -1;
    let inString = false;
    let escapeNext = false;

    for (let i = 0; i < text.length; i++) {
      const char = text[i];

      if (escapeNext) {
        escapeNext = false;
        continue;
      }

      if (char === '\\' && inString) {
        escapeNext = true;
        continue;
      }

      if (char === '"' && !escapeNext) {
        inString = !inString;
        continue;
      }

      if (inString) continue;

      if (char === '{') {
        if (depth === 0) {
          start = i;
        }
        depth++;
      } else if (char === '}') {
        depth--;
        if (depth === 0 && start !== -1) {
          const candidate = text.slice(start, i + 1);
          // Quick check if it might be our understanding object
          if (candidate.includes('"summary"') && candidate.includes('"type"')) {
            candidates.push(candidate);
          }
          start = -1;
        }
      }
    }

    // Try each candidate, preferring longer ones (more complete)
    candidates.sort((a, b) => b.length - a.length);

    for (const jsonStr of candidates) {
      try {
        const parsed = JSON.parse(jsonStr);
        if (parsed.summary && (parsed.summary.type || parsed.summary.language)) {
          callbacks.onUnderstanding?.(jsonStr);
          return;
        }
      } catch {
        // Not valid JSON, try next
      }
    }
  }


  // Simple non-agentic mode for short prompts (adversarial validation)
  private async runSimpleClaude(prompt: string, cwd: string): Promise<string> {
    const claudeCommand = getProviderCommand('claude-code');

    try {
      const { stdout } = await execa(
        claudeCommand,
        ['-p', prompt, '--output-format', 'text'],
        {
          cwd,
          timeout: 120000, // 2 min for simple prompts
          env: { ...process.env, NO_COLOR: '1' },
        }
      );
      return stdout;
    } catch (error: any) {
      if (error.stdout) return error.stdout;
      throw error;
    }
  }

  // ─────────────────────────────────────────────────────────────
  // Response Parsers
  // ─────────────────────────────────────────────────────────────

  private parseBugData(json: string, index: number, files: string[]): Bug | null {
    // Pre-process to handle Claude's simpler confidence format
    let parsed: any;
    try {
      parsed = JSON.parse(json);
      // Convert string confidence to object format
      if (typeof parsed.confidence === 'string') {
        parsed.confidence = { overall: parsed.confidence };
      }
    } catch {
      return null;
    }

    // Use Zod validation for safe parsing
    const result = PartialBugFromLLM.safeParse(parsed);
    if (!result.success) {
      return null;
    }

    const data = result.data;

    // Resolve file path
    let filePath = data.file;
    if (!filePath.startsWith('/')) {
      const match = files.find(f => f.endsWith(filePath) || f.includes(filePath));
      if (match) filePath = match;
    }

    return {
      id: generateBugId(index),
      title: String(data.title).slice(0, 100),
      description: String(data.description || ''),
      file: filePath,
      line: data.line,
      endLine: data.endLine,
      kind: data.kind || 'bug',
      severity: data.severity ?? 'medium',
      category: data.category ?? 'logic-error',
      confidence: {
        overall: data.confidence?.overall || 'medium',
        codePathValidity: data.confidence?.codePathValidity ?? 0.8,
        reachability: data.confidence?.reachability ?? 0.8,
        intentViolation: data.confidence?.intentViolation ?? false,
        staticToolSignal: data.confidence?.staticToolSignal ?? false,
        adversarialSurvived: data.confidence?.adversarialSurvived ?? false,
      },
      codePath: (data.codePath || []).map((step, idx) => ({
        step: idx + 1,
        file: step.file || filePath,
        line: step.line || data.line,
        code: step.code || '',
        explanation: step.explanation || '',
      })),
      evidence: data.evidence || [],
      suggestedFix: data.suggestedFix,
      createdAt: new Date().toISOString(),
      status: 'open',
    };
  }

  private parseAdversarialResponse(response: string, bug: Bug): AdversarialResult {
    const json = this.extractJson(response);
    if (!json) {
      return { survived: true, counterArguments: [] };
    }

    // Use Zod validation for safe parsing
    const result = safeParseJson(json, AdversarialResultSchema);
    if (!result.success) {
      // Conservative: if parsing fails, assume bug survived
      return { survived: true, counterArguments: [] };
    }

    const parsed = result.data;
    const survived = parsed.survived !== false;

    return {
      survived,
      counterArguments: parsed.counterArguments || [],
      adjustedConfidence: survived
        ? {
            ...bug.confidence,
            overall: parsed.confidence || bug.confidence.overall,
            adversarialSurvived: true,
          }
        : undefined,
    };
  }

  private parseUnderstandingResponse(response: string, files: string[]): CodebaseUnderstanding {
    // Count total lines from all files
    let totalLines = 0;
    for (const file of files) {
      try {
        const content = readFileSync(file, 'utf-8');
        totalLines += content.split('\n').length;
      } catch {
        // Skip unreadable files
      }
    }

    const json = this.extractJson(response);
    if (!json) {
      // Return minimal understanding when no JSON found
      return {
        version: '1',
        generatedAt: new Date().toISOString(),
        summary: {
          type: 'unknown',
          language: 'unknown',
          description: 'Failed to analyze codebase: No JSON found in response',
        },
        features: [],
        contracts: [],
        dependencies: {},
        structure: { totalFiles: files.length, totalLines },
      };
    }

    // Use Zod validation for safe parsing
    const result = safeParseJson(json, PartialUnderstandingFromLLM);

    if (!result.success) {
      // Return minimal understanding on validation failure
      return {
        version: '1',
        generatedAt: new Date().toISOString(),
        summary: {
          type: 'unknown',
          language: 'unknown',
          description: `Failed to analyze codebase: ${result.error}`,
        },
        features: [],
        contracts: [],
        dependencies: {},
        structure: { totalFiles: files.length, totalLines },
      };
    }

    const parsed = result.data;

    return {
      version: '1',
      generatedAt: new Date().toISOString(),
      summary: {
        type: parsed.summary?.type || 'unknown',
        framework: parsed.summary?.framework || undefined,
        language: parsed.summary?.language || 'typescript',
        description: parsed.summary?.description || 'No description available',
      },
      features: (parsed.features || []).map((f) => ({
        name: f.name || 'Unknown',
        description: f.description || '',
        priority: f.priority || 'medium',
        constraints: f.constraints || [],
        relatedFiles: f.relatedFiles || [],
      })),
      contracts: (parsed.contracts || []).map((c) => ({
        function: c.function || 'unknown',
        file: c.file || 'unknown',
        inputs: c.inputs || [],
        outputs: c.outputs || { type: 'unknown' },
        invariants: c.invariants || [],
        sideEffects: c.sideEffects || [],
        throws: c.throws,
      })),
      dependencies: {},
      structure: {
        totalFiles: files.length,
        totalLines,
      },
    };
  }

  // ─────────────────────────────────────────────────────────────
  // Utilities
  // ─────────────────────────────────────────────────────────────

  private extractJson(text: string): string | null {
    // Try markdown code blocks first (most reliable)
    const codeBlockMatch = text.match(/```(?:json)?\s*([\s\S]*?)```/);
    if (codeBlockMatch) {
      return codeBlockMatch[1].trim();
    }

    // Find the first balanced JSON object or array
    return this.findBalancedJson(text);
  }

  // Find the first balanced JSON object or array in text
  private findBalancedJson(text: string): string | null {
    // Find first { or [
    const objectStart = text.indexOf('{');
    const arrayStart = text.indexOf('[');

    let start = -1;
    let openChar = '{';
    let closeChar = '}';

    if (objectStart === -1 && arrayStart === -1) {
      return null;
    } else if (objectStart === -1) {
      start = arrayStart;
      openChar = '[';
      closeChar = ']';
    } else if (arrayStart === -1) {
      start = objectStart;
    } else {
      // Use whichever comes first
      if (arrayStart < objectStart) {
        start = arrayStart;
        openChar = '[';
        closeChar = ']';
      } else {
        start = objectStart;
      }
    }

    // Count balanced braces, respecting strings
    let depth = 0;
    let inString = false;
    let escapeNext = false;

    for (let i = start; i < text.length; i++) {
      const char = text[i];

      if (escapeNext) {
        escapeNext = false;
        continue;
      }

      if (char === '\\' && inString) {
        escapeNext = true;
        continue;
      }

      if (char === '"' && !escapeNext) {
        inString = !inString;
        continue;
      }

      if (inString) continue;

      if (char === openChar) {
        depth++;
      } else if (char === closeChar) {
        depth--;
        if (depth === 0) {
          return text.slice(start, i + 1);
        }
      }
    }

    return null;
  }
}

function normalizeFilePath(filePath: string, cwd: string): string {
  if (!filePath) return filePath;
  return isAbsolute(filePath) ? filePath : resolve(cwd, filePath);
}
