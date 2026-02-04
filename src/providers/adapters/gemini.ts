/**
 * Google Gemini CLI Provider
 *
 * Uses the Gemini CLI for agentic code analysis.
 * Supports parallel execution for 10x faster scanning.
 *
 * Configuration:
 * - Gemini CLI must be installed: npm install -g @google/gemini-cli
 * - Authentication via Google account or GOOGLE_API_KEY environment variable
 *
 * @see https://github.com/google-gemini/gemini-cli
 * @see https://geminicli.com/docs/
 */

import { spawn, type ChildProcess } from 'child_process';
import { execa } from 'execa';
import { readFileSync, existsSync } from 'fs';
import {
  LLMProvider,
  ProviderType,
  AnalysisContext,
  Bug,
  AdversarialResult,
  CodebaseUnderstanding,
  BugSeverity,
  BugCategory,
  ConfidenceLevel,
} from '../../types.js';
import { isProviderAvailable, getProviderCommand } from '../detect.js';
import { generateBugId } from '../../core/utils.js';
import {
  buildUnderstandingPrompt,
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

type ProgressCallback = (message: string) => void;
type BugFoundCallback = (bug: Bug) => void;

export class GeminiProvider implements LLMProvider {
  name: ProviderType = 'gemini';

  private progressCallback?: ProgressCallback;
  private bugFoundCallback?: BugFoundCallback;
  private currentProcess?: ChildProcess;

  async detect(): Promise<boolean> {
    return isProviderAvailable('gemini');
  }

  async isAvailable(): Promise<boolean> {
    return isProviderAvailable('gemini');
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

  cancel(): void {
    if (this.currentProcess) {
      this.currentProcess.kill();
      this.currentProcess = undefined;
    }
  }

  async analyze(context: AnalysisContext, options?: { quick?: boolean }): Promise<Bug[]> {
    const { files, understanding } = context;

    if (files.length === 0) {
      return [];
    }

    if (options?.quick) {
      return this.quickScan(files, understanding);
    }

    return this.thoroughScan(files, understanding);
  }

  // ─────────────────────────────────────────────────────────────
  // Quick Scan - Fast single-pass analysis
  // ─────────────────────────────────────────────────────────────
  private async quickScan(
    files: string[],
    understanding: CodebaseUnderstanding
  ): Promise<Bug[]> {
    this.reportProgress(`Quick scan: analyzing ${files.length} files with Gemini...`);

    const prompt = this.buildQuickScanPrompt(files, understanding);
    const result = await this.runGemini(prompt, process.cwd());

    return this.parseAnalysisResponse(result, files);
  }

  // ─────────────────────────────────────────────────────────────
  // Thorough Scan - Parallel multi-pass analysis
  // ─────────────────────────────────────────────────────────────
  private async thoroughScan(
    files: string[],
    understanding: CodebaseUnderstanding
  ): Promise<Bug[]> {
    const cwd = process.cwd();
    const startTime = Date.now();

    // Get all passes from the pipeline
    const pipeline = getFullAnalysisPipeline();
    const unitPasses = pipeline[0].passes;
    const integrationPasses = pipeline[1].passes;
    const e2ePasses = pipeline[2].passes;
    const totalPasses = unitPasses.length + integrationPasses.length + e2ePasses.length;

    this.reportProgress(`\n════ GEMINI 10x BUG HUNTER (PARALLEL) ════`);
    this.reportProgress(`  Running ${totalPasses} passes in parallel`);
    this.reportProgress(`  - ${unitPasses.length} unit passes`);
    this.reportProgress(`  - ${integrationPasses.length} integration passes`);
    this.reportProgress(`  - ${e2ePasses.length} E2E passes`);
    this.reportProgress(`  Expected: ~5 minutes total\n`);

    let globalBugIndex = 0;

    // Helper to run a single pass
    const runPass = async (passName: string, prompt: string): Promise<Bug[]> => {
      const bugs: Bug[] = [];

      try {
        this.reportProgress(`  [${passName}] Starting...`);
        const result = await this.runGemini(prompt, cwd);
        const parsedBugs = this.parseAnalysisResponse(result, files);

        for (const bug of parsedBugs) {
          bug.id = generateBugId(globalBugIndex++);
          bugs.push(bug);
          this.reportBug(bug);
        }

        this.reportProgress(`  ✓ ${passName}: ${bugs.length} bugs`);
      } catch (error: any) {
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
        }),
      });
    }

    // Run passes in batches to avoid rate limits
    // Gemini free tier: 60 req/min, so we batch 5 at a time with small delays
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

    // Post-processing
    this.reportProgress(`\n════ POST-PROCESSING ════`);

    const { unique: dedupedBugs, duplicatesRemoved } = deduplicateBugs(allBugs);
    this.reportProgress(`  Removed ${duplicatesRemoved} exact duplicates`);

    const mergedBugs = mergeSimilarBugs(dedupedBugs);
    const similarMerged = dedupedBugs.length - mergedBugs.length;
    if (similarMerged > 0) {
      this.reportProgress(`  Merged ${similarMerged} similar findings`);
    }

    // Final summary
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

  async adversarialValidate(bug: Bug, _context: AnalysisContext): Promise<AdversarialResult> {
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
      // Continue without content
    }

    const prompt = this.buildAdversarialPrompt(bug, fileContent);
    const result = await this.runGemini(prompt, process.cwd());

    return this.parseAdversarialResponse(result, bug);
  }

  async generateUnderstanding(files: string[], existingDocsSummary?: string): Promise<CodebaseUnderstanding> {
    this.reportProgress(`Starting codebase analysis (${files.length} files)...`);

    const prompt = buildUnderstandingPrompt({ existingDocsSummary });
    const result = await this.runGeminiAgentic(prompt, process.cwd());

    return this.parseUnderstandingResponse(result, files);
  }

  // ─────────────────────────────────────────────────────────────
  // Prompt Builders
  // ─────────────────────────────────────────────────────────────

  private buildQuickScanPrompt(
    files: string[],
    understanding: CodebaseUnderstanding
  ): string {
    return `You are a security auditor and bug hunter. Analyze the codebase for bugs.

This is a ${understanding.summary.type} application using ${understanding.summary.framework || 'no specific framework'}.
Language: ${understanding.summary.language}
Total files: ${files.length}

Explore the codebase and find bugs in these categories:
1. Security vulnerabilities (injection, auth bypass, data exposure)
2. Logic errors (off-by-one, wrong operators, incorrect conditions)
3. Null/undefined dereference
4. Async/race conditions
5. Resource leaks
6. Type safety issues

For each bug found, output a JSON block:
<json>
{"file": "path/to/file.ts", "line": 42, "title": "Bug title", "description": "Detailed description", "severity": "critical|high|medium|low", "category": "null-reference|logic-error|injection|auth-bypass|async-issue|resource-leak", "evidence": ["evidence1"], "suggestedFix": "fix"}
</json>

At the end, output:
<json>{"type": "complete", "summary": {"bugsFound": N}}</json>`;
  }

  private buildAdversarialPrompt(bug: Bug, fileContent: string): string {
    return `You are a skeptical code reviewer. Challenge this bug report.

BUG REPORT:
- Title: ${bug.title}
- Description: ${bug.description}
- File: ${bug.file}:${bug.line}
- Severity: ${bug.severity}
- Category: ${bug.category}

Code context:
${fileContent}

Find reasons this might NOT be a bug:
- Guards or type checks that prevent this issue?
- Is the code path actually reachable?
- Runtime checks we might have missed?

Output ONLY JSON:
{"survived": true|false, "counterArguments": ["reason1", "reason2"], "confidence": "high|medium|low"}`;
  }

  // ─────────────────────────────────────────────────────────────
  // Gemini CLI Execution
  // ─────────────────────────────────────────────────────────────

  private async runGemini(prompt: string, cwd: string): Promise<string> {
    const geminiCommand = getProviderCommand('gemini');

    try {
      const { stdout } = await execa(
        geminiCommand,
        ['-p', prompt, '--output-format', 'text'],
        {
          cwd,
          timeout: 300000, // 5 min
          env: { ...process.env, NO_COLOR: '1' },
        }
      );
      return stdout;
    } catch (error: any) {
      if (error.stdout) return error.stdout;

      if (error.message?.includes('ENOENT')) {
        throw new Error('Gemini CLI not found. Install it with: npm install -g @google/gemini-cli');
      }

      throw error;
    }
  }

  private async runGeminiAgentic(prompt: string, cwd: string): Promise<string> {
    const geminiCommand = getProviderCommand('gemini');

    return new Promise((resolve, reject) => {
      let output = '';

      this.currentProcess = spawn(geminiCommand, ['-p', prompt, '--output-format', 'stream-json'], {
        cwd,
        env: { ...process.env, NO_COLOR: '1' },
        stdio: ['ignore', 'pipe', 'pipe'],
      });

      const timeout = setTimeout(() => {
        this.currentProcess?.kill();
        reject(new Error('Gemini analysis timed out after 10 minutes'));
      }, 600000);

private async runGeminiAgentic(prompt: string, cwd: string): Promise<string> {
      const geminiCommand = getProviderCommand('gemini');

      return new Promise((resolve, reject) => {
      let output = '';

      this.currentProcess = spawn(geminiCommand, ['-p', prompt, '--output-format', 'stream-json'], {
      cwd,
      env: { ...process.env, NO_COLOR: '1' },
      stdio: ['ignore', 'pipe', 'pipe'],
      });

      const timeout = setTimeout(() => {
      cleanup();
      this.currentProcess?.kill();
      reject(new Error('Gemini analysis timed out after 10 minutes'));
      }, 600000);

      const onStdout = (chunk: Buffer) => {
      const text = chunk.toString();
      output += text;
      for (const line of text.split('\n')) {
      try {
      const event = JSON.parse(line.trim());
      if (event.type === 'assistant' && event.message?.content) {
      for (const item of event.message.content) {
      if (item.type === 'tool_use') {
      this.reportProgress(`Using ${item.name || 'tool'}...`);
      }
      }
      }
      } catch { }
      }
      };

      const onStderr = (chunk: Buffer) => {
      const text = chunk.toString().trim();
      if (text) this.reportProgress(`Gemini: ${text.slice(0, 100)}`);
      };

      const cleanup = () => {
      clearTimeout(timeout);
      this.currentProcess?.stdout?.off('data', onStdout);
      this.currentProcess?.stderr?.off('data', onStderr);
      this.currentProcess?.off('exit', onExit);
      this.currentProcess?.off('error', onError);
      };

      const onExit = (code: number | null) => {
      cleanup();
      if (code !== 0 && code !== null) {
      this.reportProgress(`Gemini exited with code ${code}`);
      }
      resolve(output);
      };

      const onError = (err: Error) => {
      cleanup();
      reject(err);
      };

      this.currentProcess.stdout?.on('data', onStdout);
      this.currentProcess.stderr?.on('data', onStderr);
      this.currentProcess.on('exit', onExit);
      this.currentProcess.on('error', onError);
      });
      }
    });
  }

  // ─────────────────────────────────────────────────────────────
  // Response Parsers
  // ─────────────────────────────────────────────────────────────

  private parseAnalysisResponse(response: string, files: string[]): Bug[] {
    const bugs: Bug[] = [];

    // Extract JSON blocks from <json></json> tags
    const jsonBlockRegex = /<json>([\s\S]*?)<\/json>/g;
    let match;

    while ((match = jsonBlockRegex.exec(response)) !== null) {
      try {
        const parsed = JSON.parse(match[1].trim());

        // Skip completion markers
        if (parsed.type === 'complete') continue;

        // Must have required fields
        if (!parsed.file || !parsed.line || !parsed.title) continue;

        let filePath = parsed.file;
        if (!filePath.startsWith('/')) {
          const found = files.find((f) => f.endsWith(filePath) || f.includes(filePath));
          if (found) filePath = found;
        }

        bugs.push({
          id: generateBugId(bugs.length),
          title: String(parsed.title).slice(0, 100),
          description: String(parsed.description || ''),
          file: filePath,
          line: Number(parsed.line) || 0,
          endLine: parsed.endLine ? Number(parsed.endLine) : undefined,
          kind: 'bug',
          severity: this.parseSeverity(parsed.severity),
          category: this.parseCategory(parsed.category),
          confidence: {
            overall: 'medium' as ConfidenceLevel,
            codePathValidity: 0.75,
            reachability: 0.75,
            intentViolation: false,
            staticToolSignal: false,
            adversarialSurvived: false,
          },
          codePath: [],
          evidence: Array.isArray(parsed.evidence) ? parsed.evidence.map(String) : [],
          suggestedFix: parsed.suggestedFix ? String(parsed.suggestedFix) : undefined,
          createdAt: new Date().toISOString(),
          status: 'open',
        });
      } catch {
        // Invalid JSON, skip
      }
    }

    // Also try to parse raw JSON arrays (fallback)
    if (bugs.length === 0) {
      const arrayMatch = response.match(/\[[\s\S]*\]/);
      if (arrayMatch) {
        try {
          const parsed = JSON.parse(arrayMatch[0]);
          if (Array.isArray(parsed)) {
            for (const item of parsed) {
              if (!item.file || !item.line || !item.title) continue;

              let filePath = item.file;
              if (!filePath.startsWith('/')) {
                const found = files.find((f) => f.endsWith(filePath) || f.includes(filePath));
                if (found) filePath = found;
              }

              bugs.push({
                id: generateBugId(bugs.length),
                title: String(item.title).slice(0, 100),
                description: String(item.description || ''),
                file: filePath,
                line: Number(item.line) || 0,
                endLine: item.endLine ? Number(item.endLine) : undefined,
                kind: 'bug',
                severity: this.parseSeverity(item.severity),
                category: this.parseCategory(item.category),
                confidence: {
                  overall: 'medium' as ConfidenceLevel,
                  codePathValidity: 0.75,
                  reachability: 0.75,
                  intentViolation: false,
                  staticToolSignal: false,
                  adversarialSurvived: false,
                },
                codePath: [],
                evidence: Array.isArray(item.evidence) ? item.evidence.map(String) : [],
                suggestedFix: item.suggestedFix ? String(item.suggestedFix) : undefined,
                createdAt: new Date().toISOString(),
                status: 'open',
              });
            }
          }
        } catch {
          // Invalid JSON
        }
      }
    }

    return bugs;
  }

  private parseAdversarialResponse(response: string, bug: Bug): AdversarialResult {
    try {
      const json = this.extractJson(response);
      if (!json) return { survived: true, counterArguments: [] };

      const parsed = JSON.parse(json);
      const survived = parsed.survived !== false;

      return {
        survived,
        counterArguments: Array.isArray(parsed.counterArguments)
          ? parsed.counterArguments.map(String)
          : [],
        adjustedConfidence: survived
          ? {
              ...bug.confidence,
              overall: this.parseConfidence(parsed.confidence),
              adversarialSurvived: true,
            }
          : undefined,
      };
    } catch {
      return { survived: true, counterArguments: [] };
    }
  }

  private parseUnderstandingResponse(response: string, files: string[]): CodebaseUnderstanding {
    let totalLines = 0;
    for (const file of files) {
      try {
        const content = readFileSync(file, 'utf-8');
        totalLines += content.split('\n').length;
      } catch {
        // Skip
      }
    }

    try {
      const json = this.extractJson(response);
      if (!json) throw new Error('No JSON found');

      const parsed = JSON.parse(json);

      return {
        version: '1',
        generatedAt: new Date().toISOString(),
        summary: {
          type: parsed.summary?.type || 'unknown',
          description: parsed.summary?.description || '',
          language: parsed.summary?.language || 'unknown',
          framework: parsed.summary?.framework,
        },
        features: parsed.features || [],
        contracts: parsed.contracts || [],
        dependencies: parsed.dependencies || {},
        structure: {
          totalFiles: files.length,
          totalLines,
        },
      };
    } catch {
      return {
        version: '1',
        generatedAt: new Date().toISOString(),
        summary: {
          type: 'unknown',
          description: 'Failed to parse Gemini response',
          language: 'unknown',
        },
        features: [],
        contracts: [],
        dependencies: {},
        structure: {
          totalFiles: files.length,
          totalLines,
        },
      };
    }
  }

  // ─────────────────────────────────────────────────────────────
  // Utilities
  // ─────────────────────────────────────────────────────────────

  private extractJson(text: string): string | null {
    // Try <json> tags first
    const tagMatch = text.match(/<json>([\s\S]*?)<\/json>/);
    if (tagMatch) return tagMatch[1].trim();

    // Try code blocks
    const codeBlockMatch = text.match(/```(?:json)?\s*([\s\S]*?)```/);
    if (codeBlockMatch) return codeBlockMatch[1].trim();

    // Try raw JSON
    const objectMatch = text.match(/\{[\s\S]*\}/);
    if (objectMatch) return objectMatch[0];

    return null;
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
    const validCategories: BugCategory[] = [
      'injection',
      'auth-bypass',
      'secrets-exposure',
      'null-reference',
      'boundary-error',
      'resource-leak',
      'async-issue',
      'logic-error',
      'data-validation',
      'type-coercion',
      'concurrency',
      'intent-violation',
    ];
    return validCategories.includes(v as BugCategory) ? (v as BugCategory) : 'logic-error';
  }

  private parseConfidence(value: any): ConfidenceLevel {
    const v = String(value).toLowerCase();
    if (v === 'high') return 'high';
    if (v === 'low') return 'low';
    return 'medium';
  }
}
