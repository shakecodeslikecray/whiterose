import { execa } from 'execa';
import { readFileSync, existsSync, writeFileSync, mkdtempSync, rmSync } from 'fs';
import { dirname, join } from 'path';
import { tmpdir } from 'os';
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
  CodePathStep,
} from '../../types.js';
import { isProviderAvailable, getProviderCommand } from '../detect.js';
import { generateBugId } from '../../core/utils.js';

const MAX_FILE_SIZE = 50000;
const MAX_TOTAL_CONTEXT = 200000;
const AIDER_TIMEOUT = 300000;

export class AiderProvider implements LLMProvider {
  name: ProviderType = 'aider';

  async detect(): Promise<boolean> {
    return isProviderAvailable('aider');
  }

  async isAvailable(): Promise<boolean> {
    return isProviderAvailable('aider');
  }

  async analyze(context: AnalysisContext): Promise<Bug[]> {
    const { files, understanding, staticAnalysisResults } = context;

    if (files.length === 0) {
      return [];
    }

    // Read file contents with size limits
    const fileContents = this.readFilesWithLimit(files, MAX_TOTAL_CONTEXT);

    // Build the analysis prompt
    const prompt = this.buildAnalysisPrompt(fileContents, understanding, staticAnalysisResults);

    // Run aider with the prompt
    const result = await this.runAider(prompt, files, dirname(files[0]));

    // Parse the response into bugs
    return this.parseAnalysisResponse(result, files);
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
    const result = await this.runAider(prompt, [bug.file], dirname(bug.file));

    return this.parseAdversarialResponse(result, bug);
  }

  async generateUnderstanding(files: string[], _existingDocsSummary?: string): Promise<CodebaseUnderstanding> {
    const sampledFiles = this.prioritizeFiles(files, 40);
    const fileContents = this.readFilesWithLimit(sampledFiles, MAX_TOTAL_CONTEXT);

    let packageJson: Record<string, unknown> | null = null;
    const packageJsonPath = files.find((f) => f.endsWith('package.json'));
    if (packageJsonPath) {
      try {
        packageJson = JSON.parse(readFileSync(packageJsonPath, 'utf-8'));
      } catch {
        // Ignore
      }
    }

    const prompt = this.buildUnderstandingPrompt(files.length, fileContents, packageJson);
    const result = await this.runAider(prompt, sampledFiles.slice(0, 5), process.cwd());

    return this.parseUnderstandingResponse(result, files);
  }

  // ─────────────────────────────────────────────────────────────
  // File Reading Helpers
  // ─────────────────────────────────────────────────────────────

  private readFilesWithLimit(
    files: string[],
    maxTotal: number
  ): Array<{ path: string; content: string }> {
    const result: Array<{ path: string; content: string }> = [];
    let totalSize = 0;

    for (const file of files) {
      if (totalSize >= maxTotal) break;

      try {
        if (!existsSync(file)) continue;

        let content = readFileSync(file, 'utf-8');

        if (content.length > MAX_FILE_SIZE) {
          content = content.slice(0, MAX_FILE_SIZE) + '\n// ... truncated ...';
        }

        if (totalSize + content.length > maxTotal) {
          const remaining = maxTotal - totalSize;
          content = content.slice(0, remaining) + '\n// ... truncated ...';
        }

        result.push({ path: file, content });
        totalSize += content.length;
      } catch {
        // Skip
      }
    }

    return result;
  }

  private prioritizeFiles(files: string[], count: number): string[] {
    if (files.length <= count) return files;

    const priorityPatterns: Array<{ pattern: RegExp; priority: number }> = [
      { pattern: /package\.json$/, priority: 100 },
      { pattern: /tsconfig\.json$/, priority: 90 },
      { pattern: /README\.md$/i, priority: 80 },
      { pattern: /\/index\.(ts|js|tsx|jsx)$/, priority: 70 },
      { pattern: /\/app\.(ts|js|tsx|jsx)$/, priority: 70 },
      { pattern: /\/main\.(ts|js|tsx|jsx)$/, priority: 70 },
      { pattern: /\/api\//, priority: 60 },
      { pattern: /\/routes?\//, priority: 55 },
      { pattern: /\/pages\//, priority: 55 },
      { pattern: /\/services?\//, priority: 50 },
      { pattern: /\.(ts|tsx)$/, priority: 30 },
      { pattern: /\.(js|jsx)$/, priority: 20 },
    ];

    const scored = files.map((file) => {
      let score = 0;
      for (const { pattern, priority } of priorityPatterns) {
        if (pattern.test(file)) {
          score = Math.max(score, priority);
        }
      }
      return { file, score };
    });

    scored.sort((a, b) => b.score - a.score);
    return scored.slice(0, count).map((s) => s.file);
  }

  // ─────────────────────────────────────────────────────────────
  // Prompt Builders (similar to Claude Code but adapted for Aider)
  // ─────────────────────────────────────────────────────────────

  private buildAnalysisPrompt(
    fileContents: Array<{ path: string; content: string }>,
    understanding: CodebaseUnderstanding,
    staticResults: Array<{ tool: string; file: string; line: number; message: string }>
  ): string {
    const filesSection = fileContents
      .map((f) => `=== ${f.path} ===\n${f.content}`)
      .join('\n\n');

    const staticSignals =
      staticResults.length > 0
        ? `\nStatic analysis signals:\n${staticResults
            .slice(0, 50)
            .map((r) => `- ${r.file}:${r.line}: ${r.message}`)
            .join('\n')}`
        : '';

    return `Analyze the following code for bugs. This is a ${understanding.summary.type} application using ${understanding.summary.framework || 'no specific framework'}.

${filesSection}
${staticSignals}

Find bugs in these categories:
1. Logic errors (off-by-one, wrong operators)
2. Null/undefined dereference
3. Security vulnerabilities
4. Async/race conditions
5. Edge cases not handled

Output as JSON array ONLY:
[{"file": "path", "line": 42, "title": "Bug title", "description": "Description", "severity": "high", "category": "null-reference", "codePath": [{"step": 1, "file": "path", "line": 40, "code": "code", "explanation": "explanation"}], "evidence": ["evidence1"], "suggestedFix": "fix code"}]

If no bugs found, output: []`;
  }

  private buildAdversarialPrompt(bug: Bug, fileContent: string): string {
    return `Try to DISPROVE this bug report:

Bug: ${bug.title}
File: ${bug.file}:${bug.line}
Description: ${bug.description}

Code context:
${fileContent}

Find reasons this is NOT a bug (guards, type checks, etc).

Output JSON ONLY:
{"survived": true/false, "counterArguments": ["reason1", "reason2"], "confidence": "high/medium/low"}`;
  }

  private buildUnderstandingPrompt(
    totalFiles: number,
    fileContents: Array<{ path: string; content: string }>,
    packageJson: Record<string, unknown> | null
  ): string {
    const filesSection = fileContents
      .map((f) => `=== ${f.path} ===\n${f.content}`)
      .join('\n\n');

    const depsSection = packageJson
      ? `\nDependencies: ${JSON.stringify((packageJson as any).dependencies || {})}`
      : '';

    return `Analyze this codebase (${totalFiles} total files).
${depsSection}

${filesSection}

Output JSON ONLY describing:
{
  "summary": {"type": "app-type", "framework": "framework", "language": "typescript", "description": "description"},
  "features": [{"name": "Feature", "description": "desc", "priority": "critical", "constraints": ["constraint"], "relatedFiles": ["file"]}],
  "contracts": [{"function": "funcName", "file": "file.ts", "inputs": [{"name": "param", "type": "string"}], "outputs": {"type": "Result"}, "invariants": ["rule"], "sideEffects": ["effect"]}]
}`;
  }

  // ─────────────────────────────────────────────────────────────
  // Aider CLI Execution
  // ─────────────────────────────────────────────────────────────

  private async runAider(prompt: string, files: string[], cwd: string): Promise<string> {
    // Create a temp file for the prompt
    const tempDir = mkdtempSync(join(tmpdir(), 'whiterose-'));
    const promptFile = join(tempDir, 'prompt.txt');

    try {
      writeFileSync(promptFile, prompt, 'utf-8');

      // Run aider in no-auto-commits mode with message from file
      const args = [
        '--no-auto-commits',
        '--no-git',
        '--yes',
        '--message-file', promptFile,
      ];

      // Add files to analyze
      for (const file of files.slice(0, 10)) {
        if (existsSync(file)) {
          args.push(file);
        }
      }

      const aiderCommand = getProviderCommand('aider');
      const { stdout, stderr } = await execa(aiderCommand, args, {
        cwd,
        timeout: AIDER_TIMEOUT,
        env: {
          ...process.env,
          NO_COLOR: '1',
        },
        reject: false,
      });

      return stdout || stderr || '';
    } catch (error: any) {
      if (error.stdout) {
        return error.stdout;
      }

      if (error.message?.includes('ENOENT')) {
        throw new Error('Aider not found. Install it with: pip install aider-chat');
      }

      throw new Error(`Aider failed: ${error.message}`);
    } finally {
      // Clean up temp files
      try {
        rmSync(tempDir, { recursive: true, force: true });
      } catch {
        // Ignore cleanup errors
      }
    }
  }

  // ─────────────────────────────────────────────────────────────
  // Response Parsers
  // ─────────────────────────────────────────────────────────────

  private parseAnalysisResponse(response: string, files: string[]): Bug[] {
    try {
      const json = this.extractJson(response);
      if (!json) return [];

      const parsed = JSON.parse(json);
      if (!Array.isArray(parsed)) return [];

      const bugs: Bug[] = [];

      for (let i = 0; i < parsed.length; i++) {
        const item = parsed[i];
        if (!item.file || !item.line || !item.title) continue;

        let filePath = item.file;
        if (!filePath.startsWith('/')) {
          const match = files.find((f) => f.endsWith(filePath) || f.includes(filePath));
          if (match) filePath = match;
        }

        const codePath: CodePathStep[] = (item.codePath || []).map(
          (step: any, idx: number) => ({
            step: step.step || idx + 1,
            file: step.file || filePath,
            line: step.line || item.line,
            code: step.code || '',
            explanation: step.explanation || '',
          })
        );

        bugs.push({
          id: generateBugId(i),
          title: String(item.title).slice(0, 100),
          description: String(item.description || ''),
          file: filePath,
          line: Number(item.line) || 0,
          endLine: item.endLine ? Number(item.endLine) : undefined,
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
          codePath,
          evidence: Array.isArray(item.evidence) ? item.evidence.map(String) : [],
          suggestedFix: item.suggestedFix ? String(item.suggestedFix) : undefined,
          createdAt: new Date().toISOString(),
          status: 'open',
        });
      }

      return bugs;
    } catch {
      return [];
    }
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

  private parseUnderstandingResponse(
    response: string,
    files: string[]
  ): CodebaseUnderstanding {
    try {
      const json = this.extractJson(response);
      if (!json) throw new Error('No JSON found');

      const parsed = JSON.parse(json);

      let totalLines = 0;
      for (const file of files.slice(0, 50)) {
        try {
          totalLines += readFileSync(file, 'utf-8').split('\n').length;
        } catch {
          // Skip
        }
      }

      return {
        version: '1',
        generatedAt: new Date().toISOString(),
        summary: {
          type: parsed.summary?.type || 'unknown',
          framework: parsed.summary?.framework,
          language: parsed.summary?.language || 'typescript',
          description: parsed.summary?.description || 'No description available',
        },
        features: (parsed.features || []).map((f: any) => ({
          name: f.name || 'Unknown',
          description: f.description || '',
          priority: f.priority || 'medium',
          constraints: Array.isArray(f.constraints) ? f.constraints : [],
          relatedFiles: Array.isArray(f.relatedFiles) ? f.relatedFiles : [],
        })),
        contracts: (parsed.contracts || []).map((c: any) => ({
          function: c.function || 'unknown',
          file: c.file || 'unknown',
          inputs: Array.isArray(c.inputs) ? c.inputs : [],
          outputs: c.outputs || { type: 'unknown' },
          invariants: Array.isArray(c.invariants) ? c.invariants : [],
          sideEffects: Array.isArray(c.sideEffects) ? c.sideEffects : [],
        })),
        dependencies: {},
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
          language: 'typescript',
          description: 'Failed to analyze codebase',
        },
        features: [],
        contracts: [],
        dependencies: {},
        structure: {
          totalFiles: files.length,
          totalLines: 0,
        },
      };
    }
  }

  // ─────────────────────────────────────────────────────────────
  // Utilities
  // ─────────────────────────────────────────────────────────────

  private extractJson(text: string): string | null {
    // Try code blocks first (most reliable)
    const codeBlockMatch = text.match(/```(?:json)?\s*([\s\S]*?)```/);
    if (codeBlockMatch) return codeBlockMatch[1].trim();

    // Use non-greedy matching to find first complete JSON array
    const arrayMatch = text.match(/\[[\s\S]*?\]/);
private extractJson(text: string): string | null {
    // Try code blocks first (most reliable)
    const codeBlockMatch = text.match(/```(?:json)?\s*([\s\S]*?)```/);
    if (codeBlockMatch) return codeBlockMatch[1].trim();

    // Find balanced JSON using bracket counting
    return this.findBalancedJson(text);
    }

    private findBalancedJson(text: string): string | null {
    const objectStart = text.indexOf('{');
    const arrayStart = text.indexOf('[');

    let start = -1;
    let openChar = '{';
    let closeChar = '}';

    if (objectStart === -1 && arrayStart === -1) return null;
    if (objectStart === -1) { start = arrayStart; openChar = '['; closeChar = ']'; }
    else if (arrayStart === -1) { start = objectStart; }
    else if (arrayStart < objectStart) { start = arrayStart; openChar = '['; closeChar = ']'; }
    else { start = objectStart; }

    let depth = 0;
    let inString = false;
    let escapeNext = false;

    for (let i = start; i < text.length; i++) {
    const char = text[i];
    if (escapeNext) { escapeNext = false; continue; }
    if (char === '\\' && inString) { escapeNext = true; continue; }
    if (char === '"' && !escapeNext) { inString = !inString; continue; }
    if (inString) continue;
    if (char === openChar) depth++;
    else if (char === closeChar) {
    depth--;
    if (depth === 0) return text.slice(start, i + 1);
    }
    }
    return null;
    }
    }

    // Use non-greedy matching to find first complete JSON object
    const objectMatch = text.match(/\{[\s\S]*?\}/);
    if (objectMatch) {
      try {
        JSON.parse(objectMatch[0]);
        return objectMatch[0];
      } catch {
        // Not valid JSON
      }
    }

    return null;
  }

  private parseSeverity(value: unknown): BugSeverity {
    const str = String(value).toLowerCase();
    if (['critical', 'high', 'medium', 'low'].includes(str)) {
      return str as BugSeverity;
    }
    return 'medium';
  }

  private parseCategory(value: unknown): BugCategory {
    const str = String(value).toLowerCase().replace(/_/g, '-');
    const validCategories: BugCategory[] = [
      // Security
      'injection', 'auth-bypass', 'secrets-exposure',
      // Reliability
      'null-reference', 'boundary-error', 'resource-leak', 'async-issue',
      // Correctness
      'logic-error', 'data-validation', 'type-coercion',
      // Design
      'concurrency', 'intent-violation',
    ];

    if (validCategories.includes(str as BugCategory)) {
      return str as BugCategory;
    }

    // Map common patterns to new categories
    if (str.includes('null') || str.includes('undefined')) return 'null-reference';
    if (str.includes('injection') || str.includes('xss') || str.includes('sql')) return 'injection';
    if (str.includes('auth') || str.includes('permission') || str.includes('access')) return 'auth-bypass';
    if (str.includes('secret') || str.includes('credential') || str.includes('password')) return 'secrets-exposure';
    if (str.includes('async') || str.includes('race') || str.includes('await') || str.includes('promise')) return 'async-issue';
    if (str.includes('boundary') || str.includes('index') || str.includes('overflow')) return 'boundary-error';
    if (str.includes('leak') || str.includes('resource') || str.includes('memory')) return 'resource-leak';
    if (str.includes('validation') || str.includes('sanitiz')) return 'data-validation';
    if (str.includes('thread') || str.includes('concurrent') || str.includes('deadlock')) return 'concurrency';
    if (str.includes('coercion') || str.includes('type')) return 'type-coercion';

    return 'logic-error';
  }

  private parseConfidence(value: unknown): ConfidenceLevel {
    const str = String(value).toLowerCase();
    if (['high', 'medium', 'low'].includes(str)) {
      return str as ConfidenceLevel;
    }
    return 'medium';
  }
}
