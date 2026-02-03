import { execa } from 'execa';
import { spawn, type ChildProcess } from 'child_process';
import { readFileSync, existsSync } from 'fs';
import {
  LLMProvider,
  ProviderType,
  AnalysisContext,
  Bug,
  AdversarialResult,
  CodebaseUnderstanding,
} from '../../types.js';
import { isProviderAvailable, getProviderCommand } from '../detect.js';
import { generateBugId } from '../../core/utils.js';
import {
  safeParseJson,
  PartialBugFromLLM,
  PartialUnderstandingFromLLM,
  AdversarialResultSchema,
} from '../../core/validation.js';

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

  async analyze(context: AnalysisContext): Promise<Bug[]> {
    const { files, understanding } = context;

    if (files.length === 0) {
      return [];
    }

    const cwd = process.cwd();
    const bugs: Bug[] = [];
    let bugIndex = 0;

    const prompt = this.buildAgenticAnalysisPrompt(understanding);

    this.reportProgress('Starting agentic analysis...');

    try {
      await this.runAgenticClaude(prompt, cwd, {
        onScanning: (file) => {
          this.reportProgress(`Scanning: ${file}`);
        },
        onBugFound: (bugData) => {
          const bug = this.parseBugData(bugData, bugIndex++, files);
          if (bug) {
            bugs.push(bug);
            this.reportBug(bug);
            this.reportProgress(`Found: ${bug.title} (${bug.severity})`);
          }
        },
        onComplete: () => {
          this.reportProgress(`Analysis complete. Found ${bugs.length} bugs.`);
        },
        onError: (error) => {
          this.reportProgress(`Error: ${error}`);
        },
      });
    } catch (error: any) {
      if (error.message?.includes('ENOENT')) {
        throw new Error('Claude CLI not found. Install it with: npm install -g @anthropic-ai/claude-code');
      }
      throw error;
    }

    return bugs;
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

    const prompt = this.buildAdversarialPrompt(bug, fileContent);
    const result = await this.runSimpleClaude(prompt, process.cwd());

    return this.parseAdversarialResponse(result, bug);
  }

  async generateUnderstanding(files: string[], existingDocsSummary?: string): Promise<CodebaseUnderstanding> {
    const cwd = process.cwd();

    this.reportProgress(`Starting codebase analysis (${files.length} files)...`);

    const prompt = this.buildAgenticUnderstandingPrompt(existingDocsSummary);
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
  // Agentic Prompts
  // ─────────────────────────────────────────────────────────────

  private buildAgenticAnalysisPrompt(understanding: CodebaseUnderstanding): string {
    return `You are whiterose, an expert bug hunter. Your task is to explore this codebase and find real bugs.

CODEBASE CONTEXT:
- Type: ${understanding.summary.type}
- Framework: ${understanding.summary.framework || 'Unknown'}
- Description: ${understanding.summary.description}

YOUR TASK:
1. Explore the codebase by reading files
2. Look for bugs in these categories:
   - Logic errors (off-by-one, wrong operators, incorrect conditions)
   - Null/undefined dereference
   - Security vulnerabilities (injection, auth bypass, XSS)
   - Async/race conditions (missing await, unhandled promises)
   - Edge cases (empty arrays, zero values, boundaries)
   - Resource leaks (unclosed connections)

PROTOCOL - You MUST output these markers:
- Before reading each file, output: ${MARKERS.SCANNING}<filepath>
- When you find a bug, output: ${MARKERS.BUG}<json>
- When completely done, output: ${MARKERS.COMPLETE}
- If you encounter an error, output: ${MARKERS.ERROR}<message>

BUG JSON FORMAT:
${MARKERS.BUG}{"file":"src/api/users.ts","line":42,"title":"Null dereference in getUserById","description":"...","severity":"high","category":"null-reference","evidence":["..."],"suggestedFix":"..."}

IMPORTANT:
- Only report bugs you have HIGH confidence in
- Include exact line numbers
- Focus on real bugs, not style issues
- Explore systematically - check API routes, data handling, auth flows

Now explore this codebase and find bugs. Start by reading the main entry points.`;
  }

  private buildAgenticUnderstandingPrompt(existingDocsSummary?: string): string {
    const docsSection = existingDocsSummary
      ? `\n\nEXISTING DOCUMENTATION (merge this with your exploration):\n${existingDocsSummary}\n`
      : '';

    return `You are whiterose. Your task is to understand this codebase.
${docsSection}
YOUR TASK:
1. Review the existing documentation above (if any)
2. Explore the codebase structure to fill in gaps
3. Read key files (main entry points, config files, core modules)
4. Build a comprehensive understanding merging docs + code exploration
5. Identify main features, business rules, and behavioral contracts

PROTOCOL - You MUST output these markers:
- Before reading each file, output: ${MARKERS.SCANNING}<filepath>
- When you have full understanding, output: ${MARKERS.UNDERSTANDING}<json>
- When completely done, output: ${MARKERS.COMPLETE}

UNDERSTANDING JSON FORMAT:
${MARKERS.UNDERSTANDING}{
  "summary": {
    "type": "api|web-app|cli|library|etc",
    "framework": "next.js|express|react|etc",
    "language": "typescript|javascript",
    "description": "2-3 sentence description"
  },
  "features": [
    {"name": "Feature", "description": "What it does", "priority": "critical|high|medium|low", "constraints": ["business rule 1", "invariant 2"], "relatedFiles": ["path/to/file.ts"]}
  ],
  "contracts": [
    {"function": "functionName", "file": "path/to/file.ts", "inputs": [], "outputs": {}, "invariants": ["must do X before Y"], "sideEffects": [], "throws": []}
  ]
}

IMPORTANT:
- Merge existing documentation with what you discover in the code
- Focus on business rules and invariants (what MUST be true)
- Identify critical paths (checkout, auth, payments, etc.)
- Document behavioral contracts for important functions

Now explore this codebase and build understanding.`;
  }

  private buildAdversarialPrompt(bug: Bug, fileContent: string): string {
    return `You are a skeptical code reviewer. Try to DISPROVE this bug report.

REPORTED BUG:
- File: ${bug.file}:${bug.line}
- Title: ${bug.title}
- Description: ${bug.description}
- Severity: ${bug.severity}

CODE CONTEXT:
${fileContent}

Try to prove this is NOT a bug by finding:
1. Guards or validation that prevents this
2. Type system guarantees
3. Framework behavior that handles this
4. Unreachable code paths

OUTPUT AS JSON:
{"survived": true/false, "counterArguments": ["reason 1"], "confidence": "high/medium/low", "explanation": "..."}

Set "survived": true if you CANNOT disprove it (it's a real bug).`;
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
    const claudeCommand = getProviderCommand('claude-code');

    // Build command arguments with proper streaming output format
    const args = [
      '-p', prompt,
      '--output-format', 'stream-json',
      '--verbose',
    ];

    // Auto-approve tools when unsafe mode is enabled
    if (this.unsafeMode) {
      args.push('--allowedTools', 'Bash,Read,Edit,Glob,Grep,Write');
    }

    // Use native spawn for proper streaming (execa v9 has buffering issues)
    this.currentProcess = spawn(claudeCommand, args, {
      cwd,
      env: {
        ...process.env,
        NO_COLOR: '1',
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    // Heartbeat to show activity
    let lastActivity = Date.now();
    const heartbeat = setInterval(() => {
      const elapsed = Math.floor((Date.now() - lastActivity) / 1000);
      if (elapsed > 10) {
        this.reportProgress(`Analyzing... (${elapsed}s since last update)`);
      }
    }, 5000);

    // Buffer for accumulating output
    let buffer = '';

    // Process streaming output
    this.currentProcess.stdout?.on('data', (chunk: Buffer) => {
      lastActivity = Date.now();
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
      const text = chunk.toString().trim();
      if (text) {
        // Report stderr activity
        this.reportProgress(`Claude: ${text.slice(0, 50)}...`);
      }
    });

    // Wait for process to complete
    await new Promise<void>((resolve, reject) => {
      // Timeout after 5 minutes
      const timeout = setTimeout(() => {
        this.currentProcess?.kill();
        reject(new Error('Claude analysis timed out after 5 minutes'));
      }, 300000);

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

    // Clean up heartbeat
    clearInterval(heartbeat);

    // Process any remaining buffer
    if (buffer.trim()) {
      this.processAgentOutput(buffer, callbacks);
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

    // Check for complete markers in the accumulated buffer
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
    // Use Zod validation for safe parsing
    const result = safeParseJson(json, PartialBugFromLLM);
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
    // Count total lines from a sample (needed for fallback and success cases)
    let totalLines = 0;
    for (const file of files.slice(0, 50)) {
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
    // Try markdown code blocks
    const codeBlockMatch = text.match(/```(?:json)?\s*([\s\S]*?)```/);
    if (codeBlockMatch) {
      return codeBlockMatch[1].trim();
    }

    // Try raw JSON array
    const arrayMatch = text.match(/\[[\s\S]*\]/);
    if (arrayMatch) {
      return arrayMatch[0];
    }

    // Try raw JSON object
    const objectMatch = text.match(/\{[\s\S]*\}/);
    if (objectMatch) {
      return objectMatch[0];
    }

    return null;
  }
}
