import { execa } from 'execa';
import { readFileSync, existsSync, realpathSync, statSync, mkdtempSync, rmSync } from 'fs';
import { resolve, relative, isAbsolute, join } from 'path';
import { tmpdir } from 'os';
import { Bug, WhiteroseConfig } from '../types.js';
import { createFixBranch, commitFix } from './git.js';
import { getProviderCommand } from '../providers/detect.js';
import { markBugAsFixed } from './bug-status.js';

/**
 * Maximum length for untrusted SARIF text fields to prevent prompt bloat attacks.
 */
const MAX_SARIF_TEXT_LENGTH = 2000;

/**
 * Patterns that indicate prompt injection attempts in SARIF content.
 * These patterns try to break out of the bug context and inject new instructions.
 */
const PROMPT_INJECTION_PATTERNS = [
  // Attempts to override or ignore instructions
  /ignore\s+(previous|all|above)\s+instructions?/i,
  /disregard\s+(previous|all|above)\s+instructions?/i,
  /forget\s+(previous|all|above)\s+instructions?/i,
  // Attempts to define new roles or personas
  /you\s+are\s+(now|actually)\s+/i,
  /act\s+as\s+(a|an)\s+/i,
  /pretend\s+(you|to\s+be)\s+/i,
  // Attempts to inject system-level commands
  /\[SYSTEM\]/i,
  /\[INST\]/i,
  /<\|system\|>/i,
  /<\|assistant\|>/i,
  /<\|user\|>/i,
  // Attempts to break out with special markers
  /###\s*(INSTRUCTION|SYSTEM|END|NEW)/i,
  /```\s*(system|instruction)/i,
  // Direct file operation injections
  /delete\s+(all|the)\s+files?/i,
  /rm\s+-rf\s+/i,
  /remove\s+(all|every)\s+file/i,
  // Exfiltration attempts
  /send\s+(this|the|all)\s+(data|content|file)/i,
  /upload\s+(to|this)/i,
  /curl\s+.*\s+-d/i,
  /fetch\s*\(\s*['"][^'"]*['"]\s*,\s*\{[^}]*method\s*:\s*['"]POST['"]/i,
];

/**
 * Sanitizes untrusted text from SARIF files to prevent prompt injection.
 *
 * This function:
 * 1. Truncates overly long text to prevent prompt bloat
 * 2. Detects and neutralizes prompt injection patterns
 * 3. Escapes special characters that could break prompt structure
 *
 * @param text - Untrusted text from SARIF file
 * @param fieldName - Name of the field for error reporting
 * @returns Sanitized text safe for prompt embedding
 */
export function sanitizeSarifText(text: string, fieldName: string = 'field'): string {
  if (!text || typeof text !== 'string') {
    return '';
  }

  // Truncate overly long text
  let sanitized = text.length > MAX_SARIF_TEXT_LENGTH
    ? text.substring(0, MAX_SARIF_TEXT_LENGTH) + `... [truncated ${fieldName}]`
    : text;

  // Check for prompt injection patterns
  for (const pattern of PROMPT_INJECTION_PATTERNS) {
    if (pattern.test(sanitized)) {
      // Replace the suspicious content with a safe placeholder
      sanitized = sanitized.replace(pattern, '[REDACTED: potential injection]');
    }
  }

  // Escape characters that could break prompt structure
  // Replace markdown-style code blocks that might confuse the LLM
  sanitized = sanitized.replace(/```+/g, '`\u200B`\u200B`'); // Insert zero-width spaces

  // Escape sequences that look like special markers
  sanitized = sanitized.replace(/###/g, '#\u200B#\u200B#');

  return sanitized;
}

/**
 * Sanitizes an array of evidence strings from SARIF.
 */
export function sanitizeSarifEvidence(evidence: unknown): string[] {
  if (!Array.isArray(evidence)) {
    return [];
  }

  return evidence
    .filter((e): e is string => typeof e === 'string')
    .slice(0, 10) // Limit number of evidence items
    .map((e) => sanitizeSarifText(e, 'evidence'));
}

/**
 * Sanitizes code path entries from SARIF.
 */
export function sanitizeSarifCodePath(codePath: unknown): Array<{
  step: number;
  file: string;
  line: number;
  code: string;
  explanation: string;
}> {
  if (!Array.isArray(codePath)) {
    return [];
  }

  return codePath
    .slice(0, 20) // Limit number of code path entries
    .map((entry, idx) => ({
      step: typeof entry?.step === 'number' ? entry.step : idx + 1,
      file: sanitizeSarifText(String(entry?.file || ''), 'codePath.file').substring(0, 500),
      line: typeof entry?.line === 'number' ? entry.line : 0,
      code: sanitizeSarifText(String(entry?.code || ''), 'codePath.code'),
      explanation: sanitizeSarifText(String(entry?.explanation || ''), 'codePath.explanation'),
    }));
}

/**
 * Validates that a file path is within the project directory.
 * Prevents path traversal attacks from malicious bug.file values.
 */
function isPathWithinProject(filePath: string, projectDir: string): boolean {
  const resolvedPath = resolve(projectDir, filePath);
  const relativePath = relative(projectDir, resolvedPath);

  // Path is outside if it starts with '..' or is an absolute path
  return !relativePath.startsWith('..') && !isAbsolute(relativePath);
}

/**
 * Sanitizes and validates a file path for safe operations.
 * Returns the resolved absolute path if valid, throws if invalid.
 */
function validateFilePath(filePath: string, projectDir: string): string {
  // Check for null bytes first (can bypass other checks)
  if (filePath.includes('\0')) {
    throw new Error(`Security: Invalid file path contains null byte: ${filePath}`);
  }

  // Resolve to absolute path
  const resolvedPath = isAbsolute(filePath) ? filePath : resolve(projectDir, filePath);

  // Resolve symlinks to get real path (prevents symlink bypass attacks)
  let realPath: string;
  let realProjectDir: string;
  try {
    realPath = existsSync(resolvedPath) ? realpathSync(resolvedPath) : resolvedPath;
    realProjectDir = realpathSync(projectDir);
  } catch {
    // If realpath fails, use resolved paths
    realPath = resolvedPath;
    realProjectDir = projectDir;
  }

  // Check real path is within project (after symlink resolution)
  if (!isPathWithinProject(realPath, realProjectDir)) {
    throw new Error(`Security: Refusing to access file outside project directory: ${filePath}`);
  }

  return realPath;
}

interface FixOptions {
  dryRun: boolean;
  branch?: string;
  onProgress?: (message: string) => void;
}

interface FixResult {
  success: boolean;
  diff?: string;
  error?: string;
  branchName?: string;
  commitHash?: string;
  falsePositive?: boolean;
  falsePositiveReason?: string;
}

/**
 * Apply a fix to a bug using an agentic approach.
 *
 * Instead of generating a fix and applying it ourselves, we give the bug
 * details to the LLM provider and let it explore the code and fix it directly.
 * This produces much better fixes because the LLM can:
 * - Read related files for context
 * - Understand the codebase architecture
 * - Make multi-file changes if needed
 * - Verify the fix makes sense
 */
export async function applyFix(
  bug: Bug,
  config: WhiteroseConfig,
  options: FixOptions
): Promise<FixResult> {
  const { dryRun, branch } = options;
  const projectDir = process.cwd();

  // SECURITY: Validate file path to prevent path traversal
  let safePath: string;
  try {
    safePath = validateFilePath(bug.file, projectDir);
  } catch (error: any) {
    return {
      success: false,
      error: error.message,
    };
  }

  // Verify file exists
  if (!existsSync(safePath)) {
    return {
      success: false,
      error: `File not found: ${bug.file}`,
    };
  }

  // Get file state before fix (for diff)
  const originalContent = readFileSync(safePath, 'utf-8');
  const originalMtime = statSync(safePath).mtime.getTime();

  // Dry run - just show what would be done
  if (dryRun) {
    console.log('\n--- Dry Run: Would run agentic fix ---');
    console.log(`Bug: ${bug.title}`);
    console.log(`File: ${bug.file}:${bug.line}`);
    console.log(`Provider: ${config.provider}`);
    console.log('--- End of dry run ---\n');
    return {
      success: true,
      diff: `[Dry run - no changes made]\nWould fix: ${bug.title}\nIn: ${bug.file}:${bug.line}`,
    };
  }

  // Create branch if needed
  let branchName: string | undefined;
  if (branch) {
    branchName = await createFixBranch(branch, bug);
  }

  // Run the agentic fix
  let agenticResult: AgenticResult;
  try {
    agenticResult = await runAgenticFix(bug, config, projectDir, options.onProgress);
  } catch (error: any) {
    return {
      success: false,
      error: error.message || 'Agentic fix failed',
    };
  }

  // Check if the LLM determined this is a false positive
  if (agenticResult.falsePositive) {
    return {
      success: true, // Operation succeeded, just no fix needed
      falsePositive: true,
      falsePositiveReason: agenticResult.falsePositiveReason,
    };
  }

  // Verify the file was modified
  const newMtime = statSync(safePath).mtime.getTime();
  if (newMtime === originalMtime) {
    // File wasn't modified - check if content changed anyway
    const newContent = readFileSync(safePath, 'utf-8');
    if (newContent === originalContent) {
      return {
        success: false,
        error: 'AI did not modify the file. The fix may require manual intervention.',
      };
    }
  }

  // Generate diff
  const newContent = readFileSync(safePath, 'utf-8');
  const diff = generateSimpleDiff(originalContent, newContent, bug.file);

  // Commit the change
  let commitHash: string | undefined;
  try {
    commitHash = await commitFix(bug);
  } catch {
    // Commit failed but fix was applied
  }

  // Track fix in bug status
  markBugAsFixed(bug, commitHash, projectDir);

  return {
    success: true,
    diff,
    branchName,
    commitHash,
  };
}

interface AgenticResult {
  falsePositive: boolean;
  falsePositiveReason?: string;
}

/**
 * Run the LLM provider in agentic mode to fix the bug.
 * The provider will explore the codebase and fix the bug directly.
 * If it determines the bug is a false positive, it will report that instead.
 */
async function runAgenticFix(
  bug: Bug,
  config: WhiteroseConfig,
  projectDir: string,
  onProgress?: (message: string) => void
): Promise<AgenticResult> {
  const providerCommand = getProviderCommand(config.provider);
  const prompt = buildAgenticFixPrompt(bug);

  // Create an AbortController for reliable timeout handling
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 300000); // 5 minute timeout

  // Run the provider
  let stdout = '';
  let stderr = '';

  try {
    if (config.provider === 'codex') {
      // Codex requires special handling: exec subcommand with stdin and temp file output
      const tempDir = mkdtempSync(join(tmpdir(), 'whiterose-fix-'));
      const outputFile = join(tempDir, 'output.txt');

      try {
        const result = await execa(
          providerCommand,
          [
            'exec',
            '--full-auto', // Allow workspace writes without approval prompts
            '--skip-git-repo-check',
            '-C', projectDir, // Set working directory for codex
            '-o', outputFile,
            '-', // Read prompt from stdin
          ],
          {
            cwd: projectDir,
            input: prompt, // Pass prompt via stdin
            timeout: 300000,
            env: { ...process.env, NO_COLOR: '1' },
            reject: false,
            cancelSignal: controller.signal,
          }
        );

        stderr = result.stderr || '';

        // Read output from file if it exists, otherwise use stdout
        if (existsSync(outputFile)) {
          try {
            stdout = readFileSync(outputFile, 'utf-8');
          } catch {
            stdout = result.stdout || '';
          }
        } else {
          stdout = result.stdout || '';
        }
      } finally {
        // Cleanup temp dir
        try {
          rmSync(tempDir, { recursive: true, force: true });
        } catch {
          // Ignore cleanup errors
        }
      }
    } else if (config.provider === 'claude-code') {
      // Claude Code: pass prompt via stdin for reliability (avoids shell escaping and arg length issues)
      // The --dangerously-skip-permissions flag allows edits without prompts
      // Use --output-format stream-json for real-time progress streaming (requires --verbose)
      const args = ['--dangerously-skip-permissions', '-p'];
      if (onProgress) {
        args.push('--verbose', '--output-format', 'stream-json');
      }

      const subprocess = execa(
        providerCommand,
        args,
        {
          cwd: projectDir,
          input: prompt, // Pass prompt via stdin (Claude reads from stdin when no prompt arg provided)
          timeout: 300000,
          env: { ...process.env, NO_COLOR: '1' },
          reject: false,
          cancelSignal: controller.signal,
        }
      );

      // Stream stdout in real-time if progress callback is provided
      // Only show tool usage events to avoid verbose output
      if (onProgress && subprocess.stdout) {
        let lineBuffer = '';
        subprocess.stdout.on('data', (chunk: Buffer) => {
          const text = chunk.toString();
          lineBuffer += text;
          // Process complete lines (stream-json outputs one JSON object per line)
          const lines = lineBuffer.split('\n');
          lineBuffer = lines.pop() || ''; // Keep incomplete line in buffer
          for (const line of lines) {
            const trimmed = line.trim();
            if (trimmed) {
              try {
                const event = JSON.parse(trimmed);
                // Only show tool_use events - skip all text content to avoid verbose output
                if (event.type === 'assistant' && event.message?.content) {
                  for (const block of event.message.content) {
                    if (block.type === 'tool_use') {
                      // Show tool usage with friendly names
                      const toolName = block.name || 'tool';
                      const friendlyNames: Record<string, string> = {
                        'Read': 'Reading file',
                        'Edit': 'Editing file',
                        'Write': 'Writing file',
                        'Bash': 'Running command',
                        'Glob': 'Searching files',
                        'Grep': 'Searching content',
                        'Task': 'Running task',
                      };
                      const displayName = friendlyNames[toolName] || `Using ${toolName}`;
                      onProgress(`${displayName}...`);
                    }
                  }
                }
              } catch {
                // Silently ignore non-JSON lines - don't show raw output
              }
            }
          }
        });
      }

      const result = await subprocess;
      stdout = result.stdout || '';
      stderr = result.stderr || '';
    } else if (config.provider === 'gemini') {
      // Gemini CLI: run in prompt mode, it will use tools automatically
      // Pass prompt as positional argument (Gemini may not support stdin)
      const result = await execa(providerCommand, ['-p', prompt], {
        cwd: projectDir,
        timeout: 300000,
        env: { ...process.env, NO_COLOR: '1' },
        reject: false,
        stdin: 'ignore', // Prevent stdin hangs
        cancelSignal: controller.signal,
      });
      stdout = result.stdout || '';
      stderr = result.stderr || '';
    } else if (config.provider === 'aider') {
      // Aider: pass the message and file
      // Aider doesn't support stdin for prompt, use --message flag
      const result = await execa(providerCommand, ['--message', prompt, bug.file], {
        cwd: projectDir,
        timeout: 300000,
        env: { ...process.env, NO_COLOR: '1' },
        reject: false,
        stdin: 'ignore', // Prevent stdin hangs
        cancelSignal: controller.signal,
      });
      stdout = result.stdout || '';
      stderr = result.stderr || '';
    } else {
      // Default: pass prompt as argument with -p flag, ignore stdin to prevent hangs
      const result = await execa(providerCommand, ['-p', prompt], {
        cwd: projectDir,
        timeout: 300000,
        env: { ...process.env, NO_COLOR: '1' },
        reject: false,
        stdin: 'ignore', // Prevent stdin hangs
        cancelSignal: controller.signal,
      });
      stdout = result.stdout || '';
      stderr = result.stderr || '';
    }
  } finally {
    clearTimeout(timeoutId);
  }

  // Check for known error patterns (only for actual ENOENT errors, not content)
  if (stderr) {
    const lowerStderr = stderr.toLowerCase();
    // Only throw if it's actually an ENOENT error from execa, not from LLM output
    if (lowerStderr.includes('enoent') && lowerStderr.includes('spawn')) {
      throw new Error(`Provider ${config.provider} not found. Is it installed?`);
    }
    if (lowerStderr.includes('permission denied') && lowerStderr.includes('spawn')) {
      throw new Error('Permission denied. Check provider configuration.');
    }
  }

  // Check if LLM reported this as a false positive
  const output = stdout;
  const falsePositiveMatch = output.match(/FALSE_POSITIVE:\s*(.+?)(?:\n|$)/i);
  if (falsePositiveMatch) {
    return {
      falsePositive: true,
      falsePositiveReason: falsePositiveMatch[1].trim(),
    };
  }

  // Also check for the structured marker
  if (output.includes('###FALSE_POSITIVE###')) {
    const reasonMatch = output.match(/###FALSE_POSITIVE###\s*(.+?)(?:###|$)/s);
    return {
      falsePositive: true,
      falsePositiveReason: reasonMatch ? reasonMatch[1].trim() : 'Bug was determined to be a false positive after code analysis.',
    };
  }

  return { falsePositive: false };
}

/**
 * Build a prompt for agentic bug fixing.
 * This prompt instructs the AI to explore and fix, not just return code.
 * It also instructs the AI to report if the bug is a false positive.
 */
function buildAgenticFixPrompt(bug: Bug): string {
  const evidenceSection = bug.evidence.length > 0
    ? `\nEVIDENCE:\n${bug.evidence.map((e) => `- ${e}`).join('\n')}`
    : '';

  const codePathSection = bug.codePath.length > 0
    ? `\nCODE PATH:\n${bug.codePath.map((s) => `${s.step}. ${s.file}:${s.line} - ${s.explanation}`).join('\n')}`
    : '';

  return `Analyze and fix this reported bug.

BUG DETAILS:
- ID: ${bug.id}
- Title: ${bug.title}
- File: ${bug.file}
- Line: ${bug.line}${bug.endLine ? `-${bug.endLine}` : ''}
- Category: ${bug.category}
- Severity: ${bug.severity}

DESCRIPTION:
${bug.description}
${evidenceSection}
${codePathSection}

INSTRUCTIONS:
1. Read the file ${bug.file} to understand the context
2. Read any related files if needed to understand the full picture
3. CRITICALLY VERIFY the bug is real:
   - Check for early returns or guard clauses that make the buggy line unreachable
   - Check for validation/sanitization upstream that prevents the issue
   - Check if framework protections make this safe
   - If the bug is NOT real, report it as a false positive (see below)
4. If the bug IS real, fix it by editing the file directly
5. Make minimal changes - only fix the identified bug
6. Do not refactor or improve other code
7. Preserve existing code style and formatting

FALSE POSITIVE DETECTION:
If after analysis you determine this is NOT a real bug, output this marker instead of fixing:
###FALSE_POSITIVE###
Reason: [Brief explanation of why this is a false positive]
###

Common false positive patterns:
- Early return: \`if (arr.length === 0) return;\` makes later \`arr[0]\` SAFE
- Guard clause: \`if (!user) throw Error();\` makes later \`user.name\` SAFE
- Upstream validation that the scanner missed
- Framework auto-sanitization (ORM, templating engine, etc.)

If it's a real bug, fix it. If it's a false positive, report it with the marker above.`;
}

/**
 * Generate a simple unified diff between two strings.
 */
function generateSimpleDiff(original: string, modified: string, filename: string): string {
  const origLines = original.split('\n');
  const modLines = modified.split('\n');

  const diff: string[] = [
    `--- a/${filename}`,
    `+++ b/${filename}`,
  ];

  let inHunk = false;
  let hunkStart = -1;
  let hunkLines: string[] = [];

  const flushHunk = () => {
    if (hunkLines.length > 0) {
      diff.push(`@@ -${hunkStart + 1} @@`);
      diff.push(...hunkLines);
      hunkLines = [];
    }
    inHunk = false;
  };

  const maxLen = Math.max(origLines.length, modLines.length);

  for (let i = 0; i < maxLen; i++) {
    const origLine = origLines[i];
    const modLine = modLines[i];

    if (origLine === modLine) {
      if (inHunk) {
        // Add context line
        hunkLines.push(` ${origLine || ''}`);
        // End hunk after 3 context lines
        if (hunkLines.filter(l => l.startsWith(' ')).length >= 3) {
          flushHunk();
        }
      }
    } else {
      if (!inHunk) {
        inHunk = true;
        hunkStart = i;
        // Add leading context
        for (let j = Math.max(0, i - 3); j < i; j++) {
          hunkLines.push(` ${origLines[j] || ''}`);
        }
      }

      if (origLine !== undefined && modLine === undefined) {
        hunkLines.push(`-${origLine}`);
      } else if (origLine === undefined && modLine !== undefined) {
        hunkLines.push(`+${modLine}`);
      } else if (origLine !== modLine) {
        hunkLines.push(`-${origLine}`);
        hunkLines.push(`+${modLine}`);
      }
    }
  }

  flushHunk();

  return diff.length > 2 ? diff.join('\n') : 'No changes detected';
}

export async function batchFix(
  bugs: Bug[],
  config: WhiteroseConfig,
  options: FixOptions
): Promise<Map<string, FixResult>> {
  const results = new Map<string, FixResult>();

  for (const bug of bugs) {
    const result = await applyFix(bug, config, options);
    results.set(bug.id, result);

    // If any fix fails in non-dry-run mode, stop
    if (!result.success && !options.dryRun) {
      break;
    }
  }

  return results;
}
