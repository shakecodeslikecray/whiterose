/**
 * Codex Executor - Simple prompt execution
 *
 * This is a "dumb" executor that just runs prompts via Codex CLI.
 * All scanning logic lives in CoreScanner.
 */

import { execa } from 'execa';
import { mkdtempSync, rmSync, existsSync, readFileSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';
import { PromptExecutor, PromptOptions, PromptResult } from '../../core/scanner.js';
import { isProviderAvailable, getProviderCommand } from '../detect.js';

const CODEX_TIMEOUT = 300000; // 5 minutes

export class CodexExecutor implements PromptExecutor {
  name = 'codex';

  async isAvailable(): Promise<boolean> {
    return isProviderAvailable('codex');
  }

  async runPrompt(prompt: string, options: PromptOptions): Promise<PromptResult> {
    const codexCommand = getProviderCommand('codex');
    const tempDir = mkdtempSync(join(tmpdir(), 'whiterose-codex-'));
    const outputFile = join(tempDir, 'output.txt');

    try {
      const { stdout, stderr } = await execa(
        codexCommand,
        [
          'exec',
          '--skip-git-repo-check',
          '-o', outputFile,
          '-', // Read from stdin
        ],
        {
          cwd: options.cwd,
          input: prompt,
          timeout: options.timeout || CODEX_TIMEOUT,
          env: {
            ...process.env,
            NO_COLOR: '1',
          },
          reject: false,
        }
      );

      // Check for API errors in stderr before processing output
      if (stderr) {
        // Rate limit / usage limit errors
        if (stderr.includes('429') || stderr.includes('usage_limit') || stderr.includes('rate limit')) {
          throw new Error('Codex API rate limit reached. Try again later or upgrade your plan.');
        }
        // Authentication errors
        if (stderr.includes('401') || stderr.includes('unauthorized') || stderr.includes('authentication')) {
          throw new Error('Codex API authentication failed. Check your API key.');
        }
        // Generic API errors
        if (stderr.includes('ERROR:') || stderr.includes('error=http')) {
          // Extract the error message
          const errorMatch = stderr.match(/ERROR:\s*(.+?)(?:\n|$)/i) || stderr.match(/error=(.+?)(?:\n|$)/);
          const errorMsg = errorMatch ? errorMatch[1].trim() : stderr.substring(0, 200);
          throw new Error(`Codex API error: ${errorMsg}`);
        }
      }

      // Try to read from output file first
      let output = stdout || '';
      if (existsSync(outputFile)) {
        try {
          output = readFileSync(outputFile, 'utf-8');
        } catch {
          // Fall back to stdout
        }
      }

      return {
        output,
        error: stderr || undefined,
      };
    } catch (error: any) {
      if (error.message?.includes('ENOENT')) {
        throw new Error('Codex not found. Install: npm install -g @openai/codex');
      }
      throw error;
    } finally {
      // Cleanup
      try {
        rmSync(tempDir, { recursive: true, force: true });
      } catch {
        // Ignore cleanup errors
      }
    }
  }
}
