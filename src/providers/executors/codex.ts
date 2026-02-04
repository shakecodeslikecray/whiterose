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
