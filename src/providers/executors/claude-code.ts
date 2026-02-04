/**
 * Claude Code Executor - Simple prompt execution
 *
 * This is a "dumb" executor that just runs prompts via Claude CLI.
 * All scanning logic lives in CoreScanner.
 */

import { execa } from 'execa';
import { PromptExecutor, PromptOptions, PromptResult } from '../../core/scanner.js';
import { isProviderAvailable, getProviderCommand } from '../detect.js';

const CLAUDE_TIMEOUT = 300000; // 5 minutes

export class ClaudeCodeExecutor implements PromptExecutor {
  name = 'claude-code';

  async isAvailable(): Promise<boolean> {
    return isProviderAvailable('claude-code');
  }

  async runPrompt(prompt: string, options: PromptOptions): Promise<PromptResult> {
    const claudeCommand = getProviderCommand('claude-code');

    try {
      const { stdout, stderr } = await execa(
        claudeCommand,
        [
          '-p', prompt,
          '--dangerously-skip-permissions', // Allow file reads without prompts
        ],
        {
          cwd: options.cwd,
          timeout: options.timeout || CLAUDE_TIMEOUT,
          env: {
            ...process.env,
            NO_COLOR: '1',
          },
          reject: false,
        }
      );

      return {
        output: stdout || '',
        error: stderr || undefined,
      };
    } catch (error: any) {
      if (error.message?.includes('ENOENT')) {
        throw new Error('Claude Code not found. Install: npm install -g @anthropic-ai/claude-code');
      }
      throw error;
    }
  }
}
