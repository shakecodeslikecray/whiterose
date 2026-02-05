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

    if (process.env.WHITEROSE_DEBUG) {
      console.log('\n[DEBUG] Running Claude Code command:', claudeCommand);
      console.log('[DEBUG] Prompt length:', prompt.length);
      console.log('[DEBUG] CWD:', options.cwd);
      console.log('[DEBUG] First 500 chars of prompt:');
      console.log(prompt.substring(0, 500));
    }

    try {
      const { stdout, stderr } = await execa(
        claudeCommand,
        [
          '-p', prompt,
          '--dangerously-skip-permissions', // Allow file reads without prompts
          '--output-format', 'text', // Ensure non-interactive output
        ],
        {
          cwd: options.cwd,
          timeout: options.timeout || CLAUDE_TIMEOUT,
          env: {
            ...process.env,
            NO_COLOR: '1',
          },
          reject: false,
          stdin: 'ignore', // Prevent waiting for stdin
        }
      );

      // Check for API errors in stderr before returning
      if (stderr) {
        // Rate limit errors
        if (stderr.includes('429') || stderr.includes('rate limit') || stderr.includes('too many requests')) {
          throw new Error('Claude API rate limit reached. Try again later.');
        }
        // Authentication errors
        if (stderr.includes('401') || stderr.includes('unauthorized') || stderr.includes('invalid api key')) {
          throw new Error('Claude API authentication failed. Check your API key.');
        }
        // Credit/billing errors
        if (stderr.includes('402') || stderr.includes('insufficient') || stderr.includes('billing')) {
          throw new Error('Claude API billing error. Check your account credits.');
        }
        // Generic errors that indicate complete failure
        if (stderr.includes('Error:') && !stdout) {
          throw new Error(`Claude Code error: ${stderr.substring(0, 200)}`);
        }
      }

      // Debug: log output and errors
      if (process.env.WHITEROSE_DEBUG) {
        console.log('\n[DEBUG] Claude Code stdout length:', stdout?.length || 0);
        console.log('[DEBUG] Claude Code stderr:', stderr?.substring(0, 300) || '(none)');
        console.log('[DEBUG] First 1000 chars of stdout:');
        console.log(stdout?.substring(0, 1000) || '(empty)');
        console.log('[DEBUG] End response\n');
      }

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
