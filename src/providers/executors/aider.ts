/**
 * Aider Executor - Simple prompt execution
 *
 * This is a "dumb" executor that just runs prompts via Aider CLI.
 * All scanning logic lives in CoreScanner.
 *
 * Note: Aider is primarily designed for editing files, but we use
 * its --message mode for analysis prompts.
 */

import { execa } from 'execa';
import { PromptExecutor, PromptOptions, PromptResult } from '../../core/scanner.js';
import { isProviderAvailable, getProviderCommand } from '../detect.js';

const AIDER_TIMEOUT = 300000; // 5 minutes

export class AiderExecutor implements PromptExecutor {
  name = 'aider';

  async isAvailable(): Promise<boolean> {
    return isProviderAvailable('aider');
  }

  async runPrompt(prompt: string, options: PromptOptions): Promise<PromptResult> {
    const aiderCommand = getProviderCommand('aider');

    try {
      const { stdout, stderr } = await execa(
        aiderCommand,
        [
          '--message', prompt,
          '--no-auto-commits',
          '--yes', // Auto-confirm
        ],
        {
          cwd: options.cwd,
          timeout: options.timeout || AIDER_TIMEOUT,
          env: {
            ...process.env,
            NO_COLOR: '1',
          },
          reject: false,
        }
      );

      // Check for API errors in stderr before returning
      if (stderr) {
        // Rate limit errors (aider uses OpenAI/Anthropic/etc APIs)
        if (stderr.includes('429') || stderr.includes('rate limit') || stderr.includes('RateLimitError')) {
          throw new Error('Aider API rate limit reached. Try again later.');
        }
        // Authentication errors
        if (stderr.includes('401') || stderr.includes('AuthenticationError') || stderr.includes('invalid api key')) {
          throw new Error('Aider API authentication failed. Check your API key.');
        }
        // Credit/billing errors
        if (stderr.includes('402') || stderr.includes('insufficient') || stderr.includes('billing')) {
          throw new Error('Aider API billing error. Check your account credits.');
        }
        // Generic errors that indicate complete failure
        if ((stderr.includes('Error') || stderr.includes('error')) && !stdout) {
          throw new Error(`Aider error: ${stderr.substring(0, 200)}`);
        }
      }

      return {
        output: stdout || '',
        error: stderr || undefined,
      };
    } catch (error: any) {
      if (error.message?.includes('ENOENT')) {
        throw new Error('Aider not found. Install: pip install aider-chat');
      }
      throw error;
    }
  }
}
