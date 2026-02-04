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
