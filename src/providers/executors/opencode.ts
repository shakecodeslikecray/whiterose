/**
 * OpenCode Executor - Simple prompt execution
 *
 * This is a "dumb" executor that just runs prompts via OpenCode CLI.
 * All scanning logic lives in CoreScanner.
 */

import { execa } from 'execa';
import { PromptExecutor, PromptOptions, PromptResult } from '../../core/scanner.js';
import { isProviderAvailable, getProviderCommand } from '../detect.js';

const OPENCODE_TIMEOUT = 300000; // 5 minutes

export class OpenCodeExecutor implements PromptExecutor {
  name = 'opencode';

  async isAvailable(): Promise<boolean> {
    return isProviderAvailable('opencode');
  }

  async runPrompt(prompt: string, options: PromptOptions): Promise<PromptResult> {
    const command = getProviderCommand('opencode');

    try {
      const { stdout, stderr } = await execa(
        command,
        ['run', prompt],
        {
          cwd: options.cwd,
          timeout: options.timeout || OPENCODE_TIMEOUT,
          env: {
            ...process.env,
            NO_COLOR: '1',
          },
          reject: false,
          stdin: 'ignore',
        }
      );

      // Check for API errors in stderr before returning
      if (stderr) {
        // Rate limit errors
        if (stderr.includes('429') || stderr.includes('rate limit') || stderr.includes('quota exceeded')) {
          throw new Error('OpenCode API rate limit reached. Try again later.');
        }
        // Authentication errors
        if (stderr.includes('401') || stderr.includes('403') || stderr.includes('unauthorized') || stderr.includes('invalid api key')) {
          throw new Error('OpenCode API authentication failed. Check your API key.');
        }
        // Generic errors that indicate complete failure
        if ((stderr.includes('Error') || stderr.includes('error')) && !stdout) {
          throw new Error(`OpenCode error: ${stderr.substring(0, 200)}`);
        }
      }

      return {
        output: stdout || '',
        error: stderr || undefined,
      };
    } catch (error: any) {
      if (error.message?.includes('ENOENT')) {
        throw new Error('OpenCode CLI not found. Install: curl -fsSL https://opencode.ai/install | bash');
      }
      throw error;
    }
  }
}
