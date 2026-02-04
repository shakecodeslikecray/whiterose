/**
 * Gemini Executor - Simple prompt execution
 *
 * This is a "dumb" executor that just runs prompts via Gemini CLI.
 * All scanning logic lives in CoreScanner.
 */

import { execa } from 'execa';
import { PromptExecutor, PromptOptions, PromptResult } from '../../core/scanner.js';
import { isProviderAvailable, getProviderCommand } from '../detect.js';

const GEMINI_TIMEOUT = 300000; // 5 minutes

export class GeminiExecutor implements PromptExecutor {
  name = 'gemini';

  async isAvailable(): Promise<boolean> {
    return isProviderAvailable('gemini');
  }

  async runPrompt(prompt: string, options: PromptOptions): Promise<PromptResult> {
    const geminiCommand = getProviderCommand('gemini');

    try {
      const { stdout, stderr } = await execa(
        geminiCommand,
        ['-p', prompt],
        {
          cwd: options.cwd,
          timeout: options.timeout || GEMINI_TIMEOUT,
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
        throw new Error('Gemini CLI not found. Install: npm install -g @google/gemini-cli');
      }
      throw error;
    }
  }
}
