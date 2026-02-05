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

      // Check for API errors in stderr before returning
      if (stderr) {
        // Rate limit errors
        if (stderr.includes('429') || stderr.includes('rate limit') || stderr.includes('quota exceeded')) {
          throw new Error('Gemini API rate limit reached. Try again later.');
        }
        // Authentication errors
        if (stderr.includes('401') || stderr.includes('403') || stderr.includes('unauthorized') || stderr.includes('invalid api key')) {
          throw new Error('Gemini API authentication failed. Check your API key.');
        }
        // Generic errors that indicate complete failure
        if ((stderr.includes('Error') || stderr.includes('error')) && !stdout) {
          throw new Error(`Gemini error: ${stderr.substring(0, 200)}`);
        }
      }

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
