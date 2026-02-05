/**
 * Provider Executors - Simple prompt execution implementations
 *
 * All executors implement the PromptExecutor interface.
 * No scanning logic - just run prompts and return results.
 */

import { PromptExecutor } from '../../core/scanner.js';
import { ClaudeCodeExecutor } from './claude-code.js';
import { CodexExecutor } from './codex.js';
import { GeminiExecutor } from './gemini.js';
import { AiderExecutor } from './aider.js';
import { OllamaExecutor } from './ollama.js';
import { OpenCodeExecutor } from './opencode.js';
import { ProviderType } from '../../types.js';

const executors: Record<string, () => PromptExecutor> = {
  'claude-code': () => new ClaudeCodeExecutor(),
  'codex': () => new CodexExecutor(),
  'gemini': () => new GeminiExecutor(),
  'aider': () => new AiderExecutor(),
  'ollama': () => new OllamaExecutor(),
  'opencode': () => new OpenCodeExecutor(),
};

/**
 * Get a prompt executor by provider name
 */
export function getExecutor(name: ProviderType): PromptExecutor {
  const factory = executors[name];
  if (!factory) {
    throw new Error(`Unknown provider: ${name}. Available: ${Object.keys(executors).join(', ')}`);
  }
  return factory();
}

/**
 * Get all available executors
 */
export async function getAvailableExecutors(): Promise<PromptExecutor[]> {
  const available: PromptExecutor[] = [];

  for (const factory of Object.values(executors)) {
    const executor = factory();
    if (await executor.isAvailable()) {
      available.push(executor);
    }
  }

  return available;
}

export { ClaudeCodeExecutor } from './claude-code.js';
export { CodexExecutor } from './codex.js';
export { GeminiExecutor } from './gemini.js';
export { AiderExecutor } from './aider.js';
export { OllamaExecutor } from './ollama.js';
export { OpenCodeExecutor } from './opencode.js';
