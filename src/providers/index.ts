import { LLMProvider, ProviderType } from '../types.js';
import { ClaudeCodeProvider } from './adapters/claude-code.js';
import { AiderProvider } from './adapters/aider.js';
import { CodexProvider } from './adapters/codex.js';
import { OllamaProvider } from './adapters/ollama.js';
import { GeminiProvider } from './adapters/gemini.js';
// OpenAI API provider kept for v2 API-based access
// import { OpenAIProvider } from './adapters/openai.js';

// ═══════════════════════════════════════════════════════════════
// NEW ARCHITECTURE (LSP-compliant)
// ═══════════════════════════════════════════════════════════════
// Use CoreScanner + PromptExecutor instead of LLMProvider.analyze()
// This ensures ALL providers get the same 19-pass scanning logic.
//
// Example:
//   import { CoreScanner } from '../core/scanner.js';
//   import { getExecutor } from './executors/index.js';
//
//   const executor = getExecutor('claude-code');
//   const scanner = new CoreScanner(executor);
//   const bugs = await scanner.scan({ files, understanding, staticResults });
//
// The old LLMProvider interface below is kept for backward compatibility.
// ═══════════════════════════════════════════════════════════════
export { getExecutor, getAvailableExecutors } from './executors/index.js';
export type { PromptExecutor, PromptOptions, PromptResult } from '../core/scanner.js';

const providers: Record<ProviderType, () => LLMProvider> = {
  'claude-code': () => new ClaudeCodeProvider(),
  aider: () => new AiderProvider(),
  codex: () => new CodexProvider(), // OpenAI Codex CLI
  opencode: () => {
    throw new Error('OpenCode provider not yet implemented');
  },
  ollama: () => new OllamaProvider(), // Local LLMs via Ollama
  gemini: () => new GeminiProvider(), // Google Gemini CLI
};

/**
 * @deprecated Use getExecutor() + CoreScanner instead for LSP-compliant architecture.
 * This function returns the old LLMProvider interface which has scanning logic
 * baked into each provider (violates LSP).
 */
export async function getProvider(name: ProviderType): Promise<LLMProvider> {
  const factory = providers[name];
  if (!factory) {
    throw new Error(`Unknown provider: ${name}`);
  }

  const provider = factory();

  // Check if provider is available
  const available = await provider.isAvailable();
  if (!available) {
    throw new Error(`Provider ${name} is not available. Make sure it's installed and configured.`);
  }

  return provider;
}

export { ClaudeCodeProvider, AiderProvider, CodexProvider, OllamaProvider, GeminiProvider };
