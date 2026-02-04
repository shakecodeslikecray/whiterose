/**
 * Provider Exports - LSP-compliant Architecture
 *
 * All providers are now "dumb prompt executors" via PromptExecutor interface.
 * Scanning logic lives in CoreScanner, not in providers.
 *
 * Usage:
 *   import { getExecutor } from './providers/index.js';
 *   import { CoreScanner } from './core/scanner.js';
 *
 *   const executor = getExecutor('claude-code');
 *   const scanner = new CoreScanner(executor);
 *   const bugs = await scanner.scan({ files, understanding, staticResults });
 */

export { getExecutor, getAvailableExecutors } from './executors/index.js';
export type { PromptExecutor, PromptOptions, PromptResult } from '../core/scanner.js';
