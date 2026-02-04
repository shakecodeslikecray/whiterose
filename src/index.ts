// whiterose - AI-powered bug hunter
// "I've been staring at your code for a long time."

export * from './types.js';
export { loadConfig, loadUnderstanding, saveConfig } from './core/config.js';
export { scanCodebase, getChangedFiles, getDependentFiles } from './core/scanner/index.js';
export { getExecutor, getAvailableExecutors } from './providers/index.js';
export { CoreScanner } from './core/scanner.js';
export type { PromptExecutor, PromptOptions, PromptResult } from './core/scanner.js';
export { detectProvider, isProviderAvailable } from './providers/detect.js';
export { runStaticAnalysis } from './analysis/static.js';
export { outputSarif } from './output/sarif.js';
export { outputMarkdown } from './output/markdown.js';
export {
  generateIntentDocument,
  parseIntentDocument,
  mergeIntentWithUnderstanding,
} from './core/contracts/intent.js';
export { applyFix, batchFix } from './core/fixer.js';
export * from './core/git.js';
export * from './core/dependencies.js';
export * from './core/monorepo.js';
export { analyzeCrossFile, getCommandEffectsSummary } from './core/cross-file-analyzer.js';
export { analyzeContracts, getContractSummary } from './core/contract-analyzer.js';
export { analyzeSmells, getSmellsSummary } from './core/smells-analyzer.js';
