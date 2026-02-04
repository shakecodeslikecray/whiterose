/**
 * Whiterose Prompts - Barrel Export
 *
 * All prompt builders and constants are exported from here.
 */

// Constants
export {
  BUG_CATEGORIES_PROMPT,
  SEVERITY_DEFINITIONS_PROMPT,
  PROJECT_TYPES_PROMPT,
  FEATURE_PRIORITY_PROMPT,
  JSON_OUTPUT_INSTRUCTION,
  TYPESCRIPT_WARNING,
  CHAIN_OF_THOUGHT_METHODOLOGY,
  CATEGORY_SPECIFIC_INSTRUCTIONS,
  getCategoryInstructions,
  SLAB_THRESHOLDS,
  detectSlab,
  getScopeInstructions,
  type Slab,
} from './constants.js';

// CWE Patterns (RAG)
export {
  CWE_PATTERNS,
  getRelevantPatterns,
  getPatternsForCategory,
  formatPatternsForPrompt,
  getCategoryFocusedPatterns,
  type CWEPattern,
} from './cwe-patterns.js';

// Prompt Builders
export {
  buildQuickScanPrompt,
  type QuickScanContext,
} from './quick-scan.js';

export {
  buildThoroughScanPrompt,
  buildCategorySpecificPrompt,
  type ThoroughScanContext,
  type StaticAnalysisFinding,
} from './thorough-scan.js';

export {
  buildUnderstandingPrompt,
  type UnderstandingContext,
} from './understanding.js';

export {
  buildAdversarialPrompt,
  type AdversarialContext,
} from './adversarial.js';

export {
  buildOptimizedQuickScanPrompt,
  type OptimizedQuickScanContext,
} from './optimized-quick-scan.js';

export {
  buildAgenticScanPrompt,
  buildCategoryFocusedPrompt,
  type AgenticScanContext,
} from './agentic-scan.js';

export {
  buildPassPrompt,
  buildAdversarialPassPrompt,
  buildHumanReadableSummaryPrompt,
  getPassOrderForProject,
  SEVERITY_THRESHOLDS,
  type PassPromptContext,
} from './multipass-prompts.js';

export {
  buildFlowAnalysisPrompt,
  buildAttackChainPrompt,
  buildFlowValidationPrompt,
  getFullAnalysisPipeline,
  type FlowPromptContext,
} from './flow-analysis-prompts.js';

// Smart Scanner (10x faster approach)
export {
  buildTriagePrompt,
  buildValidationPrompt,
  buildDeepDivePrompt,
  selectDeepDives,
  mergeAndDedupe,
  type TriageResult,
  type SuspiciousArea,
  type ValidationResult,
  type DeepDiveResult,
  type SmartScanResult,
} from '../../core/smart-scanner.js';
