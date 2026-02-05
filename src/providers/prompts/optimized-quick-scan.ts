/**
 * Optimized Quick Scan Prompt - AST-based function analysis
 *
 * Uses the optimized context from AST analysis for precise,
 * function-level bug detection.
 *
 * Input: Optimized context with extracted functions
 * Output: Single JSON response with bugs array
 * Speed: Fast (focused analysis, better cache hits)
 */

import {
  BUG_CATEGORIES_PROMPT,
  SEVERITY_DEFINITIONS_PROMPT,
  JSON_OUTPUT_INSTRUCTION,
  TYPESCRIPT_WARNING,
  CHAIN_OF_THOUGHT_METHODOLOGY,
} from './constants.js';
import { getRelevantPatterns } from './cwe-patterns.js';

export interface OptimizedQuickScanContext {
  filePath: string;
  projectType: string;
  framework: string;
  language: string;
  // From AST analysis
  changedFunctions: Array<{
    name: string;
    type: string;
    code: string;
    signature?: string;
    startLine: number;
    endLine: number;
  }>;
  supportingContext: Array<{
    name: string;
    type: string;
    code: string;
    startLine: number;
    endLine: number;
  }>;
  typeDefinitions: string[];
  imports: string[];
  // Static analysis findings for this file
  staticFindings?: Array<{ line: number; tool: string; message: string }>;
  // Estimated tokens for context budget awareness
  estimatedTokens: number;
}

export function buildOptimizedQuickScanPrompt(ctx: OptimizedQuickScanContext): string {
  // Get relevant CWE patterns
  const patterns = getRelevantPatterns(ctx.projectType, ctx.language);
  const patternsSection = patterns.length > 0
    ? `\nKNOWN VULNERABILITY PATTERNS TO CHECK:\n${patterns.slice(0, 5).map(p => `- ${p.id}: ${p.name} - ${p.codePatterns[0]}`).join('\n')}\n`
    : '';

  // Format static analysis findings if present
  const staticSection = ctx.staticFindings && ctx.staticFindings.length > 0
    ? `\nSTATIC ANALYSIS FINDINGS TO INVESTIGATE:\n${ctx.staticFindings.map(f => `- Line ${f.line} [${f.tool}]: ${f.message}`).join('\n')}\n`
    : '';

  // Format the changed functions (primary analysis targets)
  const changedFunctionsSection = ctx.changedFunctions.map(fn =>
    `### ${fn.type.toUpperCase()}: ${fn.name} (lines ${fn.startLine}-${fn.endLine})
${fn.signature ? `Signature: ${fn.signature}\n` : ''}\`\`\`
${fn.code}
\`\`\``
  ).join('\n\n');

  // Format supporting context (called functions, related code)
  const supportingSection = ctx.supportingContext.length > 0
    ? `\n# SUPPORTING CONTEXT (referenced by changed functions)\n${ctx.supportingContext.map(fn =>
      `### ${fn.type}: ${fn.name} (lines ${fn.startLine}-${fn.endLine})
\`\`\`
${fn.code}
\`\`\``
    ).join('\n\n')}\n`
    : '';

  // Format type definitions
  const typesSection = ctx.typeDefinitions.length > 0
    ? `\n# TYPE DEFINITIONS\n\`\`\`typescript\n${ctx.typeDefinitions.join('\n')}\n\`\`\`\n`
    : '';

  // Format imports
  const importsSection = ctx.imports.length > 0
    ? `# IMPORTS\n\`\`\`typescript\n${ctx.imports.join('\n')}\n\`\`\`\n`
    : '';

  return `You are whiterose, an expert bug hunter with a 98% precision rate. Analyze ONLY the CHANGED FUNCTIONS below for ACTUAL BUGS - not potential issues, not code smells, not suggestions. Only report code that IS WRONG.

${JSON_OUTPUT_INSTRUCTION}

PROJECT CONTEXT:
- Type: ${ctx.projectType}
- Framework: ${ctx.framework || 'unknown'}
- Language: ${ctx.language || 'unknown'}

FILE: ${ctx.filePath}
${patternsSection}${staticSection}
${importsSection}
${typesSection}
# FUNCTIONS TO ANALYZE (changed/added)

${changedFunctionsSection}
${supportingSection}
# CHAIN-OF-THOUGHT ANALYSIS

${CHAIN_OF_THOUGHT_METHODOLOGY}

# WHAT IS A BUG (report these)
- Code that WILL crash/fail in realistic scenarios
- Edge cases users WILL hit (empty string, null, bad input)
- Logic that produces WRONG results
- Security flaws exploitable with realistic inputs
- Missing null checks where null WILL occur in actual usage
- Resource leaks in error paths

# WHAT IS NOT A BUG (do NOT report)
- Code that "could be improved" but works correctly
- Theoretical issues requiring attacker manipulation
- Missing validation that exists elsewhere in call chain
- TypeScript type assertions (intentional)
- Code patterns you dislike
- Performance concerns (unless they cause failures)

# CRITICAL RULES
${TYPESCRIPT_WARNING}

1. **PRECISION OVER RECALL** - Only 95%+ confident bugs. Not sure? Don't report.
2. **EVERY BUG MUST HAVE A FIX** - No fix = not a confirmed bug.
3. **PROVE IT** - "This WILL fail because X" not "This could be a problem"
4. **TRACE THE FLOW** - Show exact path from input to failure

${BUG_CATEGORIES_PROMPT}

${SEVERITY_DEFINITIONS_PROMPT}

# OUTPUT FORMAT

Respond with ONLY this JSON wrapped in <json></json> tags:

<json>
{
  "bugs": [
    {
      "line": 42,
      "endLine": 45,
      "title": "Null dereference in getUserById",
      "description": "user.profile is accessed but findOne returns null when user not found. This WILL crash because the function is called from the login flow where invalid userIds are common.",
      "category": "null-reference",
      "severity": "high",
      "confidence": "high",
      "triggerInput": "getUserById('nonexistent-id')",
      "codePath": [
        {"line": 40, "code": "const user = await db.users.findOne({ id })", "explanation": "Returns null when not found"},
        {"line": 42, "code": "return user.profile.name", "explanation": "Crashes if user is null"}
      ],
      "evidence": [
        "Line 40: findOne returns null when no match (verified in db docs)",
        "Line 42: No null check before accessing user.profile",
        "Called from login flow where invalid IDs occur"
      ],
      "suggestedFix": "if (!user) return null;\\nreturn user.profile.name;"
    }
  ]
}
</json>

# REQUIREMENTS CHECKLIST

Before including ANY bug, verify ALL:
[ ] Can you write exact triggering input? (triggerInput)
[ ] Can you show the data flow? (codePath with line numbers)
[ ] Have you verified no guards prevent it? (evidence)
[ ] Can you write the exact fix code? (suggestedFix)
[ ] Is this a real scenario, not theoretical?

If ANY is NO, do not include the bug.

# suggestedFix IS OPTIONAL
- Include a fix if you can, but it's not required
- Focus on finding issues first, fixes second

# OUTPUT RULES
- Output MUST be valid JSON wrapped in <json></json> tags
- Empty array only if truly nothing suspicious: {"bugs": []}
- Thoroughness over precision - report potential issues
- Use kind="bug" for confirmed issues, kind="smell" for risky patterns
- ONLY analyze the CHANGED FUNCTIONS above

Analyze the changed functions. Report ALL suspicious patterns, not just confirmed exploits.`;
}
