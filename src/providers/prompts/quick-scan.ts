/**
 * Quick Scan Prompt - Single file analysis for pre-commit hooks
 *
 * Uses Chain-of-Thought methodology for reliable bug detection.
 *
 * Input: File contents provided directly
 * Output: Single JSON response with bugs array
 * Speed: Fast (single API call, no exploration)
 */

import {
  BUG_CATEGORIES_PROMPT,
  SEVERITY_DEFINITIONS_PROMPT,
  JSON_OUTPUT_INSTRUCTION,
  TYPESCRIPT_WARNING,
} from './constants.js';
import { getRelevantPatterns } from './cwe-patterns.js';

export interface QuickScanContext {
  filePath: string;
  content: string;
  projectType: string;
  framework: string;
  language: string;
  staticFindings?: Array<{ line: number; tool: string; message: string }>;
}

export function buildQuickScanPrompt(ctx: QuickScanContext): string {
  // Get relevant CWE patterns
  const patterns = getRelevantPatterns(ctx.projectType, ctx.language);
  const patternsSection = patterns.length > 0
    ? `\nKNOWN VULNERABILITY PATTERNS TO CHECK:\n${patterns.slice(0, 5).map(p => `- ${p.id}: ${p.name} - ${p.codePatterns[0]}`).join('\n')}\n`
    : '';

  // Format static analysis findings if present
  const staticSection = ctx.staticFindings && ctx.staticFindings.length > 0
    ? `\nSTATIC ANALYSIS FINDINGS TO INVESTIGATE:\n${ctx.staticFindings.map(f => `- Line ${f.line} [${f.tool}]: ${f.message}`).join('\n')}\n`
    : '';

  return `You are whiterose, an expert bug hunter with a 98% precision rate. Find ACTUAL BUGS in this file - not potential issues, not code smells, not suggestions. Only report code that IS WRONG.

${JSON_OUTPUT_INSTRUCTION}

PROJECT CONTEXT:
- Type: ${ctx.projectType}
- Framework: ${ctx.framework || 'unknown'}
- Language: ${ctx.language || 'unknown'}

FILE: ${ctx.filePath}
${patternsSection}${staticSection}
CODE:
\`\`\`
${ctx.content.slice(0, 50000)}
\`\`\`

# CHAIN-OF-THOUGHT ANALYSIS

For EACH function in this file:

**STEP 1: UNDERSTAND** - What does it do? What are inputs/outputs?
**STEP 2: TRACE INPUTS** - Where do they come from? Are they validated?
**STEP 3: ANALYZE OPERATIONS** - What if input is null? Empty? Malicious?
**STEP 4: CHECK ERROR PATHS** - Are errors handled? Resources cleaned up?
**STEP 5: VERIFY** - Is there a guard I missed? Framework handling?
**STEP 6: PROVE** - Can I construct a triggering input? Write the fix?

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

# REPORTING GUIDELINES

Report issues if they match ANY of these:
- Looks like a security vulnerability
- Risky pattern that could cause bugs
- Missing error handling
- Potential null/undefined access
- Suspicious logic or conditions
- Hardcoded values that might be secrets

Use kind="bug" for confirmed issues, kind="smell" for risky patterns.

# suggestedFix IS OPTIONAL
- Include a fix if you can, but it's not required
- Focus on finding issues first, fixes second

# OUTPUT RULES
- Output MUST be valid JSON wrapped in <json></json> tags
- Empty array only if truly nothing suspicious: {"bugs": []}
- Thoroughness over precision - report potential issues

Analyze the file. Report ALL suspicious patterns, not just confirmed exploits.`;
}
