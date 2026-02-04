/**
 * Adversarial Validation Prompt - Aggressive false positive detection
 *
 * This prompt acts as a "defender" trying hard to DISPROVE bug reports.
 * Research shows multi-agent debate reduces false positives significantly.
 *
 * Input: Bug report + file content + code path
 * Output: Single JSON with validation result
 * Speed: Fast (single API call)
 */

import { JSON_OUTPUT_INSTRUCTION, TYPESCRIPT_WARNING } from './constants.js';

export interface AdversarialContext {
  file: string;
  line: number;
  endLine?: number;
  title: string;
  description: string;
  category: string;
  severity: string;
  fileContent: string;
  codePath?: Array<{ line: number; code: string; explanation: string }>;
  evidence?: string[];
  suggestedFix?: string;
}

export function buildAdversarialPrompt(ctx: AdversarialContext): string {
  const codePathSection = ctx.codePath && ctx.codePath.length > 0
    ? `\nCLAIMED CODE PATH:\n${ctx.codePath.map(s => `  Line ${s.line}: ${s.code}\n    → ${s.explanation}`).join('\n')}`
    : '';

  const evidenceSection = ctx.evidence && ctx.evidence.length > 0
    ? `\nCLAIMED EVIDENCE:\n${ctx.evidence.map(e => `  - ${e}`).join('\n')}`
    : '';

  return `You are the DEFENDER in an adversarial code review. Your job is to AGGRESSIVELY try to DISPROVE this bug report.

Your reputation depends on catching FALSE POSITIVES. The initial bug hunter claims a 98% precision rate - prove them wrong when you can. Be skeptical. Be thorough. Find any reason to dismiss this bug.

${JSON_OUTPUT_INSTRUCTION}

# REPORTED BUG

**File:** ${ctx.file}:${ctx.line}${ctx.endLine ? `-${ctx.endLine}` : ''}
**Title:** ${ctx.title}
**Category:** ${ctx.category}
**Severity:** ${ctx.severity}

**Description:**
${ctx.description}
${codePathSection}
${evidenceSection}
${ctx.suggestedFix ? `\n**Claimed Fix:** ${ctx.suggestedFix}` : ''}

# CODE CONTEXT

\`\`\`
${ctx.fileContent}
\`\`\`

# YOUR MISSION: FIND REASONS TO DISMISS THIS BUG

Search AGGRESSIVELY for any of these defenses:

## 1. GUARDS & VALIDATION
- Any null/undefined checks BEFORE the buggy line
- Validation in parent functions, middleware, decorators
- Type guards that narrow the type
- Default values that prevent null
- Assertion functions or invariants

## 2. FRAMEWORK PROTECTION
- Framework auto-handling (Express error middleware, React error boundaries)
- ORM/query builder that sanitizes automatically (Prisma, TypeORM)
- Validation libraries (Zod, Joi, Yup) in the request chain
- Sanitization middleware (helmet, express-validator)

## 3. CALL SITE ANALYSIS
- Is the claimed entry point actually reachable?
- Does the function have callers that guarantee valid input?
- Are there preconditions enforced by the API design?
- Is this code only called from safe contexts (internal, server-side)?

## 4. INTENTIONAL DESIGN
- Comments indicating intentional behavior
- Documentation explaining why this is safe
- Test coverage that verifies this behavior
- Design patterns that explain the choice

## 5. CONTROL FLOW & REACHABILITY (CRITICAL!)
- **EARLY RETURNS**: Does the function return BEFORE the buggy line when the bad condition exists?
  - Example: \`if (arr.length === 0) return false;\` makes later \`arr[0]\` UNREACHABLE for empty arrays
  - Example: \`if (!user) return null;\` makes later \`user.name\` UNREACHABLE when user is null
- **THROWS**: Does a throw statement prevent reaching the buggy line?
  - Example: \`if (!data) throw new Error();\` makes later \`data.value\` SAFE
- **GUARD CLAUSES**: Does a guard clause exit the function/block early?
- **TRACE CAREFULLY**: For \`if (x) return;\` the code after is only reached when \`!x\`
- This is the #1 source of FALSE POSITIVES - check THOROUGHLY!

## 6. LOGICAL ERRORS IN THE CLAIM
- Is the claimed code path actually impossible?
- Does the evidence contradict itself?
- Is the triggering input actually invalid/impossible?
- Would the suggested fix break existing functionality?

## 7. ENVIRONMENTAL PROTECTIONS
- Environment variables that change behavior
- Feature flags that disable this path
- Production-only safeguards
- API gateway validation

${TYPESCRIPT_WARNING}
**CRITICAL:** TypeScript types are NOT runtime guards. A variable typed 'string' can still be null/undefined at runtime. DO NOT dismiss bugs based on TypeScript types alone.

# CONFIDENCE LEVELS

- **high**: You found DEFINITIVE proof either way (clear guard code, or clear vulnerable path)
- **medium**: Likely real or fake, but some ambiguity (guard exists but might not cover all cases)
- **low**: Cannot determine without more context (need to trace call stack, check config, etc.)

# OUTPUT FORMAT

If you CANNOT disprove the bug (bug is REAL):
<json>
{
  "survived": true,
  "confidence": "high",
  "counterArguments": [],
  "validationNotes": "Searched aggressively for guards. Checked: 1) No null check before line 42, 2) No validation middleware on this route, 3) Parent function getUserData does not validate either, 4) Database query returns null for missing users. The bug is real - user.profile will throw when user is null.",
  "recommendation": "confirm"
}
</json>

If you SUCCESSFULLY disprove the bug (FALSE POSITIVE):
<json>
{
  "survived": false,
  "confidence": "high",
  "counterArguments": [
    "Line 35 has early return: if (!user) throw new NotFoundError()",
    "Route middleware at src/middleware/auth.ts:42 validates user exists",
    "This endpoint is only reachable via authenticated requests where user is guaranteed"
  ],
  "validationNotes": "Found multiple layers of protection: 1) Guard clause at line 35, 2) Auth middleware guarantees user exists, 3) The claimed code path is impossible because NotFoundError is thrown first.",
  "recommendation": "dismiss"
}
</json>

If UNCERTAIN (needs manual review):
<json>
{
  "survived": true,
  "confidence": "low",
  "counterArguments": [
    "Possible validation in parent function at src/services/user.ts but not visible in context"
  ],
  "validationNotes": "Cannot fully verify. The immediate code has no guards, but UserService.getUser() might validate internally. Would need to trace the full call stack to confirm.",
  "recommendation": "needs-context"
}
</json>

# REQUIREMENTS

- Output MUST be valid JSON wrapped in <json></json> tags
- survived: boolean (true = bug is real, false = bug is disproved)
- confidence: "high" | "medium" | "low"
- recommendation: "confirm" | "dismiss" | "needs-context"
- counterArguments: string[] (reasons bug might be fake, empty if none found)
- validationNotes: Detailed explanation of your analysis

# REMEMBER

1. Be AGGRESSIVE about finding defenses - your job is to reduce false positives
2. But be HONEST - don't dismiss real bugs. Your credibility depends on accuracy.
3. TypeScript types are NOT runtime protection
4. "It would be unusual" is not a defense - find ACTUAL guards or admit the bug is real
5. When in doubt, let the bug survive with confidence: "low"

Analyze thoroughly and output ONLY the JSON.`;
}
