/**
 * Multi-Pass Prompts - Laser-focused prompts for each bug category
 *
 * Each prompt is designed to:
 * 1. Focus on ONE category only - no distractions
 * 2. Provide specific search patterns and grep queries
 * 3. Give clear methodology for finding bugs
 * 4. Include false positive hints to reduce noise
 * 5. Require exact fix code for confirmation
 */

import { PassConfig } from '../../core/multipass-scanner.js';
import { getCategoryFocusedPatterns } from './cwe-patterns.js';

export interface StaticFinding {
  tool: string;
  file: string;
  line: number;
  message: string;
  severity: string;
}

export interface PassPromptContext {
  pass: PassConfig;
  projectType: string;
  framework: string;
  language: string;
  totalFiles: number;
  entryPoints?: string[];
  staticFindings?: StaticFinding[];
}

/**
 * Build a laser-focused prompt for a single pass
 */
export function buildPassPrompt(ctx: PassPromptContext): string {
  const { pass, projectType, framework, language, totalFiles, entryPoints } = ctx;

  // Get CWE patterns for this category
  const cwePatterns = getCategoryFocusedPatterns(pass.category);

  const entryPointsSection = entryPoints?.length
    ? `
## STARTING POINTS
These files are likely entry points - good places to start tracing data flow:
${entryPoints.map(e => `- ${e}`).join('\n')}
`
    : '';

  // Include static analysis findings if available
  const staticSection = ctx.staticFindings?.length
    ? `
## STATIC ANALYSIS SIGNALS (from tsc/eslint - run BEFORE you)
These issues were found by static analysis tools. Use them as starting points:
${ctx.staticFindings.slice(0, 20).map(f => `- ${f.tool}: ${f.file}:${f.line} - ${f.message}`).join('\n')}
${ctx.staticFindings.length > 20 ? `\n... and ${ctx.staticFindings.length - 20} more` : ''}

IMPORTANT: Static tools already checked control flow, types, and reachability.
If they didn't flag something, it's likely NOT a bug (early returns, guards, etc. are handled).
Focus on SEMANTIC issues static tools can't catch (logic errors, business logic, auth bypass).
`
    : '';

  return `You are a security specialist. Your ONLY job is to find ${pass.name.toUpperCase()} bugs.

## YOUR SINGLE MISSION
Find ${pass.description} vulnerabilities in this codebase. IGNORE everything else.

## PROJECT CONTEXT
- Type: ${projectType}
- Framework: ${framework || 'Unknown'}
- Language: ${language}
- Size: ${totalFiles} files
${entryPointsSection}
${staticSection}
## WHAT TO LOOK FOR

${pass.searchPatterns.map(p => `- ${p}`).join('\n')}

## SEARCH STRATEGY

Use these grep patterns to find potential issues:
${pass.grepPatterns.map(p => `\`${p}\``).join('\n')}

## METHODOLOGY

${pass.methodology}

## FALSE POSITIVE HINTS

These are often NOT bugs - verify before reporting:
${pass.falsePositiveHints.map(h => `- ${h}`).join('\n')}

${cwePatterns ? `## KNOWN VULNERABILITY PATTERNS\n${cwePatterns}` : ''}

## CRITICAL RULES

1. **ONLY ${pass.name.toUpperCase()} BUGS** - Ignore all other categories
2. **MUST HAVE FIX** - No fix = not confirmed = don't report
3. **TRACE THE DATA** - Follow user input to the vulnerable sink
4. **CHECK GUARDS** - Verify there's no validation you missed
5. **BE SPECIFIC** - Exact file, line, and triggering input
6. **CHECK CONTROL FLOW** - CRITICAL: Verify the buggy line is actually REACHABLE:
   - Look for early returns: \`if (x.length === 0) return;\` makes later \`x[0]\` SAFE
   - Look for throws: \`if (!user) throw new Error()\` makes later \`user.name\` SAFE
   - Look for guard clauses that exit before the buggy line
   - If a condition causes function exit, code after is UNREACHABLE in that case
   - Example FALSE POSITIVE: \`if (arr.length === 0) return false; ... arr[0].name\` - the access is SAFE because empty array caused early return

## REPORTING FORMAT

When you find a CONFIRMED ${pass.name} bug:

<json>
{
  "type": "bug",
  "data": {
    "file": "src/api/users.ts",
    "line": 42,
    "endLine": 45,
    "title": "Short description of the bug",
    "description": "Detailed explanation of why this is a bug and how it can be exploited.",
    "category": "${pass.category}",
    "severity": "critical|high|medium|low",
    "confidence": "high|medium|low",
    "triggerInput": "Exact input that triggers the bug",
    "codePath": [
      {"step": 1, "file": "src/api/users.ts", "line": 38, "code": "const name = req.query.name", "explanation": "User input enters here"},
      {"step": 2, "file": "src/api/users.ts", "line": 42, "code": "db.execute(query)", "explanation": "Used unsafely here"}
    ],
    "evidence": [
      "Evidence point 1",
      "Evidence point 2"
    ],
    "suggestedFix": "const result = await db.query('SELECT * FROM users WHERE name = $1', [req.query.name]);"
  }
}
</json>

Progress updates:
###SCANNING:path/to/file.ts

When done:
###COMPLETE

## BEGIN

Start by searching for ${pass.name} patterns using grep. Then read the files and trace the data flow. Report bugs as you confirm them.

REMEMBER: Only ${pass.name.toUpperCase()} bugs. Quality over quantity. Every bug must have an exact fix.`;
}

/**
 * Build prompt for the final adversarial validation pass
 */
export function buildAdversarialPassPrompt(bugs: Array<{
  id: string;
  title: string;
  file: string;
  line: number;
  description: string;
  category: string;
  severity: string;
}>): string {
  const bugList = bugs.map((b, i) => `
### Bug ${i + 1}: ${b.title}
- File: ${b.file}:${b.line}
- Category: ${b.category}
- Severity: ${b.severity}
- Description: ${b.description}
`).join('\n');

  return `You are a senior engineer reviewing bug reports. Your job is to CHALLENGE each finding.

## YOUR MISSION
For each bug, try to prove it's a FALSE POSITIVE. Look for:
- Guards or validation that were missed
- Framework protections that make it safe
- Context that makes the scenario unrealistic
- Misunderstanding of the code's purpose

## BUGS TO REVIEW
${bugList}

## METHODOLOGY

For each bug:
1. Read the code at the reported location
2. Look UPSTREAM for validation/guards
3. Check framework documentation for built-in protections
4. Consider if the attack scenario is realistic
5. Try to construct a counter-argument

## REPORTING FORMAT

For each bug, report your findings:

<json>
{
  "bugId": "WR-001",
  "verdict": "confirmed|rejected|needs-review",
  "confidence": "high|medium|low",
  "counterArguments": [
    "Counter argument 1",
    "Counter argument 2"
  ],
  "additionalEvidence": [
    "Evidence supporting rejection"
  ],
  "reasoning": "Explanation of your verdict"
}
</json>

When done with all bugs:
###COMPLETE

## BEGIN

Review each bug. Be skeptical. Reject anything that isn't clearly exploitable.`;
}

/**
 * Build a quick summary prompt to describe findings in human terms
 */
export function buildHumanReadableSummaryPrompt(bug: {
  title: string;
  file: string;
  line: number;
  description: string;
  category: string;
  severity: string;
  evidence: string[];
  suggestedFix?: string;
}): string {
  return `Convert this technical bug report into a tester-friendly format.

## ORIGINAL BUG
- Title: ${bug.title}
- File: ${bug.file}:${bug.line}
- Category: ${bug.category}
- Severity: ${bug.severity}
- Description: ${bug.description}
- Evidence: ${bug.evidence.join(', ')}
${bug.suggestedFix ? `- Fix: ${bug.suggestedFix}` : ''}

## CONVERT TO TESTER FORMAT

Create a report with:
1. **Title** = What goes wrong (outcome, not implementation)
2. **What happens** = Plain English consequence (no code terms)
3. **How to trigger** = Steps a QA tester would take
4. **Impact** = Why the business/user should care
5. **Technical details** = Original technical info (for devs)

Respond with JSON:
<json>
{
  "humanTitle": "User-friendly title describing the problem",
  "whatHappens": "Plain English explanation of the bug's effect",
  "howToTrigger": ["Step 1", "Step 2", "Step 3"],
  "impact": "Business impact statement",
  "technicalTitle": "${bug.title}",
  "technicalDetails": "Original technical description"
}
</json>`;
}

/**
 * Severity-specific guidance for prompts
 */
export const SEVERITY_THRESHOLDS = {
  critical: {
    description: 'Immediate exploitation possible, data breach or RCE',
    examples: [
      'SQL injection in login endpoint',
      'Command injection with user input',
      'Hardcoded admin credentials',
      'Auth bypass in payment flow',
    ],
  },
  high: {
    description: 'Significant risk with some exploitation barriers',
    examples: [
      'XSS requiring social engineering',
      'IDOR accessing other users data',
      'Path traversal with limited scope',
      'Weak crypto in sensitive operations',
    ],
  },
  medium: {
    description: 'Moderate risk, requires specific conditions',
    examples: [
      'Information disclosure in errors',
      'Missing rate limiting on auth',
      'Unsafe deserialization of trusted input',
      'Type confusion in edge cases',
    ],
  },
  low: {
    description: 'Minor issues, defense in depth concerns',
    examples: [
      'Verbose error messages',
      'Missing security headers',
      'Deprecated crypto (but not broken)',
      'Code quality issues with security implications',
    ],
  },
};

/**
 * Category-specific pass order (can be customized based on project type)
 */
export function getPassOrderForProject(projectType: string): string[] {
  const baseOrder = [
    'injection',
    'auth-bypass',
    'secrets-exposure',
    'null-safety',
    'type-safety',
    'async-issues',
    'data-validation',
    'resource-leaks',
    'logic-errors',
    'cross-file-flow',
  ];

  // Prioritize passes based on project type
  switch (projectType.toLowerCase()) {
    case 'api':
    case 'backend':
      // APIs: focus on injection and auth first
      return ['injection', 'auth-bypass', 'data-validation', 'secrets-exposure', ...baseOrder.filter(p => !['injection', 'auth-bypass', 'data-validation', 'secrets-exposure'].includes(p))];

    case 'web-app':
    case 'frontend':
      // Frontend: XSS and client-side issues
      return ['injection', 'secrets-exposure', 'type-safety', 'null-safety', ...baseOrder.filter(p => !['injection', 'secrets-exposure', 'type-safety', 'null-safety'].includes(p))];

    case 'cli':
      // CLI: command injection and path traversal
      return ['injection', 'data-validation', 'null-safety', 'async-issues', ...baseOrder.filter(p => !['injection', 'data-validation', 'null-safety', 'async-issues'].includes(p))];

    case 'library':
      // Libraries: type safety and API contracts
      return ['type-safety', 'null-safety', 'cross-file-flow', 'logic-errors', ...baseOrder.filter(p => !['type-safety', 'null-safety', 'cross-file-flow', 'logic-errors'].includes(p))];

    default:
      return baseOrder;
  }
}
