/**
 * Agentic Scan Prompt - True exploration-based bug hunting
 *
 * The key insight: DON'T pre-read files and stuff them into a prompt.
 * Let the LLM explore the codebase itself using its tools (Read, Grep, Glob).
 * This produces BETTER results because the LLM can:
 * - Follow imports naturally
 * - Read related files when needed
 * - Understand context properly
 * - Think through issues without JSON constraints
 *
 * Input: Just context about the project
 * Output: Bugs reported via marker format as discovered
 * Speed: Variable (depends on codebase size and findings)
 */

import {
  BUG_CATEGORIES_PROMPT,
  SEVERITY_DEFINITIONS_PROMPT,
} from './constants.js';
import {
  getRelevantPatterns,
  formatPatternsForPrompt,
} from './cwe-patterns.js';

export interface AgenticScanContext {
  projectType: string;
  framework: string;
  language: string;
  description: string;
  totalFiles: number;
  totalLOC: number;
  entryPoints?: string[];
  staticAnalysisFindings?: Array<{
    tool: string;
    file: string;
    line: number;
    message: string;
    severity: string;
  }>;
}

/**
 * Build the agentic scan prompt
 *
 * This prompt tells the LLM to EXPLORE the codebase itself, not analyze
 * pre-loaded content. This is how security auditors actually work.
 */
export function buildAgenticScanPrompt(ctx: AgenticScanContext): string {
  const staticHints = ctx.staticAnalysisFindings?.length
    ? `
## STATIC ANALYSIS HINTS
These issues were flagged by static tools. Investigate them but also look beyond:
${ctx.staticAnalysisFindings
  .slice(0, 30)
  .map((f) => `- ${f.file}:${f.line} [${f.tool}]: ${f.message}`)
  .join('\n')}
`
    : '';

  const entryPointHints = ctx.entryPoints?.length
    ? `
## SUGGESTED STARTING POINTS
${ctx.entryPoints.map((e) => `- ${e}`).join('\n')}
`
    : '';

  // Get relevant CWE patterns for this project type
  const cwePatterns = getRelevantPatterns(ctx.projectType, ctx.language);
  const cweSection = cwePatterns.length > 0
    ? `
## KNOWN VULNERABILITY PATTERNS (CWE Database)
${formatPatternsForPrompt(cwePatterns)}
`
    : '';

  return `You are a senior security auditor conducting a thorough code review. Your job is to find REAL bugs - not theoretical issues.

## YOUR TASK
Explore this codebase and find bugs. You have full access to read any file, search for patterns, and follow the code.

## PROJECT CONTEXT
- Type: ${ctx.projectType}
- Framework: ${ctx.framework || 'Unknown'}
- Language: ${ctx.language}
- Size: ${ctx.totalFiles} files, ~${ctx.totalLOC.toLocaleString()} lines
- Description: ${ctx.description}
${staticHints}
${entryPointHints}

## HOW TO WORK

1. **EXPLORE FREELY** - Use your tools to read files, grep for patterns, understand the codebase
2. **FOLLOW THE DATA** - Trace user input from entry points through the code
3. **THINK BEFORE REPORTING** - For each potential issue, verify it's actually exploitable
4. **WRITE THE FIX** - If you can't write exact fix code, it's not a confirmed bug

## WHAT TO LOOK FOR

**High-Value Targets:**
- API endpoints, route handlers, controllers
- Authentication/authorization logic
- Database queries, file operations
- User input processing
- Error handling paths
- Third-party integrations

**Bug Categories:**
${BUG_CATEGORIES_PROMPT}

${SEVERITY_DEFINITIONS_PROMPT}
${cweSection}

## CODE QUALITY ISSUES TO FLAG

Also look for these common code quality bugs:

**Insecure Randomness:**
- Math.random() used for IDs, tokens, or anything security-sensitive
- Date.now() as sole source of uniqueness

**Unsafe Type Assertions (TypeScript):**
- \`as any\` bypassing type safety
- Non-null assertions \`!\` without actual null checks
- \`as unknown as T\` double assertions

**JSON Parsing Issues:**
- JSON.parse() without try/catch
- JSON.parse() result used without schema validation (Zod, etc.)
- Type assertion after parse: \`JSON.parse(x) as MyType\`

**Regex Problems:**
- Regex matching braces/brackets without skipping string literals
- Unanchored regex allowing substring matches: /pattern/ vs /^pattern$/
- Greedy .* when .*? was intended

**Array/String Bounds:**
- .slice() or .substring() with potentially negative/OOB indices
- .map()/.filter() on potentially undefined arrays
- Array access without bounds checking

**Missing Null Checks:**
- Calling methods on optional properties: \`obj.prop.map()\` vs \`obj.prop?.map()\`
- Object.keys(obj) where obj could be undefined

## REPORTING FORMAT

When you find a CONFIRMED bug, report it like this:

###BUG:{
  "file": "src/api/users.ts",
  "line": 42,
  "endLine": 45,
  "title": "SQL injection in user search",
  "description": "User input from req.query.name is concatenated into SQL query without parameterization.",
  "category": "injection",
  "severity": "critical",
  "confidence": "high",
  "triggerInput": "GET /api/users?name='; DROP TABLE users; --",
  "codePath": [
    {"step": 1, "file": "src/api/users.ts", "line": 38, "code": "const name = req.query.name", "explanation": "User input enters here"},
    {"step": 2, "file": "src/api/users.ts", "line": 41, "code": "const query = 'SELECT * FROM users WHERE name = \\\"' + name + '\\\"'", "explanation": "Concatenated into SQL"},
    {"step": 3, "file": "src/api/users.ts", "line": 42, "code": "db.execute(query)", "explanation": "Executed with injected SQL"}
  ],
  "evidence": [
    "No input validation on req.query.name",
    "Direct string concatenation into SQL",
    "No parameterized query or ORM protection"
  ],
  "suggestedFix": "const result = await db.query('SELECT * FROM users WHERE name = $1', [req.query.name]);"
}

When you're scanning a file, report:
###SCANNING:path/to/file.ts

When done:
###COMPLETE

## CRITICAL RULES

1. **PRECISION MATTERS** - Only report bugs you're 95%+ confident about
2. **MUST HAVE FIX** - If you can't write the exact fix code, don't report it
3. **CHECK UPSTREAM** - Verify there are no guards/validation you missed
4. **REAL SCENARIOS** - Bug must be triggerable with realistic input
5. **DON'T HALLUCINATE** - If unsure about code behavior, read more files

## WHAT NOT TO REPORT

- Code that "could be improved" but works correctly
- Theoretical issues requiring unrealistic attacker access
- Missing validation for inputs validated elsewhere
- TypeScript type assertions (intentional)
- Performance concerns (unless they cause failures)
- Framework behaviors (React StrictMode, etc.)

## BEGIN

Start by exploring the codebase structure. Read key files. Follow the data flow from user input to database/output. Report bugs as you find them with the ###BUG: marker.

Take your time. Quality over quantity. Find the bugs that actually matter.`;
}

/**
 * Build a focused prompt for a specific vulnerability category
 */
export function buildCategoryFocusedPrompt(
  ctx: AgenticScanContext,
  category: string,
  patterns: string[]
): string {
  return `You are a security specialist focused ONLY on ${category.toUpperCase()} vulnerabilities.

## YOUR SINGLE FOCUS
Find ${category} bugs in this codebase. Ignore everything else.

## PROJECT
- Type: ${ctx.projectType}
- Framework: ${ctx.framework || 'Unknown'}
- Language: ${ctx.language}

## PATTERNS TO LOOK FOR
${patterns.map((p) => `- ${p}`).join('\n')}

## METHODOLOGY
1. Search for code patterns that commonly cause ${category} bugs
2. For each potential issue:
   - Read the surrounding code
   - Trace data flow
   - Verify no guards prevent it
   - Construct triggering input
   - Write the exact fix

## REPORTING
When you find a bug:
###BUG:{"file": "...", "line": N, "title": "...", "category": "${category}", ...}

When done:
###COMPLETE

Begin searching for ${category} vulnerabilities.`;
}
