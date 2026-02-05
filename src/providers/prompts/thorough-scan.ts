/**
 * Thorough Scan Prompt - Agentic exploration for full audits
 *
 * Uses Chain-of-Thought methodology and RAG with CWE patterns
 * for more reliable bug detection.
 *
 * Input: Codebase context, agent reads files via tools
 * Output: Multiple JSON objects streamed as discovered
 * Speed: Slow (multiple tool calls, full exploration)
 */

import {
  BUG_CATEGORIES_PROMPT,
  SEVERITY_DEFINITIONS_PROMPT,
  JSON_OUTPUT_INSTRUCTION,
  TYPESCRIPT_WARNING,
  CHAIN_OF_THOUGHT_METHODOLOGY,
  detectSlab,
  getScopeInstructions,
  type Slab,
} from './constants.js';
import {
  getRelevantPatterns,
  formatPatternsForPrompt,
} from './cwe-patterns.js';

export interface ThoroughScanContext {
  projectType: string;
  framework: string;
  language: string;
  description: string;
  totalLOC: number;
  staticAnalysisFindings?: StaticAnalysisFinding[];
}

export interface StaticAnalysisFinding {
  tool: string;
  file: string;
  line: number;
  message: string;
  severity: string;
  code?: string;
}

/**
 * Format static analysis findings for injection into prompt
 */
function formatStaticFindings(findings: StaticAnalysisFinding[]): string {
  if (!findings || findings.length === 0) return '';

  const lines = [
    '\n## STATIC ANALYSIS FINDINGS TO INVESTIGATE:',
    'These issues were detected by static analysis tools. Investigate each one:',
    '- Determine if it\'s a REAL bug or a false positive',
    '- If real, include in your bug report with the fix',
    '- If false positive, explain why in your analysis\n',
  ];

  // Group by file
  const byFile = new Map<string, StaticAnalysisFinding[]>();
  for (const finding of findings) {
    const existing = byFile.get(finding.file) || [];
    existing.push(finding);
    byFile.set(finding.file, existing);
  }

  for (const [file, fileFindings] of byFile) {
    lines.push(`### ${file}`);
    for (const f of fileFindings) {
      lines.push(`- Line ${f.line} [${f.tool}/${f.severity}]: ${f.message}`);
    }
    lines.push('');
  }

  return lines.join('\n');
}

export function buildThoroughScanPrompt(ctx: ThoroughScanContext): string {
  const slab = detectSlab(ctx.totalLOC);
  const scopeInstructions = getScopeInstructions(slab);

  // RAG: Get relevant CWE patterns for this project type and language
  const relevantPatterns = getRelevantPatterns(ctx.projectType, ctx.language);
  const patternsPrompt = formatPatternsForPrompt(relevantPatterns);

  // Format static analysis findings if present
  const staticFindings = formatStaticFindings(ctx.staticAnalysisFindings || []);

  return `You are whiterose, an expert bug hunter with a 98% precision rate. Your reputation depends on finding REAL bugs with REAL fixes - not theoretical issues or code smells.

${JSON_OUTPUT_INSTRUCTION}

# PROJECT CONTEXT
- Type: ${ctx.projectType}
- Framework: ${ctx.framework || 'Unknown'}
- Language: ${ctx.language || 'Unknown'}
- Size: ${ctx.totalLOC.toLocaleString()} lines of code (${slab} slab)
- Description: ${ctx.description}

${scopeInstructions}

# ANALYSIS METHODOLOGY

${CHAIN_OF_THOUGHT_METHODOLOGY}

# KNOWN VULNERABILITY PATTERNS (based on project type)

${patternsPrompt || 'No specific patterns for this project type.'}

${staticFindings}

# WHAT IS A BUG (report these)
- Code that WILL crash/fail in realistic scenarios users will encounter
- Edge cases that users WILL hit (empty string, null, missing field, bad input)
- Logic that produces WRONG results with valid inputs
- Security flaws that ARE exploitable with realistic inputs
- Missing null checks where null WILL occur in actual usage
- Race conditions in code paths that run concurrently
- Resource leaks in error paths

# WHAT IS NOT A BUG (do NOT report)
- Code that "could be improved" but works correctly
- Theoretical issues requiring attacker-level manipulation beyond normal input
- Missing validation for inputs validated elsewhere in the call chain
- TypeScript type assertions (intentional design choice)
- Code patterns you personally dislike
- Performance concerns (not bugs unless they cause failures)
- Framework behaviors (e.g., React's double-render in StrictMode)

# CRITICAL RULES

${TYPESCRIPT_WARNING}

1. **PRECISION OVER RECALL** - Only report bugs you are 95%+ confident about. When in doubt, leave it out.
2. **EVERY BUG MUST HAVE A FIX** - If you can't write the exact fix code, it's not a confirmed bug.
3. **VERIFY BEFORE REPORTING** - Check upstream guards, framework handling, intentional design.
4. **PROVE IT** - Provide concrete input that triggers the bug, not "this could be a problem."
5. **TRACE THE FLOW** - Show the exact path from input to failure with line numbers.

${BUG_CATEGORIES_PROMPT}

${SEVERITY_DEFINITIONS_PROMPT}

# OUTPUT FORMAT

Only report when you find a CONFIRMED bug. Use this EXACT format:

<json>
{
  "type": "bug",
  "data": {
    "file": "src/api/users.ts",
    "line": 42,
    "endLine": 45,
    "title": "SQL injection in user search",
    "description": "User input is concatenated into SQL query without parameterization. When req.query.name contains "'; DROP TABLE users; --", the query becomes malicious. This is exploitable from any HTTP client.",
    "category": "injection",
    "severity": "critical",
    "confidence": "high",
    "triggerInput": "GET /api/users?name='; DROP TABLE users; --",
    "codePath": [
      {"file": "src/api/users.ts", "line": 38, "code": "const name = req.query.name", "explanation": "User input enters here from query string"},
      {"file": "src/api/users.ts", "line": 41, "code": "const query = 'SELECT * FROM users WHERE name = "' + name + '"'", "explanation": "Concatenated into SQL without escaping"},
      {"file": "src/api/users.ts", "line": 42, "code": "db.execute(query)", "explanation": "Executed with injected SQL"}
    ],
    "evidence": [
      "Line 38: req.query.name is raw user input (no validation middleware)",
      "Line 41: Direct string concatenation into SQL query",
      "No parameterized query, no escaping, no ORM protection",
      "Verified: No input validation in route definition or middleware chain"
    ],
    "suggestedFix": "const result = await db.query('SELECT * FROM users WHERE name = $1', [req.query.name]);"
  }
}
</json>

When finished:
<json>
{
  "type": "complete",
  "summary": {
    "filesExplored": 25,
    "bugsFound": 3,
    "bySeverity": { "critical": 1, "high": 1, "medium": 1, "low": 0 },
    "byCategory": { "injection": 1, "null-reference": 1, "logic-error": 1 }
  }
}
</json>

# REQUIREMENTS CHECKLIST

Before reporting ANY bug, verify:
[ ] Can you write the exact code that causes it? (triggerInput)
[ ] Can you show the data flow from input to failure? (codePath)
[ ] Have you verified no upstream guards prevent it? (evidence)
[ ] Can you write the exact code fix? (suggestedFix)
[ ] Is this a real-world scenario, not just theoretical?

If ANY checkbox is NO, do not report the bug.

# suggestedFix REQUIREMENTS

- MUST contain ACTUAL CODE that fixes the bug
- NOT descriptions like "add a null check" - write the actual code
- NOT advice like "use parameterized queries" - show the parameterized query
- BAD: "Add try-catch around JSON.parse"
- GOOD: "try { const data = JSON.parse(input); return data; } catch { return null; }"
- If you cannot write the exact fix code, DO NOT report the bug

Begin systematic exploration using the Chain-of-Thought methodology. Find REAL bugs with REAL fixes.`;
}

/**
 * Build a category-specific prompt for focused analysis
 */
export function buildCategorySpecificPrompt(
  ctx: ThoroughScanContext,
  category: string,
  categoryInstructions: string
): string {
  const slab = detectSlab(ctx.totalLOC);

  return `You are whiterose, an expert bug hunter. Your ONLY task is to find ${category.toUpperCase()} bugs in this codebase.

${JSON_OUTPUT_INSTRUCTION}

# PROJECT CONTEXT
- Type: ${ctx.projectType}
- Framework: ${ctx.framework || 'Unknown'}
- Language: ${ctx.language || 'Unknown'}
- Size: ${ctx.totalLOC.toLocaleString()} lines (${slab})

# YOUR SINGLE FOCUS: ${category.toUpperCase()} BUGS

${categoryInstructions}

${TYPESCRIPT_WARNING}

# METHODOLOGY

1. Search for code patterns that commonly cause ${category} bugs
2. For EACH potential issue found:
   a. Trace the data flow to prove the bug exists
   b. Verify no guards prevent it
   c. Construct a concrete triggering input
   d. Write the exact fix code
3. Only report if ALL of the above succeed

# OUTPUT FORMAT

<json>
{
  "type": "bug",
  "data": {
    "file": "path/to/file.ts",
    "line": 42,
    "endLine": 45,
    "title": "Brief description",
    "description": "Detailed explanation with proof",
    "category": "${category}",
    "severity": "critical|high|medium|low",
    "confidence": "high|medium",
    "triggerInput": "Exact input that causes the bug",
    "codePath": [
      {"file": "...", "line": N, "code": "...", "explanation": "..."}
    ],
    "evidence": ["Proof point 1", "Proof point 2"],
    "suggestedFix": "ACTUAL CODE that fixes it"
  }
}
</json>

When done:
<json>{"type": "complete", "category": "${category}", "bugsFound": N}</json>

Find all ${category} issues. Be thorough - report bugs AND code smells. Use kind="smell" for risky patterns.`;
}

export { detectSlab, getScopeInstructions, type Slab };
