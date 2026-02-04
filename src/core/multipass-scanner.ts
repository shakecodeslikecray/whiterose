/**
 * Multi-Pass Scanner - 10x Bug Hunter
 *
 * Why this is better than a single prompt:
 * - A human does 1 pass, this does 10
 * - Each pass is laser-focused on ONE category
 * - No bug category gets overlooked
 * - Adversarial validation kills false positives
 * - Same thoroughness at file 57 as file 1
 *
 * The passes:
 * 1. Injection - SQL, command, path, XSS, SSRF
 * 2. Auth/Authz - Authentication/authorization bypasses
 * 3. Null Safety - Null/undefined dereference
 * 4. Type Safety - as any, !, unsafe casts
 * 5. Resource Leaks - Files, connections, timers
 * 6. Async Issues - Missing await, race conditions
 * 7. Data Validation - Input sanitization, schema
 * 8. Secrets Exposure - Hardcoded creds, Math.random()
 * 9. Logic Errors - Wrong operators, conditions, regex
 * 10. Cross-File - Data flow across module boundaries
 */

import { Bug, CodebaseUnderstanding, BugCategory, AdversarialResult } from '../types.js';

export interface PassConfig {
  name: string;
  category: BugCategory;
  description: string;
  searchPatterns: string[];
  grepPatterns: string[];
  methodology: string;
  falsePositiveHints: string[];
}

export interface PassResult {
  pass: string;
  category: BugCategory;
  duration: number;
  bugs: Bug[];
  filesScanned: number;
}

export interface MultiPassResult {
  passes: PassResult[];
  totalDuration: number;
  rawBugs: Bug[];
  validatedBugs: Bug[];
  duplicatesRemoved: number;
  falsePositivesRejected: number;
}

// ─────────────────────────────────────────────────────────────
// Pass Definitions - Each pass is a laser-focused bug hunter
// ─────────────────────────────────────────────────────────────

export const SCAN_PASSES: PassConfig[] = [
  {
    name: 'injection',
    category: 'injection',
    description: 'SQL injection, command injection, path traversal, XSS, SSRF',
    searchPatterns: [
      'SQL queries with string concatenation or template literals',
      'exec(), spawn(), execSync() with user input',
      'path.join(), readFile(), writeFile() with user input',
      'innerHTML, dangerouslySetInnerHTML, document.write()',
      'fetch(), axios(), request() with user-controlled URLs',
    ],
    grepPatterns: [
      'exec\\s*\\(',
      'spawn\\s*\\(',
      'execSync\\s*\\(',
      'eval\\s*\\(',
      'Function\\s*\\(',
      'innerHTML\\s*=',
      'dangerouslySetInnerHTML',
      'document\\.write',
      'SELECT.*FROM.*WHERE.*\\+',
      'SELECT.*FROM.*\\$\\{',
    ],
    methodology: `1. Search for injection sinks (exec, spawn, SQL queries, innerHTML)
2. For each sink, trace back to find data sources
3. Check if user input reaches the sink without sanitization
4. Verify no guards/validation in the path
5. Construct triggering input
6. Write exact fix`,
    falsePositiveHints: [
      'Parameterized queries are safe',
      'Static strings passed to exec are safe',
      'Input validated with allowlist before use is safe',
      'React/Vue templates auto-escape (unless dangerouslySetInnerHTML)',
    ],
  },
  {
    name: 'auth-bypass',
    category: 'auth-bypass',
    description: 'Missing authentication, authorization bypass, privilege escalation',
    searchPatterns: [
      'API routes without auth middleware',
      'Authorization checks that can be skipped',
      'Admin endpoints accessible without role check',
      'IDOR: accessing resources by ID without ownership check',
      'JWT verification that catches errors and continues',
    ],
    grepPatterns: [
      'router\\.(get|post|put|delete|patch)\\s*\\(',
      'app\\.(get|post|put|delete|patch)\\s*\\(',
      '\\.findById\\s*\\(',
      '\\.findOne\\s*\\(',
      'req\\.user',
      'req\\.session',
      'isAdmin|isAuthenticated|requireAuth',
      'role.*===|===.*role',
    ],
    methodology: `1. Find all API endpoints and route handlers
2. Check each endpoint for auth middleware
3. For protected resources, verify ownership checks
4. Look for early returns that skip auth on error
5. Test if admin-only actions are protected
6. Write exact fix with proper middleware`,
    falsePositiveHints: [
      'Public endpoints dont need auth (health, docs, etc)',
      'Middleware applied at router level protects all routes',
      'GraphQL resolvers may have field-level auth',
    ],
  },
  {
    name: 'null-safety',
    category: 'null-reference',
    description: 'Null/undefined dereference, missing optional chaining',
    searchPatterns: [
      'Property access on potentially null/undefined values',
      'Array methods on optional arrays without null check',
      'Object.keys/values on potentially undefined objects',
      'Chained property access without optional chaining',
      'Async functions returning null but caller expects object',
    ],
    grepPatterns: [
      '\\.map\\s*\\(',
      '\\.filter\\s*\\(',
      '\\.reduce\\s*\\(',
      '\\.forEach\\s*\\(',
      'Object\\.keys\\s*\\(',
      'Object\\.values\\s*\\(',
      'Object\\.entries\\s*\\(',
      '\\[0\\]\\.',
      '\\.length',
    ],
    methodology: `1. Search for array methods (.map, .filter, .reduce)
2. Trace back to see if the array could be undefined
3. Check for missing optional chaining (?.)
4. Look for [0] access without checking array length
5. Find Object.keys/values on potentially null objects
6. Write fix with proper null checks`,
    falsePositiveHints: [
      'TypeScript strict mode catches many of these',
      'If variable is guaranteed by control flow, its safe',
      'Default parameters and destructuring defaults help',
    ],
  },
  {
    name: 'type-safety',
    category: 'type-coercion',
    description: 'Unsafe type assertions, as any, non-null assertions, JSON.parse without validation',
    searchPatterns: [
      '`as any` bypassing type safety',
      'Non-null assertion (!) without actual null check',
      '`as unknown as T` double assertion',
      'JSON.parse() without try/catch or schema validation',
      'Type assertion after JSON.parse: JSON.parse(x) as MyType',
    ],
    grepPatterns: [
      'as\\s+any',
      'as\\s+unknown\\s+as',
      '!\\s*[;,)]',
      '!\\.',
      'JSON\\.parse\\s*\\(',
    ],
    methodology: `1. Search for "as any" patterns
2. Find JSON.parse calls without try/catch
3. Look for non-null assertions (!) without preceding checks
4. Check if parsed JSON is validated before use
5. Find double assertions (as unknown as T)
6. Write fix with proper validation/type guards`,
    falsePositiveHints: [
      'as any in test files is often acceptable',
      '! after definite assignment in same scope is safe',
      'Zod/Joi validation after JSON.parse is safe',
    ],
  },
  {
    name: 'resource-leaks',
    category: 'resource-leak',
    description: 'Unclosed file handles, DB connections, timers, event listeners',
    searchPatterns: [
      'setInterval without clearInterval',
      'setTimeout stored but never cleared',
      'Database connections not closed on error',
      'File handles opened but not closed in finally/catch',
      'Event listeners added but never removed',
    ],
    grepPatterns: [
      'setInterval\\s*\\(',
      'setTimeout\\s*\\(',
      'addEventListener\\s*\\(',
      '\\.on\\s*\\(',
      'createConnection\\s*\\(',
      'fs\\.open',
      'new.*Stream\\s*\\(',
    ],
    methodology: `1. Find setInterval calls, check for corresponding clearInterval
2. Look for event listeners, check if removed on cleanup
3. Find DB connection opens, verify close in error paths
4. Check file operations have proper finally/catch cleanup
5. Look for growing caches/maps without eviction
6. Write fix with proper cleanup code`,
    falsePositiveHints: [
      'Global singletons may intentionally keep connections open',
      'React useEffect cleanup handles listener removal',
      'Connection pools manage their own lifecycle',
    ],
  },
  {
    name: 'async-issues',
    category: 'async-issue',
    description: 'Missing await, race conditions, unhandled promises',
    searchPatterns: [
      'async function called without await',
      'Promise.all without error handling',
      '.then() without .catch()',
      'Shared state modified in parallel operations',
      'TOCTOU: check then use without atomicity',
    ],
    grepPatterns: [
      'async\\s+function',
      'async\\s*\\(',
      'await\\s+',
      '\\.then\\s*\\(',
      'Promise\\.all\\s*\\(',
      'Promise\\.race\\s*\\(',
    ],
    methodology: `1. Find async function calls, verify they are awaited
2. Look for .then() chains without .catch()
3. Check Promise.all for error handling
4. Find shared state mutations in async contexts
5. Look for check-then-use patterns without transactions
6. Write fix with proper await/error handling`,
    falsePositiveHints: [
      'Fire-and-forget async calls may be intentional',
      'Top-level .catch() at entry point is sufficient',
      'Promise.allSettled handles its own errors',
    ],
  },
  {
    name: 'data-validation',
    category: 'data-validation',
    description: 'Missing input validation, schema validation, sanitization',
    searchPatterns: [
      'req.body used directly without validation',
      'parseInt/parseFloat without NaN check',
      'Array index from user input without bounds check',
      'Missing schema validation (Zod, Joi, etc)',
      'Validation that accepts if ANY condition passes',
    ],
    grepPatterns: [
      'req\\.body',
      'req\\.query',
      'req\\.params',
      'parseInt\\s*\\(',
      'parseFloat\\s*\\(',
      'Number\\s*\\(',
      '\\.safeParse\\s*\\(',
      '\\.validate\\s*\\(',
    ],
    methodology: `1. Find all user input entry points (req.body, req.query, etc)
2. Trace each input to see if its validated
3. Check parseInt/parseFloat results for NaN
4. Look for array indexing with user-controlled values
5. Verify schema validation exists and is correct
6. Write fix with proper validation`,
    falsePositiveHints: [
      'Framework middleware may validate automatically',
      'GraphQL type system provides some validation',
      'ORMs may validate at the schema level',
    ],
  },
  {
    name: 'secrets-exposure',
    category: 'secrets-exposure',
    description: 'Hardcoded credentials, Math.random() for security, leaked tokens',
    searchPatterns: [
      'Hardcoded passwords, API keys, or tokens',
      'Math.random() used for IDs, tokens, or keys',
      'Date.now() as sole source of uniqueness',
      'Credentials in logs or error messages',
      'Secrets in URL query parameters',
    ],
    grepPatterns: [
      'password\\s*=\\s*["\']',
      'apiKey\\s*=\\s*["\']',
      'api_key\\s*=\\s*["\']',
      'secret\\s*=\\s*["\']',
      'token\\s*=\\s*["\']',
      'Math\\.random\\s*\\(',
      'Date\\.now\\s*\\(',
      'console\\.log.*password',
      'console\\.log.*token',
    ],
    methodology: `1. Search for hardcoded credential patterns
2. Find Math.random() calls, check if used for security
3. Look for Date.now() as unique ID source
4. Check logs for sensitive data exposure
5. Find secrets in URL parameters or error messages
6. Write fix using env vars or crypto.randomUUID()`,
    falsePositiveHints: [
      'Test files may have fake credentials',
      '.env.example files are documentation',
      'Math.random() for non-security uses is fine',
    ],
  },
  {
    name: 'logic-errors',
    category: 'logic-error',
    description: 'Wrong operators, incorrect conditions, regex issues, off-by-one',
    searchPatterns: [
      'Assignment instead of comparison: if (x = 5)',
      'Bitwise vs logical operators: & vs &&',
      'Regex matching without anchors: /pattern/ vs /^pattern$/',
      'Greedy matching that captures too much: .* vs .*?',
      'Off-by-one in loops or array access',
    ],
    grepPatterns: [
      'if\\s*\\([^=!<>]*=[^=]',
      '\\s&\\s[^&]',
      '\\s\\|\\s[^|]',
      '\\.match\\s*\\(',
      '\\.test\\s*\\(',
      '\\.replace\\s*\\(',
      'for\\s*\\(.*<.*\\.length',
      'while\\s*\\(',
    ],
    methodology: `1. Search for regex patterns, check for proper anchoring
2. Find comparisons, look for = instead of ===
3. Check bitwise operators that should be logical
4. Look for loop bounds that could be off-by-one
5. Find string operations that could exceed bounds
6. Write fix with correct operators/bounds`,
    falsePositiveHints: [
      'Some bitwise operations are intentional',
      'Unanchored regex may be intentional for substring match',
      'Assignment in condition is sometimes intentional (with extra parens)',
    ],
  },
  {
    name: 'cross-file-flow',
    category: 'intent-violation',
    description: 'Data flow across module boundaries, API contract violations',
    searchPatterns: [
      'Function returns type A but callers expect type B',
      'Error thrown but not caught by callers',
      'Null returned but callers dont check',
      'Side effects not documented or expected',
      'Module exports not matching imports',
    ],
    grepPatterns: [
      'export\\s+(function|const|class|interface)',
      'import\\s+\\{',
      'throw\\s+new',
      'return\\s+null',
      'return\\s+undefined',
    ],
    methodology: `1. Find exported functions and their signatures
2. Trace callers to verify they handle all return types
3. Check if thrown errors are caught by callers
4. Look for null returns that callers dont handle
5. Verify interface contracts match implementations
6. Write fix to align contracts and usage`,
    falsePositiveHints: [
      'TypeScript enforces many interface contracts',
      'Central error handlers may catch everything',
      'Some null returns are intentional API design',
    ],
  },
];

/**
 * Get pass configuration by name
 */
export function getPassConfig(name: string): PassConfig | undefined {
  return SCAN_PASSES.find(p => p.name === name);
}

/**
 * Get passes for a specific category
 */
export function getPassesForCategory(category: BugCategory): PassConfig[] {
  return SCAN_PASSES.filter(p => p.category === category);
}

/**
 * Calculate hash for deduplication
 */
export function calculateBugHash(bug: Bug): string {
  // Bugs are duplicates if same file, line range, and category
  const key = `${bug.file}:${bug.line}:${bug.endLine || bug.line}:${bug.category}`;
  return key;
}

/**
 * Deduplicate bugs from multiple passes
 * Keeps the bug with highest confidence when duplicates exist
 */
export function deduplicateBugs(bugs: Bug[]): { unique: Bug[]; duplicatesRemoved: number } {
  const seen = new Map<string, Bug>();

  for (const bug of bugs) {
    const hash = calculateBugHash(bug);
    const existing = seen.get(hash);

    if (!existing) {
      seen.set(hash, bug);
    } else {
      // Keep the one with higher confidence
      const confidenceOrder = { high: 3, medium: 2, low: 1 };
      if (confidenceOrder[bug.confidence.overall] > confidenceOrder[existing.confidence.overall]) {
        seen.set(hash, bug);
      }
    }
  }

  return {
    unique: Array.from(seen.values()),
    duplicatesRemoved: bugs.length - seen.size,
  };
}

/**
 * Check if two bugs are semantically similar (for near-duplicate detection)
 */
export function areSimilarBugs(a: Bug, b: Bug): boolean {
  // Same file and overlapping line range
  if (a.file !== b.file) return false;

  const aStart = a.line;
  const aEnd = a.endLine || a.line;
  const bStart = b.line;
  const bEnd = b.endLine || b.line;

  // Check for overlap
  const overlap = !(aEnd < bStart || bEnd < aStart);
  if (!overlap) return false;

  // Same or related category
  const relatedCategories: Record<string, string[]> = {
    'injection': ['injection', 'data-validation'],
    'null-reference': ['null-reference', 'type-coercion'],
    'type-coercion': ['type-coercion', 'null-reference', 'logic-error'],
    'logic-error': ['logic-error', 'type-coercion', 'boundary-error'],
  };

  const related = relatedCategories[a.category] || [a.category];
  return related.includes(b.category);
}

/**
 * Merge similar bugs (near-duplicates from different passes)
 */
export function mergeSimilarBugs(bugs: Bug[]): Bug[] {
  const merged: Bug[] = [];
  const used = new Set<number>();

  for (let i = 0; i < bugs.length; i++) {
    if (used.has(i)) continue;

    let best = bugs[i];

    for (let j = i + 1; j < bugs.length; j++) {
      if (used.has(j)) continue;

      if (areSimilarBugs(best, bugs[j])) {
        used.add(j);
        // Keep the one with higher confidence and more evidence
        const jBetter =
          bugs[j].confidence.overall === 'high' && best.confidence.overall !== 'high' ||
          bugs[j].evidence.length > best.evidence.length;

        if (jBetter) {
          // Merge evidence from both
          bugs[j].evidence = [...new Set([...bugs[j].evidence, ...best.evidence])];
          best = bugs[j];
        } else {
          // Add evidence from the other bug
          best.evidence = [...new Set([...best.evidence, ...bugs[j].evidence])];
        }
      }
    }

    merged.push(best);
  }

  return merged;
}
