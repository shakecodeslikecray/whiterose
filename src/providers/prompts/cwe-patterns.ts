/**
 * CWE (Common Weakness Enumeration) Patterns Database
 *
 * RAG-style retrieval of known vulnerability patterns based on project type.
 * These patterns are injected into prompts to guide the LLM on what to look for.
 */

export interface CWEPattern {
  id: string;
  name: string;
  description: string;
  category: string;
  codePatterns: string[];
  languages: string[];
  projectTypes: string[];
}

// Top 25 CWE patterns most relevant for modern web/API development
export const CWE_PATTERNS: CWEPattern[] = [
  // INJECTION VULNERABILITIES
  {
    id: 'CWE-89',
    name: 'SQL Injection',
    description: 'User input concatenated into SQL queries without parameterization',
    category: 'injection',
    codePatterns: [
      'String concatenation in SQL: query = "SELECT * FROM users WHERE id = " + userId',
      'Template literals in SQL: `SELECT * FROM ${table} WHERE ${column} = ${value}`',
      'Missing parameterized queries when using raw SQL',
    ],
    languages: ['javascript', 'typescript', 'python', 'java', 'go'],
    projectTypes: ['api', 'fullstack', 'web-app'],
  },
  {
    id: 'CWE-79',
    name: 'Cross-Site Scripting (XSS)',
    description: 'User input rendered in HTML without proper escaping',
    category: 'injection',
    codePatterns: [
      'innerHTML = userInput',
      'dangerouslySetInnerHTML={{ __html: userContent }}',
      'document.write(userInput)',
      'eval(userInput)',
    ],
    languages: ['javascript', 'typescript'],
    projectTypes: ['web-app', 'fullstack'],
  },
  {
    id: 'CWE-78',
    name: 'OS Command Injection',
    description: 'User input passed to shell commands without sanitization',
    category: 'injection',
    codePatterns: [
      'exec(userInput)',
      'spawn(command + userInput)',
      'child_process with unsanitized input',
      'shell: true with user-controlled arguments',
    ],
    languages: ['javascript', 'typescript', 'python'],
    projectTypes: ['api', 'cli', 'fullstack'],
  },
  {
    id: 'CWE-22',
    name: 'Path Traversal',
    description: 'User input used in file paths without validation, allowing ../../../ attacks',
    category: 'injection',
    codePatterns: [
      'readFile(basePath + userInput)',
      'join(uploadDir, filename) without basename extraction',
      'Missing path.resolve and startsWith check',
    ],
    languages: ['javascript', 'typescript', 'python', 'go'],
    projectTypes: ['api', 'cli', 'fullstack'],
  },

  // AUTHENTICATION/AUTHORIZATION
  {
    id: 'CWE-287',
    name: 'Improper Authentication',
    description: 'Missing or bypassable authentication checks',
    category: 'auth-bypass',
    codePatterns: [
      'API routes without auth middleware',
      'Authentication check returns early but continues execution',
      'Token verification that catches exceptions and continues',
    ],
    languages: ['javascript', 'typescript', 'python', 'go'],
    projectTypes: ['api', 'fullstack', 'web-app'],
  },
  {
    id: 'CWE-862',
    name: 'Missing Authorization',
    description: 'Actions performed without checking user permissions',
    category: 'auth-bypass',
    codePatterns: [
      'Delete/update operations without ownership check',
      'Admin endpoints accessible to regular users',
      'Missing role-based access control',
    ],
    languages: ['javascript', 'typescript', 'python', 'go'],
    projectTypes: ['api', 'fullstack'],
  },
  {
    id: 'CWE-306',
    name: 'Missing Authentication for Critical Function',
    description: 'Sensitive operations without requiring authentication',
    category: 'auth-bypass',
    codePatterns: [
      'Password reset without token verification',
      'Account deletion without re-authentication',
      'Payment processing without session validation',
    ],
    languages: ['javascript', 'typescript', 'python'],
    projectTypes: ['api', 'fullstack', 'web-app'],
  },

  // SENSITIVE DATA EXPOSURE
  {
    id: 'CWE-798',
    name: 'Hardcoded Credentials',
    description: 'Passwords, API keys, or secrets hardcoded in source code',
    category: 'secrets-exposure',
    codePatterns: [
      'const API_KEY = "sk-..."',
      'password = "admin123"',
      'Credentials in config files committed to repo',
    ],
    languages: ['javascript', 'typescript', 'python', 'go', 'java'],
    projectTypes: ['api', 'fullstack', 'cli', 'library'],
  },
  {
    id: 'CWE-532',
    name: 'Sensitive Info in Logs',
    description: 'Passwords, tokens, or PII written to log files',
    category: 'secrets-exposure',
    codePatterns: [
      'console.log(user) where user contains password',
      'logger.info(request.body) with sensitive fields',
      'Error messages exposing database credentials',
    ],
    languages: ['javascript', 'typescript', 'python', 'go'],
    projectTypes: ['api', 'fullstack', 'cli'],
  },

  // NULL REFERENCE / UNDEFINED
  {
    id: 'CWE-476',
    name: 'NULL Pointer Dereference',
    description: 'Accessing properties of null/undefined without checking',
    category: 'null-reference',
    codePatterns: [
      'user.profile.name without null check on user or profile',
      'array[0].property when array might be empty',
      'Optional chaining missing: obj.prop instead of obj?.prop',
      'Async function returns null but caller assumes object',
    ],
    languages: ['javascript', 'typescript', 'go', 'java'],
    projectTypes: ['api', 'fullstack', 'web-app', 'cli', 'library'],
  },

  // RESOURCE MANAGEMENT
  {
    id: 'CWE-772',
    name: 'Missing Release of Resource',
    description: 'File handles, connections, or timers not properly closed/cleared',
    category: 'resource-leak',
    codePatterns: [
      'setInterval without corresponding clearInterval',
      'Database connection opened but not closed in error path',
      'File opened with fs.open but not closed on exception',
      'Event listeners added but never removed',
    ],
    languages: ['javascript', 'typescript', 'python', 'go'],
    projectTypes: ['api', 'fullstack', 'cli', 'library'],
  },
  {
    id: 'CWE-401',
    name: 'Memory Leak',
    description: 'Memory allocated but never freed, growing unboundedly',
    category: 'resource-leak',
    codePatterns: [
      'Global arrays/maps that grow without bounds',
      'Closures holding references preventing garbage collection',
      'Cache without eviction policy',
    ],
    languages: ['javascript', 'typescript', 'go'],
    projectTypes: ['api', 'fullstack', 'cli'],
  },

  // ASYNC ISSUES
  {
    id: 'CWE-367',
    name: 'Time-of-Check Time-of-Use (TOCTOU)',
    description: 'Race condition between checking a condition and using the result',
    category: 'async-issue',
    codePatterns: [
      'if (exists(file)) { read(file) } - file could be deleted between check and read',
      'Check balance then deduct - concurrent requests could overdraw',
      'Verify permission then perform action without transaction',
    ],
    languages: ['javascript', 'typescript', 'python', 'go'],
    projectTypes: ['api', 'fullstack'],
  },
  {
    id: 'CWE-662',
    name: 'Improper Synchronization',
    description: 'Missing await, unhandled promises, or race conditions',
    category: 'async-issue',
    codePatterns: [
      'async function called without await',
      'Promise.all with no error handling',
      '.then() without .catch()',
      'Shared state modified in parallel without locking',
    ],
    languages: ['javascript', 'typescript'],
    projectTypes: ['api', 'fullstack', 'web-app', 'cli'],
  },

  // INPUT VALIDATION
  {
    id: 'CWE-20',
    name: 'Improper Input Validation',
    description: 'User input not validated before processing',
    category: 'data-validation',
    codePatterns: [
      'req.body used directly without schema validation',
      'parseInt(userInput) without checking for NaN',
      'Array index from user input without bounds check',
    ],
    languages: ['javascript', 'typescript', 'python', 'go'],
    projectTypes: ['api', 'fullstack', 'web-app'],
  },
  {
    id: 'CWE-1284',
    name: 'Improper Validation of Array Index',
    description: 'Array accessed with user-controlled index without bounds checking',
    category: 'boundary-error',
    codePatterns: [
      'items[userIndex] without checking userIndex < items.length',
      'Negative index not checked: items[id] where id could be -1',
    ],
    languages: ['javascript', 'typescript', 'python', 'go'],
    projectTypes: ['api', 'fullstack', 'library'],
  },

  // TYPE COERCION
  {
    id: 'CWE-843',
    name: 'Type Confusion',
    description: 'Incorrect type assumptions leading to unexpected behavior',
    category: 'type-coercion',
    codePatterns: [
      'if (value) when value could be 0 or empty string (both falsy but valid)',
      '== instead of === causing type coercion',
      'JSON.parse result used without type checking',
    ],
    languages: ['javascript', 'typescript'],
    projectTypes: ['api', 'fullstack', 'web-app', 'library'],
  },

  // LOGIC ERRORS
  {
    id: 'CWE-670',
    name: 'Always-Incorrect Control Flow',
    description: 'Logic that always takes wrong branch or never executes',
    category: 'logic-error',
    codePatterns: [
      'if (x = 5) instead of if (x === 5) - assignment instead of comparison',
      'if (a && a) - duplicate condition',
      'Loop that never executes or never terminates',
      'Return statement before important code',
    ],
    languages: ['javascript', 'typescript', 'python', 'go'],
    projectTypes: ['api', 'fullstack', 'web-app', 'cli', 'library'],
  },
  {
    id: 'CWE-480',
    name: 'Use of Incorrect Operator',
    description: 'Wrong operator used (& vs &&, | vs ||, etc.)',
    category: 'logic-error',
    codePatterns: [
      '& instead of && (bitwise vs logical)',
      '| instead of || (bitwise vs logical)',
      '+ with strings causing concatenation instead of addition',
    ],
    languages: ['javascript', 'typescript'],
    projectTypes: ['api', 'fullstack', 'web-app', 'library'],
  },

  // INSECURE RANDOMNESS
  {
    id: 'CWE-330',
    name: 'Insufficient Randomness',
    description: 'Using weak random number generators for security-sensitive operations',
    category: 'secrets-exposure',
    codePatterns: [
      'Math.random() used for IDs, tokens, or keys',
      'Math.random().toString(36) for unique identifiers',
      'Date.now() as sole source of uniqueness',
      'Sequential IDs that can be guessed',
    ],
    languages: ['javascript', 'typescript'],
    projectTypes: ['api', 'fullstack', 'web-app', 'cli', 'library'],
  },

  // UNSAFE TYPE ASSERTIONS
  {
    id: 'CWE-704',
    name: 'Incorrect Type Conversion',
    description: 'Unsafe type assertions that bypass type checking',
    category: 'type-coercion',
    codePatterns: [
      'as any - bypasses all type checking',
      'as unknown as T - double assertion to force types',
      '! (non-null assertion) - assumes value is not null without checking',
      'Type assertion on API response without validation',
    ],
    languages: ['typescript'],
    projectTypes: ['api', 'fullstack', 'web-app', 'cli', 'library'],
  },

  // UNSAFE JSON PARSING
  {
    id: 'CWE-502',
    name: 'Unsafe Deserialization',
    description: 'JSON.parse or similar without validation or error handling',
    category: 'data-validation',
    codePatterns: [
      'JSON.parse(input) without try/catch',
      'JSON.parse result used directly without schema validation',
      'Zod/Joi schema exists but not used for parsing',
      'Type assertion after JSON.parse: JSON.parse(x) as MyType',
    ],
    languages: ['javascript', 'typescript'],
    projectTypes: ['api', 'fullstack', 'web-app', 'cli', 'library'],
  },

  // REGEX ISSUES
  {
    id: 'CWE-185',
    name: 'Incorrect Regular Expression',
    description: 'Regex that matches unintended content or misses edge cases',
    category: 'logic-error',
    codePatterns: [
      'Regex matching braces/brackets without skipping strings: line.match(/{/g)',
      'Unanchored regex that matches substrings: /pattern/ instead of /^pattern$/',
      'Regex without escaping special chars in user input',
      'Greedy matching that captures too much: .* instead of .*?',
    ],
    languages: ['javascript', 'typescript', 'python', 'go'],
    projectTypes: ['api', 'fullstack', 'web-app', 'cli', 'library'],
  },

  // STRING MANIPULATION ERRORS
  {
    id: 'CWE-131',
    name: 'Incorrect Buffer Size',
    description: 'String slice/substring with incorrect bounds',
    category: 'boundary-error',
    codePatterns: [
      'str.slice(0, str.length - x) where x could exceed length',
      'str.substring(start, end) without validating start < end',
      'Array index from string length calculation without bounds check',
      'Negative index to slice without checking string length',
    ],
    languages: ['javascript', 'typescript'],
    projectTypes: ['api', 'fullstack', 'web-app', 'cli', 'library'],
  },

  // MISSING NULL CHECKS BEFORE METHOD CALLS
  {
    id: 'CWE-252',
    name: 'Unchecked Return Value',
    description: 'Calling methods on values that could be null/undefined',
    category: 'null-reference',
    codePatterns: [
      '.map() on potentially undefined array: items.map() without items &&',
      '.filter()/.reduce() on optional property without null check',
      'Object.keys(obj) where obj could be undefined',
      'Chained method calls without optional chaining: a.b.c.map()',
    ],
    languages: ['javascript', 'typescript'],
    projectTypes: ['api', 'fullstack', 'web-app', 'cli', 'library'],
  },

  // WEAK VALIDATION
  {
    id: 'CWE-183',
    name: 'Permissive Whitelist',
    description: 'Validation logic that accepts invalid input',
    category: 'data-validation',
    codePatterns: [
      'Validation that accepts if ANY condition passes instead of ALL',
      'Length-based validation as only check for correctness',
      'Regex that allows injection via alternation: (valid|.+)',
      'Fallback to default on validation failure instead of rejecting',
    ],
    languages: ['javascript', 'typescript', 'python', 'go'],
    projectTypes: ['api', 'fullstack', 'web-app', 'cli', 'library'],
  },
];

/**
 * Get relevant CWE patterns for a specific project type and language
 */
export function getRelevantPatterns(
  projectType: string,
  language: string
): CWEPattern[] {
  return CWE_PATTERNS.filter(pattern =>
    pattern.projectTypes.includes(projectType) &&
    pattern.languages.includes(language.toLowerCase())
  );
}

/**
 * Get patterns for a specific bug category
 */
export function getPatternsForCategory(category: string): CWEPattern[] {
  return CWE_PATTERNS.filter(pattern => pattern.category === category);
}

/**
 * Format patterns for injection into prompt (RAG-style)
 */
export function formatPatternsForPrompt(patterns: CWEPattern[]): string {
  if (patterns.length === 0) return '';

  const sections: string[] = [];

  // Group by category
  const byCategory = new Map<string, CWEPattern[]>();
  for (const pattern of patterns) {
    const existing = byCategory.get(pattern.category) || [];
    existing.push(pattern);
    byCategory.set(pattern.category, existing);
  }

  for (const [category, categoryPatterns] of byCategory) {
    const categoryLines = [`## ${category.toUpperCase()} Vulnerabilities to Check:`];

    for (const pattern of categoryPatterns) {
      categoryLines.push(`\n### ${pattern.id}: ${pattern.name}`);
      categoryLines.push(`${pattern.description}`);
      categoryLines.push(`Look for patterns like:`);
      for (const code of pattern.codePatterns) {
        categoryLines.push(`  - ${code}`);
      }
    }

    sections.push(categoryLines.join('\n'));
  }

  return sections.join('\n\n');
}

/**
 * Get a focused set of patterns for category-specific analysis
 */
export function getCategoryFocusedPatterns(category: string): string {
  const patterns = getPatternsForCategory(category);
  if (patterns.length === 0) return '';

  const lines = [`KNOWN ${category.toUpperCase()} PATTERNS TO DETECT:\n`];

  for (const pattern of patterns) {
    lines.push(`${pattern.id} - ${pattern.name}:`);
    lines.push(`  ${pattern.description}`);
    lines.push(`  Common code patterns:`);
    for (const code of pattern.codePatterns) {
      lines.push(`    * ${code}`);
    }
    lines.push('');
  }

  return lines.join('\n');
}
