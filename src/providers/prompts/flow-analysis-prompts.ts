/**
 * Flow Analysis Prompts - Integration & E2E Bug Hunting
 *
 * These prompts tell Claude to TRACE actual code flows, not just pattern match.
 * This is the difference between finding "there's a SQL query here" and
 * finding "user input from /api/users reaches this SQL query without validation".
 */

import { FlowPassConfig } from '../../core/flow-analyzer.js';

export interface StaticFinding {
  tool: string;
  file: string;
  line: number;
  message: string;
  severity: string;
}

export interface FlowPromptContext {
  pass: FlowPassConfig;
  projectType: string;
  framework: string;
  language: string;
  totalFiles: number;
  entryPoints?: string[];
  previousFindings?: Array<{
    title: string;
    file: string;
    line: number;
    category: string;
    severity: string;
  }>;
  staticFindings?: StaticFinding[];
}

/**
 * Build a flow analysis prompt that actually traces code paths
 */
export function buildFlowAnalysisPrompt(ctx: FlowPromptContext): string {
  const { pass, projectType, framework, language, totalFiles, entryPoints, previousFindings, staticFindings } = ctx;

  const entryPointsSection = entryPoints?.length
    ? `
## SUGGESTED STARTING POINTS
${entryPoints.map(e => `- ${e}`).join('\n')}
`
    : '';

  const previousFindingsSection = previousFindings?.length
    ? `
## PREVIOUS FINDINGS TO BUILD ON
These issues were found in earlier passes. Use them to find chains and deeper issues:
${previousFindings.map(f => `- [${f.severity}] ${f.title} at ${f.file}:${f.line} (${f.category})`).join('\n')}
`
    : '';

  const staticSection = staticFindings?.length
    ? `
## STATIC ANALYSIS SIGNALS (from tsc/eslint - run BEFORE you)
${staticFindings.slice(0, 15).map(f => `- ${f.tool}: ${f.file}:${f.line} - ${f.message}`).join('\n')}
${staticFindings.length > 15 ? `... and ${staticFindings.length - 15} more` : ''}

NOTE: Static tools already verified control flow. Don't report issues they would have caught.
`
    : '';

  const levelDescription = pass.level === 'integration'
    ? 'how components interact across the codebase'
    : 'complete attack scenarios from start to exploitation';

  return `You are a security auditor doing ${pass.level.toUpperCase()}-LEVEL analysis.

## YOUR MISSION: ${pass.name.toUpperCase()}
${pass.description}

You are looking at ${levelDescription}. This is NOT pattern matching - you must TRACE actual code paths.

## PROJECT CONTEXT
- Type: ${projectType}
- Framework: ${framework || 'Unknown'}
- Language: ${language}
- Size: ${totalFiles} files
${entryPointsSection}
${previousFindingsSection}
${staticSection}
## WHAT YOU'RE LOOKING FOR
${pass.whatToFind.map(w => `- ${w}`).join('\n')}

## HOW TO DO THIS ANALYSIS

${pass.traceInstructions}

## ENTRY POINTS TO START FROM
${pass.entryPointPatterns.map(p => `- ${p}`).join('\n')}

## EXAMPLE VULNERABILITY
This is what a real finding looks like for this pass:

\`\`\`
${pass.exampleVulnerability}
\`\`\`

## CRITICAL: TRACE, DON'T PATTERN MATCH

❌ WRONG: "I found exec() in this file, might be command injection"
✅ RIGHT: "User input from req.query.cmd at routes/admin.ts:15 flows through
          buildCommand() at utils/cmd.ts:42 and reaches exec() at utils/cmd.ts:58
          without any sanitization. The full path is:
          1. routes/admin.ts:15 - cmd = req.query.cmd (user input)
          2. routes/admin.ts:18 - adminService.runCommand(cmd)
          3. services/admin.ts:23 - buildCommand(cmd)
          4. utils/cmd.ts:42 - return 'ls ' + directory (concatenation!)
          5. utils/cmd.ts:58 - exec(command) (SINK)
          Trigger: GET /admin/run?cmd=; rm -rf /"

## REPORTING FORMAT

When you find a CONFIRMED flow vulnerability:

<json>
{
  "type": "bug",
  "data": {
    "file": "src/routes/admin.ts",
    "line": 15,
    "endLine": 18,
    "title": "Command injection via admin endpoint",
    "description": "User input from req.query.cmd reaches exec() without sanitization through a 5-step call chain.",
    "category": "injection",
    "severity": "critical",
    "confidence": "high",
    "flowType": "${pass.level}",
    "passName": "${pass.name}",
    "dataFlow": [
      {"step": 1, "file": "src/routes/admin.ts", "line": 15, "code": "const cmd = req.query.cmd", "type": "source", "explanation": "User input enters the system"},
      {"step": 2, "file": "src/routes/admin.ts", "line": 18, "code": "adminService.runCommand(cmd)", "type": "propagation", "explanation": "Passed to service layer"},
      {"step": 3, "file": "src/services/admin.ts", "line": 23, "code": "buildCommand(cmd)", "type": "propagation", "explanation": "Passed to utility function"},
      {"step": 4, "file": "src/utils/cmd.ts", "line": 42, "code": "return 'ls ' + directory", "type": "transformation", "explanation": "Concatenated into command string - NO SANITIZATION"},
      {"step": 5, "file": "src/utils/cmd.ts", "line": 58, "code": "exec(command)", "type": "sink", "explanation": "Executed as shell command"}
    ],
    "triggerScenario": "1. Attacker sends GET /admin/run?cmd=; rm -rf /\\n2. Input flows through buildCommand()\\n3. exec() runs: ls ; rm -rf /\\n4. Server filesystem deleted",
    "evidence": [
      "No input validation at entry point",
      "No sanitization in buildCommand()",
      "Direct string concatenation",
      "exec() called with user-tainted data"
    ],
    "securityControls": {
      "present": ["Admin route requires auth"],
      "missing": ["Input sanitization", "Command allowlist", "Shell escaping"],
      "bypassable": []
    },
    "suggestedFix": "const allowedCommands = ['ls', 'pwd', 'whoami'];\\nif (!allowedCommands.includes(cmd)) throw new Error('Invalid command');\\nexecFile(cmd, [], callback);  // Use execFile with no shell"
  }
}
</json>

For ${pass.level === 'e2e' ? 'attack chains' : 'integration issues'}, include the FULL flow across all files involved.

Progress updates:
###SCANNING:path/to/file.ts

When done:
###COMPLETE

## BEGIN

Start by finding ${pass.entryPointPatterns[0]}. Then TRACE the flow through the codebase. Report only CONFIRMED vulnerabilities where you've traced the complete path.

Remember: You're not looking for "might be vulnerable" - you're looking for "I traced the input from A to B to C and it's definitely exploitable because..."`;
}

/**
 * Build a prompt for attack chain analysis (uses previous findings)
 */
export function buildAttackChainPrompt(
  ctx: FlowPromptContext,
  allFindings: Array<{
    id: string;
    title: string;
    file: string;
    line: number;
    category: string;
    severity: string;
    description: string;
  }>
): string {
  const findingsList = allFindings.map(f =>
    `- [${f.id}] ${f.title} (${f.category}, ${f.severity})
      File: ${f.file}:${f.line}
      ${f.description.slice(0, 200)}${f.description.length > 200 ? '...' : ''}`
  ).join('\n');

  return `You are a security auditor looking for ATTACK CHAINS.

## YOUR MISSION
Find combinations of vulnerabilities that create more severe exploits.

Individual bugs may be low/medium severity. Combined, they become critical.

## ALL FINDINGS FROM PREVIOUS PASSES
${findingsList}

## COMMON CHAINS TO LOOK FOR

1. **XSS + Missing CSRF** → Full Account Takeover
   - XSS lets attacker run JS in victim's browser
   - Missing CSRF lets that JS perform actions as victim
   - Combined: Attacker sends XSS link, steals account

2. **Information Disclosure + IDOR** → Mass Data Breach
   - Info disclosure reveals user IDs/patterns
   - IDOR allows accessing any user by ID
   - Combined: Enumerate and dump all user data

3. **SSRF + Cloud Metadata** → Credential Theft
   - SSRF allows internal requests
   - Cloud metadata (169.254.169.254) has credentials
   - Combined: Steal AWS/GCP keys, pivot to infrastructure

4. **Open Redirect + OAuth** → Token Theft
   - Open redirect can redirect anywhere
   - OAuth redirects token to redirect_uri
   - Combined: Redirect OAuth flow to attacker's server

5. **Low-Priv SQLi + Credential Storage** → Full Compromise
   - SQLi with read access only
   - Password hashes in database
   - Combined: Dump hashes, crack passwords, escalate

6. **Race Condition + Financial** → Money Theft
   - Race condition in balance check
   - Financial transaction endpoint
   - Combined: Overdraw account, double-spend

## ANALYSIS INSTRUCTIONS

1. For each finding, ask: "What else could an attacker do with this?"
2. Look for findings that ENABLE each other
3. Look for findings in the same USER FLOW
4. Consider: If attacker has A, how does that help exploit B?

## REPORTING FORMAT

When you find a chain:

<json>
{
  "type": "bug",
  "data": {
    "title": "Attack Chain: XSS + Missing CSRF = Account Takeover",
    "description": "Combining reflected XSS (WR-003) with missing CSRF on profile update (WR-007) allows complete account takeover.",
    "category": "auth-bypass",
    "severity": "critical",
    "confidence": "high",
    "flowType": "e2e",
    "passName": "attack-chain-analysis",
    "chain": {
      "components": ["WR-003", "WR-007"],
      "steps": [
        "1. Attacker crafts URL with XSS payload targeting /search endpoint",
        "2. Victim (admin) clicks link, XSS executes in their browser",
        "3. XSS payload calls /api/profile/update with attacker's email",
        "4. No CSRF token required - request succeeds",
        "5. Password reset sent to attacker's email",
        "6. Attacker now controls admin account"
      ],
      "individualSeverities": ["medium", "medium"],
      "combinedSeverity": "critical",
      "amplification": "Medium + Medium = Critical account takeover"
    },
    "evidence": [
      "XSS confirmed exploitable at /search",
      "Profile update has no CSRF protection",
      "Both endpoints accessible in same origin"
    ],
    "suggestedFix": "1. Fix XSS: Encode output in search results\\n2. Add CSRF tokens to all state-changing requests\\n3. Require password for email changes"
  }
}
</json>

## BEGIN

Review all findings. Find chains. Report only CONFIRMED chains where you've verified both components work together.`;
}

/**
 * Build prompt for validating a specific flow finding
 */
export function buildFlowValidationPrompt(finding: {
  title: string;
  file: string;
  line: number;
  description: string;
  dataFlow: Array<{ step: number; file: string; line: number; explanation: string }>;
}): string {
  const flowSteps = finding.dataFlow.map(s =>
    `${s.step}. ${s.file}:${s.line} - ${s.explanation}`
  ).join('\n');

  return `You are validating a flow-based vulnerability finding. Your job is to CHALLENGE it.

## FINDING TO VALIDATE
- Title: ${finding.title}
- Location: ${finding.file}:${finding.line}
- Description: ${finding.description}

## CLAIMED DATA FLOW
${flowSteps}

## YOUR TASK

1. Read EACH file in the flow
2. Verify the data actually flows as claimed
3. Look for GUARDS that might prevent exploitation:
   - Validation between steps
   - Type checking
   - Sanitization
   - Error handling that stops the flow

## QUESTIONS TO ANSWER

1. Does the input actually reach step 1 as claimed?
2. At each step, is data passed WITHOUT transformation?
3. Are there guards between any steps?
4. Does the final sink actually execute with tainted data?
5. Is this flow actually reachable in production?

## REPORT FORMAT

<json>
{
  "verdict": "confirmed|rejected|needs-review",
  "confidence": "high|medium|low",
  "flowVerified": true|false,
  "guardsFound": [
    {"location": "file:line", "type": "validation|sanitization|error-handling", "description": "What it does"}
  ],
  "reasoning": "Detailed explanation of your verdict",
  "adjustedSeverity": "critical|high|medium|low|null"
}
</json>

If you find guards, explain whether they actually prevent exploitation or can be bypassed.`;
}

/**
 * Get the full analysis pipeline order
 * Unit passes → Integration passes → E2E passes
 */
export function getFullAnalysisPipeline(): { phase: string; passes: string[] }[] {
  return [
    {
      phase: 'Unit Analysis',
      passes: [
        'injection',
        'auth-bypass',
        'null-safety',
        'type-safety',
        'resource-leaks',
        'async-issues',
        'data-validation',
        'secrets-exposure',
        'logic-errors',
      ],
    },
    {
      phase: 'Integration Analysis',
      passes: [
        'auth-flow-trace',
        'data-flow-trace',
        'validation-boundary-trace',
        'error-propagation-trace',
        'trust-boundary-trace',
      ],
    },
    {
      phase: 'E2E Analysis',
      passes: [
        'attack-chain-analysis',
        'privilege-escalation-trace',
        'session-lifecycle-trace',
        'user-journey-simulation',
        'api-contract-verification',
      ],
    },
  ];
}
