/**
 * Smart Scanner - 10x Bug Hunter That's Actually Fast
 *
 * The old approach: 19 passes × 5 min = 95 minutes (WRONG)
 * A skilled human: 2-3 prompts × 5 min = 10-15 minutes (RIGHT)
 *
 * This scanner mimics how a skilled human hunts bugs:
 * 1. One comprehensive look (triage) - find ALL potential issues
 * 2. Challenge each finding (validation) - kill false positives
 * 3. Deep dive only on suspicious areas (targeted) - max 3 passes
 *
 * Total: 10-25 minutes, not 95 minutes
 */

import { Bug, BugCategory, CodebaseUnderstanding, Confidence, Severity } from '../types.js';
import { SCAN_PASSES } from './multipass-scanner.js';
import { FLOW_PASSES, FlowPassConfig } from './flow-analyzer.js';

// ─────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────

export interface TriageResult {
  bugs: Bug[];
  suspiciousAreas: SuspiciousArea[];
  duration: number;
}

export interface SuspiciousArea {
  file: string;
  lines?: { start: number; end: number };
  reason: string;
  suggestedDeepDive: 'auth-flow' | 'data-flow' | 'attack-chain' | 'session' | 'none';
  confidence: 'high' | 'medium' | 'low';
}

export interface ValidationResult {
  validated: Bug[];
  rejected: Bug[];
  duration: number;
}

export interface DeepDiveResult {
  passName: string;
  bugs: Bug[];
  duration: number;
}

export interface SmartScanResult {
  triageResult: TriageResult;
  validationResult: ValidationResult;
  deepDiveResults: DeepDiveResult[];
  totalDuration: number;
  finalBugs: Bug[];
}

// ─────────────────────────────────────────────────────────────
// Triage Prompt - One comprehensive pass covering everything
// ─────────────────────────────────────────────────────────────

export function buildTriagePrompt(
  understanding: CodebaseUnderstanding,
  files: string[],
): string {
  // Combine all category search patterns into one comprehensive list
  const allPatterns = SCAN_PASSES.flatMap(p => p.searchPatterns);
  const allCategories = SCAN_PASSES.map(p => `- ${p.name}: ${p.description}`).join('\n');

  return `# Security Bug Triage - Find Everything

You are a senior security researcher doing a comprehensive code review.
Look at this code with fresh eyes and find ALL potential security issues.

## Project Context
${understanding.summary || 'No summary available'}

## Bug Categories to Look For
${allCategories}

## What Makes a Real Bug (not a false positive)
- Attacker-controlled input reaches a dangerous sink
- Security check can be bypassed or skipped
- Authentication/authorization is missing or incomplete
- Sensitive data exposed without authorization
- Race condition or TOCTOU that's exploitable

## What to Ignore
- Theoretical issues without realistic attack vector
- Code patterns that look dangerous but are actually safe
- Test files and example code
- Issues behind proper validation/sanitization
- **CRITICAL: Code after early returns** - If \`if (x.length === 0) return;\` exists, then \`x[0]\` after it is SAFE (unreachable when empty)
- **Guard clauses that exit** - \`if (!user) throw Error()\` makes \`user.name\` after it SAFE
- Check control flow CAREFULLY before reporting null/undefined/array access bugs

## Files to Analyze
${files.slice(0, 30).join('\n')}
${files.length > 30 ? `\n... and ${files.length - 30} more files` : ''}

## Your Task

1. **SCAN** - Review each file for security issues
2. **TRIAGE** - For each potential issue, ask:
   - Is there a realistic attack vector?
   - Can user input actually reach this code path?
   - Is this exploitable in practice?
3. **REPORT** - Output only issues that pass triage

For each bug, also note if it needs deeper flow analysis:
- Auth issues → needs auth-flow deep dive
- Data handling → needs data-flow deep dive
- Cross-file patterns → needs attack-chain analysis
- Session/token issues → needs session deep dive

## Output Format

Return a JSON object with this structure:
\`\`\`json
{
  "bugs": [
    {
      "id": "BUG-001",
      "title": "Short descriptive title",
      "category": "injection|auth-bypass|null-reference|...",
      "severity": "critical|high|medium|low",
      "confidence": {
        "overall": "high|medium|low",
        "factors": {
          "patternMatch": true,
          "dataFlowConfirmed": false,
          "exploitPathClear": true
        }
      },
      "file": "path/to/file.ts",
      "line": 42,
      "endLine": 45,
      "description": "What's wrong and why it's exploitable",
      "evidence": ["Code snippet 1", "Code snippet 2"],
      "triggerScenario": "How an attacker would trigger this",
      "impact": "What happens if exploited",
      "suggestedFix": "How to fix it"
    }
  ],
  "suspiciousAreas": [
    {
      "file": "path/to/file.ts",
      "lines": { "start": 10, "end": 50 },
      "reason": "Why this area is suspicious",
      "suggestedDeepDive": "auth-flow|data-flow|attack-chain|session|none",
      "confidence": "high|medium|low"
    }
  ]
}
\`\`\`

Now analyze the code and find bugs:`;
}

// ─────────────────────────────────────────────────────────────
// Validation Prompt - Challenge each finding
// ─────────────────────────────────────────────────────────────

export function buildValidationPrompt(bugs: Bug[]): string {
  const bugList = bugs.map((b, i) => `
### Bug ${i + 1}: ${b.title}
- **File**: ${b.file}:${b.line}
- **Category**: ${b.category}
- **Severity**: ${b.severity}
- **Description**: ${b.description}
- **Evidence**: ${b.evidence.join(' | ')}
- **Trigger**: ${b.triggerScenario || 'Not specified'}
`).join('\n');

  return `# Adversarial Bug Validation

You are a senior engineer reviewing bug reports from an automated scanner.
Your job is to CHALLENGE each finding and reject false positives.

## Bugs to Validate
${bugList}

## Challenge Questions (ask for EACH bug)

1. **Is it reachable?**
   - Can user input actually reach this code path?
   - Are there guards/checks earlier that prevent exploitation?

2. **Is it exploitable?**
   - Does the attacker have enough control to exploit this?
   - Are there mitigations in place (CSP, parameterization, etc.)?

3. **Is it real or theoretical?**
   - Could this be triggered in normal/malicious use?
   - Or is it only exploitable in unrealistic scenarios?

4. **Could this be intentional?**
   - Is this a known pattern that looks dangerous but is safe?
   - Is there context we're missing?

## Common False Positive Patterns

- exec() with hardcoded strings (no user input)
- SQL with parameterized queries (looks like string concat but isn't)
- innerHTML with sanitized/encoded content
- "Missing" auth on intentionally public endpoints
- TypeScript "as any" in test files
- JSON.parse with immediate Zod validation

## CRITICAL: Check Control Flow / Early Returns

**#1 cause of false positives!** Before validating, check if the buggy line is REACHABLE:

- **Early returns**: \`if (arr.length === 0) return;\` makes later \`arr[0]\` SAFE (unreachable for empty arrays)
- **Throws**: \`if (!x) throw new Error();\` makes later \`x.value\` SAFE
- **Guard clauses**: Any condition that exits the function before the buggy line

Example FALSE POSITIVE:
\`\`\`typescript
if (codeModels.length === 0) {
  return models.models.length > 0;  // RETURNS HERE when empty
}
this.model = codeModels[0].name;  // Only reached when length > 0, so SAFE!
\`\`\`

If an early return/throw makes the buggy line unreachable for the problematic case, it's a FALSE POSITIVE.

## Output Format

Return a JSON object:
\`\`\`json
{
  "validated": [
    {
      "bugId": "BUG-001",
      "verdict": "VALID",
      "reasoning": "Why this is a real bug",
      "adjustedSeverity": "high",
      "adjustedConfidence": "high"
    }
  ],
  "rejected": [
    {
      "bugId": "BUG-002",
      "verdict": "FALSE_POSITIVE",
      "reasoning": "Why this is not actually a bug"
    }
  ]
}
\`\`\`

Now validate each bug:`;
}

// ─────────────────────────────────────────────────────────────
// Deep Dive Prompts - Targeted analysis of suspicious areas
// ─────────────────────────────────────────────────────────────

export function buildDeepDivePrompt(
  type: 'auth-flow' | 'data-flow' | 'attack-chain' | 'session',
  areas: SuspiciousArea[],
  understanding: CodebaseUnderstanding,
): string {
  // Get the relevant flow pass config
  const passMap: Record<string, string> = {
    'auth-flow': 'auth-flow-trace',
    'data-flow': 'data-flow-trace',
    'attack-chain': 'attack-chain-analysis',
    'session': 'session-lifecycle-trace',
  };

  const passConfig = FLOW_PASSES.find(p => p.name === passMap[type]);
  if (!passConfig) {
    throw new Error(`Unknown deep dive type: ${type}`);
  }

  const areaList = areas.map(a => `
- **File**: ${a.file}${a.lines ? `:${a.lines.start}-${a.lines.end}` : ''}
  **Reason**: ${a.reason}
`).join('\n');

  return `# Deep Dive: ${passConfig.description}

## Suspicious Areas Identified in Triage
${areaList}

## What to Look For
${passConfig.whatToFind.map(w => `- ${w}`).join('\n')}

## Trace Instructions
${passConfig.traceInstructions}

## Example Vulnerability
\`\`\`
${passConfig.exampleVulnerability}
\`\`\`

## Project Context
${understanding.summary || 'No summary available'}

## Your Task

1. **FOCUS** on the suspicious areas identified above
2. **TRACE** data/control flow as specified
3. **FIND** bugs that require cross-file analysis
4. **REPORT** only confirmed vulnerabilities

## Output Format

Return a JSON object:
\`\`\`json
{
  "bugs": [
    {
      "id": "FLOW-001",
      "title": "Short descriptive title",
      "category": "auth-bypass|injection|...",
      "severity": "critical|high|medium|low",
      "confidence": {
        "overall": "high|medium|low",
        "factors": {
          "patternMatch": true,
          "dataFlowConfirmed": true,
          "exploitPathClear": true
        }
      },
      "file": "path/to/file.ts",
      "line": 42,
      "endLine": 45,
      "description": "What's wrong and how the flow creates the vulnerability",
      "evidence": ["Entry point code", "Sink code", "Missing check"],
      "triggerScenario": "Step-by-step attack scenario",
      "impact": "What happens if exploited",
      "suggestedFix": "How to fix it"
    }
  ]
}
\`\`\`

Now trace the flows and find bugs:`;
}

// ─────────────────────────────────────────────────────────────
// Smart Pass Selection - Choose deep dives based on triage
// ─────────────────────────────────────────────────────────────

export function selectDeepDives(
  suspiciousAreas: SuspiciousArea[],
  maxDives: number = 3,
): ('auth-flow' | 'data-flow' | 'attack-chain' | 'session')[] {
  // Count votes for each deep dive type
  const votes: Record<string, number> = {
    'auth-flow': 0,
    'data-flow': 0,
    'attack-chain': 0,
    'session': 0,
  };

  for (const area of suspiciousAreas) {
    if (area.suggestedDeepDive !== 'none') {
      // Weight by confidence
      const weight = area.confidence === 'high' ? 3 : area.confidence === 'medium' ? 2 : 1;
      votes[area.suggestedDeepDive] += weight;
    }
  }

  // Sort by votes and take top N
  const sorted = Object.entries(votes)
    .filter(([_, count]) => count > 0)
    .sort((a, b) => b[1] - a[1])
    .slice(0, maxDives)
    .map(([type]) => type as 'auth-flow' | 'data-flow' | 'attack-chain' | 'session');

  return sorted;
}

// ─────────────────────────────────────────────────────────────
// Merge and Dedupe Final Results
// ─────────────────────────────────────────────────────────────

export function mergeAndDedupe(
  triageBugs: Bug[],
  deepDiveBugs: Bug[],
): Bug[] {
  const all = [...triageBugs, ...deepDiveBugs];
  const seen = new Map<string, Bug>();

  for (const bug of all) {
    // Key by file + line range + category
    const key = `${bug.file}:${bug.line}:${bug.endLine || bug.line}:${bug.category}`;
    const existing = seen.get(key);

    if (!existing) {
      seen.set(key, bug);
    } else {
      // Keep the one with higher confidence, merge evidence
      const confOrder = { high: 3, medium: 2, low: 1 };
      if (confOrder[bug.confidence.overall] >= confOrder[existing.confidence.overall]) {
        bug.evidence = [...new Set([...bug.evidence, ...existing.evidence])];
        seen.set(key, bug);
      } else {
        existing.evidence = [...new Set([...existing.evidence, ...bug.evidence])];
      }
    }
  }

  return Array.from(seen.values());
}

// ─────────────────────────────────────────────────────────────
// Phase Progress Callbacks
// ─────────────────────────────────────────────────────────────

export interface ScanProgress {
  onPhaseStart: (phase: string, description: string) => void;
  onPhaseComplete: (phase: string, result: string) => void;
  onBugFound: (bug: Bug) => void;
}

export const DEFAULT_PROGRESS: ScanProgress = {
  onPhaseStart: () => {},
  onPhaseComplete: () => {},
  onBugFound: () => {},
};
