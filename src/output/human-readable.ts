/**
 * Human-Readable Bug Report Formatter
 *
 * Transforms technical bug reports into tester-friendly format:
 * - Title = What goes wrong (outcome, not implementation)
 * - What happens = Plain English consequence
 * - How to trigger = Steps a tester would take
 * - Impact = Why should I care
 * - Technical details = Hidden, for developers
 */

import { Bug, ScanResult, BugCategory, BugSeverity } from '../types.js';

export interface HumanReadableBug {
  id: string;
  humanTitle: string;
  whatHappens: string;
  howToTrigger: string[];
  impact: string;
  severity: BugSeverity;
  category: BugCategory;
  technicalDetails: {
    title: string;
    file: string;
    line: number;
    endLine?: number;
    description: string;
    evidence: string[];
    suggestedFix?: string;
    codePath: Array<{ step: number; file: string; line: number; explanation: string }>;
  };
}

// ─────────────────────────────────────────────────────────────
// Category-specific templates for human-readable descriptions
// ─────────────────────────────────────────────────────────────

const CATEGORY_TEMPLATES: Record<BugCategory, {
  humanTitleTemplate: (title: string) => string;
  whatHappensTemplate: (desc: string) => string;
  impactTemplate: (severity: BugSeverity) => string;
  triggerHints: string[];
}> = {
  'injection': {
    humanTitleTemplate: (t) => t.includes('SQL') ? 'Database can be manipulated by attackers' :
                               t.includes('command') ? 'System commands can be hijacked' :
                               t.includes('path') ? 'Attackers can access unauthorized files' :
                               t.includes('XSS') ? 'Malicious scripts can run in user browsers' :
                               'User input can be used to attack the system',
    whatHappensTemplate: (d) => `An attacker can inject malicious data that the system executes as code or commands. ${d.split('.')[0]}.`,
    impactTemplate: (s) => s === 'critical' ? 'Complete system compromise, data breach, or unauthorized access is possible.' :
                          s === 'high' ? 'Sensitive data exposure or unauthorized actions are possible.' :
                          'Limited data exposure or restricted unauthorized actions.',
    triggerHints: ['Enter special characters in input fields', 'Include quotes or semicolons in form data', 'Try URL parameters with encoded characters'],
  },
  'auth-bypass': {
    humanTitleTemplate: () => 'Users can access features they shouldnt have permission for',
    whatHappensTemplate: (d) => `Some users can bypass authentication or authorization checks to access restricted features. ${d.split('.')[0]}.`,
    impactTemplate: (s) => s === 'critical' ? 'Any user can gain admin access or access all user data.' :
                          s === 'high' ? 'Users can access other users data or restricted features.' :
                          'Minor privilege escalation in non-critical features.',
    triggerHints: ['Try accessing admin pages while logged out', 'Access resources using another users ID', 'Remove auth cookies and retry requests'],
  },
  'secrets-exposure': {
    humanTitleTemplate: (t) => t.includes('random') ? 'Predictable IDs or tokens can be guessed' :
                               t.includes('hardcoded') ? 'Passwords or API keys are visible in the code' :
                               'Sensitive information may be exposed',
    whatHappensTemplate: (d) => `Sensitive information like passwords, API keys, or tokens could be exposed to attackers. ${d.split('.')[0]}.`,
    impactTemplate: (s) => s === 'critical' ? 'Attackers can gain full access to external services or admin accounts.' :
                          s === 'high' ? 'Attackers can guess tokens or access partial system credentials.' :
                          'Information useful for further attacks may be exposed.',
    triggerHints: ['Check browser console for exposed data', 'Look at network requests for sensitive info', 'Review error messages for credential leaks'],
  },
  'null-reference': {
    humanTitleTemplate: () => 'The page or feature can crash unexpectedly',
    whatHappensTemplate: (d) => `The application may crash or show an error when encountering unexpected empty data. ${d.split('.')[0]}.`,
    impactTemplate: () => 'Users experience crashes, error pages, or incomplete data when this happens.',
    triggerHints: ['Leave optional fields empty', 'Delete data that other features depend on', 'Access items that have been removed'],
  },
  'boundary-error': {
    humanTitleTemplate: () => 'Data can be corrupted or lost at edge cases',
    whatHappensTemplate: (d) => `The system doesnt handle boundary conditions correctly, which can cause data issues. ${d.split('.')[0]}.`,
    impactTemplate: () => 'Data may be truncated, lost, or display incorrectly at the limits.',
    triggerHints: ['Enter very long text in input fields', 'Try negative numbers or zero', 'Create empty lists then access items'],
  },
  'resource-leak': {
    humanTitleTemplate: () => 'System performance degrades over time',
    whatHappensTemplate: (d) => `System resources are not properly released, causing gradual performance degradation. ${d.split('.')[0]}.`,
    impactTemplate: () => 'The system becomes slower over time, may crash, or stop responding after extended use.',
    triggerHints: ['Use the feature repeatedly many times', 'Leave the page open for extended periods', 'Navigate away and back multiple times'],
  },
  'async-issue': {
    humanTitleTemplate: () => 'Operations can happen out of order causing data issues',
    whatHappensTemplate: (d) => `Concurrent operations may interfere with each other, causing race conditions or data corruption. ${d.split('.')[0]}.`,
    impactTemplate: () => 'Data may be saved incorrectly or operations may fail silently when used rapidly.',
    triggerHints: ['Click buttons rapidly multiple times', 'Submit forms twice quickly', 'Open the same feature in multiple tabs'],
  },
  'logic-error': {
    humanTitleTemplate: (t) => t.includes('operator') ? 'Calculations or comparisons give wrong results' :
                               t.includes('regex') ? 'Search or validation accepts invalid data' :
                               'The feature doesnt work as expected',
    whatHappensTemplate: (d) => `The code logic produces incorrect results in certain situations. ${d.split('.')[0]}.`,
    impactTemplate: () => 'Features may produce wrong results, accept invalid data, or skip important checks.',
    triggerHints: ['Enter edge case values (0, negative, very large)', 'Test with special characters', 'Try inputs that almost match expected format'],
  },
  'data-validation': {
    humanTitleTemplate: () => 'Invalid data can be submitted and saved',
    whatHappensTemplate: (d) => `User input is not properly validated, allowing bad data into the system. ${d.split('.')[0]}.`,
    impactTemplate: (s) => s === 'critical' || s === 'high' ? 'Invalid data can cause system errors or security issues.' :
                          'Data quality issues and inconsistent behavior.',
    triggerHints: ['Enter wrong format data (letters in number fields)', 'Submit empty required fields', 'Exceed maximum lengths'],
  },
  'type-coercion': {
    humanTitleTemplate: () => 'Data types can get mixed up causing errors',
    whatHappensTemplate: (d) => `The system doesnt properly check data types, leading to unexpected behavior. ${d.split('.')[0]}.`,
    impactTemplate: () => 'Features may crash or produce incorrect results with certain inputs.',
    triggerHints: ['Enter text where numbers are expected', 'Submit data from API tools with wrong types', 'Modify hidden form fields'],
  },
  'concurrency': {
    humanTitleTemplate: () => 'Multiple users can cause data conflicts',
    whatHappensTemplate: (d) => `When multiple users work on the same data simultaneously, conflicts can occur. ${d.split('.')[0]}.`,
    impactTemplate: () => 'Data can be lost or corrupted when multiple users edit the same item.',
    triggerHints: ['Edit the same item in two browser tabs', 'Have two users modify the same record', 'Submit changes rapidly'],
  },
  'intent-violation': {
    humanTitleTemplate: () => 'The feature doesnt do what its supposed to',
    whatHappensTemplate: (d) => `The actual behavior differs from what the code comments or names suggest it should do. ${d.split('.')[0]}.`,
    impactTemplate: () => 'Features may work differently than documented or expected.',
    triggerHints: ['Compare actual behavior to documentation', 'Test edge cases not covered in docs', 'Check if error handling matches expectations'],
  },
};

/**
 * Transform a technical bug into a human-readable format
 */
export function toHumanReadable(bug: Bug): HumanReadableBug {
  const template = CATEGORY_TEMPLATES[bug.category];

  // Generate human-friendly title
  const humanTitle = template.humanTitleTemplate(bug.title);

  // Generate what happens description
  const whatHappens = template.whatHappensTemplate(bug.description);

  // Generate impact statement
  const impact = template.impactTemplate(bug.severity);

  // Generate trigger steps based on category hints + bug specifics
  const howToTrigger = generateTriggerSteps(bug, template.triggerHints);

  return {
    id: bug.id,
    humanTitle,
    whatHappens,
    howToTrigger,
    impact,
    severity: bug.severity,
    category: bug.category,
    technicalDetails: {
      title: bug.title,
      file: bug.file,
      line: bug.line,
      endLine: bug.endLine,
      description: bug.description,
      evidence: bug.evidence,
      suggestedFix: bug.suggestedFix,
      codePath: bug.codePath.map(s => ({
        step: s.step,
        file: s.file,
        line: s.line,
        explanation: s.explanation,
      })),
    },
  };
}

/**
 * Generate specific trigger steps from bug details
 */
function generateTriggerSteps(bug: Bug, categoryHints: string[]): string[] {
  const steps: string[] = [];

  // Try to extract trigger info from bug details
  const bugData = bug as any;
  if (bugData.triggerInput) {
    steps.push(`Use this input: ${bugData.triggerInput}`);
  }

  // Add file-based hint
  const fileName = bug.file.split('/').pop() || bug.file;
  if (fileName.includes('api') || fileName.includes('route') || fileName.includes('controller')) {
    steps.push(`Access the API endpoint related to ${fileName}`);
  } else if (fileName.includes('component') || fileName.includes('page')) {
    steps.push(`Navigate to the page containing this feature`);
  }

  // Add category-specific hints
  steps.push(...categoryHints.slice(0, 2));

  // If we have code path, extract trigger hints
  if (bug.codePath.length > 0) {
    const entry = bug.codePath[0];
    if (entry.explanation.toLowerCase().includes('user input') ||
        entry.explanation.toLowerCase().includes('enters')) {
      steps.unshift(`Start by providing input at: ${entry.file.split('/').pop()}:${entry.line}`);
    }
  }

  return steps.slice(0, 4); // Max 4 steps
}

/**
 * Format human-readable bug as markdown
 */
export function formatHumanReadableMarkdown(bug: HumanReadableBug): string {
  const severityIcon = {
    critical: '🔴',
    high: '🟠',
    medium: '🟡',
    low: '⚪',
  }[bug.severity];

  return `### ${severityIcon} ${bug.humanTitle}

**What happens:** ${bug.whatHappens}

**How to trigger:**
${bug.howToTrigger.map((s, i) => `${i + 1}. ${s}`).join('\n')}

**Impact:** ${bug.impact}

<details>
<summary>Technical Details</summary>

- **ID:** ${bug.id}
- **File:** \`${bug.technicalDetails.file}:${bug.technicalDetails.line}\`
- **Category:** ${bug.category}
- **Technical Title:** ${bug.technicalDetails.title}

${bug.technicalDetails.description}

${bug.technicalDetails.evidence.length > 0 ? `**Evidence:**\n${bug.technicalDetails.evidence.map(e => `- ${e}`).join('\n')}` : ''}

${bug.technicalDetails.suggestedFix ? `**Suggested Fix:**\n\`\`\`\n${bug.technicalDetails.suggestedFix}\n\`\`\`` : ''}

${bug.technicalDetails.codePath.length > 0 ? `**Code Path:**\n${bug.technicalDetails.codePath.map(s => `${s.step}. \`${s.file.split('/').pop()}:${s.line}\` - ${s.explanation}`).join('\n')}` : ''}

</details>

---
`;
}

/**
 * Generate a complete human-readable report
 */
export function outputHumanReadableMarkdown(result: ScanResult): string {
  const humanBugs = result.bugs
    .filter(b => b.kind === 'bug')
    .map(toHumanReadable);

  const sections: string[] = [];

  // Header
  sections.push(`# Bug Report

> Human-readable summary generated by whiterose on ${new Date(result.timestamp).toLocaleDateString()}
> **${result.summary.bugs} bugs found** in ${result.filesScanned} files

---

## Summary

| Severity | Count | Description |
|----------|-------|-------------|
| 🔴 Critical | ${result.summary.critical} | Requires immediate attention |
| 🟠 High | ${result.summary.high} | Should be fixed soon |
| 🟡 Medium | ${result.summary.medium} | Fix when convenient |
| ⚪ Low | ${result.summary.low} | Minor issues |

---
`);

  // Group by severity
  const bySeverity = {
    critical: humanBugs.filter(b => b.severity === 'critical'),
    high: humanBugs.filter(b => b.severity === 'high'),
    medium: humanBugs.filter(b => b.severity === 'medium'),
    low: humanBugs.filter(b => b.severity === 'low'),
  };

  if (bySeverity.critical.length > 0) {
    sections.push(`## 🔴 Critical Issues\n\nThese must be fixed immediately.\n\n${bySeverity.critical.map(formatHumanReadableMarkdown).join('\n')}`);
  }

  if (bySeverity.high.length > 0) {
    sections.push(`## 🟠 High Priority Issues\n\nThese should be fixed soon.\n\n${bySeverity.high.map(formatHumanReadableMarkdown).join('\n')}`);
  }

  if (bySeverity.medium.length > 0) {
    sections.push(`## 🟡 Medium Priority Issues\n\nFix when convenient.\n\n${bySeverity.medium.map(formatHumanReadableMarkdown).join('\n')}`);
  }

  if (bySeverity.low.length > 0) {
    sections.push(`## ⚪ Low Priority Issues\n\nMinor improvements.\n\n${bySeverity.low.map(formatHumanReadableMarkdown).join('\n')}`);
  }

  // Footer
  sections.push(`---

*Generated by [whiterose](https://github.com/whiterose) - 10x Bug Hunter*
`);

  return sections.join('\n\n');
}
