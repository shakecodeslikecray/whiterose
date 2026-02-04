/**
 * Bug Merger - Union bugs across multiple scans
 *
 * Ensures deterministic bug accumulation by merging new bugs
 * with existing bugs using fingerprint-based deduplication.
 *
 * Fingerprint: file + function name + category
 * This survives minor line number shifts and code reformatting.
 */

import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'fs';
import { join, dirname, relative } from 'path';
import { Bug } from '../types.js';

// ─────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────

interface BugFingerprint {
  file: string;        // Relative file path
  functionName: string; // Extracted from title or code path
  category: string;     // Bug category
  kind: string;         // Bug vs smell
  lineRange: string;    // Approximate line range (rounded to 10s)
}

interface MergeResult {
  bugs: Bug[];
  stats: {
    total: number;
    newBugs: number;
    existingBugs: number;
    duplicatesSkipped: number;
  };
}

interface StoredBugList {
  version: string;
  lastUpdated: string;
  bugs: Bug[];
  fingerprints: Record<string, string>; // fingerprint hash -> bug id
}

// ─────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────

const STORAGE_VERSION = '1';
const BUGS_FILENAME = 'accumulated-bugs.json';

// ─────────────────────────────────────────────────────────────
// Fingerprinting
// ─────────────────────────────────────────────────────────────

/**
 * Extract function name from bug data
 * Tries: title, code path, or falls back to line-based identifier
 */
function extractFunctionName(bug: Bug): string {
  // Try to extract from title (e.g., "Null dereference in getUserById")
  const titleMatch = bug.title.match(/\bin\s+(\w+)/i);
  if (titleMatch) {
    return titleMatch[1];
  }

  // Try to extract from code path
  if (bug.codePath && bug.codePath.length > 0) {
    // Look for function calls or definitions in code
    for (const step of bug.codePath) {
      const funcMatch = step.code?.match(/(?:function|async function|const|let|var)\s+(\w+)|(\w+)\s*\(/);
      if (funcMatch) {
        return funcMatch[1] || funcMatch[2];
      }
    }
  }

  // Fall back to "unknown" + line range
  return `unknown_L${Math.floor(bug.line / 10) * 10}`;
}

/**
 * Create a fingerprint for a bug
 */
function createFingerprint(bug: Bug, cwd: string): BugFingerprint {
  // Normalize file path to relative
  const relativeFile = bug.file.startsWith('/')
    ? relative(cwd, bug.file)
    : bug.file;

  return {
    file: relativeFile,
    functionName: extractFunctionName(bug),
    category: bug.category,
    kind: bug.kind || 'bug',
    lineRange: `${Math.floor(bug.line / 10) * 10}-${Math.floor((bug.endLine || bug.line) / 10) * 10 + 10}`,
  };
}

/**
 * Hash a fingerprint to a string key
 */
function hashFingerprint(fp: BugFingerprint): string {
  return `${fp.file}::${fp.functionName}::${fp.category}::${fp.kind}::${fp.lineRange}`;
}

/**
 * Create a looser fingerprint for fuzzy matching
 * (ignores line range for catching bugs that moved slightly)
 */
function hashFingerprintLoose(fp: BugFingerprint): string {
  return `${fp.file}::${fp.functionName}::${fp.category}::${fp.kind}`;
}

// ─────────────────────────────────────────────────────────────
// Storage
// ─────────────────────────────────────────────────────────────

/**
 * Get the path to the accumulated bugs file
 */
function getBugsPath(cwd: string): string {
  return join(cwd, '.whiterose', BUGS_FILENAME);
}

/**
 * Load existing accumulated bugs
 */
export function loadAccumulatedBugs(cwd: string): StoredBugList {
  const bugsPath = getBugsPath(cwd);

  if (!existsSync(bugsPath)) {
    return {
      version: STORAGE_VERSION,
      lastUpdated: new Date().toISOString(),
      bugs: [],
      fingerprints: {},
    };
  }

  try {
    const content = readFileSync(bugsPath, 'utf-8');
    const stored = JSON.parse(content) as StoredBugList;

    // Version check
    if (stored.version !== STORAGE_VERSION) {
      console.warn('Bug list version mismatch, starting fresh');
      return {
        version: STORAGE_VERSION,
        lastUpdated: new Date().toISOString(),
        bugs: [],
        fingerprints: {},
      };
    }

    // Normalize missing fields for backward compatibility
    if (!Array.isArray(stored.bugs)) {
      stored.bugs = [];
    }
    stored.bugs = stored.bugs.map((b) => ({ ...b, kind: b.kind || 'bug' }));
    return stored;
  } catch {
    return {
      version: STORAGE_VERSION,
      lastUpdated: new Date().toISOString(),
      bugs: [],
      fingerprints: {},
    };
  }
}

/**
 * Save accumulated bugs
 */
export function saveAccumulatedBugs(cwd: string, stored: StoredBugList): void {
  const bugsPath = getBugsPath(cwd);
  const bugsDir = dirname(bugsPath);

  // Ensure directory exists
  if (!existsSync(bugsDir)) {
    mkdirSync(bugsDir, { recursive: true });
  }

  stored.lastUpdated = new Date().toISOString();
  writeFileSync(bugsPath, JSON.stringify(stored, null, 2));
}

// ─────────────────────────────────────────────────────────────
// Merging
// ─────────────────────────────────────────────────────────────

/**
 * Merge new bugs with existing accumulated bugs
 * Returns the merged list and stats about what was added
 */
export function mergeBugs(
  newBugs: Bug[],
  cwd: string
): MergeResult {
  const stored = loadAccumulatedBugs(cwd);
  const existingFingerprints = new Set(Object.keys(stored.fingerprints));
  const existingLooseFingerprints = new Map<string, string>(); // loose hash -> bug id

  // Build loose fingerprint map for existing bugs
  for (const bug of stored.bugs) {
    const fp = createFingerprint(bug, cwd);
    existingLooseFingerprints.set(hashFingerprintLoose(fp), bug.id);
  }

  let duplicatesSkipped = 0;
  const bugsToAdd: Bug[] = [];

  for (const bug of newBugs) {
    bug.kind = bug.kind || 'bug';
    const fp = createFingerprint(bug, cwd);
    const strictHash = hashFingerprint(fp);
    const looseHash = hashFingerprintLoose(fp);

    // Check strict match first
    if (existingFingerprints.has(strictHash)) {
      duplicatesSkipped++;
      continue;
    }

    // Check loose match (same file + function + category, different line range)
    if (existingLooseFingerprints.has(looseHash)) {
      // Update the existing bug's line numbers if the new one is more recent
      const existingBugId = existingLooseFingerprints.get(looseHash)!;
      const existingBugIndex = stored.bugs.findIndex(b => b.id === existingBugId);
      if (existingBugIndex !== -1) {
        // Update line numbers to latest
        stored.bugs[existingBugIndex].line = bug.line;
        stored.bugs[existingBugIndex].endLine = bug.endLine;
        // Update suggested fix if new one is better
        if (bug.suggestedFix && (!stored.bugs[existingBugIndex].suggestedFix || bug.suggestedFix.length > stored.bugs[existingBugIndex].suggestedFix!.length)) {
          stored.bugs[existingBugIndex].suggestedFix = bug.suggestedFix;
        }
      }
      duplicatesSkipped++;
      continue;
    }

    // New bug - add it
    bugsToAdd.push(bug);
    stored.fingerprints[strictHash] = bug.id;
    existingFingerprints.add(strictHash);
    existingLooseFingerprints.set(looseHash, bug.id);
  }

  // Add new bugs to stored list with unique IDs
  // Find the highest existing ID number
  let maxIdNum = 0;
  for (const bug of stored.bugs) {
    const match = bug.id.match(/WR-(\d+)/);
    if (match) {
      maxIdNum = Math.max(maxIdNum, parseInt(match[1], 10));
    }
  }

  // Assign new unique IDs to bugs being added
  for (const bug of bugsToAdd) {
    maxIdNum++;
    const oldId = bug.id;
    bug.id = `WR-${String(maxIdNum).padStart(3, '0')}`;
    // Update fingerprint mapping with new ID
    for (const [hash, id] of Object.entries(stored.fingerprints)) {
      if (id === oldId) {
        stored.fingerprints[hash] = bug.id;
      }
    }
    stored.bugs.push(bug);
  }

  // Save updated list
  saveAccumulatedBugs(cwd, stored);

  return {
    bugs: stored.bugs,
    stats: {
      total: stored.bugs.length,
      newBugs: bugsToAdd.length,
      existingBugs: stored.bugs.length - bugsToAdd.length,
      duplicatesSkipped,
    },
  };
}

/**
 * Get only the new bugs from a merge (for reporting to user)
 */
export function getNewBugsOnly(
  newBugs: Bug[],
  cwd: string
): Bug[] {
  const stored = loadAccumulatedBugs(cwd);
  const existingLooseFingerprints = new Set<string>();

  // Build loose fingerprint set for existing bugs
  for (const bug of stored.bugs) {
    const fp = createFingerprint(bug, cwd);
    existingLooseFingerprints.add(hashFingerprintLoose(fp));
  }

  // Filter to only new bugs
  return newBugs.filter(bug => {
    const fp = createFingerprint(bug, cwd);
    return !existingLooseFingerprints.has(hashFingerprintLoose(fp));
  });
}

/**
 * Clear all accumulated bugs (start fresh)
 */
export function clearAccumulatedBugs(cwd: string): void {
  const bugsPath = getBugsPath(cwd);
  if (existsSync(bugsPath)) {
    const fresh: StoredBugList = {
      version: STORAGE_VERSION,
      lastUpdated: new Date().toISOString(),
      bugs: [],
      fingerprints: {},
    };
    writeFileSync(bugsPath, JSON.stringify(fresh, null, 2));
  }
}

/**
 * Remove a specific bug from accumulated list (after it's been fixed)
 */
export function removeBugFromAccumulated(cwd: string, bugId: string): boolean {
  const stored = loadAccumulatedBugs(cwd);
  const bugIndex = stored.bugs.findIndex(b => b.id === bugId);

  if (bugIndex === -1) {
    return false;
  }

  const bug = stored.bugs[bugIndex];
  const fp = createFingerprint(bug, cwd);
  const strictHash = hashFingerprint(fp);

  // Remove from bugs array
  stored.bugs.splice(bugIndex, 1);

  // Remove from fingerprints
  delete stored.fingerprints[strictHash];

  // Save
  saveAccumulatedBugs(cwd, stored);
  return true;
}

/**
 * Get accumulated bugs stats
 */
export function getAccumulatedBugsStats(cwd: string): {
  total: number;
  byCategory: Record<string, number>;
  bySeverity: Record<string, number>;
  lastUpdated: string;
} {
  const stored = loadAccumulatedBugs(cwd);

  const byCategory: Record<string, number> = {};
  const bySeverity: Record<string, number> = {};

  for (const bug of stored.bugs) {
    byCategory[bug.category] = (byCategory[bug.category] || 0) + 1;
    bySeverity[bug.severity] = (bySeverity[bug.severity] || 0) + 1;
  }

  return {
    total: stored.bugs.length,
    byCategory,
    bySeverity,
    lastUpdated: stored.lastUpdated,
  };
}
