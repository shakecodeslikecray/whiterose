/**
 * Analysis Cache
 *
 * Caches bug analysis results at the function level.
 * Uses content hashes to skip re-analyzing unchanged code.
 *
 * Cache structure:
 * - Key: function/method hash (content-based)
 * - Value: analysis result (bugs found, or clean)
 */

import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'fs';
import { join } from 'path';
import { Bug } from '../types.js';

// ─────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────

interface CachedAnalysis {
  hash: string;
  filePath: string;
  unitName: string;
  unitType: string;
  analyzedAt: string;
  bugs: CachedBug[];
  isClean: boolean;
}

interface CachedBug {
  line: number;
  endLine?: number;
  title: string;
  description: string;
  category: string;
  severity: string;
  kind?: string;
  suggestedFix?: string;
}

export interface CacheFile {
  version: string;
  createdAt: string;
  lastUpdated: string;
  entries: Record<string, CachedAnalysis>;
  stats: {
    totalEntries: number;
    cacheHits: number;
    cacheMisses: number;
  };
}

// ─────────────────────────────────────────────────────────────
// Cache Implementation
// ─────────────────────────────────────────────────────────────

const CACHE_VERSION = '1';
const CACHE_FILENAME = 'analysis-cache.json';

/**
 * Get the cache file path
 */
function getCachePath(projectDir: string): string {
  return join(projectDir, '.whiterose', 'cache', CACHE_FILENAME);
}

/**
 * Load the cache from disk
 */
export function loadCache(projectDir: string): CacheFile {
  const cachePath = getCachePath(projectDir);

  if (!existsSync(cachePath)) {
    return createEmptyCache();
  }

  try {
    const content = readFileSync(cachePath, 'utf-8');
    const cache = JSON.parse(content) as CacheFile;

    // Check version compatibility
    if (cache.version !== CACHE_VERSION) {
      console.warn('Cache version mismatch, creating new cache');
      return createEmptyCache();
    }

    if (!cache.entries || typeof cache.entries !== 'object') {
      cache.entries = {};
    }
    if (!cache.stats || typeof cache.stats !== 'object') {
      cache.stats = {
        totalEntries: 0,
        cacheHits: 0,
        cacheMisses: 0,
      };
    } else {
      cache.stats.totalEntries =
        typeof cache.stats.totalEntries === 'number' ? cache.stats.totalEntries : 0;
      cache.stats.cacheHits =
        typeof cache.stats.cacheHits === 'number' ? cache.stats.cacheHits : 0;
      cache.stats.cacheMisses =
        typeof cache.stats.cacheMisses === 'number' ? cache.stats.cacheMisses : 0;
    }

    return cache;
  } catch {
    return createEmptyCache();
  }
}

/**
 * Save the cache to disk
 */
export function saveCache(projectDir: string, cache: CacheFile): void {
  const cachePath = getCachePath(projectDir);
  const cacheDir = join(projectDir, '.whiterose', 'cache');

  // Ensure directory exists
  if (!existsSync(cacheDir)) {
    mkdirSync(cacheDir, { recursive: true });
  }

  cache.lastUpdated = new Date().toISOString();
  writeFileSync(cachePath, JSON.stringify(cache, null, 2));
}

/**
 * Create an empty cache
 */
function createEmptyCache(): CacheFile {
  return {
    version: CACHE_VERSION,
    createdAt: new Date().toISOString(),
    lastUpdated: new Date().toISOString(),
    entries: {},
    stats: {
      totalEntries: 0,
      cacheHits: 0,
      cacheMisses: 0,
    },
  };
}

/**
 * Check if we have a cached result for a code unit
 */
export function getCachedResult(
  cache: CacheFile,
  hash: string
): CachedAnalysis | null {
  const entry = cache.entries[hash];
  if (entry) {
    cache.stats.cacheHits++;
    return entry;
  }
  cache.stats.cacheMisses++;
  return null;
}

/**
 * Store analysis result in cache
 */
export function setCachedResult(
  cache: CacheFile,
  hash: string,
  filePath: string,
  unitName: string,
  unitType: string,
  bugs: Bug[]
): void {
  const cachedBugs: CachedBug[] = bugs.map((bug) => ({
    line: bug.line,
    endLine: bug.endLine,
    title: bug.title,
    description: bug.description,
    category: bug.category,
    severity: bug.severity,
    kind: bug.kind,
    suggestedFix: bug.suggestedFix,
  }));

  cache.entries[hash] = {
    hash,
    filePath,
    unitName,
    unitType,
    analyzedAt: new Date().toISOString(),
    bugs: cachedBugs,
    isClean: bugs.length === 0,
  };

  cache.stats.totalEntries = Object.keys(cache.entries).length;
}

/**
 * Convert cached bugs back to full Bug objects
 */
export function expandCachedBugs(
  cached: CachedAnalysis,
  filePath: string,
  idPrefix: string
): Bug[] {
  return cached.bugs.map((cachedBug, index) => ({
    id: `${idPrefix}-${index}`,
    title: cachedBug.title,
    description: cachedBug.description,
    file: filePath,
    line: cachedBug.line,
    endLine: cachedBug.endLine,
    kind: (cachedBug.kind as Bug['kind']) || 'bug',
    severity: cachedBug.severity as Bug['severity'],
    category: cachedBug.category as Bug['category'],
    confidence: {
      overall: 'high' as const, // Cached results were already validated
      codePathValidity: 0.9,
      reachability: 0.9,
      intentViolation: false,
      staticToolSignal: false,
      adversarialSurvived: true,
    },
    codePath: [],
    evidence: [`Cached result from ${cached.analyzedAt}`],
    suggestedFix: cachedBug.suggestedFix,
    createdAt: cached.analyzedAt,
    status: 'open' as const,
  }));
}

/**
 * Clear old entries from cache (entries older than maxAge days)
 */
export function pruneCache(cache: CacheFile, maxAgeDays: number = 30): number {
  const maxAgeMs = maxAgeDays * 24 * 60 * 60 * 1000;
  const now = Date.now();
  let pruned = 0;

  for (const [hash, entry] of Object.entries(cache.entries)) {
    const entryAge = now - new Date(entry.analyzedAt).getTime();
    if (entryAge > maxAgeMs) {
      delete cache.entries[hash];
      pruned++;
    }
  }

  cache.stats.totalEntries = Object.keys(cache.entries).length;
  return pruned;
}

/**
 * Get cache statistics
 */
export function getCacheStats(cache: CacheFile): {
  totalEntries: number;
  cacheHits: number;
  cacheMisses: number;
  hitRate: string;
  oldestEntry: string | null;
  newestEntry: string | null;
} {
  const entries = Object.values(cache.entries);
  const dates = entries.map((e) => new Date(e.analyzedAt).getTime());

  const total = cache.stats.cacheHits + cache.stats.cacheMisses;
  const hitRate = total > 0 ? ((cache.stats.cacheHits / total) * 100).toFixed(1) + '%' : 'N/A';

  return {
    totalEntries: cache.stats.totalEntries,
    cacheHits: cache.stats.cacheHits,
    cacheMisses: cache.stats.cacheMisses,
    hitRate,
    oldestEntry: dates.length > 0 ? new Date(Math.min(...dates)).toISOString() : null,
    newestEntry: dates.length > 0 ? new Date(Math.max(...dates)).toISOString() : null,
  };
}

/**
 * Clear all cache entries
 */
export function clearCache(projectDir: string): void {
  const cachePath = getCachePath(projectDir);
  if (existsSync(cachePath)) {
    writeFileSync(cachePath, JSON.stringify(createEmptyCache(), null, 2));
  }
}
