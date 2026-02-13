import * as p from '@clack/prompts';
import chalk from 'chalk';
import { existsSync, readFileSync } from 'fs';
import { join, basename } from 'path';
import { loadConfig, loadUnderstanding } from '../../core/config.js';
import { detectProvider } from '../../providers/detect.js';
import { getAccumulatedBugsStats } from '../../core/bug-merger.js';
import { ScanResult } from '../../types.js';
import { renderScanCard, renderStatusCard, CardData } from '../components/card.js';


/**
 * Get repository name from git or directory name
 */
function getRepoName(cwd: string): string {
  try {
    const gitConfigPath = join(cwd, '.git', 'config');
    if (existsSync(gitConfigPath)) {
      const config = readFileSync(gitConfigPath, 'utf-8');
      const match = config.match(/url\s*=\s*.*[/:]([^/]+?)(?:\.git)?$/m);
      if (match) return match[1];
    }
  } catch {
    // Fall through to basename
  }
  return basename(cwd);
}

export async function statusCommand(): Promise<void> {
  const cwd = process.cwd();
  const whiterosePath = join(cwd, '.whiterose');

  // Check if initialized
  if (!existsSync(whiterosePath)) {
    p.log.error('whiterose is not initialized in this directory.');
    p.log.info('Run "whiterose init" first.');
    process.exit(1);
  }

  console.log();
  console.log(chalk.red.bold('whiterose') + chalk.dim(' status'));
  console.log();

  // Load config
  const config = await loadConfig(cwd);
  const repoName = getRepoName(cwd);

  // Try to load last scan result for the card
  const lastScanPath = join(whiterosePath, 'last-scan.json');
  let lastScan: ScanResult | null = null;

  if (existsSync(lastScanPath)) {
    try {
      lastScan = JSON.parse(readFileSync(lastScanPath, 'utf-8')) as ScanResult;
    } catch {
      // Corrupted file, ignore
    }
  }

  // Show the card if we have a recent scan
  if (lastScan && lastScan.meta) {
    const cardData: CardData = {
      meta: lastScan.meta,
      bugs: lastScan.summary.bugs,
      smells: lastScan.summary.smells,
      reportPath: './whiterose-output/bugs-human.md',
    };
    console.log(renderScanCard(cardData));
    console.log();
    console.log(chalk.dim(`Last scan: ${new Date(lastScan.timestamp).toLocaleString()}`));
  } else {
    // Show minimal status card
    const bugStats = getAccumulatedBugsStats(cwd);
    const totalBugs = bugStats.bySeverity ? Object.values(bugStats.bySeverity).reduce((a, b) => a + b, 0) : 0;

    console.log(renderStatusCard(
      repoName,
      config.provider,
      totalBugs,
      0, // No smell tracking in accumulated bugs
      bugStats.lastUpdated ? new Date(bugStats.lastUpdated).toLocaleDateString() : undefined
    ));
  }

  console.log();

  // Detect available providers
  const availableProviders = await detectProvider();

  console.log(chalk.dim('Configuration'));
  console.log(`  Provider:  ${config.provider}`);
  console.log(`  Available: ${availableProviders.join(', ') || 'none'}`);
  console.log();

  // Load understanding if available
  const understanding = await loadUnderstanding(cwd);
  if (understanding) {
    console.log(chalk.dim('Codebase'));
    console.log(`  Type:      ${understanding.summary.type}`);
    console.log(`  Framework: ${understanding.summary.framework || 'none'}`);
    console.log(`  Files:     ${understanding.structure.totalFiles}`);
    console.log(`  Features:  ${understanding.features.length}`);
    console.log(`  Contracts: ${understanding.contracts.length}`);
    console.log();
  }

  // Check cache status
  const hashesPath = join(whiterosePath, 'cache', 'file-hashes.json');
  if (existsSync(hashesPath)) {
    try {
      const hashes = JSON.parse(readFileSync(hashesPath, 'utf-8'));
      console.log(chalk.dim('Cache'));
      console.log(`  Files tracked: ${hashes.fileHashes?.length || 0}`);
      console.log(`  Last full:     ${hashes.lastFullScan ? new Date(hashes.lastFullScan).toLocaleDateString() : 'never'}`);
      console.log();
    } catch {
      // Corrupted cache file, skip
    }
  }

  // Footer
  const bugStats = getAccumulatedBugsStats(cwd);
  if (bugStats.total > 0) {
    console.log(chalk.dim('Run "whiterose fix" to fix bugs, or "whiterose clear" to reset'));
  } else {
    console.log(chalk.dim('Run "whiterose scan" to scan for bugs'));
  }
  console.log();
}
