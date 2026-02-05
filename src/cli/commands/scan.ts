import * as p from '@clack/prompts';
import chalk from 'chalk';
import { existsSync, writeFileSync } from 'fs';
import { join } from 'path';
import fg from 'fast-glob';
import { WhiteroseConfig, ScanResult, Bug, ConfidenceLevel, ProviderType } from '../../types.js';
import { loadConfig, loadUnderstanding } from '../../core/config.js';
import { CoreScanner } from '../../core/scanner.js';
import { getExecutor } from '../../providers/executors/index.js';
import { scanCodebase, getChangedFiles, saveFileHashes } from '../../core/scanner/index.js';
import { runStaticAnalysis } from '../../analysis/static.js';
import { generateBugId } from '../../core/utils.js';
import { outputSarif } from '../../output/sarif.js';
import { outputMarkdown } from '../../output/markdown.js';
import { outputHumanReadableMarkdown } from '../../output/human-readable.js';
import { mergeBugs } from '../../core/bug-merger.js';
import { analyzeCrossFile } from '../../core/cross-file-analyzer.js';
import { analyzeContracts } from '../../core/contract-analyzer.js';
import { analyzeIntentContracts, classifyFindings } from '../../core/findings.js';

interface ScanOptions {
  full: boolean;
  json: boolean;
  sarif: boolean;
  provider?: string;
  category?: string[];
  minConfidence: string;
  ci?: boolean; // CI mode: non-interactive, exit 1 if bugs found
  quick?: boolean; // Quick scan: parallel single-file analysis, works without init
  unsafe?: boolean; // Deprecated: read-only operations always auto-approve
  phase?: 'unit' | 'integration' | 'e2e' | 'all'; // Which analysis phase to run
}

export async function scanCommand(paths: string[], options: ScanOptions): Promise<void> {
  const cwd = process.cwd();
  const whiterosePath = join(cwd, '.whiterose');

  // Quick scan mode: works without init, uses changed files only
  const isQuickScan = options.quick || options.ci;
  const isQuiet = options.json || options.sarif || options.ci;

  // For thorough scan, require init
  if (!isQuickScan && !existsSync(whiterosePath)) {
    if (!isQuiet) {
      p.log.error('whiterose is not initialized in this directory.');
      p.log.info('Run "whiterose init" first, or use --quick for fast pre-commit scanning.');
    } else {
      console.error(JSON.stringify({ error: 'Not initialized. Run whiterose init first.' }));
    }
    process.exit(1);
  }

  if (!isQuiet) {
    const scanMode = isQuickScan ? 'quick scan (pre-commit)' : 'thorough scan';
    p.intro(chalk.red('whiterose') + chalk.dim(` - ${scanMode}`));
  }

  // ─────────────────────────────────────────────────────────────
  // Load config and understanding (optional for quick scan)
  // ─────────────────────────────────────────────────────────────
  let config: WhiteroseConfig | undefined;
  let understanding: any;

  if (existsSync(whiterosePath)) {
    try {
      config = await loadConfig(cwd);
      understanding = await loadUnderstanding(cwd);
    } catch (err) {
      // Config load failed - warn user that defaults will be used
      const errorMessage = err instanceof Error ? err.message : String(err);
      if (!isQuiet) {
        p.log.warn(`Failed to load config: ${errorMessage}`);
        p.log.info('Continuing with default settings. Run "whiterose init" to fix.');
      } else if (options.ci) {
        // In CI mode, config parse errors should fail the build
        console.error(JSON.stringify({
          error: 'Config parse error',
          message: errorMessage,
          hint: 'Fix config.yml or run "whiterose init" to regenerate'
        }));
        process.exit(1);
      }
    }
  }

  // Create minimal understanding for quick scan if none exists
  if (!understanding) {
    understanding = {
      version: '1',
      generatedAt: new Date().toISOString(),
      summary: {
        type: 'unknown',
        framework: 'unknown',
        language: 'typescript', // Assume TS for now
        description: 'Quick scan mode - no understanding available',
      },
      features: [],
      contracts: [],
      dependencies: {},
      structure: { totalFiles: 0, totalLines: 0 },
    };
  }

  // ─────────────────────────────────────────────────────────────
  // Determine files to scan
  // ─────────────────────────────────────────────────────────────
  let filesToScan: string[];
  let scanType: 'full' | 'incremental';
  let pendingHashState: any = null;

  if (options.full || paths.length > 0) {
    scanType = 'full';
    if (!isQuiet) {
      const spinner = p.spinner();
      spinner.start('Scanning files...');
      if (paths.length > 0) {
        // Expand glob patterns in provided paths
        filesToScan = await fg(paths, {
          cwd,
          ignore: ['node_modules/**', 'dist/**', 'build/**', '.next/**'],
          absolute: false,
        });
      } else {
        filesToScan = await scanCodebase(cwd, config);
      }
      spinner.stop(`Found ${filesToScan.length} files to scan`);
    } else {
      if (paths.length > 0) {
        filesToScan = await fg(paths, {
          cwd,
          ignore: ['node_modules/**', 'dist/**', 'build/**', '.next/**'],
          absolute: false,
        });
      } else {
        filesToScan = await scanCodebase(cwd, config);
      }
    }
  } else {
    // Incremental scan requires config
    if (!config) {
      // Fall back to full scan if no config
      scanType = 'full';
      filesToScan = await scanCodebase(cwd);
    } else {
      scanType = 'incremental';
      const changed = await getChangedFiles(cwd, config, { writeCache: false });
      filesToScan = changed.files;
      pendingHashState = changed.state;
    }

    if (filesToScan.length === 0) {
      if (!isQuiet) {
        p.log.info('No files changed since last scan. Use --full for a complete scan.');
      } else {
        console.log(JSON.stringify({ bugs: [], message: 'No changes detected' }));
      }
      process.exit(0);
    }

    if (!isQuiet) {
      p.log.info(`Incremental scan: ${filesToScan.length} changed files`);
    }
  }

  // ─────────────────────────────────────────────────────────────
  // Run static analysis
  // ─────────────────────────────────────────────────────────────
  let staticResults;
  if (!isQuiet) {
    const staticSpinner = p.spinner();
    staticSpinner.start('Running static analysis (tsc, eslint)...');
    staticResults = await runStaticAnalysis(cwd, filesToScan, config);
    staticSpinner.stop(`Static analysis: ${staticResults.length} signals found`);
  } else {
    staticResults = await runStaticAnalysis(cwd, filesToScan, config);
  }

  // ─────────────────────────────────────────────────────────────
  // LLM Analysis (using CoreScanner - LSP-compliant architecture)
  // ─────────────────────────────────────────────────────────────
  const providerName = (options.provider || config?.provider || 'claude-code') as ProviderType;

  // Get the executor (simple prompt runner) for the selected provider
  const executor = getExecutor(providerName);

  // Check if provider is available
  if (!await executor.isAvailable()) {
    if (!isQuiet) {
      p.log.error(`Provider ${providerName} is not available. Is it installed?`);
    }
    process.exit(1);
  }

  let bugs: Bug[];
  if (!isQuiet) {
    const llmSpinner = p.spinner();
    const analysisStartTime = Date.now();
    llmSpinner.start(`Analyzing with ${providerName}...`);

    // Create scanner with progress callback
    const scanner = new CoreScanner(executor, {}, {
      onProgress: (message: string) => {
        // Stop spinner and print all progress messages
        // This ensures users see batch status, pass results, etc.
        if (message.trim()) {
          llmSpinner.stop('');

          // Color code based on content
          if (message.includes('════')) {
            console.log(chalk.cyan(message));
          } else if (message.includes('✓')) {
            console.log(chalk.green(message));
          } else if (message.includes('✗')) {
            console.log(chalk.red(message));
          } else if (message.includes('[Batch')) {
            console.log(chalk.yellow(message));
          } else {
            console.log(chalk.dim(message));
          }

          llmSpinner.start('Scanning...');
        }
      },
      onBugFound: (bug: Bug) => {
        llmSpinner.stop('');
        console.log(chalk.magenta(`  ★ Found: ${bug.title} (${bug.severity})`));
        llmSpinner.start('Scanning...');
      },
    });

    try {
      // Use quickScan for --quick/--ci, full scan otherwise
      if (isQuickScan) {
        bugs = await scanner.quickScan({
          files: filesToScan,
          understanding,
          staticResults: staticResults || [],
          config,
        });
      } else {
        bugs = await scanner.scan({
          files: filesToScan,
          understanding,
          staticResults: staticResults || [],
          config,
        });
      }
      const totalTime = Math.floor((Date.now() - analysisStartTime) / 1000);
      llmSpinner.stop(`Found ${bugs.length} potential bugs (${totalTime}s)`);

      // Check for pass errors - warn user if some passes failed
      if (scanner.hasPassErrors()) {
        const errors = scanner.getPassErrors();
        p.log.warn(`${errors.length} analysis pass(es) failed:`);
        for (const err of errors.slice(0, 5)) {
          console.log(chalk.yellow(`  - ${err.passName}: ${err.error}`));
        }
        if (errors.length > 5) {
          console.log(chalk.yellow(`  ... and ${errors.length - 5} more`));
        }
      }
    } catch (error) {
      llmSpinner.stop('Analysis failed');
      p.log.error(String(error));
      process.exit(1);
    }
  } else {
    const scanner = new CoreScanner(executor);

    if (isQuickScan) {
      bugs = await scanner.quickScan({
        files: filesToScan,
        understanding,
        staticResults: staticResults || [],
        config,
      });
    } else {
      bugs = await scanner.scan({
        files: filesToScan,
        understanding,
        staticResults: staticResults || [],
        config,
      });
    }

    // In CI mode, if ALL passes failed and we have no bugs, exit with error
    // This prevents silent failures from being reported as successful scans
    if (options.ci && scanner.hasPassErrors()) {
      const errors = scanner.getPassErrors();
      // If we have some bugs despite errors, continue (partial success)
      // But if we have 0 bugs and errors occurred, that's a scan failure
      if (bugs.length === 0) {
        console.error(JSON.stringify({
          error: 'Analysis failed',
          passErrors: errors,
        }));
        process.exit(1);
      }
    }
  }

  // Note: Adversarial validation is now inline during analysis
  // Claude validates each bug before reporting it

  // ─────────────────────────────────────────────────────────────
  // Cross-file analysis (finds bugs spanning multiple files)
  // ─────────────────────────────────────────────────────────────
  if (!isQuickScan) {
    if (!isQuiet) {
      const crossFileSpinner = p.spinner();
      crossFileSpinner.start('Running cross-file analysis...');
      try {
        const crossFileBugs = await analyzeCrossFile(cwd);
        if (crossFileBugs.length > 0) {
          bugs.push(...crossFileBugs);
          crossFileSpinner.stop(`Cross-file analysis: ${crossFileBugs.length} issues found`);
        } else {
          crossFileSpinner.stop('Cross-file analysis: no issues');
        }
      } catch {
        crossFileSpinner.stop('Cross-file analysis: skipped');
      }
    } else {
      try {
        const crossFileBugs = await analyzeCrossFile(cwd);
        bugs.push(...crossFileBugs);
      } catch (err) {
        // In CI mode, surface analysis failures so they don't go unnoticed
        if (options.ci) {
          console.error(JSON.stringify({
            error: 'Cross-file analysis failed',
            message: err instanceof Error ? err.message : String(err),
          }));
          process.exit(1);
        }
        // For non-CI quiet modes (--json, --sarif), skip silently
      }
    }
  }

  // ─────────────────────────────────────────────────────────────
  // Contract analysis (finds missing rollback, verification, etc.)
  // ─────────────────────────────────────────────────────────────
  if (!isQuickScan) {
    if (!isQuiet) {
      const contractSpinner = p.spinner();
      contractSpinner.start('Running contract analysis...');
      try {
        const contractBugs = await analyzeContracts(cwd);
        if (contractBugs.length > 0) {
          bugs.push(...contractBugs);
          contractSpinner.stop(`Contract analysis: ${contractBugs.length} issues found`);
        } else {
          contractSpinner.stop('Contract analysis: no issues');
        }
      } catch {
        contractSpinner.stop('Contract analysis: skipped');
      }
    } else {
      try {
        const contractBugs = await analyzeContracts(cwd);
        bugs.push(...contractBugs);
      } catch (err) {
        // In CI mode, surface analysis failures so they don't go unnoticed
        if (options.ci) {
          console.error(JSON.stringify({
            error: 'Contract analysis failed',
            message: err instanceof Error ? err.message : String(err),
          }));
          process.exit(1);
        }
        // For non-CI quiet modes (--json, --sarif), skip silently
      }
    }
  }

  // ─────────────────────────────────────────────────────────────
  // Intent validation (contract existence + intent alignment)
  // ─────────────────────────────────────────────────────────────
  if (!isQuickScan) {
    try {
      const intentBugs = analyzeIntentContracts(cwd, understanding);
      if (intentBugs.length > 0) {
        bugs.push(...intentBugs);
      }
    } catch (err) {
      // In CI mode, surface analysis failures so they don't go unnoticed
      if (options.ci) {
        console.error(JSON.stringify({
          error: 'Intent validation failed',
          message: err instanceof Error ? err.message : String(err),
        }));
        process.exit(1);
      }
      // For non-CI quiet modes (--json, --sarif) or interactive, skip silently
    }
  }

  // ─────────────────────────────────────────────────────────────
  // Filter by confidence
  // ─────────────────────────────────────────────────────────────
  const confidenceOrder: Record<ConfidenceLevel, number> = { high: 3, medium: 2, low: 1 };
  const validConfidenceLevels: ConfidenceLevel[] = ['high', 'medium', 'low'];
  const minConfidence: ConfidenceLevel = validConfidenceLevels.includes(options.minConfidence as ConfidenceLevel)
    ? (options.minConfidence as ConfidenceLevel)
    : 'low';
  bugs = bugs.filter((bug) => confidenceOrder[bug.confidence.overall] >= confidenceOrder[minConfidence]);

  // ─────────────────────────────────────────────────────────────
  // Filter by category
  // ─────────────────────────────────────────────────────────────
  if (options.category && options.category.length > 0) {
    bugs = bugs.filter((bug) => options.category!.includes(bug.category));
  }

  // ─────────────────────────────────────────────────────────────
  // Classify findings (bug vs smell) using intent + evidence
  // ─────────────────────────────────────────────────────────────
  bugs = classifyFindings(bugs, cwd, understanding);

  // ─────────────────────────────────────────────────────────────
  // Assign IDs
  // ─────────────────────────────────────────────────────────────
  bugs = bugs.map((bug, index) => ({
    ...bug,
    id: bug.id || generateBugId(index),
  }));

  // ─────────────────────────────────────────────────────────────
  // Merge with accumulated bugs (union across scans)
  // ─────────────────────────────────────────────────────────────
  const mergeResult = mergeBugs(bugs, cwd);
  const newBugsThisScan = mergeResult.stats.newBugs;

  if (!isQuiet && mergeResult.stats.existingBugs > 0) {
    p.log.info(
      `Merged: ${newBugsThisScan} new bugs + ${mergeResult.stats.existingBugs} existing = ${mergeResult.stats.total} total` +
      (mergeResult.stats.duplicatesSkipped > 0 ? ` (${mergeResult.stats.duplicatesSkipped} duplicates skipped)` : '')
    );
  }

  // Use the full accumulated bug list for output
  const allBugs = mergeResult.bugs;

  // ─────────────────────────────────────────────────────────────
  // Create scan result
  // ─────────────────────────────────────────────────────────────
  const result: ScanResult = {
    id: `scan-${Date.now()}`,
    timestamp: new Date().toISOString(),
    scanType,
    filesScanned: filesToScan.length,
    filesChanged: scanType === 'incremental' ? filesToScan.length : undefined,
    duration: 0, // TODO: track actual duration
    bugs: allBugs, // Use accumulated bugs (union across all scans)
    summary: {
      critical: allBugs.filter((b) => b.kind === 'bug' && b.severity === 'critical').length,
      high: allBugs.filter((b) => b.kind === 'bug' && b.severity === 'high').length,
      medium: allBugs.filter((b) => b.kind === 'bug' && b.severity === 'medium').length,
      low: allBugs.filter((b) => b.kind === 'bug' && b.severity === 'low').length,
      total: allBugs.length,
      bugs: allBugs.filter((b) => b.kind === 'bug').length,
      smells: allBugs.filter((b) => b.kind === 'smell').length,
    },
  };

  // ─────────────────────────────────────────────────────────────
  // Output
  // ─────────────────────────────────────────────────────────────
  // Persist hash cache only after a successful analysis run
  if (pendingHashState) {
    try {
      saveFileHashes(cwd, pendingHashState);
    } catch {
      // Non-fatal: cache persistence failure should not break scan output
    }
  }

  if (options.json || (options.ci && !options.sarif)) {
    // JSON output (default for CI mode)
    console.log(JSON.stringify(result, null, 2));
    // CI mode: exit with code 1 if bugs found
    if (options.ci && result.summary.bugs > 0) {
      process.exit(1);
    }
  } else if (options.sarif) {
    console.log(JSON.stringify(outputSarif(result), null, 2));
    // CI mode: exit with code 1 if bugs found
    if (options.ci && result.summary.bugs > 0) {
      process.exit(1);
    }
  } else {
    // Create output directory
    const outputDir = join(cwd, 'whiterose-output');
    const reportsDir = join(whiterosePath, 'reports');
    const { mkdirSync } = await import('fs');

    try {
      mkdirSync(outputDir, { recursive: true });
      mkdirSync(reportsDir, { recursive: true });
    } catch {
      // Directory already exists
    }

    const timestamp = new Date().toISOString().split('T')[0];

    // Always save all formats
    // 1. Technical Markdown
    const markdown = outputMarkdown(result);
    const mdPath = join(outputDir, 'bugs.md');
    writeFileSync(mdPath, markdown);

    // 2. Human-Readable Markdown (tester-friendly)
    const humanReadable = outputHumanReadableMarkdown(result);
    const humanPath = join(outputDir, 'bugs-human.md');
    writeFileSync(humanPath, humanReadable);

    // 3. SARIF
    const sarifPath = join(outputDir, 'bugs.sarif');
    writeFileSync(sarifPath, JSON.stringify(outputSarif(result), null, 2));

    // 4. JSON
    const jsonPath = join(outputDir, 'bugs.json');
    writeFileSync(jsonPath, JSON.stringify(result, null, 2));

    // Also save to reports directory with timestamp for history
    writeFileSync(join(reportsDir, `${timestamp}.sarif`), JSON.stringify(outputSarif(result), null, 2));

    // Show summary
    console.log();
    p.log.message(chalk.bold('Scan Results'));
    console.log();
    console.log(`  ${chalk.red('●')} Critical: ${result.summary.critical}`);
    console.log(`  ${chalk.yellow('●')} High: ${result.summary.high}`);
    console.log(`  ${chalk.blue('●')} Medium: ${result.summary.medium}`);
    console.log(`  ${chalk.dim('●')} Low: ${result.summary.low}`);
    console.log();
    if (newBugsThisScan > 0) {
      console.log(`  ${chalk.green('+')} New this scan: ${newBugsThisScan}`);
    }
    console.log(
      `  ${chalk.bold('Total findings:')} ${result.summary.total} ` +
      `(bugs: ${result.summary.bugs}, smells: ${result.summary.smells})`
    );
    console.log();

    // Show saved files
    p.log.success('Reports saved:');
    console.log(`  ${chalk.dim('├')} ${chalk.cyan(humanPath)} ${chalk.dim('(tester-friendly)')}`);
    console.log(`  ${chalk.dim('├')} ${chalk.cyan(mdPath)} ${chalk.dim('(technical)')}`);
    console.log(`  ${chalk.dim('├')} ${chalk.cyan(sarifPath)}`);
    console.log(`  ${chalk.dim('└')} ${chalk.cyan(jsonPath)}`);
    console.log();

    if (result.summary.total > 0) {
      p.log.info(`Run ${chalk.cyan('whiterose fix')} to fix bugs interactively.`);
    }

    p.outro(chalk.green('Scan complete'));
  }
}
