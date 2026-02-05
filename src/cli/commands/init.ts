import * as p from '@clack/prompts';
import chalk from 'chalk';
import { existsSync, mkdirSync, writeFileSync, rmSync, readFileSync } from 'fs';
import { join } from 'path';
import { WhiteroseConfig, ProviderType, CodebaseUnderstanding } from '../../types.js';
import { detectProvider, getProviderCommand } from '../../providers/detect.js';
import { getExecutor } from '../../providers/executors/index.js';
import { CoreScanner } from '../../core/scanner.js';
import { execa } from 'execa';
import { scanCodebase } from '../../core/scanner/index.js';
import { generateIntentDocument } from '../../core/contracts/intent.js';
import { readExistingDocs, extractIntentFromDocs, buildDocsSummary } from '../../core/docs.js';
import YAML from 'yaml';

interface InitOptions {
  provider: string;
  skipQuestions?: boolean;
  force: boolean;
  ci?: boolean; // CI mode: non-interactive, use defaults
  unsafe?: boolean; // Deprecated: read-only operations always auto-approve
  skipProviderDetection?: boolean; // Skip provider detection when already verified (e.g., from wizard)
}

export async function initCommand(options: InitOptions): Promise<void> {
  const cwd = process.cwd();
  const whiterosePath = join(cwd, '.whiterose');

  // Check if already initialized
  if (existsSync(whiterosePath) && !options.force) {
    p.log.error('whiterose is already initialized in this directory.');
    p.log.info('Use --force to reinitialize, or run "whiterose refresh" to update understanding.');
    process.exit(1);
  }

  p.intro(chalk.red('whiterose') + chalk.dim(' - initialization'));

  // ─────────────────────────────────────────────────────────────
  // Phase 1: Detect available providers (skip if already verified)
  // ─────────────────────────────────────────────────────────────
  let selectedProvider: ProviderType;

  if (options.skipProviderDetection && options.provider) {
    // Provider already verified by wizard - use directly
    selectedProvider = options.provider as ProviderType;
  } else {
    const providerSpinner = p.spinner();
    providerSpinner.start('Detecting available LLM providers...');

    const availableProviders = await detectProvider();

    if (availableProviders.length === 0) {
      providerSpinner.stop('No LLM providers detected');
      p.log.error('whiterose requires an LLM provider to function.');
      p.log.info('Supported providers: claude-code, aider, codex, opencode');
      p.log.info('Install one and ensure it\'s configured, then run init again.');
      process.exit(1);
    }

    providerSpinner.stop(`Detected providers: ${availableProviders.join(', ')}`);

    // Check if provider was passed and is available
    const passedProvider = options.provider as ProviderType;
    const isPassedProviderAvailable = availableProviders.includes(passedProvider);

    if (isPassedProviderAvailable) {
      // Use the passed provider without asking
      selectedProvider = passedProvider;
      p.log.info(`Using ${selectedProvider} as your LLM provider.`);
    } else if (options.skipQuestions) {
      // Only auto-select in skip mode
      selectedProvider = availableProviders[0] as ProviderType;
      p.log.info(`Using ${selectedProvider} as your LLM provider.`);
    } else {
      const providerChoice = await p.select({
        message: 'Which LLM provider should whiterose use?',
        options: availableProviders.map((prov) => ({
          value: prov,
          label: prov,
          hint: prov === 'claude-code' ? 'recommended' : undefined,
        })),
      });

      if (p.isCancel(providerChoice)) {
        p.cancel('Initialization cancelled.');
        process.exit(0);
      }

      selectedProvider = providerChoice as ProviderType;
    }
  }

  // ─────────────────────────────────────────────────────────────
  // Phase 1.5: Verify provider CLI actually works (fail fast)
  // ─────────────────────────────────────────────────────────────
  const verifySpinner = p.spinner();
  verifySpinner.start('Verifying provider CLI works...');

  try {
    const command = getProviderCommand(selectedProvider);
    await execa(command, ['--version'], { timeout: 10000 });
    verifySpinner.stop(`Using ${selectedProvider} at: ${command}`);
  } catch (error: any) {
    verifySpinner.stop('Provider CLI verification failed');
    const installHint = selectedProvider === 'claude-code'
      ? 'npm install -g @anthropic-ai/claude-code'
      : `Install ${selectedProvider} and ensure it's in your PATH`;
    p.log.error(`Cannot run ${selectedProvider} CLI. ${installHint}`);
    p.log.info(`Resolved path: ${getProviderCommand(selectedProvider)}`);
    if (error.message) {
      p.log.info(`Error: ${error.message}`);
    }
    process.exit(1);
  }

  // ─────────────────────────────────────────────────────────────
  // Phase 2: Full codebase scan
  // ─────────────────────────────────────────────────────────────
  const scanSpinner = p.spinner();
  scanSpinner.start('Scanning codebase...');

  let codebaseFiles: string[];
  try {
    codebaseFiles = await scanCodebase(cwd);
    scanSpinner.stop(`Found ${codebaseFiles.length} source files`);
  } catch (error) {
    scanSpinner.stop('Failed to scan codebase');
    p.log.error(String(error));
    process.exit(1);
  }

  // ─────────────────────────────────────────────────────────────
  // Phase 2.5: Read existing documentation (Layer 0)
  // ─────────────────────────────────────────────────────────────
  const docsSpinner = p.spinner();
  docsSpinner.start('Reading existing documentation...');

  let docsSummary: string | undefined;
  try {
    const existingDocs = await readExistingDocs(cwd);
    const extractedIntent = extractIntentFromDocs(existingDocs);
    docsSummary = buildDocsSummary(existingDocs, extractedIntent);

    const docsFound = [];
    if (existingDocs.readme) docsFound.push('README');
    if (existingDocs.contributing) docsFound.push('CONTRIBUTING');
    if (existingDocs.packageJson) docsFound.push('package.json');
    if (existingDocs.envExample) docsFound.push('.env.example');
    if (existingDocs.apiDocs.length > 0) docsFound.push(`${existingDocs.apiDocs.length} API docs`);

    if (docsFound.length > 0) {
      docsSpinner.stop(`Found existing docs: ${docsFound.join(', ')}`);
    } else {
      docsSpinner.stop('No existing documentation found (will generate from code)');
      docsSummary = undefined;
    }
  } catch (error) {
    docsSpinner.stop('Could not read existing docs (continuing without)');
    docsSummary = undefined;
  }

  // ─────────────────────────────────────────────────────────────
  // Phase 3: Generate understanding via LLM (merge with existing docs)
  // ─────────────────────────────────────────────────────────────
  const understandingSpinner = p.spinner();
  const startTime = Date.now();

  understandingSpinner.start('Starting codebase analysis...');

  let understanding: CodebaseUnderstanding;
  try {
    const executor = getExecutor(selectedProvider);
    const scanner = new CoreScanner(executor, {}, {
      onProgress: (message: string) => {
        if (message.trim()) {
          understandingSpinner.message(message);
        }
      },
    });

    // Pass existing docs summary to merge with AI exploration
    understanding = await scanner.generateUnderstanding(codebaseFiles, docsSummary);

    const totalTime = Math.floor((Date.now() - startTime) / 1000);
    understandingSpinner.stop(`Analysis complete (${totalTime}s)`);
  } catch (error) {
    understandingSpinner.stop('Analysis failed');
    p.log.error(String(error));
    process.exit(1);
  }

  // ─────────────────────────────────────────────────────────────
  // Phase 4: Show summary and confirm understanding
  // ─────────────────────────────────────────────────────────────
  const skipInteractive = options.skipQuestions || options.ci;
  if (!skipInteractive) {
    p.log.message(chalk.bold('\nHere\'s what I understand about your codebase:\n'));
    p.log.message(`  ${chalk.cyan('Type:')} ${understanding.summary.type}`);
    p.log.message(`  ${chalk.cyan('Framework:')} ${understanding.summary.framework || 'None detected'}`);
    p.log.message(`  ${chalk.cyan('Language:')} ${understanding.summary.language}`);
    p.log.message(`  ${chalk.cyan('Files:')} ${understanding.structure.totalFiles}`);
    p.log.message(`  ${chalk.cyan('Lines:')} ${understanding.structure.totalLines.toLocaleString()}`);
    p.log.message(`\n  ${chalk.dim(understanding.summary.description)}\n`);

    if (understanding.features.length > 0) {
      p.log.message(chalk.bold('Detected features:'));
      for (const feature of understanding.features.slice(0, 5)) {
        p.log.message(`  ${chalk.yellow('●')} ${feature.name} - ${chalk.dim(feature.description)}`);
      }
      if (understanding.features.length > 5) {
        p.log.message(`  ${chalk.dim(`...and ${understanding.features.length - 5} more`)}`);
      }
      console.log();
    }

    const isAccurate = await p.confirm({
      message: 'Is this understanding accurate?',
      initialValue: true,
    });

    if (p.isCancel(isAccurate)) {
      p.cancel('Initialization cancelled.');
      process.exit(0);
    }

    if (!isAccurate) {
      p.log.info('You can edit .whiterose/intent.md after initialization to correct the understanding.');
    }

    // Priorities are now auto-determined by the LLM based on detected features
    // Auth, payments, checkout = critical. User data = high. UI = medium. etc.
    const priorities: Record<string, 'critical' | 'high' | 'medium' | 'low' | 'ignore'> = {};
    for (const feature of understanding.features) {
      for (const file of feature.relatedFiles) {
        priorities[file] = feature.priority;
      }
    }
    (understanding as any)._userPriorities = priorities;
  }

  // ─────────────────────────────────────────────────────────────
  // Phase 6: Create .whiterose directory and files
  // ─────────────────────────────────────────────────────────────
  const writeSpinner = p.spinner();
  writeSpinner.start('Creating configuration...');

  // Track whether .whiterose existed before (for rollback decisions)
  const whiteroseExistedBefore = existsSync(whiterosePath);
  // Save original .gitignore content for rollback
  const gitignorePath = join(cwd, '.gitignore');
  const originalGitignore = existsSync(gitignorePath) ? readFileSync(gitignorePath, 'utf-8') : null;

  try {
    // Create directory structure
    mkdirSync(join(whiterosePath, 'cache'), { recursive: true });
    mkdirSync(join(whiterosePath, 'reports'), { recursive: true });

    // Generate config
    const config: WhiteroseConfig = {
      version: '1',
      provider: selectedProvider,
      include: ['**/*.ts', '**/*.tsx', '**/*.js', '**/*.jsx'],
      exclude: ['node_modules', 'dist', 'build', '.next', 'coverage', '**/*.test.*', '**/*.spec.*'],
      priorities: (understanding as any)._userPriorities || {},
      categories: [
        'injection', 'auth-bypass', 'secrets-exposure',
        'null-reference', 'boundary-error', 'resource-leak', 'async-issue',
        'logic-error', 'data-validation', 'type-coercion',
        'concurrency', 'intent-violation',
      ],
      minConfidence: 'low',
      staticAnalysis: {
        typescript: true,
        eslint: true,
      },
      output: {
        sarif: true,
        markdown: true,
        sarifPath: '.whiterose/reports',
        markdownPath: 'BUGS.md',
      },
    };

    // Prepare all file contents before writing (fail fast on generation errors)
    const intentDoc = generateIntentDocument(understanding);
    const configContent = YAML.stringify(config);
    const understandingContent = JSON.stringify(understanding, null, 2);
    const hashesContent = JSON.stringify({ version: '1', fileHashes: [], lastFullScan: null }, null, 2);

    // Write all files atomically (all-or-nothing approach)
    writeFileSync(join(whiterosePath, 'config.yml'), configContent, 'utf-8');
    writeFileSync(join(whiterosePath, 'cache', 'understanding.json'), understandingContent, 'utf-8');
    writeFileSync(join(whiterosePath, 'intent.md'), intentDoc, 'utf-8');
    writeFileSync(join(whiterosePath, 'cache', 'file-hashes.json'), hashesContent, 'utf-8');

    // Add to .gitignore if it exists and doesn't already have the entry
    if (originalGitignore !== null && !originalGitignore.includes('.whiterose/cache')) {
      writeFileSync(gitignorePath, originalGitignore + '\n# whiterose cache\n.whiterose/cache/\n', 'utf-8');
    }

    writeSpinner.stop('Configuration created');
  } catch (error) {
    writeSpinner.stop('Failed to create configuration');

    // Rollback: clean up .whiterose if we created it
    if (!whiteroseExistedBefore && existsSync(whiterosePath)) {
      try {
        rmSync(whiterosePath, { recursive: true, force: true });
        p.log.info('Rolled back: removed .whiterose directory');
      } catch {
        // Ignore rollback errors
      }
    }

    // Rollback: restore original .gitignore if we modified it
    if (originalGitignore !== null && existsSync(gitignorePath)) {
      try {
        const currentGitignore = readFileSync(gitignorePath, 'utf-8');
        if (currentGitignore !== originalGitignore) {
          writeFileSync(gitignorePath, originalGitignore, 'utf-8');
          p.log.info('Rolled back: restored .gitignore');
        }
      } catch {
        // Ignore rollback errors
      }
    }

    p.log.error(String(error));
    process.exit(1);
  }

  // ─────────────────────────────────────────────────────────────
  // Done
  // ─────────────────────────────────────────────────────────────
  p.outro(chalk.green('whiterose initialized successfully!'));

  console.log();
  console.log(chalk.dim('  Next steps:'));
  console.log(chalk.dim('  1. Review .whiterose/intent.md and edit if needed'));
  console.log(chalk.dim('  2. Run ') + chalk.cyan('whiterose scan') + chalk.dim(' to find bugs'));
  console.log(chalk.dim('  3. Run ') + chalk.cyan('whiterose fix') + chalk.dim(' to fix them interactively'));
  console.log();
}
