import { Command } from 'commander';
import chalk from 'chalk';
import * as p from '@clack/prompts';
import { existsSync } from 'fs';
import { join, resolve, basename } from 'path';
import { initCommand } from './commands/init.js';
import { scanCommand } from './commands/scan.js';
import { fixCommand } from './commands/fix.js';
import { refreshCommand } from './commands/refresh.js';
import { statusCommand } from './commands/status.js';
import { reportCommand } from './commands/report.js';
import { detectProvider } from '../providers/detect.js';
import { ProviderType } from '../types.js';
import { pathInput } from './utils/path-input.js';

const BANNER = `
${chalk.red('██╗    ██╗██╗  ██╗██╗████████╗███████╗██████╗  ██████╗ ███████╗███████╗')}
${chalk.red('██║    ██║██║  ██║██║╚══██╔══╝██╔════╝██╔══██╗██╔═══██╗██╔════╝██╔════╝')}
${chalk.red('██║ █╗ ██║███████║██║   ██║   █████╗  ██████╔╝██║   ██║███████╗█████╗  ')}
${chalk.red('██║███╗██║██╔══██║██║   ██║   ██╔══╝  ██╔══██╗██║   ██║╚════██║██╔══╝  ')}
${chalk.red('╚███╔███╔╝██║  ██║██║   ██║   ███████╗██║  ██║╚██████╔╝███████║███████╗')}
${chalk.red(' ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚══════╝')}

${chalk.dim('  "I\'ve been staring at your code for a long time."')}
`;

const program = new Command();

program
  .name('whiterose')
  .description('AI-powered bug hunter that uses your existing LLM subscription')
  .version('0.2.1')
  .hook('preAction', () => {
    // Show banner only for main commands, not help
    const args = process.argv.slice(2);
    if (!args.includes('--help') && !args.includes('-h') && args.length > 0) {
      console.log(BANNER);
    }
  });

// ─────────────────────────────────────────────────────────────
// init - First-time setup with intelligent onboarding
// ─────────────────────────────────────────────────────────────
program
  .command('init')
  .description('Initialize whiterose for this project (scans codebase, asks questions, generates config)')
  .option('-p, --provider <provider>', 'LLM provider to use', 'claude-code')
  .option('--skip-questions', 'Skip interactive questions, use defaults')
  .option('--force', 'Overwrite existing .whiterose directory')
  .option('--unsafe', 'Bypass LLM permission prompts (use with caution)')
  .action(initCommand);

// ─────────────────────────────────────────────────────────────
// scan - Find bugs
// ─────────────────────────────────────────────────────────────
program
  .command('scan [paths...]')
  .description('Scan for bugs in the codebase')
  .option('-f, --full', 'Force full scan (ignore cache)')
  .option('--json', 'Output as JSON only')
  .option('--sarif', 'Output as SARIF only')
  .option('-p, --provider <provider>', 'Override LLM provider')
  .option('-c, --category <categories...>', 'Filter by bug categories')
  .option('--min-confidence <level>', 'Minimum confidence level to report', 'low')
  .option('--no-adversarial', 'Skip adversarial validation (faster, less accurate)')
  .option('--unsafe', 'Bypass LLM permission prompts (use with caution)')
  .action(scanCommand);

// ─────────────────────────────────────────────────────────────
// fix - Interactive bug fixing TUI
// ─────────────────────────────────────────────────────────────
program
  .command('fix [bugId]')
  .description('Fix bugs interactively or by ID')
  .option('--dry-run', 'Show proposed fixes without applying')
  .option('--branch <name>', 'Create fixes in a new branch')
  .option('--sarif <path>', 'Load bugs from an external SARIF file')
  .option('--github <url>', 'Load bug from a GitHub issue URL')
  .option('--describe', 'Manually describe a bug to fix')
  .action(fixCommand);

// ─────────────────────────────────────────────────────────────
// refresh - Rebuild understanding from scratch
// ─────────────────────────────────────────────────────────────
program
  .command('refresh')
  .description('Rebuild codebase understanding from scratch')
  .option('--keep-config', 'Keep existing config, only regenerate understanding')
  .action(refreshCommand);

// ─────────────────────────────────────────────────────────────
// status - Show cache and scan status
// ─────────────────────────────────────────────────────────────
program
  .command('status')
  .description('Show whiterose status (cache, last scan, provider)')
  .action(statusCommand);

// ─────────────────────────────────────────────────────────────
// report - Generate bug report
// ─────────────────────────────────────────────────────────────
program
  .command('report')
  .description('Generate BUGS.md from last scan')
  .option('-o, --output <path>', 'Output path', 'BUGS.md')
  .option('--format <format>', 'Output format (markdown, sarif, json)', 'markdown')
  .action(reportCommand);

// ─────────────────────────────────────────────────────────────
// Interactive wizard when no command provided
// ─────────────────────────────────────────────────────────────
async function showInteractiveWizard(): Promise<void> {
  console.log(BANNER);

  p.intro(chalk.red('whiterose') + chalk.dim(' - AI Bug Hunter'));

  // ─────────────────────────────────────────────────────────────
  // Step 1: Repository path (with Tab completion)
  // ─────────────────────────────────────────────────────────────
  const cwd = process.cwd();
  const defaultPath = cwd;

  const repoPath = await pathInput({
    message: 'Repository path',
    defaultValue: defaultPath,
    validate: (value) => {
      const path = value || defaultPath;
      if (!existsSync(path)) {
        return 'Directory does not exist';
      }
      return undefined;
    },
  });

  if (repoPath === null) {
    p.cancel('Cancelled.');
    process.exit(0);
  }

  const targetPath = resolve(repoPath || defaultPath);
  const projectName = basename(targetPath);
  const whiterosePath = join(targetPath, '.whiterose');
  const isInitialized = existsSync(whiterosePath);

  // ─────────────────────────────────────────────────────────────
  // Step 2: Detect and select LLM provider
  // ─────────────────────────────────────────────────────────────
  const detectSpinner = p.spinner();
  detectSpinner.start('Detecting LLM providers...');

  const availableProviders = await detectProvider();
  detectSpinner.stop(`Found ${availableProviders.length} provider(s)`);

  if (availableProviders.length === 0) {
    p.log.error('No LLM providers detected on your system.');
    console.log();
    console.log(chalk.dim('  Supported providers:'));
    console.log(chalk.dim('  - claude-code: ') + chalk.cyan('npm install -g @anthropic-ai/claude-code'));
    console.log(chalk.dim('  - aider: ') + chalk.cyan('pip install aider-chat'));
    console.log();
    p.outro(chalk.red('Install a provider and try again.'));
    process.exit(1);
  }

  let selectedProvider: ProviderType;

  if (availableProviders.length === 1) {
    selectedProvider = availableProviders[0];
    p.log.info(`Using ${chalk.cyan(selectedProvider)} (only available provider)`);
  } else {
    const providerChoice = await p.select({
      message: 'Select LLM provider',
      options: availableProviders.map((provider) => ({
        value: provider,
        label: provider,
        hint: provider === 'claude-code' ? 'recommended' : undefined,
      })),
    });

    if (p.isCancel(providerChoice)) {
      p.cancel('Cancelled.');
      process.exit(0);
    }

    selectedProvider = providerChoice as ProviderType;
  }

  // ─────────────────────────────────────────────────────────────
  // Step 3: Ask about LLM permission prompts
  // ─────────────────────────────────────────────────────────────
  const bypassPrompts = await p.confirm({
    message: 'Bypass LLM permission prompts? (recommended for smoother experience)',
    initialValue: true,
  });

  if (p.isCancel(bypassPrompts)) {
    p.cancel('Cancelled.');
    process.exit(0);
  }

  const unsafeMode = bypassPrompts === true;

  if (!unsafeMode) {
    p.log.info(chalk.dim('You may need to accept prompts in the LLM CLI during analysis.'));
  }

  // ─────────────────────────────────────────────────────────────
  // Step 4: Initialize if needed
  // ─────────────────────────────────────────────────────────────
  if (!isInitialized) {
    p.log.warn(`Project "${projectName}" is not initialized.`);

    const shouldInit = await p.confirm({
      message: 'Initialize whiterose for this project?',
      initialValue: true,
    });

    if (p.isCancel(shouldInit) || !shouldInit) {
      p.cancel('Cannot scan without initialization.');
      process.exit(0);
    }

    // Change to target directory for init
    process.chdir(targetPath);

    await initCommand({
      provider: selectedProvider,
      skipQuestions: false,
      force: false,
      unsafe: unsafeMode,
      skipProviderDetection: true, // Already verified in wizard
    });

    console.log(); // spacing after init
  } else {
    // Change to target directory
    process.chdir(targetPath);
  }

  // ─────────────────────────────────────────────────────────────
  // Step 5: Scan depth
  // ─────────────────────────────────────────────────────────────
  const scanDepth = await p.select({
    message: 'Scan depth',
    options: [
      {
        value: 'quick',
        label: 'Quick scan',
        hint: 'faster, incremental changes only',
      },
      {
        value: 'deep',
        label: 'Deep scan',
        hint: 'thorough, full codebase analysis (recommended)',
      },
    ],
    initialValue: 'deep',
  });

  if (p.isCancel(scanDepth)) {
    p.cancel('Cancelled.');
    process.exit(0);
  }

  // ─────────────────────────────────────────────────────────────
  // Step 6: Start scan
  // ─────────────────────────────────────────────────────────────
  console.log();
  p.log.step('Starting scan...');
  console.log();

  await scanCommand([], {
    full: scanDepth === 'deep',
    json: false,
    sarif: false,
    provider: selectedProvider,
    category: undefined,
    minConfidence: 'low',
    adversarial: true,
    unsafe: unsafeMode,
  });
}

// Show interactive wizard when no command provided
if (process.argv.length === 2) {
  showInteractiveWizard().catch((error) => {
    console.error(chalk.red('Error:'), error.message);
    process.exit(1);
  });
} else {
  program.parse();
}
