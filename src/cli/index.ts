import { Command } from 'commander';
import chalk from 'chalk';
import * as p from '@clack/prompts';
import { existsSync, readFileSync } from 'fs';
import { join, basename, dirname } from 'path';
import { fileURLToPath } from 'url';
import { initCommand } from './commands/init.js';
import { scanCommand } from './commands/scan.js';
import { fixCommand } from './commands/fix.js';
import { refreshCommand } from './commands/refresh.js';
import { statusCommand } from './commands/status.js';
import { reportCommand } from './commands/report.js';
import { clearCommand } from './commands/clear.js';
import { profileCommand } from './commands/profile.js';
import { detectProvider } from '../providers/detect.js';
import { ProviderType } from '../types.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const pkg = JSON.parse(readFileSync(join(__dirname, '../../package.json'), 'utf-8'));

// Increase max listeners to avoid warning when spawning multiple child processes
process.setMaxListeners(50);

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
  .version(pkg.version)
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
  .description('Initialize whiterose for this project (scans codebase, generates config)')
  .option('-p, --provider <provider>', 'LLM provider to use', 'claude-code')
  .option('--force', 'Overwrite existing .whiterose directory')
  .option('--ci', 'CI mode: non-interactive, use defaults (same as --skip-questions)')
  .option('--skip-questions', 'Skip interactive questions, use defaults')
  .action(initCommand);

// ─────────────────────────────────────────────────────────────
// scan - Find bugs
// ─────────────────────────────────────────────────────────────
program
  .command('scan [paths...]')
  .description('Scan for bugs in the codebase (includes inline validation)')
  .option('-f, --full', 'Force full scan (ignore cache)')
  .option('--json', 'Output as JSON only')
  .option('--sarif', 'Output as SARIF only')
  .option('-p, --provider <provider>', 'Override LLM provider')
  .option('-c, --category <categories...>', 'Filter by bug categories')
  .option('--min-confidence <level>', 'Minimum confidence level to report', 'low')
  .option('--ci', 'CI mode: non-interactive, exit code 1 if bugs found (for CI/CD and git hooks)')
  .option('--quick', 'Quick scan: fast parallel analysis without init (for pre-commit hooks)')
  .option('--phase <phase>', 'Run specific phase only: unit, integration, e2e, or all (default: all)')
  .action(scanCommand);

// ─────────────────────────────────────────────────────────────
// fix - Interactive bug fixing TUI
// ─────────────────────────────────────────────────────────────
program
  .command('fix [bugId]')
  .description('Fix bugs interactively or by ID')
  .option('-p, --provider <provider>', 'LLM provider to use for fixing')
  .option('--dry-run', 'Show proposed fixes without applying')
  .option('--branch <name>', 'Create fixes in a new branch')
  .option('--sarif <path>', 'Load bugs from an external SARIF file')
  .option('--github <url>', 'Load bug from a GitHub issue URL')
  .option('--describe', 'Manually describe a bug to fix')
  .option('--unsafe', 'Skip all permission prompts (full trust mode)')
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
// clear - Clear accumulated bugs
// ─────────────────────────────────────────────────────────────
program
  .command('clear')
  .description('Clear accumulated bug list (start fresh)')
  .option('--force', 'Skip confirmation prompt')
  .action(clearCommand);

// ─────────────────────────────────────────────────────────────
// profile - Generate risk profile for targeted scanning
// ─────────────────────────────────────────────────────────────
program
  .command('profile')
  .description('Generate risk profile for targeted scanning')
  .option('--json', 'Output as JSON')
  .action(profileCommand);

// ─────────────────────────────────────────────────────────────
// Auto-run: Minimal questions, maximum action
// ─────────────────────────────────────────────────────────────
async function autoRun(): Promise<void> {
  console.log(BANNER);

  p.intro(chalk.red('whiterose') + chalk.dim(' - AI Bug Hunter'));

  // Check if current directory looks like a project
  const cwd = process.cwd();
  const looksLikeProject = existsSync(join(cwd, 'package.json')) ||
                           existsSync(join(cwd, 'go.mod')) ||
                           existsSync(join(cwd, 'Cargo.toml')) ||
                           existsSync(join(cwd, 'requirements.txt')) ||
                           existsSync(join(cwd, 'pyproject.toml')) ||
                           existsSync(join(cwd, '.git')) ||
                           existsSync(join(cwd, 'src'));

  let targetPath = cwd;

  // If current dir doesn't look like a project, ask for path
  if (!looksLikeProject) {
    const { pathInput } = await import('./utils/path-input.js');
    const inputPath = await pathInput({
      message: 'Enter project path',
      defaultValue: cwd,
      validate: (value) => {
        const path = value || cwd;
        if (!existsSync(path)) {
          return 'Directory does not exist';
        }
        return undefined;
      },
    });

    if (inputPath === null) {
      p.cancel('Cancelled.');
      process.exit(0);
    }

    targetPath = inputPath || cwd;
    process.chdir(targetPath);
  }

  const projectName = basename(targetPath);
  const whiterosePath = join(targetPath, '.whiterose');
  const isInitialized = existsSync(whiterosePath);

  // ─────────────────────────────────────────────────────────────
  // Detect and select provider
  // ─────────────────────────────────────────────────────────────
  const detectSpinner = p.spinner();
  detectSpinner.start('Detecting LLM providers...');

  const availableProviders = await detectProvider();

  if (availableProviders.length === 0) {
    detectSpinner.stop('No providers found');
    p.log.error('No LLM providers detected on your system.');
    console.log();
    console.log(chalk.dim('  Install one of:'));
    console.log(chalk.dim('  - claude-code: ') + chalk.cyan('npm install -g @anthropic-ai/claude-code'));
    console.log(chalk.dim('  - aider: ') + chalk.cyan('pip install aider-chat'));
    console.log();
    process.exit(1);
  }

  detectSpinner.stop(`Found ${availableProviders.length} provider(s)`);

  let selectedProvider: ProviderType;

  if (availableProviders.length === 1) {
    selectedProvider = availableProviders[0];
    p.log.info(`Using ${chalk.cyan(selectedProvider)}`);
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
  // Auto-initialize if needed
  // ─────────────────────────────────────────────────────────────
  if (!isInitialized) {
    p.log.step(`Initializing whiterose for "${projectName}"...`);
    console.log();

    await initCommand({
      provider: selectedProvider,
      skipQuestions: true, // No questions, use defaults
      force: false,
      unsafe: false,
      skipProviderDetection: true,
    });

    console.log();
  }

  // ─────────────────────────────────────────────────────────────
  // Start bug hunting
  // ─────────────────────────────────────────────────────────────
  p.log.step('Starting bug hunt...');
  console.log();

  await scanCommand([], {
    full: true,
    json: false,
    sarif: false,
    provider: selectedProvider,
    category: undefined,
    minConfidence: 'low',
  });
}

// Auto-run when no command provided
if (process.argv.length === 2) {
  autoRun().catch((error) => {
    console.error(chalk.red('Error:'), error.message);
    process.exit(1);
  });
} else {
  program.parse();
}
